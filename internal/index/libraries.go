package index

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/archiveio"
	"github.com/shinyvision/kotlsp/internal/classfile"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

const gradleInitScript = `
gradle.projectsEvaluated {
    rootProject.tasks.register("kotlspClasspath") {
        doLast {
			def kotlspEmitSetting = { projectPath, sourceSet, key, value ->
				if (value != null && value.toString() != "") {
					def encoded = value.toString().getBytes("UTF-8").encodeBase64().toString()
					println("KOTLSP_COMPILER_SETTING=" + projectPath + "\t" + sourceSet + "\t" + key + "\t" + encoded)
				}
			}
			def kotlspDependencyTarget = { dependency ->
				if (dependency instanceof org.gradle.api.artifacts.ProjectDependency) return dependency.dependencyProject.path
				return "gradle:" + (dependency.group ?: "") + ":" + dependency.name + ":" + (dependency.version ?: "")
			}
			def kotlspEmitExclusions = { marker, projectPath, owner, dependency ->
				if (!(dependency instanceof org.gradle.api.artifacts.ModuleDependency)) return
				def target = kotlspDependencyTarget(dependency)
				dependency.excludeRules.each { rule ->
					println(marker + projectPath + "\t" + owner + "\t" + target + "\t" + (rule.group ?: "*") + "\t" + (rule.module ?: "*"))
				}
			}
            rootProject.allprojects.each { project ->
				println("KOTLSP_MODULE=" + project.path + "\t" + project.projectDir.absolutePath)
				println("KOTLSP_MODULE_COORDINATE=" + project.path + "\t" + (project.group ?: "") + "\t" + project.name + "\t" + (project.version ?: ""))
                project.configurations.findAll {
					it.canBeResolved && (it.name.endsWith("CompileClasspath") || it.name == "compileClasspath")
                }.each { configuration ->
					configuration.resolve().each { println("KOTLSP_CLASSPATH=" + project.path + "\t" + configuration.name + "\t" + it.absolutePath) }
				}
				project.configurations.findAll {
					it.canBeResolved && (it.name.endsWith("RuntimeClasspath") || it.name == "runtimeClasspath")
				}.each { configuration ->
					configuration.resolve().each { println("KOTLSP_RUNTIME=" + project.path + "\t" + configuration.name + "\t" + it.absolutePath) }
				}
				project.configurations.each { configuration ->
					configuration.allDependencies.each { dependency ->
						if (dependency instanceof org.gradle.api.artifacts.ProjectDependency) {
							println("KOTLSP_DEPENDENCY=" + project.path + "\t" + configuration.name + "\t" + dependency.dependencyProject.path)
						}
						kotlspEmitExclusions("KOTLSP_DEPENDENCY_EXCLUSION=", project.path, configuration.name, dependency)
					}
				}
				def kotlinExtension = project.extensions.findByName("kotlin")
				if (kotlinExtension != null && kotlinExtension.hasProperty("sourceSets")) {
					kotlinExtension.sourceSets.each { sourceSet ->
						if (sourceSet.hasProperty("kotlin")) {
							sourceSet.kotlin.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
						sourceSet.dependsOn.each { dependency ->
							println("KOTLSP_SOURCESET_DEPENDENCY=" + project.path + "\t" + sourceSet.name + "\t" + dependency.name)
						}
					}
					// KMP compilation classpaths belong to the compilation's default
					// source set. Its declared dependsOn graph then makes common sources
					// visible in the platform direction without leaking platform
					// dependencies back into commonMain.
					try {
						if (kotlinExtension.hasProperty("targets")) {
							kotlinExtension.targets.each { target ->
								target.compilations.each { compilation ->
									def defaultSet = compilation.hasProperty("defaultSourceSet") ? compilation.defaultSourceSet : null
									if (defaultSet != null && compilation.hasProperty("compileDependencyFiles")) {
										compilation.compileDependencyFiles.files.each { file -> println("KOTLSP_SOURCESET_CLASSPATH=" + project.path + "\t" + defaultSet.name + "\t" + file.absolutePath) }
									}
									if (defaultSet != null && compilation.hasProperty("runtimeDependencyFiles") && compilation.runtimeDependencyFiles != null) {
										compilation.runtimeDependencyFiles.files.each { file -> println("KOTLSP_SOURCESET_RUNTIME=" + project.path + "\t" + defaultSet.name + "\t" + file.absolutePath) }
									}
								}
							}
						}
					} catch (Throwable limitation) {
						println("KOTLSP_MODEL_LIMITATION=" + project.path + "\tKMP compilation model unavailable: " + limitation.class.simpleName)
					}
				}
				def javaSourceSets = project.extensions.findByName("sourceSets")
				if (javaSourceSets != null) {
					javaSourceSets.each { sourceSet ->
						try {
							def compileTask = project.tasks.findByName(sourceSet.compileJavaTaskName)
							if (compileTask != null) {
								kotlspEmitSetting(project.path, sourceSet.name, "java.source", compileTask.sourceCompatibility)
								kotlspEmitSetting(project.path, sourceSet.name, "java.target", compileTask.targetCompatibility)
								if (compileTask.options.hasProperty("release")) {
									kotlspEmitSetting(project.path, sourceSet.name, "java.release", compileTask.options.release.orNull)
								}
								compileTask.options.compilerArgs.each { argument -> kotlspEmitSetting(project.path, sourceSet.name, "java.arg", argument) }
								if (compileTask.options.hasProperty("annotationProcessorPath") && compileTask.options.annotationProcessorPath != null && !compileTask.options.annotationProcessorPath.files.empty) {
									kotlspEmitSetting(project.path, sourceSet.name, "java.arg", "-processorpath")
									kotlspEmitSetting(project.path, sourceSet.name, "java.arg", compileTask.options.annotationProcessorPath.files.collect { it.absolutePath }.join(File.pathSeparator))
								}
								if (compileTask.hasProperty("javaCompiler") && compileTask.javaCompiler.orNull != null) {
									kotlspEmitSetting(project.path, sourceSet.name, "java.home", compileTask.javaCompiler.get().metadata.installationPath.asFile.absolutePath)
								}
							}
						} catch (Throwable limitation) {
							println("KOTLSP_MODEL_LIMITATION=" + project.path + "\tJava compiler settings unavailable for " + sourceSet.name + ": " + limitation.class.simpleName)
						}
						if (sourceSet.hasProperty("compileClasspath")) {
							sourceSet.compileClasspath.files.each { file -> println("KOTLSP_SOURCESET_CLASSPATH=" + project.path + "\t" + sourceSet.name + "\t" + file.absolutePath) }
						}
						if (sourceSet.hasProperty("runtimeClasspath")) {
							sourceSet.runtimeClasspath.files.each { file -> println("KOTLSP_SOURCESET_RUNTIME=" + project.path + "\t" + sourceSet.name + "\t" + file.absolutePath) }
						}
						[["implementationConfigurationName", true, true, false], ["compileOnlyConfigurationName", true, false, false], ["apiConfigurationName", true, true, true], ["runtimeOnlyConfigurationName", false, true, false]].each { description ->
							if (sourceSet.hasProperty(description[0])) {
								def configuration = project.configurations.findByName(sourceSet.getProperty(description[0]))
								if (configuration != null) {
									configuration.allDependencies.each { dependency ->
										if (dependency instanceof org.gradle.api.artifacts.ProjectDependency) {
											if (description[1]) println("KOTLSP_SOURCESET_PROJECT_DEPENDENCY=" + project.path + "\t" + sourceSet.name + "\t" + description[3] + "\t" + dependency.dependencyProject.path)
											if (description[2]) println("KOTLSP_SOURCESET_RUNTIME_PROJECT_DEPENDENCY=" + project.path + "\t" + sourceSet.name + "\t" + dependency.dependencyProject.path)
										}
										kotlspEmitExclusions("KOTLSP_SOURCESET_DEPENDENCY_EXCLUSION=", project.path, sourceSet.name, dependency)
									}
								}
							}
						}
						if (sourceSet.hasProperty("java")) {
							sourceSet.java.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
						if (sourceSet.hasProperty("kotlin")) {
							sourceSet.kotlin.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
					}
				}
				project.tasks.each { task ->
					if (!task.class.name.toLowerCase().contains("kotlin") || !task.name.toLowerCase().contains("compile")) return
					try {
						def sourceSet = task.hasProperty("sourceSetName") ? task.sourceSetName.toString() : task.name.replaceFirst(/^compile/, "").replaceFirst(/Kotlin.*$/, "")
						if (sourceSet == "") sourceSet = "main"
						sourceSet = sourceSet.substring(0, 1).toLowerCase() + sourceSet.substring(1)
						def options = task.hasProperty("compilerOptions") ? task.compilerOptions : null
						if (options != null) {
							if (options.hasProperty("languageVersion")) kotlspEmitSetting(project.path, sourceSet, "kotlin.languageVersion", options.languageVersion.orNull)
							if (options.hasProperty("apiVersion")) kotlspEmitSetting(project.path, sourceSet, "kotlin.apiVersion", options.apiVersion.orNull)
							if (options.hasProperty("jvmTarget")) kotlspEmitSetting(project.path, sourceSet, "kotlin.jvmTarget", options.jvmTarget.orNull)
							if (options.hasProperty("freeCompilerArgs")) options.freeCompilerArgs.getOrElse([]).each { argument -> kotlspEmitSetting(project.path, sourceSet, "kotlin.arg", argument) }
						} else if (task.hasProperty("kotlinOptions")) {
							kotlspEmitSetting(project.path, sourceSet, "kotlin.languageVersion", task.kotlinOptions.languageVersion)
							kotlspEmitSetting(project.path, sourceSet, "kotlin.apiVersion", task.kotlinOptions.apiVersion)
							kotlspEmitSetting(project.path, sourceSet, "kotlin.jvmTarget", task.kotlinOptions.jvmTarget)
							task.kotlinOptions.freeCompilerArgs.each { argument -> kotlspEmitSetting(project.path, sourceSet, "kotlin.arg", argument) }
						}
						if (task.hasProperty("compilerClasspath")) {
							task.compilerClasspath.files.each { compilerFile ->
								def match = (compilerFile.name =~ /kotlin-compiler(?:-embeddable)?-(.+)\.jar/)
								if (match.matches()) kotlspEmitSetting(project.path, sourceSet, "kotlin.version", match.group(1))
							}
						}
						if (task.hasProperty("pluginClasspath") && task.pluginClasspath != null) {
							task.pluginClasspath.files.each { pluginFile -> kotlspEmitSetting(project.path, sourceSet, "kotlin.arg", "-Xplugin=" + pluginFile.absolutePath) }
						}
					} catch (Throwable limitation) {
						println("KOTLSP_MODEL_LIMITATION=" + project.path + "\tKotlin compiler settings unavailable for " + task.name + ": " + limitation.class.simpleName)
					}
				}
				def generatedCompilerTasks = project.tasks.findAll { task ->
					def lowerName = task.name.toLowerCase()
					lowerName.contains("kapt") || lowerName.contains("ksp")
				}
				if (!generatedCompilerTasks.empty) {
					println("KOTLSP_MODEL_LIMITATION=" + project.path + "\tKAPT/KSP generated-source execution is not reproduced by diagnostics; generated roots are indexed when the build exposes them")
				}
				def androidExtension = project.extensions.findByName("android")
				if (androidExtension != null && androidExtension.hasProperty("sourceSets")) {
					// No editor-selected Android variant is supplied through LSP. Keep
					// discovered roots useful, but mark the model non-authoritative rather
					// than silently choosing a flavor/build type.
					println("KOTLSP_MODEL_LIMITATION=" + project.path + "\tAndroid active variant was not specified; source roots are available but variant classpaths remain partial")
					androidExtension.sourceSets.each { sourceSet ->
						if (sourceSet.hasProperty("java")) {
							sourceSet.java.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
						if (sourceSet.hasProperty("kotlin")) {
							sourceSet.kotlin.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
					}
				}
            }
        }
    }
}
`

// skipLibraryScan suppresses dependency indexing. Only tests set it: indexing
// the JDK and every jar in the Gradle cache is tens of thousands of files, and
// a test whose fixture has no dependencies pays five seconds for nothing.
var skipLibraryScan bool

// libraryArchiveFilter restricts which archives are indexed. Only tests set
// it: a compiler-backed test needs the standard library and java.base so that
// `String` means kotlin.String, and nothing else from the dependency cache.
var libraryArchiveFilter func(sourceArchive) bool

func filterArchives(archives []sourceArchive) []sourceArchive {
	kept := archives[:0:0]
	for _, archive := range archives {
		if libraryArchiveFilter(archive) {
			kept = append(kept, archive)
		}
	}
	return kept
}

// scanTiming prints per-phase library scan timing to stderr, for profiling a
// cold start: KOTLSP_SCAN_TIMING=1.
var scanTiming = os.Getenv("KOTLSP_SCAN_TIMING") != ""

// scanDeclarationsCompleteHook lets a test hold the scan immediately after the
// complete declaration/source barrier becomes ready.
var scanDeclarationsCompleteHook func()

func (i *Index) scanLibraries(ctx context.Context, roots []string, generation uint64, declarationsComplete func(), prepared ...map[string]classpathResolution) {
	// Not complete until this pass finishes; a rescan starts incomplete again.
	i.setLibrariesScanned(false)
	if skipLibraryScan {
		// Tests/embedders that explicitly suppress archive discovery define an
		// empty library universe; leaving it permanently "incomplete" makes Ready
		// internally contradictory and disables all completeness-based features.
		i.setLibrariesScanned(true)
		return
	}
	binaryArchives := make([]sourceArchive, 0)
	sourceArchives := make([]sourceArchive, 0)
	deferredSources := make([]sourceArchive, 0, 1)
	libraryScanComplete := true
	jdkBinaries, jdkInventoryComplete := jdkBinaryArchives(i.DefaultJavaHome())
	if !jdkInventoryComplete {
		libraryScanComplete = false
		i.recordHealth("library", "JDK modules", "JDK module inventory exceeded its 4096-entry/512-archive safety limit")
	} else if len(jdkBinaries) == 0 {
		libraryScanComplete = false
		i.recordHealth("library", "JDK modules", "no bounded JDK module inventory was available; unresolved fast diagnostics will abstain")
	}
	if len(jdkBinaries) > 0 {
		// java.base covers the implicit language surface and is inserted first,
		// which keeps it first among equally relevant archives. Direct imports are
		// allowed to outrank it below: staging the whole JMOD before a requested
		// Spring/Jakarta API otherwise creates a several-second navigation hole.
		binaryArchives = append(binaryArchives, jdkBinaries[0])
	}
	if jdk := jdkSourcesForHome(i.DefaultJavaHome()); jdk != "" {
		deferredSources = append(deferredSources, sourceArchive{path: jdk, jdk: true})
	}
	seen := map[string]bool{}
	classpathSeen := map[string]bool{}
	classpath := make([]string, 0)
	for _, root := range roots {
		cleanRoot, _ := filepath.Abs(root)
		cleanRoot = filepath.Clean(cleanRoot)
		var resolution classpathResolution
		var found bool
		if len(prepared) > 0 {
			resolution, found = prepared[0][cleanRoot]
		}
		if !found {
			resolution = resolveClasspathModel(ctx, cleanRoot)
			i.mergeModuleBuildResolution(cleanRoot, resolution)
		}
		compileClasspath, compileClasspathComplete := compileClasspathEntries(resolution)
		if !compileClasspathComplete {
			libraryScanComplete = false
			i.recordHealth("library", cleanRoot, "compile classpath exceeds its 100000-path safety limit")
		}
		for _, binary := range compileClasspath {
			lowerBinary := strings.ToLower(binary)
			if strings.HasSuffix(lowerBinary, "-sources.jar") || strings.HasSuffix(lowerBinary, "-javadoc.jar") {
				// Navigation artifacts are attachments, never executable/compile
				// classpath entries. Treating one as a binary can consume the shared
				// archive identity before its real JAR is paired.
				continue
			}
			if !classpathSeen[binary] {
				classpathSeen[binary] = true
				classpath = append(classpath, binary)
			}
			info, statErr := os.Stat(binary)
			if statErr != nil || info.IsDir() || !strings.HasSuffix(lowerBinary, ".jar") {
				continue
			}
			// Source attachments provide navigation text, but the compiled archive
			// remains the authoritative API. Annotation processors, Lombok, and
			// compiler-generated members commonly exist only in bytecode.
			if !seen[binary] {
				seen[binary] = true
				binaryArchives = append(binaryArchives, sourceArchive{path: binary, binary: true, release: i.javaReleaseForLibrary(binary)})
			}
			sourceJars, sourceJarsExhausted := sourceJarsFor(binary)
			if sourceJarsExhausted {
				i.recordHealth("library-source-attachment", binary, "source attachment search exceeded its 4096-entry/64-archive safety limit")
			}
			for _, source := range sourceJars {
				i.copyLibraryAccess(binary, source)
				if !seen[source] {
					seen[source] = true
					sourceArchives = append(sourceArchives, sourceArchive{path: source})
				}
			}
		}
	}
	// Kotlin's default imports are available even in an unconfigured directory.
	// Index the stdlib which the diagnostic compiler itself uses so navigation,
	// completion, signatures, and immediate diagnostics share one symbol world.
	defaultKotlin := defaultKotlinLibraries(ctx)
	if len(defaultKotlin) == 0 {
		libraryScanComplete = false
		i.recordHealth("library", "Kotlin standard library", "no bounded Kotlin standard-library inventory was available; unresolved fast diagnostics will abstain")
	}
	for _, binary := range defaultKotlin {
		if !classpathSeen[binary] {
			classpathSeen[binary] = true
			classpath = append(classpath, binary)
		}
		// Put bytecode first: it is compact and authoritative, so default-import
		// symbols become available while the larger source attachment is still
		// being parsed in the background.
		if !seen[binary] {
			seen[binary] = true
			binaryArchives = append(binaryArchives, sourceArchive{path: binary, binary: true, release: i.javaReleaseForLibrary(binary)})
		}
		sourceJars, sourceJarsExhausted := sourceJarsFor(binary)
		if sourceJarsExhausted {
			i.recordHealth("library-source-attachment", binary, "source attachment search exceeded its 4096-entry/64-archive safety limit")
		}
		for _, source := range sourceJars {
			i.copyLibraryAccess(binary, source)
			if !seen[source] {
				seen[source] = true
				sourceArchives = append(sourceArchives, sourceArchive{path: source})
			}
		}
	}
	wantedImports := i.workspaceLibraryImports(ctx)
	focusImports := i.openDocumentLibraryImports(ctx)
	wantedTargets := i.workspaceLibraryTargets(ctx, wantedImports)
	if libraryArchiveFilter != nil {
		binaryArchives = filterArchives(binaryArchives)
		sourceArchives = filterArchives(sourceArchives)
		jdkBinaries = filterArchives(jdkBinaries)
		deferredSources = filterArchives(deferredSources)
	}
	const maxLibraryScanArchives = 4096
	const maxLibraryScanEntries = 2_000_000
	remainingArchives := maxLibraryScanArchives
	boundArchiveCount := func(values []sourceArchive) []sourceArchive {
		if len(values) <= remainingArchives {
			remainingArchives -= len(values)
			return values
		}
		libraryScanComplete = false
		kept := append([]sourceArchive(nil), values[:remainingArchives]...)
		remainingArchives = 0
		return kept
	}
	binaryArchives = boundArchiveCount(binaryArchives)
	sourceArchives = boundArchiveCount(sourceArchives)
	jdkAdditional := make([]sourceArchive, 0, len(jdkBinaries))
	for _, archive := range jdkBinaries {
		if archive.module != "java.base" {
			jdkAdditional = append(jdkAdditional, archive)
		}
	}
	jdkAdditional = boundArchiveCount(jdkAdditional)
	deferredSources = boundArchiveCount(deferredSources)
	i.populateArchiveMetadata(ctx, binaryArchives, generation)
	i.populateArchiveMetadata(ctx, sourceArchives, generation)
	i.populateArchiveMetadata(ctx, jdkAdditional, generation)
	i.populateArchiveMetadata(ctx, deferredSources, generation)
	prioritizeLibraryArchives(binaryArchives, wantedImports)
	prioritizeLibraryArchives(sourceArchives, wantedImports)
	// The whole workspace may contain hundreds of exact imports spread across
	// unrelated modules. Those are equal for eventual completeness, but not for
	// the author waiting on `gd` in a visible buffer. A second stable priority
	// tier moves archives imported by open documents ahead of the background
	// workspace order without starving anything from the complete pass.
	prioritizeLibraryArchives(binaryArchives, focusImports)
	prioritizeLibraryArchives(sourceArchives, focusImports)
	// Kotlin builtins have no classfile declarations. Keep their source archive
	// ahead of optional navigation attachments when a pathological classpath
	// reaches the global scan budget.
	sort.SliceStable(sourceArchives, func(left, right int) bool {
		return strings.Contains(strings.ToLower(filepath.Base(sourceArchives[left].path)), "kotlin-stdlib") &&
			!strings.Contains(strings.ToLower(filepath.Base(sourceArchives[right].path)), "kotlin-stdlib")
	})
	prioritizeLibraryArchives(jdkAdditional, wantedImports)
	prioritizeLibraryArchives(jdkAdditional, focusImports)
	jdkAdditional = relevantJDKArchives(jdkAdditional, wantedImports, wantedTargets)
	setArchivePriorityTargets(binaryArchives, wantedTargets)
	setArchivePriorityTargets(sourceArchives, wantedTargets)
	setArchivePriorityTargets(jdkAdditional, wantedTargets)
	setArchivePriorityTargets(deferredSources, wantedTargets)
	// Dependency and JDK source archives are display artifacts, not the
	// authoritative executable API. Eagerly parsing every attached source used
	// tree-sitter, duplicated the bytecode symbol graph, delayed Ready by minutes,
	// and retained enough archive transactions to exhaust the process budget.
	// Kotlin's builtin declarations are the sole exception: several language
	// types have no classfile declaration. Binary definitions remain immediately
	// navigable through rendered, editor-openable stubs; individual source
	// attachments can be loaded when a navigation request actually needs them.
	semanticSources := sourceArchives[:0:0]
	for _, archive := range sourceArchives {
		if strings.Contains(strings.ToLower(filepath.Base(archive.path)), "kotlin-stdlib") {
			semanticSources = append(semanticSources, archive)
		}
	}
	sourceArchives = semanticSources
	deferredSources = nil
	remainingEntries := maxLibraryScanEntries
	boundPhase := func(values []sourceArchive) []sourceArchive {
		kept := values[:0:0]
		for _, archive := range values {
			entries := 0
			if archive.manifestOK {
				entries = archiveSemanticEntryCount(archive)
			}
			if entries > remainingEntries {
				libraryScanComplete = false
				continue
			}
			remainingEntries -= entries
			kept = append(kept, archive)
		}
		return kept
	}
	binaryArchives = boundPhase(binaryArchives)
	sourceArchives = boundPhase(sourceArchives)
	jdkAdditional = boundPhase(jdkAdditional)
	deferredSources = boundPhase(deferredSources)
	if !libraryScanComplete {
		i.recordHealth("library", "classpath", "library inventory exceeded its 4096-archive/2000000-entry safety limit; indexed prefix retained and unresolved diagnostics remain conservative")
	}
	archives := make([]sourceArchive, 0, len(binaryArchives)+len(sourceArchives)+len(jdkAdditional)+len(deferredSources))
	archives = append(archives, binaryArchives...)
	archives = append(archives, sourceArchives...)
	archives = append(archives, jdkAdditional...)
	archives = append(archives, deferredSources...)
	sort.Strings(classpath)
	i.mu.Lock()
	if i.generation.Load() != generation {
		i.mu.Unlock()
		return
	}
	i.classpath = classpath
	i.mu.Unlock()
	var total int64
	for _, archive := range archives {
		if archive.manifestOK {
			total += int64(archiveSemanticEntryCount(archive))
			continue
		}
		reader, err := zip.OpenReader(archive.path)
		if err != nil {
			i.recordHealth("library", archive.path, err.Error())
			continue
		}
		budget, budgetErr := archiveio.NewBudget(archiveSemanticBudgetFiles(archive, reader.File))
		if budgetErr != nil {
			i.recordHealth("library", archive.path, budgetErr.Error())
			_ = reader.Close()
			continue
		}
		selected, selectErr := selectedArchiveFilesWithBudgetContext(ctx, archive, reader.File, budget)
		if selectErr != nil {
			i.recordHealth("library", archive.path, selectErr.Error())
			_ = reader.Close()
			continue
		}
		total += int64(len(selected))
		_ = reader.Close()
	}
	p := i.Progress()
	p.LibrariesTotal = total
	i.progress.Store(&p)
	i.mu.Lock()
	i.reserveLibraryCapacityLocked(total)
	i.mu.Unlock()
	// An archive is staged completely before publication. The commit itself is
	// serialized, so concurrent decoders do not increase commit throughput: they
	// merely retain several complete archive transactions while waiting for
	// libraryCommitMu. With the former eight cached workers and a 512 MiB
	// per-archive allowance, that queue had a four-GiB theoretical live set and
	// reached 3.3 GiB RSS on a small Spring project. Decode one transaction at a
	// time until archive state is represented by independently swappable shards;
	// foreground navigation gets its speed from priority ordering, not speculative
	// whole-classpath concurrency.
	parseWorkers := 1
	var parsed atomic.Int64
	scanStart := time.Now()
	indexPhase := func(phase []sourceArchive, countProgress bool) bool {
		workers := parseWorkers
		if scanTiming {
			defer func(started time.Time, count int, workers int) {
				fmt.Fprintf(os.Stderr, "kotlsp scan: %d archives on %d workers in %s (t+%s)\n", count, workers, time.Since(started).Round(time.Millisecond), time.Since(scanStart).Round(time.Millisecond))
			}(time.Now(), len(phase), workers)
		}
		jobs := make(chan sourceArchive, 8)
		var wg sync.WaitGroup
		var archiveFailed atomic.Bool
		for worker := 0; worker < workers; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for archive := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}
					archiveStarted := time.Now()
					complete := i.indexSourceArchive(ctx, archive, generation, func(delta int64) {
						if !countProgress {
							return
						}
						count := parsed.Add(delta)
						if i.generation.Load() != generation {
							return
						}
						current := i.Progress()
						current.LibrariesParsed = count
						i.progress.Store(&current)
					})
					if scanTiming {
						fmt.Fprintf(os.Stderr, "kotlsp scan archive: %s entries=%d importScore=%d importMatch=%q duration=%s\n", filepath.Base(archive.path), archiveSemanticEntryCount(archive), libraryArchiveImportScore(archive, wantedImports), libraryEntryImportMatch(archive.manifest, wantedImports), time.Since(archiveStarted).Round(time.Millisecond))
					}
					if !complete && ctx.Err() == nil && i.generation.Load() == generation {
						archiveFailed.Store(true)
						i.retainLibraryArchiveGeneration(archive.path, generation)
					}
				}
			}()
		}
		cancelled := false
		for _, archive := range phase {
			select {
			case jobs <- archive:
			case <-ctx.Done():
				cancelled = true
			}
			if cancelled {
				break
			}
		}
		close(jobs)
		wg.Wait()
		if archiveFailed.Load() {
			libraryScanComplete = false
		}
		return !cancelled && ctx.Err() == nil
	}
	// Finish vendor bytecode before its sources. This makes the complete
	// compiled API available deterministically and lets the source phase collapse
	// matching declarations into navigation attachments instead of duplicates.
	if !indexPhase(binaryArchives, true) {
		return
	}
	if len(jdkAdditional) > 0 && !indexPhase(jdkAdditional, true) {
		return
	}
	// The Kotlin builtins -- Any, Unit, Int, Nothing, the Function types --
	// have no class files: they exist only in the standard library's sources.
	// Those sources are the one archive that adds declarations rather than
	// attaching them, so they come before the index may call itself complete.
	var builtinSources, otherSources []sourceArchive
	for _, archive := range sourceArchives {
		if strings.Contains(strings.ToLower(filepath.Base(archive.path)), "kotlin-stdlib") {
			builtinSources = append(builtinSources, archive)
		} else {
			otherSources = append(otherSources, archive)
		}
	}
	if len(builtinSources) > 0 && !indexPhase(builtinSources, true) {
		return
	}
	// A sources archive normally attaches text to bytecode, but it may also
	// contain type aliases, source-retention declarations, or generated APIs
	// with no class-file counterpart. Absence is not proof until every selected
	// source archive has had the opportunity to publish those names.
	if !indexPhase(otherSources, true) {
		return
	}
	// The monolithic JDK source ZIP is deferred so it cannot postpone vendor
	// source attachment, but it is still part of the declaration-completeness
	// barrier.
	if !indexPhase(deferredSources, true) {
		return
	}
	// Archive decoding leaves large temporary buffers and transaction slices
	// behind precisely when the compiler JVM is about to become eligible. Return
	// their pages before declaring readiness so the two memory peaks do not
	// overlap in the process-tree envelope. This runs once per complete scan,
	// outside every index lock.
	debug.FreeOSMemory()
	i.setLibrariesScanned(libraryScanComplete)
	if declarationsComplete != nil {
		declarationsComplete()
	}
	if scanDeclarationsCompleteHook != nil {
		scanDeclarationsCompleteHook()
	}
}

func (i *Index) openDocumentLibraryImports(ctx context.Context) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	const maxOpenDocuments = 4096
	const maxOpenImports = 100_000
	i.mu.RLock()
	seen := make(map[string]bool)
	documents := 0
	for uri := range i.docs {
		if documents >= maxOpenDocuments || len(seen) >= maxOpenImports || ctx.Err() != nil {
			break
		}
		file := i.files[uri]
		if file == nil {
			continue
		}
		documents++
		for _, imported := range file.Imports {
			path := strings.TrimSuffix(imported.Path, ".*")
			if path != "" {
				seen[path] = true
			}
		}
		// Default imports have no syntax node, but they are just as relevant to
		// the visible buffer. One exact anchor is enough to identify the archive
		// containing each language's implicit core surface.
		if file.Language == analysis.LanguageKotlin {
			seen["kotlin.Unit"] = true
		} else if file.Language == analysis.LanguageJava {
			seen["java.lang.Object"] = true
		}
	}
	i.mu.RUnlock()
	if documents >= maxOpenDocuments || len(seen) >= maxOpenImports {
		i.recordHealth("library-priority", "open documents", "open-document import inventory exceeded its 4096-document/100000-import safety limit")
	}
	imports := make([]string, 0, len(seen))
	for imported := range seen {
		imports = append(imports, imported)
	}
	sort.Strings(imports)
	return imports
}

func (i *Index) workspaceLibraryImports(ctx context.Context) []string {
	files, truncated := i.WorkspaceFilesContext(ctx, 100_001)
	if truncated || len(files) > 100_000 {
		i.recordHealth("library-priority", "workspace", "import prioritization exceeded its 100000-source safety limit and was skipped")
		return nil
	}
	seen := make(map[string]bool)
	for fileIndex, file := range files {
		if fileIndex&255 == 0 && ctx.Err() != nil {
			return nil
		}
		if file == nil {
			continue
		}
		for _, imported := range file.Imports {
			path := strings.TrimSuffix(imported.Path, ".*")
			if path != "" {
				seen[path] = true
			}
		}
	}
	imports := make([]string, 0, len(seen))
	for imported := range seen {
		imports = append(imports, imported)
	}
	sort.Strings(imports)
	return imports
}

func (i *Index) workspaceLibraryTargets(ctx context.Context, imports []string) []string {
	seen := make(map[string]bool, len(imports)*2)
	for _, imported := range imports {
		if !strings.HasSuffix(imported, ".*") {
			seen[strings.ReplaceAll(imported, ".", "/")] = true
		}
	}
	files, truncated := i.WorkspaceFilesContext(ctx, 100_001)
	if truncated || len(files) > 100_000 {
		i.recordHealth("library-priority", "workspace", "reference prioritization exceeded its 100000-source safety limit and was skipped")
		return nil
	}
	occurrences := 0
	for fileIndex, file := range files {
		if fileIndex&255 == 0 && ctx.Err() != nil {
			return nil
		}
		if file == nil {
			continue
		}
		for _, reference := range file.References {
			occurrences++
			if occurrences > 1_000_000 {
				i.recordHealth("library-priority", "workspace", "reference prioritization exceeded its 1000000-occurrence safety limit and was skipped")
				return nil
			}
			if reference.Qualifier != "" || reference.Name == "" || reference.Name[0] < 'A' || reference.Name[0] > 'Z' {
				continue
			}
			for _, packageName := range []string{"java/lang/", "java/util/", "kotlin/"} {
				seen[packageName+reference.Name] = true
			}
		}
	}
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func archiveEntryMatchesTargets(archive sourceArchive, name string, targets []string) bool {
	name = strings.TrimPrefix(filepath.ToSlash(name), "classes/")
	if strings.HasPrefix(strings.ToLower(name), "meta-inf/versions/") {
		parts := strings.SplitN(name, "/", 4)
		if len(parts) == 4 {
			name = parts[3]
		}
	}
	if archive.jdk && !archive.binary {
		if slash := strings.IndexByte(name, '/'); slash >= 0 {
			name = name[slash+1:]
		}
	}
	name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".class"), ".java"), ".kt")
	if dollar := strings.IndexByte(name, '$'); dollar >= 0 {
		name = name[:dollar]
	}
	index := sort.SearchStrings(targets, name)
	return index < len(targets) && targets[index] == name
}

func relevantJDKArchives(archives []sourceArchive, imports, targets []string) []sourceArchive {
	kept := archives[:0:0]
	for _, archive := range archives {
		if libraryArchiveImportScore(archive, imports) > 0 {
			kept = append(kept, archive)
			continue
		}
		for _, entry := range archive.manifest {
			if archiveEntryMatchesTargets(archive, entry, targets) {
				kept = append(kept, archive)
				break
			}
		}
	}
	return kept
}

// kotlinBuiltinSourceEntry selects the stdlib source files that declare the
// language's builtin types. Several of them (Any, Nothing, String, the
// primitives, arrays, Comparable, CharSequence, Enum, Throwable, and the mapped
// collection interfaces in Collections.kt and Iterator.kt, the exception
// aliases in ExceptionsH.kt, the annotations) have no classfile of their own,
// so the binary archive cannot supply them. They all live directly under
// kotlin/ in the archive, so that directory is the bounded selection; the two
// deeper files carry the builtin annotations and kotlin.util's standard
// functions.
func kotlinBuiltinSourceEntry(name string) bool {
	name = strings.TrimPrefix(filepath.ToSlash(name), "/")
	for _, prefix := range []string{"", "commonMain/", "jvmMain/"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := name[len(prefix):]
		if strings.HasPrefix(rest, "kotlin/") && strings.HasSuffix(rest, ".kt") && !strings.Contains(rest[len("kotlin/"):], "/") {
			return true
		}
		if rest == "kotlin/internal/AnnotationsBuiltin.kt" || rest == "kotlin/util/Standard.kt" {
			return true
		}
	}
	return false
}

func kotlinBuiltinSourceArchive(archive sourceArchive) bool {
	return !archive.binary && strings.Contains(strings.ToLower(filepath.Base(archive.path)), "kotlin-stdlib")
}

func archiveSemanticEntryCount(archive sourceArchive) int {
	return len(archiveSemanticManifest(archive))
}

// archiveSemanticManifest is the manifest subset an archive actually
// contributes to the index: everything for a binary or ordinary source
// archive, and only the builtin declarations for the Kotlin stdlib sources. The
// cache is keyed on this subset, since it is what a complete transaction holds.
func archiveSemanticManifest(archive sourceArchive) []string {
	if !kotlinBuiltinSourceArchive(archive) {
		return archive.manifest
	}
	selected := kotlinBuiltinSourceSelection(archive.manifest)
	kept := make([]string, 0, len(selected))
	for _, entry := range archive.manifest {
		if selected[entry] {
			kept = append(kept, entry)
		}
	}
	return kept
}

// kotlinBuiltinSourceSelection picks one declaration of every builtin. The
// stdlib sources carry an `expect` declaration under commonMain/ and its JVM
// `actual` under jvmMain/ for most builtins; indexing both makes every builtin
// type an equal-precedence ambiguity that resolution correctly refuses to
// choose between. On the JVM the actual is the declaration, so a commonMain
// file is taken only when no jvmMain file of the same name exists.
func kotlinBuiltinSourceSelection(entries []string) map[string]bool {
	jvm := make(map[string]bool)
	for _, entry := range entries {
		name := strings.TrimPrefix(filepath.ToSlash(entry), "/")
		if kotlinBuiltinSourceEntry(name) && strings.HasPrefix(name, "jvmMain/") {
			jvm[strings.TrimPrefix(name, "jvmMain/")] = true
		}
	}
	selected := make(map[string]bool)
	for _, entry := range entries {
		name := strings.TrimPrefix(filepath.ToSlash(entry), "/")
		if !kotlinBuiltinSourceEntry(name) {
			continue
		}
		if strings.HasPrefix(name, "commonMain/") && jvm[strings.TrimPrefix(name, "commonMain/")] {
			continue
		}
		selected[entry] = true
	}
	return selected
}

func prioritizeLibraryArchives(archives []sourceArchive, imports []string) {
	if len(archives) < 2 || len(imports) == 0 {
		return
	}
	scores := make(map[string]int, len(archives))
	for _, archive := range archives {
		scores[archive.path] = libraryArchiveImportScore(archive, imports)
	}
	sort.SliceStable(archives, func(left, right int) bool {
		return scores[archives[left].path] > scores[archives[right].path]
	})
}

func libraryArchiveImportScore(archive sourceArchive, imports []string) int {
	if archive.manifestOK {
		return libraryEntryImportScore(archive.manifest, imports)
	}
	reader, err := zip.OpenReader(archive.path)
	if err != nil {
		return 0
	}
	defer reader.Close()
	if archiveio.ValidateZipFiles(archiveSemanticBudgetFiles(archive, reader.File)) != nil {
		return 0
	}
	entries := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		entries = append(entries, file.Name)
	}
	return libraryEntryImportScore(entries, imports)
}

func libraryEntryImportMatch(entries, imports []string) string {
	for _, imported := range imports {
		path := strings.ReplaceAll(imported, ".", "/")
		for _, entry := range entries {
			name := strings.TrimPrefix(filepath.ToSlash(entry), "classes/")
			if strings.HasPrefix(name, path+".") || strings.HasPrefix(name, path+"$") {
				return imported + " <- " + name
			}
		}
	}
	return ""
}

func libraryEntryImportScore(entries, imports []string) int {
	type target struct{ dot, dollar, pkg string }
	targets := make([]target, 0, len(imports))
	for _, imported := range imports {
		path := strings.ReplaceAll(imported, ".", "/")
		pkg := path
		if slash := strings.LastIndexByte(pkg, '/'); slash >= 0 {
			pkg = pkg[:slash+1]
		}
		targets = append(targets, target{dot: path + ".", dollar: path + "$", pkg: pkg})
	}
	score := 0
	for _, entry := range entries {
		name := strings.TrimPrefix(filepath.ToSlash(entry), "classes/")
		var lower string
		for _, t := range targets {
			if strings.HasPrefix(name, t.dot) || strings.HasPrefix(name, t.dollar) {
				return 1000
			}
			if score < 100 && strings.HasPrefix(name, t.pkg) {
				if lower == "" {
					lower = strings.ToLower(name)
				}
				if strings.HasSuffix(lower, ".class") || sourceEntry(name) {
					score = 100
				}
			}
		}
	}
	return score
}

// archivesAreCached reports whether every archive of a phase has a snapshot,
// in which case the phase does no parsing and may use many workers.
func defaultKotlinLibraries(ctx context.Context) []string {
	seen := make(map[string]bool)
	var libraries []string
	add := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && !seen[path] {
			seen[path] = true
			libraries = append(libraries, path)
		}
	}
	if compiler, ok := findKotlinCompilerContext(ctx); ok {
		add(compiler.stdlib)
		if compiler.executable != "" && !compiler.embedded {
			if resolved, err := filepath.EvalSymlinks(compiler.executable); err == nil {
				lib := filepath.Join(filepath.Dir(filepath.Dir(resolved)), "lib")
				for _, name := range []string{"kotlin-stdlib.jar", "kotlin-stdlib-jdk7.jar", "kotlin-stdlib-jdk8.jar", "kotlin-script-runtime.jar"} {
					add(filepath.Join(lib, name))
				}
			}
		}
	}
	cacheRoot := os.Getenv("GRADLE_USER_HOME")
	if cacheRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cacheRoot = filepath.Join(home, ".gradle")
		}
	}
	modules := filepath.Join(cacheRoot, "caches", "modules-2", "files-2.1", "org.jetbrains.kotlin")
	for _, artifact := range []string{"kotlin-stdlib", "kotlin-stdlib-jdk7", "kotlin-stdlib-jdk8", "kotlin-script-runtime"} {
		add(latestBinaryGlob(filepath.Join(modules, artifact, "*", "*", "*.jar")))
	}
	sort.Strings(libraries)
	return libraries
}

const libraryCacheVersion = 34

const maxLibraryCacheRecordBytes = 64 << 20

type cachedArchive struct {
	Version  int
	Entries  int
	Manifest bool
}

type cachedSourceFile struct {
	Source LibrarySource
	Parsed analysis.ParsedFile
}

func libraryFileStagingWeight(file LibraryFile) int64 {
	weight := int64(1024 + len(file.Source.Archive) + len(file.Source.Entry) + len(file.Source.LanguageID) + len(file.Content) + len(file.Parsed.URI) + len(file.Parsed.Package) + len(file.Parsed.JVMFacadeName) + len(file.Parsed.ParseMode))
	weight += int64(len(file.Parsed.Imports)) * 256
	for _, imported := range file.Parsed.Imports {
		weight += int64(len(imported.Path) + len(imported.Alias))
	}
	for _, symbol := range file.Parsed.Symbols {
		weight += int64(512 + len(symbol.ID) + len(symbol.Name) + len(symbol.FQN) + len(symbol.URI) + len(symbol.ContainerID) + len(symbol.ContainerName) + len(symbol.Package) + len(symbol.Type) + len(symbol.Initializer) + len(symbol.ReceiverType) + len(symbol.Signature) + len(symbol.JVMName) + len(symbol.JVMDescriptor) + len(symbol.Documentation) + len(symbol.OriginID) + len(symbol.SourceURI))
		weight += int64(len(symbol.AdditionalScopes))*32 + int64(len(symbol.Parameters))*128
		for _, parameter := range symbol.Parameters {
			weight += int64(len(parameter.Name) + len(parameter.Type) + len(parameter.Default))
		}
		for _, value := range symbol.TypeParameters {
			weight += int64(32 + len(value))
		}
		for name, bounds := range symbol.TypeParameterBounds {
			weight += int64(64 + len(name))
			for _, bound := range bounds {
				weight += int64(32 + len(bound))
			}
		}
		for _, value := range symbol.Supertypes {
			weight += int64(32 + len(value))
		}
		for _, value := range symbol.Modifiers {
			weight += int64(16 + len(value))
		}
	}
	return weight
}

func (i *Index) indexSourceArchive(ctx context.Context, archive sourceArchive, generation uint64, progress func(int64), accessSnapshots ...map[string]bool) bool {
	// Content identity is needed by the cache and source mirror, but computing
	// it for the entire classpath before publishing the first archive creates a
	// long artificial period in which LibrariesParsed remains zero. Hash each
	// archive immediately before its priority-ordered transaction instead.
	if !archive.digestOK {
		if digest, err := digestArchiveContext(ctx, archive.path); err == nil {
			archive.digest, archive.digestOK = digest, true
			i.mu.Lock()
			i.storeArchiveDigestLocked(archive.path, digest)
			i.mu.Unlock()
		} else if ctx.Err() != nil {
			return false
		} else {
			i.recordHealth("library", archive.path, err.Error())
		}
	}
	mirror := i.newArchiveMirror(archive)
	// An archive is one semantic generation. Parsing into the live index entry
	// by entry made a corrupt tail overwrite part of the last good generation.
	// Stage a bounded summary and publish it under one generation check only
	// after every selected entry has proved readable and parseable.
	const maxStagedArchiveFiles = 100_000
	const maxStagedArchiveSymbols = 1_000_000
	const maxStagedArchiveWeight int64 = 512 << 20
	staged := make([]LibraryFile, 0)
	stagedSymbols := 0
	var stagedWeight int64
	stagingComplete := true
	stage := func(file LibraryFile) bool {
		weight := libraryFileStagingWeight(file)
		if len(staged) >= maxStagedArchiveFiles || len(file.Parsed.Symbols) > maxStagedArchiveSymbols-stagedSymbols || weight > maxStagedArchiveWeight-stagedWeight {
			stagingComplete = false
			return false
		}
		staged = append(staged, file)
		stagedSymbols += len(file.Parsed.Symbols)
		stagedWeight += weight
		return true
	}
	if loadArchiveCache(ctx, archive, func(entry cachedSourceFile) bool {
		if i.generation.Load() != generation {
			return false
		}
		if kotlinBuiltinSourceArchive(archive) && !kotlinBuiltinSourceEntry(entry.Source.Entry) {
			return true
		}
		// Re-apply the current cold-summary policy to older compatible cache
		// records. It is idempotent and prevents implementation-only declarations
		// from surviving merely because this archive was indexed before the
		// memory policy tightened.
		summarizeLibraryFile(&entry.Parsed)
		i.canonicalizeLibraryFile(&entry.Parsed)
		for symbol := range entry.Parsed.Symbols {
			entry.Parsed.Symbols[symbol].Library = true
		}
		return stage(LibraryFile{Source: entry.Source, Parsed: entry.Parsed})
	}) {
		if !stagingComplete || ctx.Err() != nil || i.generation.Load() != generation {
			if !stagingComplete {
				i.recordHealth("library", archive.path, "archive snapshot exceeds its transactional staging safety limit")
			}
			return false
		}
		// The parse came from the snapshot cache, so the loop below never ran
		// and never produced entry content. Mirror the archive separately when
		// its files are missing; a complete mirror makes this a no-op.
		i.mirrorArchive(ctx, archive, mirror)
		if ctx.Err() != nil || !i.addLibraryArchiveTransaction(archive.path, staged, generation, accessSnapshots...) {
			return false
		}
		progress(int64(len(staged)))
		return true
	}
	reader, err := zip.OpenReader(archive.path)
	if err != nil {
		i.recordHealth("library", archive.path, err.Error())
		return false
	}
	defer reader.Close()
	budget, err := archiveio.NewBudget(archiveSemanticBudgetFiles(archive, reader.File))
	if err != nil {
		i.recordHealth("library", archive.path, err.Error())
		return false
	}
	var cacheWriter *archiveCacheWriter
	cacheWriter, err = newArchiveCacheWriter(ctx, archive)
	if err != nil && !errors.Is(err, os.ErrInvalid) {
		i.recordHealth("library-cache", archive.path, err.Error())
	}
	if cacheWriter != nil {
		defer cacheWriter.Abort()
	}
	selected, err := selectedArchiveFilesWithBudgetContext(ctx, archive, reader.File, budget)
	if err != nil {
		i.recordHealth("library", archive.path, err.Error())
		return false
	}
	if kotlinBuiltinSourceArchive(archive) {
		names := make([]string, 0, len(selected))
		for _, file := range selected {
			names = append(names, file.Name)
		}
		chosen := kotlinBuiltinSourceSelection(names)
		builtins := selected[:0:0]
		for _, file := range selected {
			if chosen[file.Name] {
				builtins = append(builtins, file)
			}
		}
		selected = builtins
	}
	if len(selected) > maxStagedArchiveFiles {
		i.recordHealth("library", archive.path, "archive exceeds its 100000-file transactional staging safety limit")
		return false
	}
	if len(archive.priorityTargets) > 0 {
		sort.SliceStable(selected, func(left, right int) bool {
			return archiveEntryMatchesTargets(archive, selected[left].Name, archive.priorityTargets) && !archiveEntryMatchesTargets(archive, selected[right].Name, archive.priorityTargets)
		})
	}
	complete := true
	mirrorComplete := true
	for _, file := range selected {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		if !archiveAccepts(archive, file) {
			continue
		}
		data, err := budget.ReadContext(ctx, file, archiveio.MaxEntryBytes)
		if err != nil {
			i.recordHealth("library", archive.path+"!/"+file.Name, err.Error())
			complete = false
			if errors.Is(err, archiveio.ErrArchiveBudget) {
				break
			}
			continue
		}
		entry := archiveEntry{archive: archive, name: file.Name}
		languageID := languageForEntry(file.Name)
		content := string(data)
		if archive.binary {
			parsedClass, parseErr := classfile.Parse(data)
			if parseErr != nil {
				i.recordHealth("classfile", archive.path+"!/"+file.Name, parseErr.Error())
				complete = false
				continue
			}
			content = classfile.RenderJava(parsedClass)
			languageID = "java"
			doc := textdoc.NewDocument(entry.URI(), languageID, 0, content)
			parsed := parsedBinaryClassfile(doc, parsedClass)
			restoreClassfileSourceIdentifiers(parsed)
			applyClassfileAnnotations(parsed, parsedClass)
			if metadataErr := applyKotlinBinaryMetadata(parsed, parsedClass); metadataErr != nil {
				i.recordHealth("kotlin-metadata", archive.path+"!/"+file.Name, metadataErr.Error())
			}
			markBinaryWrapperSymbols(parsed, parsedClass.InternalName)
			if !mirror.write(file.Name, content, true) {
				mirrorComplete = false
			}
			summarizeLibraryFile(parsed)
			parsed.References = nil
			parsed.Tokens = nil
			parsed.Diagnostics = nil
			parsed.Folds = nil
			i.canonicalizeLibraryFile(parsed)
			source := LibrarySource{Archive: archive.path, Entry: file.Name, LanguageID: languageID, Binary: true}
			if !stage(LibraryFile{Source: source, Parsed: *parsed}) {
				complete = false
				break
			}
			if cacheWriter != nil {
				if writeErr := cacheWriter.Write(cachedSourceFile{Source: source, Parsed: *parsed}); writeErr != nil {
					i.recordHealth("library-cache", archive.path, writeErr.Error())
					cacheWriter.Abort()
					cacheWriter = nil
				}
			}
			continue
		}
		doc := textdoc.NewDocument(entry.URI(), languageID, 0, content)
		if !mirror.write(file.Name, content, false) {
			mirrorComplete = false
		}
		parsed := analysis.Parse(ctx, doc)
		if ctx.Err() != nil {
			return false
		}
		summarizeLibraryFile(parsed)
		parsed.References = nil
		parsed.Tokens = nil
		parsed.Diagnostics = nil
		parsed.Folds = nil
		i.canonicalizeLibraryFile(parsed)
		source := LibrarySource{Archive: archive.path, Entry: file.Name, LanguageID: languageID, Binary: archive.binary}
		if !stage(LibraryFile{Source: source, Parsed: *parsed}) {
			complete = false
			break
		}
		if cacheWriter != nil {
			if writeErr := cacheWriter.Write(cachedSourceFile{Source: source, Parsed: *parsed}); writeErr != nil {
				i.recordHealth("library-cache", archive.path, writeErr.Error())
				cacheWriter.Abort()
				cacheWriter = nil
			}
		}
	}
	if !complete || !stagingComplete || ctx.Err() != nil || i.generation.Load() != generation {
		if !stagingComplete {
			i.recordHealth("library", archive.path, "archive exceeds its transactional staging safety limit")
		}
		return false
	}
	if cacheWriter != nil {
		if commitErr := cacheWriter.Commit(); commitErr != nil {
			i.recordHealth("library-cache", archive.path, commitErr.Error())
		}
	}
	if !i.addLibraryArchiveTransaction(archive.path, staged, generation, accessSnapshots...) {
		return false
	}
	progress(int64(len(staged)))
	if mirrorComplete {
		mirror.finish()
	}
	return true
}

func (i *Index) retainLibraryArchiveGeneration(path string, generation uint64) {
	path = filepath.Clean(path)
	i.mu.Lock()
	for uri, source := range i.librarySources {
		if filepath.Clean(source.Archive) == path {
			i.fileGeneration[uri] = generation
		}
	}
	i.mu.Unlock()
}

func parsedBinaryClassfile(document *textdoc.Document, class *classfile.Class) *analysis.ParsedFile {
	parsed := &analysis.ParsedFile{URI: document.URI, Language: analysis.LanguageJava, Version: document.Version, ParseMode: "classfile"}
	digest := sha256.Sum256([]byte(document.Text))
	parsed.TextHash = binary.LittleEndian.Uint64(digest[:8])
	declarations := classfile.JavaDeclarations(class, document.Text)
	if len(declarations) == 0 {
		return parsed
	}
	parsed.Package = strings.TrimSuffix(declarations[0].FQN, "."+declarations[0].Name)
	if parsed.Package == declarations[0].FQN {
		parsed.Package = ""
	}
	if parsed.Package != "" {
		if start := strings.Index(document.Text, parsed.Package); start >= 0 {
			parsed.PackageRange = protocol.Range{Start: document.Position(start), End: document.Position(start + len(parsed.Package))}
		}
	}
	idsByFQN := make(map[string]string, len(declarations))
	seenIDs := make(map[string]int, len(declarations))
	for _, declaration := range declarations {
		start := declaration.NameStart
		if start < 0 || start > len(document.Text) {
			start = 0
		}
		end := declaration.NameEnd
		if end < start || end > len(document.Text) {
			end = start
		}
		kind := binaryDeclarationKind(declaration.Kind)
		id := analysis.SymbolID(document.URI, start, kind, declaration.Name)
		// A malformed navigation stub must not collapse overload identity. The
		// descriptor-derived signature is stable even when several declarations
		// necessarily share their owner's fallback source location.
		if duplicates := seenIDs[id]; duplicates > 0 {
			id += "#" + strconv.Itoa(duplicates)
		}
		seenIDs[analysis.SymbolID(document.URI, start, kind, declaration.Name)]++
		selection := protocol.Range{Start: document.Position(start), End: document.Position(end)}
		parameters := make([]analysis.Parameter, len(declaration.Parameters))
		for index, parameter := range declaration.Parameters {
			parameters[index] = analysis.Parameter{Name: parameter.Name, Type: parameter.Type, Variadic: parameter.Variadic}
		}
		bounds := make(map[string][]string, len(declaration.TypeParameterBounds))
		for name, values := range declaration.TypeParameterBounds {
			bounds[name] = append([]string(nil), values...)
		}
		if len(bounds) == 0 {
			bounds = nil
		}
		symbol := analysis.Symbol{
			ID: id, Name: declaration.Name, FQN: declaration.FQN, Kind: kind,
			Language: analysis.LanguageJava, URI: document.URI, Range: selection, SelectionRange: selection,
			StartByte: start, EndByte: end, NameStartByte: start, NameEndByte: end,
			ScopeStartByte: 0, ScopeEndByte: len(document.Text), ContainerName: binaryContainerName(declaration.ContainerFQN),
			Package: parsed.Package, Type: declaration.Type, Initializer: declaration.Initializer, Signature: declaration.Signature, JVMName: declaration.JVMName, JVMDescriptor: declaration.JVMDescriptor,
			Parameters: parameters, TypeParameters: append([]string(nil), declaration.TypeParameters...), TypeParameterBounds: bounds,
			Supertypes: append([]string(nil), declaration.Supertypes...), Modifiers: append([]string(nil), declaration.Modifiers...), Deprecated: declaration.Deprecated,
		}
		if declaration.ContainerFQN != "" {
			symbol.ContainerID = idsByFQN[declaration.ContainerFQN]
		}
		parsed.Symbols = append(parsed.Symbols, symbol)
		idsByFQN[declaration.FQN] = id
	}
	return parsed
}

func binaryDeclarationKind(kind string) analysis.SymbolKind {
	switch kind {
	case "class":
		return analysis.KindClass
	case "interface":
		return analysis.KindInterface
	case "enum":
		return analysis.KindEnum
	case "annotation":
		return analysis.KindAnnotation
	case "record":
		return analysis.KindRecord
	case "constructor":
		return analysis.KindConstructor
	case "method":
		return analysis.KindMethod
	case "enumMember":
		return analysis.KindEnumMember
	default:
		return analysis.KindField
	}
}

func binaryContainerName(fqn string) string {
	if separator := strings.LastIndexByte(fqn, '.'); separator >= 0 {
		return fqn[separator+1:]
	}
	return fqn
}

func restoreClassfileSourceIdentifiers(parsed *analysis.ParsedFile) {
	if parsed == nil {
		return
	}
	restore := classfile.RestoreSourceJavaIdentifiers
	parsed.Package = restore(parsed.Package)
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		symbol.Name = restore(symbol.Name)
		symbol.FQN = restore(symbol.FQN)
		symbol.ContainerName = restore(symbol.ContainerName)
		symbol.Type = restore(symbol.Type)
		symbol.ReceiverType = restore(symbol.ReceiverType)
		symbol.Signature = restore(symbol.Signature)
		symbol.JVMName = restore(symbol.JVMName)
		for parameter := range symbol.Parameters {
			symbol.Parameters[parameter].Name = restore(symbol.Parameters[parameter].Name)
			symbol.Parameters[parameter].Type = restore(symbol.Parameters[parameter].Type)
		}
		for supertype := range symbol.Supertypes {
			symbol.Supertypes[supertype] = restore(symbol.Supertypes[supertype])
		}
	}
	for index := range parsed.References {
		parsed.References[index].Name = restore(parsed.References[index].Name)
		parsed.References[index].Qualifier = restore(parsed.References[index].Qualifier)
	}
}

func (i *Index) canonicalizeLibraryFile(parsed *analysis.ParsedFile) {
	if parsed == nil {
		return
	}
	parsed.Package = i.internLibraryString(parsed.Package)
	canonicalIDs := make(map[string]string, len(parsed.Symbols))
	ownerNames := make(map[string]string)
	shapes := make([]string, len(parsed.Symbols))
	shapeCounts := make(map[string]int, len(parsed.Symbols))
	for index := range parsed.Symbols {
		shapes[index] = stableLibrarySymbolShape(parsed.URI, parsed.Symbols[index])
		shapeCounts[shapes[index]]++
	}
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		oldID := symbol.ID
		shape := shapes[index]
		if shapeCounts[shape] > 1 {
			// Invalid/ambiguous duplicate declarations have no semantic pairing.
			// Their parser ID is a deterministic tie-breaker within this archive.
			shape += "\x00" + oldID
		}
		digest := sha256.Sum256([]byte(shape))
		newID := "L" + hex.EncodeToString(digest[:16])
		canonicalIDs[oldID] = newID
		symbol.ID = newID
		symbol.Name = i.internLibraryString(symbol.Name)
		if analysis.IsTypeKind(symbol.Kind) {
			ownerNames[newID] = symbol.Name
		}
	}
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		symbol.URI = parsed.URI
		symbol.Package = parsed.Package
		if symbol.SourceURI == parsed.URI {
			symbol.SourceURI = parsed.URI
		}
		if canonical, ok := canonicalIDs[symbol.ContainerID]; ok {
			symbol.ContainerID = canonical
			if name := ownerNames[canonical]; name != "" {
				symbol.ContainerName = name
			}
		}
		if canonical, ok := canonicalIDs[symbol.OriginID]; ok {
			symbol.OriginID = canonical
		}
		symbol.ContainerName = i.internLibraryString(symbol.ContainerName)
		symbol.Type = i.internLibraryString(symbol.Type)
		symbol.ReceiverType = i.internLibraryString(symbol.ReceiverType)
		symbol.JVMName = i.internLibraryString(symbol.JVMName)
		symbol.JVMDescriptor = i.internLibraryString(symbol.JVMDescriptor)
		for modifier := range symbol.Modifiers {
			symbol.Modifiers[modifier] = i.internLibraryString(symbol.Modifiers[modifier])
		}
		for parameter := range symbol.Parameters {
			symbol.Parameters[parameter].Name = i.internLibraryString(symbol.Parameters[parameter].Name)
			symbol.Parameters[parameter].Type = i.internLibraryString(symbol.Parameters[parameter].Type)
			symbol.Parameters[parameter].Default = i.internLibraryString(symbol.Parameters[parameter].Default)
		}
		for parameter := range symbol.TypeParameters {
			symbol.TypeParameters[parameter] = i.internLibraryString(symbol.TypeParameters[parameter])
		}
		for supertype := range symbol.Supertypes {
			symbol.Supertypes[supertype] = i.internLibraryString(symbol.Supertypes[supertype])
		}
	}
}

func stableLibrarySymbolShape(uri protocol.URI, symbol analysis.Symbol) string {
	var value strings.Builder
	write := func(part string) {
		value.WriteString(part)
		value.WriteByte(0)
	}
	write(string(uri))
	write(strconv.Itoa(int(symbol.Kind)))
	write(symbol.FQN)
	write(symbol.ContainerName)
	write(symbol.Name)
	write(symbol.JVMName)
	write(symbol.JVMDescriptor)
	write(symbol.ReceiverType)
	if analysis.IsCallableKind(symbol.Kind) {
		for _, parameter := range symbol.Parameters {
			write(parameter.Name)
			write(parameter.Type)
			write(strconv.FormatBool(parameter.Variadic))
		}
		for _, parameter := range symbol.TypeParameters {
			write(parameter)
		}
	} else if !analysis.IsTypeKind(symbol.Kind) {
		write(symbol.Type)
	}
	return value.String()
}

func (i *Index) internLibraryString(value string) string {
	if canonical, ok := canonicalLibraryStrings[value]; ok {
		return canonical
	}
	if value == "" || len(value) > 256 {
		return value
	}
	i.libraryStringMu.Lock()
	defer i.libraryStringMu.Unlock()
	if canonical, ok := i.libraryStrings[value]; ok {
		return canonical
	}
	if len(i.libraryStrings) >= 1_000_000 {
		return value
	}
	i.libraryStrings[value] = value
	return value
}

var canonicalLibraryStrings = func() map[string]string {
	values := []string{"", "public", "protected", "private", "internal", "static", "final", "abstract", "open", "default", "native", "synchronized", "strictfp", "transient", "volatile", "deprecated", "var", "val", "const", "override", "operator", "infix", "suspend", "inline", "external", "expect", "actual", "companion", "data", "sealed", "annotation", "enum", "record", "void", "boolean", "byte", "short", "int", "long", "float", "double", "char", "String", "Object", "Any", "Unit", "Boolean", "Byte", "Short", "Int", "Long", "Float", "Double", "Char", "T", "E", "K", "V", "R", "value", "other", "name", "index", "key"}
	canonical := make(map[string]string, len(values))
	for _, value := range values {
		canonical[value] = value
	}
	return canonical
}()

func markBinaryWrapperSymbols(parsed *analysis.ParsedFile, internalName string) {
	if !strings.Contains(internalName, "$") {
		return
	}
	targetFQN := strings.ReplaceAll(strings.ReplaceAll(internalName, "/", "."), "$", ".")
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		if analysis.IsTypeKind(symbol.Kind) && symbol.FQN != targetFQN && strings.HasPrefix(targetFQN, symbol.FQN+".") {
			// Retain the wrapper only as an internal container node. It must not
			// become a second navigable declaration of the real outer class.
			symbol.Synthetic = true
		}
	}
}

func summarizeLibraryFile(parsed *analysis.ParsedFile) {
	declarations := make(map[string]analysis.SymbolKind, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		declarations[symbol.ID] = symbol.Kind
	}
	kept := parsed.Symbols[:0]
	for _, symbol := range parsed.Symbols {
		// Private bytecode declarations cannot participate in a workspace lookup.
		// If the editor opens this library file, Open reparses its rendered stub
		// and restores its complete private scope for navigation within the class.
		// Dropping them from the cold global graph avoids retaining implementation
		// detail for every dependency and JDK class.
		if containsString(symbol.Modifiers, "private") {
			continue
		}
		if symbol.Kind == analysis.KindParameter {
			// Callable Parameter values already preserve the public signature.
			// Parameter declarations exist only for lexical source binding and have
			// no role in an unopened library file.
			continue
		}
		if symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindTypeParameter {
			continue
		}
		if analysis.IsTypeKind(symbol.Kind) || symbol.ContainerID == "" {
			kept = append(kept, symbol)
			continue
		}
		if containerKind, ok := declarations[symbol.ContainerID]; ok && analysis.IsTypeKind(containerKind) && containerKind != analysis.KindTypeParameter {
			kept = append(kept, symbol)
		}
	}
	parsed.Symbols = kept
}

func archiveCachePath(archive sourceArchive) (string, bool) {
	return archiveCachePathContext(context.Background(), archive)
}

func archiveCachePathContext(ctx context.Context, archive sourceArchive) (string, bool) {
	digest := archive.digest
	if !archive.digestOK {
		var err error
		digest, err = digestArchiveContext(ctx, archive.path)
		if err != nil {
			return "", false
		}
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	keyInput := strings.Join([]string{archive.path, hex.EncodeToString(digest[:]), itoa64(libraryCacheVersion), itoa64(int64(archive.release))}, "\x00")
	sum := sha256.Sum256([]byte(keyInput))
	base := filepath.Join(cacheRoot, "kotlsp", "libraries")
	versionDir := "v" + strconv.Itoa(libraryCacheVersion)
	dir := filepath.Join(base, versionDir)
	if err := secureMirrorDirectory(cacheRoot, dir, true); err != nil {
		return "", false
	}
	libraryCacheCleanupOnce.Do(func() { cleanupObsoleteLibraryCaches(base, versionDir) })
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json.gz"), true
}

func (i *Index) populateArchiveMetadata(ctx context.Context, archives []sourceArchive, generations ...uint64) {
	current := func() bool {
		return len(generations) == 0 || i.generation.Load() == generations[0]
	}
	for index := range archives {
		if ctx.Err() != nil || !current() {
			return
		}
		reader, openErr := zip.OpenReader(archives[index].path)
		if openErr != nil {
			i.recordHealth("library", archives[index].path, openErr.Error())
			continue
		}
		budget, validateErr := archiveio.NewBudget(archiveSemanticBudgetFiles(archives[index], reader.File))
		if validateErr != nil {
			i.recordHealth("library", archives[index].path, validateErr.Error())
			_ = reader.Close()
			continue
		}
		selected, selectErr := selectedArchiveFilesWithBudgetContext(ctx, archives[index], reader.File, budget)
		if selectErr != nil {
			i.recordHealth("library", archives[index].path, selectErr.Error())
			_ = reader.Close()
			continue
		}
		archives[index].manifest = make([]string, 0, len(selected))
		for _, file := range selected {
			archives[index].manifest = append(archives[index].manifest, file.Name)
		}
		archives[index].manifestOK = true
		if archives[index].binary {
			module, ok, moduleErr := binaryJavaModule(ctx, archives[index], reader.File, budget)
			if moduleErr != nil {
				i.recordHealth("library", archives[index].path, moduleErr.Error())
			}
			if ok {
				i.mu.Lock()
				if !current() {
					i.mu.Unlock()
					_ = reader.Close()
					return
				}
				binaryPath := filepath.Clean(archives[index].path)
				i.libraryModules[binaryPath] = module
				i.semanticEnvironmentVersion++
				for source, binary := range i.libraryModuleAliases {
					if binary == binaryPath {
						i.libraryModules[source] = module
					}
				}
				i.mu.Unlock()
			}
		}
		_ = reader.Close()
	}
}

// binaryJavaModule reads the one archive-level declaration that class entry
// indexing deliberately skips. Multi-release archives select the newest
// descriptor supported by the workspace toolchain, just as their classes do.
// A JAR with only Automatic-Module-Name (or merely placed on the module path)
// still has a real module identity and exports every package.
func binaryJavaModule(ctx context.Context, archive sourceArchive, files []*zip.File, budget *archiveio.Budget) (libraryJavaModule, bool, error) {
	type candidate struct {
		version int
		file    *zip.File
	}
	selected := candidate{version: -1}
	multiRelease, automaticName, manifestErr := archiveManifestModuleMetadata(ctx, files, budget)
	if manifestErr != nil {
		return libraryJavaModule{}, false, manifestErr
	}
	for _, file := range files {
		name := filepath.ToSlash(file.Name)
		logical, version := name, 0
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "meta-inf/versions/") {
			if !multiRelease {
				continue
			}
			remainder := name[len("META-INF/versions/"):]
			slash := strings.IndexByte(remainder, '/')
			if slash <= 0 {
				continue
			}
			parsed, err := strconv.Atoi(remainder[:slash])
			if err != nil || parsed > archive.release {
				continue
			}
			version, logical = parsed, remainder[slash+1:]
		}
		logical = strings.TrimPrefix(filepath.ToSlash(logical), "classes/")
		if strings.EqualFold(logical, "module-info.class") && version > selected.version {
			selected = candidate{version: version, file: file}
		}
	}
	if selected.file != nil {
		if data, err := budget.ReadContext(ctx, selected.file, archiveio.MaxMetadataBytes); err == nil {
			if parsed, parseErr := classfile.Parse(data); parseErr == nil && parsed.Module != nil {
				return libraryModuleFromClassfile(parsed.Module), true, nil
			}
		} else {
			return libraryJavaModule{}, false, err
		}
	}
	name := automaticName
	if name == "" {
		name = archive.module
	}
	if name == "" && strings.HasSuffix(strings.ToLower(archive.path), ".jar") {
		name = derivedAutomaticModuleName(filepath.Base(archive.path))
	}
	if name == "" {
		return libraryJavaModule{}, false, nil
	}
	return libraryJavaModule{Name: name, Automatic: true}, true, nil
}

func libraryModuleFromClassfile(descriptor *classfile.ModuleDescriptor) libraryJavaModule {
	module := libraryJavaModule{
		Name: descriptor.Name, Open: descriptor.Open,
		Requires: make(map[string]JavaModuleRequirement, len(descriptor.Requires)),
		Exports:  make(map[string][]string, len(descriptor.Exports)),
		Opens:    make(map[string][]string, len(descriptor.Opens)),
	}
	for _, requirement := range descriptor.Requires {
		module.Requires[requirement.Name] = JavaModuleRequirement{Transitive: requirement.Transitive, Static: requirement.Static}
	}
	for _, exported := range descriptor.Exports {
		targets := append([]string(nil), exported.Targets...)
		if len(targets) == 0 {
			targets = []string{"*"}
		}
		module.Exports[exported.Package] = targets
	}
	for _, opened := range descriptor.Opens {
		targets := append([]string(nil), opened.Targets...)
		if len(targets) == 0 {
			targets = []string{"*"}
		}
		module.Opens[opened.Package] = targets
	}
	return module
}

func archiveManifestModuleMetadata(ctx context.Context, files []*zip.File, budget *archiveio.Budget) (multiRelease bool, automaticName string, resultErr error) {
	for _, file := range files {
		if !strings.EqualFold(filepath.ToSlash(file.Name), "META-INF/MANIFEST.MF") {
			continue
		}
		data, err := budget.ReadContext(ctx, file, archiveio.MaxMetadataBytes)
		if err != nil {
			return false, "", err
		}
		unfolded := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n ", ""), "\n ", "")
		for _, line := range strings.Split(unfolded, "\n") {
			key, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			switch {
			case strings.EqualFold(strings.TrimSpace(key), "Multi-Release"):
				multiRelease = strings.EqualFold(strings.TrimSpace(value), "true")
			case strings.EqualFold(strings.TrimSpace(key), "Automatic-Module-Name"):
				automaticName = strings.TrimSpace(value)
			}
		}
		break
	}
	return multiRelease, automaticName, nil
}

func derivedAutomaticModuleName(filename string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	for index := 0; index+1 < len(name); index++ {
		if name[index] != '-' || name[index+1] < '0' || name[index+1] > '9' {
			continue
		}
		name = name[:index]
		break
	}
	var result strings.Builder
	dot := true
	for _, character := range name {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !alphaNumeric {
			if !dot {
				result.WriteByte('.')
				dot = true
			}
			continue
		}
		result.WriteRune(character)
		dot = false
	}
	return strings.Trim(result.String(), ".")
}

func setArchivePriorityTargets(archives []sourceArchive, targets []string) {
	for index := range archives {
		archives[index].priorityTargets = targets
	}
}

func digestArchive(path string) ([sha256.Size]byte, error) {
	return digestArchiveContext(context.Background(), path)
}

func digestArchiveContext(ctx context.Context, path string) ([sha256.Size]byte, error) {
	const maxArchiveFileBytes int64 = 4 << 30
	if ctx == nil {
		ctx = context.Background()
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil {
		return [sha256.Size]byte{}, statErr
	} else if info.Size() > maxArchiveFileBytes {
		return [sha256.Size]byte{}, fmt.Errorf("archive exceeds its %d-byte content-identity safety limit", maxArchiveFileBytes)
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	for {
		if ctx.Err() != nil {
			return [sha256.Size]byte{}, ctx.Err()
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [sha256.Size]byte{}, readErr
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

var libraryCacheCleanupOnce sync.Once

func cleanupObsoleteLibraryCaches(base, currentVersion string) {
	directory, err := os.Open(base)
	if err != nil {
		return
	}
	defer directory.Close()
	visited := 0
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			visited++
			if visited > 10_000 {
				return
			}
			path := filepath.Join(base, entry.Name())
			if entry.IsDir() {
				if strings.HasPrefix(entry.Name(), "v") && entry.Name() != currentVersion {
					_ = os.RemoveAll(path)
				}
				continue
			}
			// Early cache versions used a flat directory. These snapshots are
			// fully reproducible and structurally incompatible with compact IDs.
			if strings.HasSuffix(entry.Name(), ".gob.gz") || strings.HasPrefix(entry.Name(), ".library-") {
				_ = os.Remove(path)
			}
		}
		if readErr != nil {
			return
		}
	}
}

func loadArchiveCache(ctx context.Context, archive sourceArchive, consume func(cachedSourceFile) bool) bool {
	path, ok := archiveCachePathContext(ctx, archive)
	if !ok {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil || info.Size() > 512<<20 {
		return false
	}
	allowed := make(map[string]bool, len(archive.manifest))
	if archive.manifestOK {
		for _, name := range archiveSemanticManifest(archive) {
			allowed[name] = true
		}
	}
	// First pass validates the complete stream and every cache-owned identity.
	// No index mutation occurs until EOF has proved the snapshot complete.
	count, valid := validateArchiveCacheStream(ctx, file, archive, allowed)
	if ctx.Err() != nil {
		return true
	}
	if !valid {
		return false
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	reader, closeReader, err := newArchiveCacheReader(file)
	if err != nil {
		return false
	}
	defer closeReader()
	headerRecord, err := readArchiveCacheRecord(reader)
	if err != nil {
		return false
	}
	var header cachedArchive
	if json.Unmarshal(headerRecord, &header) != nil || !validCachedArchiveHeader(header, archive, len(allowed)) {
		return false
	}
	for index := 0; index < count; index++ {
		if ctx.Err() != nil {
			return true
		}
		record, readErr := readArchiveCacheRecord(reader)
		if readErr != nil {
			return false
		}
		var entry cachedSourceFile
		if json.Unmarshal(record, &entry) != nil || !validCachedSourceFile(entry, archive, allowed) {
			return false
		}
		if !consume(entry) {
			return true
		}
	}
	_, err = readArchiveCacheRecord(reader)
	return err == io.EOF
}

func newArchiveCacheReader(file io.Reader) (*bufio.Reader, func(), error) {
	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, func() {}, err
	}
	return bufio.NewReaderSize(zr, 64<<10), func() { _ = zr.Close() }, nil
}

func readArchiveCacheRecord(reader *bufio.Reader) ([]byte, error) {
	var record bytes.Buffer
	for {
		fragment, err := reader.ReadSlice('\n')
		if record.Len()+len(fragment) > maxLibraryCacheRecordBytes {
			return nil, fmt.Errorf("library cache record exceeds its %d-byte safety limit", maxLibraryCacheRecordBytes)
		}
		record.Write(fragment)
		switch err {
		case nil:
			value := record.Bytes()
			return bytes.TrimSuffix(value, []byte{'\n'}), nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if record.Len() == 0 {
				return nil, io.EOF
			}
			return nil, io.ErrUnexpectedEOF
		default:
			return nil, err
		}
	}
}

func validateArchiveCacheStream(ctx context.Context, file io.Reader, archive sourceArchive, allowed map[string]bool) (int, bool) {
	reader, closeReader, err := newArchiveCacheReader(file)
	if err != nil {
		return 0, false
	}
	defer closeReader()
	headerRecord, err := readArchiveCacheRecord(reader)
	if err != nil {
		return 0, false
	}
	var header cachedArchive
	if json.Unmarshal(headerRecord, &header) != nil || !validCachedArchiveHeader(header, archive, len(allowed)) {
		return 0, false
	}
	expanded := uint64(len(headerRecord) + 1)
	seen := make(map[string]bool, min(header.Entries, archiveio.MaxArchiveEntries))
	for count := 0; ; count++ {
		if ctx.Err() != nil {
			return count, true
		}
		record, readErr := readArchiveCacheRecord(reader)
		if readErr == io.EOF {
			return count, count == header.Entries && (!archive.manifestOK || len(seen) == len(allowed))
		}
		if readErr != nil || count >= archiveio.MaxArchiveEntries || uint64(len(record)+1) > archiveio.MaxArchiveExpandedBytes-expanded {
			return count, false
		}
		expanded += uint64(len(record) + 1)
		var entry cachedSourceFile
		if json.Unmarshal(record, &entry) != nil || !validCachedSourceFile(entry, archive, allowed) {
			return count, false
		}
		if seen[entry.Source.Entry] {
			return count, false
		}
		seen[entry.Source.Entry] = true
	}
}

func validCachedArchiveHeader(header cachedArchive, archive sourceArchive, allowed int) bool {
	if header.Version != libraryCacheVersion || header.Entries < 0 || header.Entries > archiveio.MaxArchiveEntries {
		return false
	}
	if archive.manifestOK {
		return header.Manifest && header.Entries == allowed
	}
	return !header.Manifest
}

func validCachedSourceFile(entry cachedSourceFile, archive sourceArchive, allowed map[string]bool) bool {
	if filepath.Clean(entry.Source.Archive) != filepath.Clean(archive.path) || entry.Source.Binary != archive.binary || entry.Source.Entry == "" {
		return false
	}
	normalizedEntry := filepath.ToSlash(entry.Source.Entry)
	if normalizedEntry != entry.Source.Entry || strings.HasPrefix(normalizedEntry, "/") || strings.IndexByte(normalizedEntry, 0) >= 0 {
		return false
	}
	for _, component := range strings.Split(normalizedEntry, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	if archive.manifestOK && !allowed[entry.Source.Entry] {
		return false
	}
	expectedLanguage := languageForEntry(entry.Source.Entry)
	if archive.binary {
		expectedLanguage = "java"
	}
	if entry.Source.LanguageID != expectedLanguage {
		return false
	}
	expectedParsedLanguage := analysis.LanguageJava
	if expectedLanguage == "kotlin" {
		expectedParsedLanguage = analysis.LanguageKotlin
	}
	expectedURI := archiveEntry{archive: archive, name: entry.Source.Entry}.URI()
	if entry.Parsed.URI != expectedURI || entry.Parsed.Language != expectedParsedLanguage || entry.Parsed.Version != 0 || !validCachedString(entry.Parsed.Package) || !validCachedString(entry.Parsed.JVMFacadeName) || !validCachedParseMode(entry.Parsed.ParseMode) || !validCachedRange(entry.Parsed.PackageRange) || len(entry.Parsed.Symbols) > 200_000 || len(entry.Parsed.Imports) > 100_000 || len(entry.Parsed.SmartCasts) > 200_000 {
		return false
	}
	if len(entry.Parsed.References) != 0 || len(entry.Parsed.Tokens) != 0 || len(entry.Parsed.Diagnostics) != 0 || len(entry.Parsed.Folds) != 0 {
		return false
	}
	for _, imported := range entry.Parsed.Imports {
		if !validCachedString(imported.Path) || !validCachedString(imported.Alias) || !validCachedRange(imported.Range) {
			return false
		}
	}
	for _, cast := range entry.Parsed.SmartCasts {
		if !validCachedString(cast.Name) || !validCachedString(cast.Type) || !validCachedByteSpan(cast.StartByte, cast.EndByte) {
			return false
		}
	}
	for _, symbol := range entry.Parsed.Symbols {
		if symbol.URI != expectedURI || symbol.Kind < analysis.KindPackage || symbol.Kind > analysis.KindLabel || symbol.Language < analysis.LanguageKotlin || symbol.Language > analysis.LanguageJava || !validCachedSymbolStrings(symbol) || !validCachedRange(symbol.Range) || !validCachedRange(symbol.SelectionRange) || !validCachedRange(symbol.SourceRange) || !validCachedByteSpan(symbol.StartByte, symbol.EndByte) || !validCachedByteSpan(symbol.NameStartByte, symbol.NameEndByte) || symbol.NameStartByte < symbol.StartByte || symbol.NameEndByte > symbol.EndByte || !validCachedByteSpan(symbol.ScopeStartByte, symbol.ScopeEndByte) || len(symbol.AdditionalScopes) > 4096 || len(symbol.Parameters) > 4096 || len(symbol.TypeParameters) > 4096 || len(symbol.TypeParameterBounds) > 4096 || len(symbol.Supertypes) > 4096 || len(symbol.Modifiers) > 4096 {
			return false
		}
		for _, scope := range symbol.AdditionalScopes {
			if !validCachedByteSpan(scope.StartByte, scope.EndByte) {
				return false
			}
		}
		for _, parameter := range symbol.Parameters {
			if !validCachedString(parameter.Name) || !validCachedString(parameter.Type) || !validCachedString(parameter.Default) || !validCachedRange(parameter.Range) {
				return false
			}
		}
		for _, value := range symbol.TypeParameters {
			if !validCachedString(value) {
				return false
			}
		}
		for name, bounds := range symbol.TypeParameterBounds {
			if !validCachedString(name) || len(bounds) > 4096 {
				return false
			}
			for _, bound := range bounds {
				if !validCachedString(bound) {
					return false
				}
			}
		}
		for _, values := range [][]string{symbol.Supertypes, symbol.Modifiers} {
			for _, value := range values {
				if !validCachedString(value) {
					return false
				}
			}
		}
	}
	return true
}

const maxCachedLibraryStringBytes = 1 << 20

func validCachedString(value string) bool {
	return len(value) <= maxCachedLibraryStringBytes && strings.IndexByte(value, 0) < 0
}

func validCachedSymbolStrings(symbol analysis.Symbol) bool {
	return validCachedString(symbol.ID) && validCachedString(symbol.Name) && validCachedString(symbol.FQN) && validCachedString(string(symbol.URI)) && validCachedString(symbol.ContainerID) && validCachedString(symbol.ContainerName) && validCachedString(symbol.Package) && validCachedString(symbol.Type) && validCachedString(symbol.Initializer) && validCachedString(symbol.ReceiverType) && validCachedString(symbol.Signature) && validCachedString(symbol.JVMName) && validCachedString(symbol.JVMDescriptor) && validCachedString(symbol.Documentation) && validCachedString(symbol.OriginID) && validCachedString(string(symbol.SourceURI))
}

func validCachedParseMode(mode string) bool {
	switch mode {
	case "full", "snapshot", "large", "classfile":
		return true
	default:
		return false
	}
}

func validCachedByteSpan(start, end int) bool {
	const maxRenderedArchiveEntryBytes = 256 << 20
	return start >= 0 && end >= start && end <= maxRenderedArchiveEntryBytes
}

func validCachedRange(value protocol.Range) bool {
	const maxCachedPosition = 256 << 20
	if value.Start.Line < 0 || value.Start.Character < 0 || value.End.Line < 0 || value.End.Character < 0 || value.Start.Line > maxCachedPosition || value.Start.Character > maxCachedPosition || value.End.Line > maxCachedPosition || value.End.Character > maxCachedPosition {
		return false
	}
	return value.Start.Line < value.End.Line || value.Start.Line == value.End.Line && value.Start.Character <= value.End.Character
}

type archiveCacheWriter struct {
	path      string
	tmpPath   string
	file      *os.File
	zip       *gzip.Writer
	expanded  uint64
	entries   int
	expected  int
	committed bool
}

func newArchiveCacheWriter(ctx context.Context, archive sourceArchive) (*archiveCacheWriter, error) {
	if !archive.manifestOK {
		return nil, os.ErrInvalid
	}
	path, ok := archiveCachePathContext(ctx, archive)
	if !ok {
		return nil, os.ErrInvalid
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".library-*.tmp")
	if err != nil {
		return nil, err
	}
	_ = tmp.Chmod(0o600)
	zw, err := gzip.NewWriterLevel(tmp, gzip.BestSpeed)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	expected := archiveSemanticEntryCount(archive)
	writer := &archiveCacheWriter{path: path, tmpPath: tmp.Name(), file: tmp, zip: zw, expected: expected}
	if err = writer.writeRecord(cachedArchive{Version: libraryCacheVersion, Entries: expected, Manifest: archive.manifestOK}); err != nil {
		_ = zw.Close()
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return writer, nil
}

func (w *archiveCacheWriter) Write(entry cachedSourceFile) error {
	if w == nil || w.zip == nil || w.committed {
		return os.ErrInvalid
	}
	if w.entries >= archiveio.MaxArchiveEntries {
		return fmt.Errorf("library cache exceeds its %d-entry safety limit", archiveio.MaxArchiveEntries)
	}
	if err := w.writeRecord(entry); err != nil {
		return err
	}
	w.entries++
	return nil
}

func (w *archiveCacheWriter) writeRecord(value any) error {
	record, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(record) > maxLibraryCacheRecordBytes {
		return fmt.Errorf("library cache record exceeds its %d-byte safety limit", maxLibraryCacheRecordBytes)
	}
	needed := uint64(len(record) + 1)
	if needed > archiveio.MaxArchiveExpandedBytes-w.expanded {
		return fmt.Errorf("library cache exceeds its %d-byte expanded safety limit", archiveio.MaxArchiveExpandedBytes)
	}
	if _, err = w.zip.Write(record); err != nil {
		return err
	}
	if _, err = w.zip.Write([]byte{'\n'}); err != nil {
		return err
	}
	w.expanded += needed
	return nil
}

func (w *archiveCacheWriter) Commit() error {
	if w == nil || w.file == nil || w.zip == nil || w.committed {
		return os.ErrInvalid
	}
	if w.entries != w.expected {
		return fmt.Errorf("library cache contains %d entries; complete manifest requires %d", w.entries, w.expected)
	}
	if err := w.zip.Close(); err != nil {
		return err
	}
	w.zip = nil
	if position, err := w.file.Seek(0, io.SeekCurrent); err != nil || position > 512<<20 {
		return fmt.Errorf("compressed library cache exceeds its 512 MiB safety limit")
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	if err := os.Rename(w.tmpPath, w.path); err != nil {
		return err
	}
	w.committed = true
	return nil
}

func (w *archiveCacheWriter) Abort() {
	if w == nil || w.committed {
		return
	}
	if w.zip != nil {
		_ = w.zip.Close()
		w.zip = nil
	}
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if w.tmpPath != "" {
		_ = os.Remove(w.tmpPath)
	}
}

func itoa64(value int64) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [32]byte
	n := len(digits)
	for value > 0 {
		n--
		digits[n] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		n--
		digits[n] = '-'
	}
	return string(digits[n:])
}

type sourceArchive struct {
	path            string
	jdk             bool
	binary          bool
	module          string
	release         int
	digest          [sha256.Size]byte
	digestOK        bool
	manifest        []string
	manifestOK      bool
	priorityTargets []string
}

type archiveEntry struct {
	archive sourceArchive
	name    string
}

func (e archiveEntry) URI() protocol.URI {
	name := strings.TrimPrefix(filepath.ToSlash(e.name), "/")
	if e.archive.jdk {
		if e.archive.binary {
			name = strings.TrimPrefix(name, "classes/")
			return protocol.URI("jrt://" + e.archive.module + "/" + name)
		}
		return protocol.URI("jrt://" + name)
	}
	return protocol.URI("jar://" + filepath.ToSlash(e.archive.path) + "!/" + name)
}

func loadLibraryDocument(uri protocol.URI, source LibrarySource) (*textdoc.Document, error) {
	return loadLibraryDocumentContext(context.Background(), uri, source)
}

func loadLibraryDocumentContext(ctx context.Context, uri protocol.URI, source LibrarySource) (*textdoc.Document, error) {
	reader, err := zip.OpenReader(source.Archive)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	entryName := filepath.ToSlash(source.Entry)
	for _, file := range reader.File {
		if filepath.ToSlash(file.Name) != entryName {
			continue
		}
		data, readErr := archiveio.ReadZipFileContext(ctx, file, archiveio.MaxEntryBytes)
		if readErr != nil {
			return nil, readErr
		}
		content := string(data)
		languageID := source.LanguageID
		if source.Binary {
			parsed, parseErr := classfile.Parse(data)
			if parseErr != nil {
				return nil, parseErr
			}
			content = classfile.RenderJava(parsed)
			languageID = "java"
		}
		return textdoc.NewDocument(uri, languageID, 0, content), nil
	}
	return nil, os.ErrNotExist
}
