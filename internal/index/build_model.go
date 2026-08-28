package index

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shinyvision/kotlsp/internal/archiveio"
	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

func resolveClasspath(ctx context.Context, root string) []string {
	return resolveClasspathModel(ctx, root).Classpath
}

type classpathResolution struct {
	Importer      string
	Authoritative bool
	// SelfContained marks a workspace no build tool describes: there is no
	// Gradle or Maven script anywhere under the root, so conventional
	// discovery is not a degraded stand-in for some truer model but the whole
	// of it. It is never set when a build script exists and its import failed.
	SelfContained                bool
	Failure                      string
	CacheWarning                 string
	UsedConfigurationFallback    bool
	Classpath                    []string
	ModuleClasspath              map[string][]string
	Dependencies                 map[string][]string
	SourceSetClasspath           map[string]map[string][]string
	RuntimeSourceSetClasspath    map[string]map[string][]string
	SourceSetDependencies        map[string]map[string][]string
	RuntimeSourceSetDependencies map[string]map[string][]string
	SourceSetExported            map[string]map[string][]string
	DependencyExclusions         map[string]map[string][]string
	ExternalDependencyExclusions map[string]map[string][]string
	SourceSetDependsOn           map[string]map[string][]string
	SourceSetRoots               map[string]map[string][]string
	CompilerSettings             map[string]map[string]CompilerSettings
}

const buildModelCacheVersion = 13

const maxBuildModelCacheBytes = 64 << 20

type cachedBuildModel struct {
	Version     int
	Fingerprint [sha256.Size]byte
	Resolution  classpathResolution
}

type boundedBuildOutput struct {
	data      []byte
	limit     int
	truncated bool
}

func (output *boundedBuildOutput) Write(value []byte) (int, error) {
	written := len(value)
	remaining := output.limit - len(output.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		output.data = append(output.data, value[:remaining]...)
	}
	if remaining < len(value) {
		output.truncated = true
	}
	return written, nil
}

func isModularPath(path string) bool {
	path = filepath.Clean(path)
	modular := false
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			for _, name := range []string{"module-info.class", "module-info.java"} {
				if _, statErr := os.Stat(filepath.Join(path, name)); statErr == nil {
					modular = true
					break
				}
			}
		} else if strings.HasSuffix(strings.ToLower(path), ".jar") {
			if archive, openErr := zip.OpenReader(path); openErr == nil {
				budget, budgetErr := archiveio.NewBudget(archive.File)
				if budgetErr != nil {
					_ = archive.Close()
					return false
				}
				for _, file := range archive.File {
					name := filepath.ToSlash(file.Name)
					if name == "module-info.class" || strings.HasPrefix(name, "META-INF/versions/") && strings.HasSuffix(name, "/module-info.class") {
						modular = true
						break
					}
					if strings.EqualFold(name, "META-INF/MANIFEST.MF") {
						manifest, readErr := budget.Read(file, archiveio.MaxMetadataBytes)
						if readErr == nil {
							for _, line := range strings.Split(strings.ReplaceAll(string(manifest), "\r\n ", ""), "\n") {
								if strings.HasPrefix(strings.ToLower(line), "automatic-module-name:") && strings.TrimSpace(strings.TrimPrefix(line, line[:strings.IndexByte(line, ':')+1])) != "" {
									modular = true
									break
								}
							}
						}
					}
				}
				_ = archive.Close()
			}
		}
	}
	return modular
}

func newClasspathResolution() classpathResolution {
	return classpathResolution{
		ModuleClasspath:              make(map[string][]string),
		Dependencies:                 make(map[string][]string),
		SourceSetClasspath:           make(map[string]map[string][]string),
		RuntimeSourceSetClasspath:    make(map[string]map[string][]string),
		SourceSetDependencies:        make(map[string]map[string][]string),
		RuntimeSourceSetDependencies: make(map[string]map[string][]string),
		SourceSetExported:            make(map[string]map[string][]string),
		DependencyExclusions:         make(map[string]map[string][]string),
		ExternalDependencyExclusions: make(map[string]map[string][]string),
		SourceSetDependsOn:           make(map[string]map[string][]string),
		SourceSetRoots:               make(map[string]map[string][]string),
		CompilerSettings:             make(map[string]map[string]CompilerSettings),
	}
}

// compileClasspathEntries returns the complete binary input inventory carried
// by a build model. Source-set-aware importers may have no useful legacy flat
// Classpath at all: Gradle, in particular, can report only
// SourceSetClasspath. Consumers which looked solely at Classpath would then
// publish the module model while indexing zero dependency declarations.
func compileClasspathEntries(resolution classpathResolution) ([]string, bool) {
	const maxClasspathEntries = 100_000
	seen := make(map[string]bool)
	entries := make([]string, 0, len(resolution.Classpath))
	complete := true
	appendValues := func(values []string) {
		for _, value := range values {
			if complete && !seen[value] {
				if len(entries) >= maxClasspathEntries {
					complete = false
					return
				}
				seen[value] = true
				entries = append(entries, value)
			}
		}
	}
	// Prefer production source sets. The legacy flat classpath commonly unions
	// main and test configurations; putting it first made a cold editor index
	// ByteBuddy/JUnit/etc. before transitive production APIs needed by an open
	// main source file.
	modules := make([]string, 0, len(resolution.SourceSetClasspath))
	for module := range resolution.SourceSetClasspath {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	for _, module := range modules {
		bySourceSet := resolution.SourceSetClasspath[module]
		sourceSets := make([]string, 0, len(bySourceSet))
		for sourceSet := range bySourceSet {
			sourceSets = append(sourceSets, sourceSet)
		}
		sort.Slice(sourceSets, func(left, right int) bool {
			priority := func(value string) int {
				lower := strings.ToLower(value)
				if lower == "main" || strings.HasSuffix(lower, "main") {
					return 0
				}
				if lower == "test" || strings.HasSuffix(lower, "test") {
					return 2
				}
				return 1
			}
			leftPriority, rightPriority := priority(sourceSets[left]), priority(sourceSets[right])
			if leftPriority != rightPriority {
				return leftPriority < rightPriority
			}
			return sourceSets[left] < sourceSets[right]
		})
		for _, sourceSet := range sourceSets {
			appendValues(bySourceSet[sourceSet])
		}
	}
	moduleNames := make([]string, 0, len(resolution.ModuleClasspath))
	for module := range resolution.ModuleClasspath {
		moduleNames = append(moduleNames, module)
	}
	sort.Strings(moduleNames)
	for _, module := range moduleNames {
		appendValues(resolution.ModuleClasspath[module])
	}
	appendValues(resolution.Classpath)
	return entries, complete
}

func resolveClasspathModel(ctx context.Context, root string) classpathResolution {
	fingerprint, fingerprintErr := buildModelFingerprint(root, false)
	if fingerprintErr == nil {
		if cached, ok := loadBuildModelCache(root, fingerprint); ok {
			cached.Classpath = append(cached.Classpath, conventionalOutputDirectories(root)...)
			var complete bool
			cached.Classpath, complete = compileClasspathEntries(cached)
			if complete && validateClasspathResolution(cached) == nil {
				return cached
			}
		}
	}
	resolution := newClasspathResolution()
	paths := make([]string, 0)
	resolvedByBuildTool := false
	if gradle := gradleLauncher(root); gradle != "" {
		gradleResolution := gradleClasspathModel(ctx, root, gradle)
		resolution.Importer = gradleResolution.Importer
		resolution.Failure = gradleResolution.Failure
		resolution.Authoritative = gradleResolution.Authoritative
		resolution.UsedConfigurationFallback = gradleResolution.UsedConfigurationFallback
		paths = append(paths, gradleResolution.Classpath...)
		resolvedByBuildTool = len(gradleResolution.Classpath) > 0
		resolution.ModuleClasspath = gradleResolution.ModuleClasspath
		resolution.Dependencies = gradleResolution.Dependencies
		resolution.SourceSetClasspath = gradleResolution.SourceSetClasspath
		resolution.RuntimeSourceSetClasspath = gradleResolution.RuntimeSourceSetClasspath
		resolution.SourceSetDependencies = gradleResolution.SourceSetDependencies
		resolution.RuntimeSourceSetDependencies = gradleResolution.RuntimeSourceSetDependencies
		resolution.SourceSetExported = gradleResolution.SourceSetExported
		resolution.DependencyExclusions = gradleResolution.DependencyExclusions
		resolution.ExternalDependencyExclusions = gradleResolution.ExternalDependencyExclusions
		resolution.SourceSetDependsOn = gradleResolution.SourceSetDependsOn
		resolution.SourceSetRoots = gradleResolution.SourceSetRoots
		resolution.CompilerSettings = gradleResolution.CompilerSettings
		gradleCompileClasspath, complete := compileClasspathEntries(gradleResolution)
		paths = append(paths, gradleCompileClasspath...)
		if !complete {
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle compile classpath exceeds its 100000-path safety limit")
		}
		resolvedByBuildTool = len(gradleCompileClasspath) > 0
	}
	if len(paths) == 0 {
		if maven := mavenLauncher(root); maven != "" {
			resolution.Importer = "maven"
			var mavenFailures []string
			effectiveModels := make(map[string]mavenPOM)
			modules, discoverErr := discoverModulesContext(ctx, []string{root})
			if discoverErr != nil {
				mavenFailures = append(mavenFailures, "Maven reactor discovery: "+discoverErr.Error())
			}
			mavenModules, importedMavenModules := 0, 0
			for moduleIndex, module := range modules {
				if moduleIndex&31 == 0 && ctx.Err() != nil {
					mavenFailures = append(mavenFailures, ctx.Err().Error())
					break
				}
				if _, err := os.Stat(filepath.Join(module.Dir, "pom.xml")); err != nil {
					continue
				}
				mavenModules++
				mergeDiscoveredModuleGraph(&resolution, module)
				mainPaths, testPaths, runtimePaths, settings, effectiveModel, modelErr := mavenClasspaths(ctx, module.Dir, maven)
				if modelErr != nil {
					mavenFailures = append(mavenFailures, module.Dir+": "+modelErr.Error())
				} else {
					importedMavenModules++
					effectiveModels[module.Name] = effectiveModel
				}
				modulePaths := uniqueSortedStrings(append(append([]string(nil), mainPaths...), testPaths...))
				resolution.ModuleClasspath[module.Name] = uniqueSortedStrings(append(resolution.ModuleClasspath[module.Name], modulePaths...))
				if resolution.SourceSetClasspath[module.Name] == nil {
					resolution.SourceSetClasspath[module.Name] = make(map[string][]string)
				}
				resolution.SourceSetClasspath[module.Name]["main"] = mainPaths
				resolution.SourceSetClasspath[module.Name]["test"] = testPaths
				if resolution.RuntimeSourceSetClasspath[module.Name] == nil {
					resolution.RuntimeSourceSetClasspath[module.Name] = make(map[string][]string)
				}
				resolution.RuntimeSourceSetClasspath[module.Name]["main"] = runtimePaths
				resolution.RuntimeSourceSetClasspath[module.Name]["test"] = testPaths
				if resolution.CompilerSettings[module.Name] == nil {
					resolution.CompilerSettings[module.Name] = make(map[string]CompilerSettings)
				}
				resolution.CompilerSettings[module.Name]["main"] = settings
				resolution.CompilerSettings[module.Name]["test"] = settings
				if resolution.SourceSetRoots[module.Name] == nil {
					resolution.SourceSetRoots[module.Name] = make(map[string][]string)
				}
				if effectiveModel.Build.SourceDirectory != "" {
					resolution.SourceSetRoots[module.Name]["main"] = appendUniqueString(resolution.SourceSetRoots[module.Name]["main"], resolveMavenModelPath(module.Dir, effectiveModel.Build.SourceDirectory))
				}
				if effectiveModel.Build.TestSourceDirectory != "" {
					resolution.SourceSetRoots[module.Name]["test"] = appendUniqueString(resolution.SourceSetRoots[module.Name]["test"], resolveMavenModelPath(module.Dir, effectiveModel.Build.TestSourceDirectory))
				}
				additionalMain, additionalTest := mavenAdditionalSourceRoots(effectiveModel, module.Dir)
				resolution.SourceSetRoots[module.Name]["main"] = append(resolution.SourceSetRoots[module.Name]["main"], additionalMain...)
				resolution.SourceSetRoots[module.Name]["test"] = append(resolution.SourceSetRoots[module.Name]["test"], additionalTest...)
				paths = append(paths, modulePaths...)
				if len(paths) > 100_000 {
					paths = paths[:100_000]
					mavenFailures = append(mavenFailures, "Maven classpath exceeds its 100000-path safety limit")
					break
				}
				resolvedByBuildTool = resolvedByBuildTool || modelErr == nil
			}
			if mavenModules == 0 {
				_, fallbackPaths, _, _, _, fallbackErr := mavenClasspaths(ctx, root, maven)
				paths = append(paths, fallbackPaths...)
				if fallbackErr != nil {
					mavenFailures = append(mavenFailures, root+": "+fallbackErr.Error())
				}
				mavenFailures = append(mavenFailures, "Maven reactor module identity was unavailable; root classpath import is degraded")
				resolvedByBuildTool = len(paths) > 0
			}
			if mavenModules > 0 && importedMavenModules != mavenModules {
				mavenFailures = append(mavenFailures, "Maven effective model was not imported for every reactor module")
			}
			if mavenModules > 0 && importedMavenModules == mavenModules && len(mavenFailures) == 0 {
				if graphErr := replaceWithEffectiveMavenGraph(&resolution, effectiveModels); graphErr != nil {
					mavenFailures = append(mavenFailures, graphErr.Error())
				}
			}
			resolution.Authoritative = resolvedByBuildTool && mavenModules > 0 && importedMavenModules == mavenModules && len(mavenFailures) == 0
			resolution.Failure = strings.Join(uniqueSortedStrings(mavenFailures), "; ")
		}
	}
	if len(paths) == 0 {
		fallbackJars, exhausted := directJarReferences(root)
		paths = append(paths, fallbackJars...)
		if resolution.Importer == "" {
			resolution.Importer = "conventional"
		}
		resolution.Authoritative = false
		if !buildScriptPresent(root) {
			resolution.SelfContained = true
			resolution.Failure = appendIncompleteReason(resolution.Failure, "no build tool is present; conventional JAR/output discovery describes the whole project")
		} else {
			resolution.Failure = appendIncompleteReason(resolution.Failure, "no authoritative build-tool model; conventional JAR/output discovery was used")
		}
		if exhausted {
			resolution.Failure = appendIncompleteReason(resolution.Failure, "conventional JAR discovery exceeded its 20000-entry/4096-archive safety limit")
		}
	}
	paths = append(paths, conventionalOutputDirectories(root)...)
	sort.Strings(paths)
	out := paths[:0]
	for _, path := range paths {
		if len(out) == 0 || out[len(out)-1] != path {
			out = append(out, path)
		}
	}
	resolution.Classpath = out
	// Never turn a transient Gradle/Maven failure into a persistent model that
	// contains only wrapper JARs or stale output directories.
	if fingerprintErr != nil {
		resolution.Authoritative = false
		resolution.SelfContained = false
		resolution.Failure = strings.Trim(strings.Join([]string{resolution.Failure, "build input inventory: " + fingerprintErr.Error()}, "; "), "; ")
	}
	if validationErr := validateClasspathResolution(resolution); validationErr != nil {
		degraded := newClasspathResolution()
		degraded.Importer = boundedStatusText(resolution.Importer, 1024)
		degraded.Authoritative = false
		degraded.Failure = appendIncompleteReason(boundedStatusText(resolution.Failure, 4096), validationErr.Error())
		for _, path := range resolution.Classpath {
			if len(degraded.Classpath) >= 100_000 {
				break
			}
			if len(path) <= 1<<20 && strings.IndexByte(path, 0) < 0 {
				degraded.Classpath = append(degraded.Classpath, path)
			}
		}
		return degraded
	}
	if fingerprintErr == nil && len(out) > 0 && resolvedByBuildTool {
		if saveErr := saveBuildModelCache(root, fingerprint, resolution); saveErr != nil {
			resolution.CacheWarning = saveErr.Error()
		}
	}
	return resolution
}

// mergeDiscoveredModuleGraph carries the effective reactor graph produced by
// discoverModulesContext into the build-tool resolution. Maven classpath
// output alone contains artifact files, not project-edge identity; omitting
// this transfer used to mark the result authoritative and then erase exactly
// the scopes/exports/exclusions that visibility and compiler closures need.
func mergeDiscoveredModuleGraph(resolution *classpathResolution, module ModuleInfo) {
	if resolution == nil || module.Name == "" {
		return
	}
	resolution.Dependencies[module.Name] = uniqueSortedStrings(append(resolution.Dependencies[module.Name], module.Dependencies...))
	mergeNested := func(destination map[string]map[string][]string, values map[string][]string) {
		if len(values) == 0 {
			return
		}
		if destination[module.Name] == nil {
			destination[module.Name] = make(map[string][]string)
		}
		for key, entries := range values {
			destination[module.Name][key] = uniqueSortedStrings(append(destination[module.Name][key], entries...))
		}
	}
	mergeNested(resolution.SourceSetDependencies, module.DependenciesBySourceSet)
	mergeNested(resolution.RuntimeSourceSetDependencies, module.RuntimeDependenciesBySourceSet)
	mergeNested(resolution.SourceSetExported, module.ExportedBySourceSet)
	mergeNested(resolution.DependencyExclusions, module.DependencyExclusions)
	mergeNested(resolution.ExternalDependencyExclusions, module.ExternalDependencyExclusions)
	mergeNested(resolution.SourceSetDependsOn, module.SourceSetDependsOn)
}

// replaceWithEffectiveMavenGraph derives reactor visibility from the models
// produced by Maven itself. The discovery graph remains useful in degraded
// mode, but it cannot support an authoritative claim because profiles,
// inheritance, property interpolation, and dependency management may change
// the raw POM view.
func replaceWithEffectiveMavenGraph(resolution *classpathResolution, models map[string]mavenPOM) error {
	if resolution == nil || len(models) == 0 {
		return fmt.Errorf("Maven effective reactor graph is empty")
	}
	coordinateToName := make(map[string]string, len(models))
	gaToNames := make(map[string][]string, len(models))
	for module, model := range models {
		group, artifact, version := strings.TrimSpace(model.effectiveGroupID()), strings.TrimSpace(model.ArtifactID), strings.TrimSpace(mavenEffectiveVersion(model))
		if module == "" || group == "" || artifact == "" || version == "" {
			return fmt.Errorf("Maven effective reactor graph contains a module without a complete GAV identity")
		}
		coordinate := mavenCoordinate(group, artifact, version)
		if previous := coordinateToName[coordinate]; previous != "" && previous != module {
			return fmt.Errorf("Maven effective reactor graph contains duplicate coordinate %s:%s:%s", group, artifact, version)
		}
		coordinateToName[coordinate] = module
		ga := strings.TrimSpace(group) + "\x00" + strings.TrimSpace(artifact)
		gaToNames[ga] = appendUniqueString(gaToNames[ga], module)
	}
	resolution.Dependencies = make(map[string][]string)
	resolution.SourceSetDependencies = make(map[string]map[string][]string)
	resolution.RuntimeSourceSetDependencies = make(map[string]map[string][]string)
	resolution.SourceSetExported = make(map[string]map[string][]string)
	resolution.DependencyExclusions = make(map[string]map[string][]string)
	resolution.ExternalDependencyExclusions = make(map[string]map[string][]string)
	resolution.SourceSetDependsOn = make(map[string]map[string][]string)
	for module, model := range models {
		resolution.SourceSetDependsOn[module] = map[string][]string{"test": {"main"}}
		for _, declared := range model.Dependencies.Items {
			ga := strings.TrimSpace(declared.GroupID) + "\x00" + strings.TrimSpace(declared.ArtifactID)
			if len(gaToNames[ga]) > 0 && (strings.TrimSpace(declared.Classifier) != "" || strings.TrimSpace(declared.Type) != "" && strings.TrimSpace(declared.Type) != "jar") {
				return fmt.Errorf("Maven reactor dependency %s:%s uses unsupported type/classifier identity %s/%s", strings.TrimSpace(declared.GroupID), strings.TrimSpace(declared.ArtifactID), strings.TrimSpace(declared.Type), strings.TrimSpace(declared.Classifier))
			}
			dependency := coordinateToName[mavenCoordinate(declared.GroupID, declared.ArtifactID, declared.Version)]
			if dependency == "" && len(gaToNames[ga]) > 0 {
				return fmt.Errorf("Maven dependency %s:%s:%s overlaps reactor GA but has no unique exact-GAV target", strings.TrimSpace(declared.GroupID), strings.TrimSpace(declared.ArtifactID), strings.TrimSpace(declared.Version))
			}
			scope := strings.TrimSpace(declared.Scope)
			compileSet := "main"
			if scope == "test" {
				compileSet = "test"
			}
			if dependency == "" {
				directCoordinate := "maven:" + strings.TrimSpace(declared.GroupID) + ":" + strings.TrimSpace(declared.ArtifactID) + ":" + strings.TrimSpace(declared.Version)
				for _, excluded := range declared.Exclusions.Items {
					if resolution.ExternalDependencyExclusions[module] == nil {
						resolution.ExternalDependencyExclusions[module] = make(map[string][]string)
					}
					key := dependencyExclusionKey(compileSet, directCoordinate)
					coordinate := strings.TrimSpace(excluded.GroupID) + ":" + strings.TrimSpace(excluded.ArtifactID)
					resolution.ExternalDependencyExclusions[module][key] = appendUniqueString(resolution.ExternalDependencyExclusions[module][key], coordinate)
				}
				continue
			}
			if dependency == module {
				continue
			}
			if scope == "import" {
				continue
			}
			if scope != "runtime" {
				if resolution.SourceSetDependencies[module] == nil {
					resolution.SourceSetDependencies[module] = make(map[string][]string)
				}
				resolution.SourceSetDependencies[module][compileSet] = appendUniqueString(resolution.SourceSetDependencies[module][compileSet], dependency)
			} else {
				// Maven runtime dependencies are absent from main compilation but
				// present on the test compile/runtime classpaths.
				if resolution.SourceSetDependencies[module] == nil {
					resolution.SourceSetDependencies[module] = make(map[string][]string)
				}
				resolution.SourceSetDependencies[module]["test"] = appendUniqueString(resolution.SourceSetDependencies[module]["test"], dependency)
			}
			if scope != "test" && scope != "runtime" {
				resolution.Dependencies[module] = appendUniqueString(resolution.Dependencies[module], dependency)
			}
			if scope == "" || scope == "compile" || scope == "runtime" {
				if resolution.RuntimeSourceSetDependencies[module] == nil {
					resolution.RuntimeSourceSetDependencies[module] = make(map[string][]string)
				}
				resolution.RuntimeSourceSetDependencies[module]["main"] = appendUniqueString(resolution.RuntimeSourceSetDependencies[module]["main"], dependency)
				resolution.RuntimeSourceSetDependencies[module]["test"] = appendUniqueString(resolution.RuntimeSourceSetDependencies[module]["test"], dependency)
			} else if scope == "test" {
				if resolution.RuntimeSourceSetDependencies[module] == nil {
					resolution.RuntimeSourceSetDependencies[module] = make(map[string][]string)
				}
				resolution.RuntimeSourceSetDependencies[module]["test"] = appendUniqueString(resolution.RuntimeSourceSetDependencies[module]["test"], dependency)
			} else if scope == "provided" || scope == "system" {
				if resolution.RuntimeSourceSetDependencies[module] == nil {
					resolution.RuntimeSourceSetDependencies[module] = make(map[string][]string)
				}
				resolution.RuntimeSourceSetDependencies[module]["test"] = appendUniqueString(resolution.RuntimeSourceSetDependencies[module]["test"], dependency)
			}
			if compileSet == "main" && (scope == "" || scope == "compile") && !strings.EqualFold(strings.TrimSpace(declared.Optional), "true") {
				if resolution.SourceSetExported[module] == nil {
					resolution.SourceSetExported[module] = make(map[string][]string)
				}
				resolution.SourceSetExported[module][compileSet] = appendUniqueString(resolution.SourceSetExported[module][compileSet], dependency)
			}
			for _, excluded := range declared.Exclusions.Items {
				excludedGA := strings.TrimSpace(excluded.GroupID) + "\x00" + strings.TrimSpace(excluded.ArtifactID)
				excludedNames := gaToNames[excludedGA]
				exclusionSets := []string{compileSet}
				if (scope == "" || scope == "compile" || scope == "runtime" || scope == "provided" || scope == "system") && compileSet != "test" {
					exclusionSets = append(exclusionSets, "test")
				}
				for _, exclusionSet := range uniqueSortedStrings(exclusionSets) {
					for _, excludedName := range excludedNames {
						if resolution.DependencyExclusions[module] == nil {
							resolution.DependencyExclusions[module] = make(map[string][]string)
						}
						key := dependencyExclusionKey(exclusionSet, dependency)
						resolution.DependencyExclusions[module][key] = appendUniqueString(resolution.DependencyExclusions[module][key], excludedName)
					}
					if len(excludedNames) == 0 {
						if resolution.ExternalDependencyExclusions[module] == nil {
							resolution.ExternalDependencyExclusions[module] = make(map[string][]string)
						}
						key := dependencyExclusionKey(exclusionSet, dependency)
						coordinate := strings.TrimSpace(excluded.GroupID) + ":" + strings.TrimSpace(excluded.ArtifactID)
						resolution.ExternalDependencyExclusions[module][key] = appendUniqueString(resolution.ExternalDependencyExclusions[module][key], coordinate)
					}
				}
			}
		}
	}
	return nil
}

func buildModelFingerprint(root string, verifyArchives bool) ([sha256.Size]byte, error) {
	hash := sha256.New()
	root, _ = filepath.Abs(root)
	manifest := cachedBuildInputManifest(root)
	if manifest.Err != nil {
		return [sha256.Size]byte{}, manifest.Err
	}
	inputs := manifest.Paths
	verifiedArchiveEntries := 0
	for _, path := range inputs {
		name := strings.ToLower(filepath.Base(path))
		relative, _ := filepath.Rel(root, path)
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write([]byte{0})
		buildInput := !strings.HasSuffix(name, ".jar")
		if buildInput {
			digest, readErr := cachedBuildInputDigest(path)
			if readErr != nil {
				return [sha256.Size]byte{}, readErr
			}
			_, _ = hash.Write(digest[:])
		} else if info, statErr := os.Stat(path); statErr == nil {
			_, _ = io.WriteString(hash, itoa64(info.Size()))
			_, _ = io.WriteString(hash, info.ModTime().UTC().Format(time.RFC3339Nano))
			if verifyArchives {
				digest, entries, digestErr := archiveCentralDirectoryDigest(path)
				if digestErr != nil {
					return [sha256.Size]byte{}, digestErr
				}
				if entries > 2_000_000-verifiedArchiveEntries {
					return [sha256.Size]byte{}, fmt.Errorf("archive identity inventory exceeds 2000000 entries")
				}
				verifiedArchiveEntries += entries
				_, _ = hash.Write(digest[:])
			}
		} else {
			_, _ = io.WriteString(hash, "missing")
		}
		_, _ = hash.Write([]byte{0})
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint, nil
}

// archiveCentralDirectoryDigest is the fallback watcher's bounded content
// identity. JAR creation tools record every member's content CRC in the
// central directory, so this observes ordinary same-size/same-mtime atomic
// replacements without rereading gigabytes of compressed class data every
// poll. Actual archive publication still validates and reads members through
// archiveio, including their CRC checks.
func archiveCentralDirectoryDigest(path string) ([sha256.Size]byte, int, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	defer reader.Close()
	if err = archiveio.ValidateZipFiles(reader.File); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	hash := sha256.New()
	var encoded [8]byte
	for _, file := range reader.File {
		if file == nil {
			continue
		}
		binary.LittleEndian.PutUint64(encoded[:], uint64(len(file.Name)))
		_, _ = hash.Write(encoded[:])
		_, _ = io.WriteString(hash, file.Name)
		binary.LittleEndian.PutUint64(encoded[:], uint64(file.CRC32))
		_, _ = hash.Write(encoded[:])
		binary.LittleEndian.PutUint64(encoded[:], file.CompressedSize64)
		_, _ = hash.Write(encoded[:])
		binary.LittleEndian.PutUint64(encoded[:], file.UncompressedSize64)
		_, _ = hash.Write(encoded[:])
		binary.LittleEndian.PutUint64(encoded[:], uint64(file.Method)<<32|uint64(file.Flags))
		_, _ = hash.Write(encoded[:])
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, len(reader.File), nil
}

// WorkspaceBuildFingerprint checks the known build/archive manifest without a
// workspace walk. A fallback watcher requests occasional rediscovery so newly
// created build files are still found, while ordinary polls only stat/read the
// inputs already discovered during import.
func (i *Index) WorkspaceBuildFingerprint(rediscover bool) uint64 {
	i.mu.RLock()
	roots := append([]string(nil), i.roots...)
	i.mu.RUnlock()
	for index := range roots {
		roots[index], _ = filepath.Abs(roots[index])
		roots[index] = filepath.Clean(roots[index])
	}
	sort.Strings(roots)
	if rediscover {
		buildInputManifestCache.Lock()
		for _, root := range roots {
			delete(buildInputManifestCache.byRoot, root)
		}
		buildInputManifestCache.Unlock()
		// The rare rediscovery pass is also the content-verification pass. It
		// catches tools that atomically replace a manifest while preserving size
		// and timestamp, which a stat-keyed hot cache alone cannot observe.
		buildInputDigestCache.Lock()
		buildInputDigestCache.values = make(map[string]buildInputDigestEntry)
		buildInputDigestCache.Unlock()
	}
	hash := sha256.New()
	var size [8]byte
	for _, root := range roots {
		fingerprint, fingerprintErr := buildModelFingerprint(root, rediscover)
		binary.LittleEndian.PutUint64(size[:], uint64(len(root)))
		_, _ = hash.Write(size[:])
		_, _ = io.WriteString(hash, root)
		if fingerprintErr != nil {
			i.recordHealth("build-model-fingerprint", root, fingerprintErr.Error())
			binary.LittleEndian.PutUint64(size[:], uint64(len(fingerprintErr.Error())))
			_, _ = hash.Write(size[:])
			_, _ = io.WriteString(hash, fingerprintErr.Error())
		} else {
			binary.LittleEndian.PutUint64(size[:], uint64(len(fingerprint)))
			_, _ = hash.Write(size[:])
			_, _ = hash.Write(fingerprint[:])
		}
	}
	digest := hash.Sum(nil)
	return binary.LittleEndian.Uint64(digest[:8])
}

var buildInputManifestCache = struct {
	sync.Mutex
	byRoot map[string]buildInputManifest
}{byRoot: make(map[string]buildInputManifest)}

type buildInputManifest struct {
	Paths []string
	Err   error
}

var buildModelInputNames = map[string]struct{}{
	"build.gradle": {}, "build.gradle.kts": {}, "settings.gradle": {},
	"settings.gradle.kts": {}, "gradle.properties": {}, "pom.xml": {},
	"libs.versions.toml": {}, "gradle-wrapper.properties": {},
}

// IsBuildModelInputPath is the single classifier shared by fingerprinting and
// LSP file watching. Keeping these paths identical prevents a watched change
// from being omitted from the cache key, or a key input from never refreshing.
func IsBuildModelInputPath(path string) bool {
	_, ok := buildModelInputNames[strings.ToLower(filepath.Base(path))]
	return ok
}

// BuildModelWatchPatterns returns a copy so callers cannot mutate the shared
// classifier. The order is stable for deterministic registrations and tests.
func BuildModelWatchPatterns() []string {
	names := make([]string, 0, len(buildModelInputNames))
	for name := range buildModelInputNames {
		names = append(names, "**/"+name)
	}
	sort.Strings(names)
	return names
}

// buildScriptPresent reports whether any Gradle or Maven build script exists
// under the root. Wrapper properties, version catalogs, and gradle.properties
// are inputs to a build but do not by themselves declare one.
func buildScriptPresent(root string) bool {
	manifest := cachedBuildInputManifest(root)
	if manifest.Err != nil {
		return true
	}
	for _, path := range manifest.Paths {
		switch strings.ToLower(filepath.Base(path)) {
		case "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "pom.xml":
			return true
		}
	}
	return false
}

func cachedBuildInputManifest(root string) buildInputManifest {
	root = filepath.Clean(root)
	buildInputManifestCache.Lock()
	known, ok := buildInputManifestCache.byRoot[root]
	buildInputManifestCache.Unlock()
	if ok {
		known.Paths = append([]string(nil), known.Paths...)
		return known
	}
	var inputs []string
	visited := 0
	var inventoryErr error
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			inventoryErr = err
			return filepath.SkipAll
		}
		visited++
		if visited > 250000 {
			inventoryErr = fmt.Errorf("workspace manifest walk exceeded 250000 entries")
			return filepath.SkipAll
		}
		if entry.IsDir() {
			if path != root && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		buildInput := IsBuildModelInputPath(path)
		lowerPath := strings.ToLower(path)
		// Source attachments are semantic/navigation inputs too. A fallback
		// watcher must observe a locally replaced -sources.jar even though that
		// archive is not on the compiler classpath.
		libraryInput := strings.HasSuffix(name, ".jar") && !strings.HasSuffix(name, "-javadoc.jar") && !strings.Contains(lowerPath, string(filepath.Separator)+"build"+string(filepath.Separator))
		if !buildInput && !libraryInput {
			return nil
		}
		if len(inputs) >= 10000 {
			inventoryErr = fmt.Errorf("build input inventory exceeded 10000 files")
			return filepath.SkipAll
		}
		inputs = append(inputs, filepath.Clean(path))
		return nil
	})
	sort.Strings(inputs)
	result := buildInputManifest{Paths: inputs, Err: inventoryErr}
	buildInputManifestCache.Lock()
	if _, exists := buildInputManifestCache.byRoot[root]; !exists && len(buildInputManifestCache.byRoot) >= 256 {
		for victim := range buildInputManifestCache.byRoot {
			delete(buildInputManifestCache.byRoot, victim)
			break
		}
	}
	buildInputManifestCache.byRoot[root] = result
	buildInputManifestCache.Unlock()
	result.Paths = append([]string(nil), inputs...)
	return result
}

type buildInputDigestEntry struct {
	size     int64
	modified int64
	digest   [sha256.Size]byte
}

var buildInputDigestCache = struct {
	sync.Mutex
	values map[string]buildInputDigestEntry
}{values: make(map[string]buildInputDigestEntry)}

func cachedBuildInputDigest(path string) ([sha256.Size]byte, error) {
	const maxBuildInputBytes = 8 << 20
	info, err := os.Stat(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if info.Size() > maxBuildInputBytes {
		return [sha256.Size]byte{}, fmt.Errorf("build input %s exceeds %d bytes", path, maxBuildInputBytes)
	}
	modified := info.ModTime().UnixNano()
	buildInputDigestCache.Lock()
	cached, ok := buildInputDigestCache.values[path]
	buildInputDigestCache.Unlock()
	if ok && cached.size == info.Size() && cached.modified == modified {
		return cached.digest, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, maxBuildInputBytes+1))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if read > maxBuildInputBytes {
		return [sha256.Size]byte{}, fmt.Errorf("build input %s expanded beyond %d bytes", path, maxBuildInputBytes)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	buildInputDigestCache.Lock()
	if _, exists := buildInputDigestCache.values[path]; !exists && len(buildInputDigestCache.values) >= 100_000 {
		for victim := range buildInputDigestCache.values {
			delete(buildInputDigestCache.values, victim)
			break
		}
	}
	buildInputDigestCache.values[path] = buildInputDigestEntry{size: info.Size(), modified: modified, digest: digest}
	buildInputDigestCache.Unlock()
	return digest, nil
}

// InvalidateBuildModels tells the next refresh to rediscover manifests. File
// watching supplies the invalidation, so ordinary cache checks touch only the
// previously known build inputs instead of walking an entire monorepo.
func (i *Index) InvalidateBuildModels() {
	i.mu.RLock()
	roots := append([]string(nil), i.roots...)
	i.mu.RUnlock()
	buildInputManifestCache.Lock()
	for _, root := range roots {
		absolute, _ := filepath.Abs(root)
		delete(buildInputManifestCache.byRoot, filepath.Clean(absolute))
	}
	buildInputManifestCache.Unlock()
	buildInputDigestCache.Lock()
	buildInputDigestCache.values = make(map[string]buildInputDigestEntry)
	buildInputDigestCache.Unlock()
}

func buildModelCachePath(root string) (string, bool) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(filepath.Clean(absolute)))
	dir := filepath.Join(cacheRoot, "kotlsp", "build-model")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".json"), true
}

func loadBuildModelCache(root string, fingerprint [sha256.Size]byte) (classpathResolution, bool) {
	path, ok := buildModelCachePath(root)
	if !ok {
		return classpathResolution{}, false
	}
	file, err := os.Open(path)
	if err != nil {
		return classpathResolution{}, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBuildModelCacheBytes+1))
	if err != nil || len(data) > maxBuildModelCacheBytes {
		return classpathResolution{}, false
	}
	var cached cachedBuildModel
	if err := json.Unmarshal(data, &cached); err != nil || cached.Version != buildModelCacheVersion || cached.Fingerprint != fingerprint {
		return classpathResolution{}, false
	}
	if err := validateClasspathResolution(cached.Resolution); err != nil {
		return classpathResolution{}, false
	}
	for _, path := range cached.Resolution.Classpath {
		if _, err := os.Stat(path); err != nil && cachedClasspathEntryMustExist(path) {
			return classpathResolution{}, false
		}
	}
	return cached.Resolution, true
}

// Build tools include output directories in their models before the first
// successful compilation creates them. Their absence is normal and must not
// invalidate an otherwise immutable dependency model on every editor restart.
// Archive dependencies are different: accepting a cached path to a missing
// JAR/JMOD/ZIP would silently remove APIs from both navigation and compiler
// validation, so those still invalidate the cache.
func cachedClasspathEntryMustExist(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jar", ".jmod", ".zip":
		return true
	default:
		return false
	}
}

func saveBuildModelCache(root string, fingerprint [sha256.Size]byte, resolution classpathResolution) error {
	if err := validateClasspathResolution(resolution); err != nil {
		return err
	}
	path, ok := buildModelCachePath(root)
	if !ok {
		return os.ErrInvalid
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".build-model-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	_ = tmp.Chmod(0o600)
	if err := json.NewEncoder(tmp).Encode(cachedBuildModel{Version: buildModelCacheVersion, Fingerprint: fingerprint, Resolution: resolution}); err != nil {
		return err
	}
	if position, err := tmp.Seek(0, io.SeekCurrent); err != nil || position > maxBuildModelCacheBytes {
		return fmt.Errorf("build model cache exceeds its %d-byte safety limit", maxBuildModelCacheBytes)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateClasspathResolution(resolution classpathResolution) error {
	const maxModelItems = 1_000_000
	items := 0
	validText := func(value string) bool {
		return len(value) <= 1<<20 && strings.IndexByte(value, 0) < 0
	}
	if !validText(resolution.Importer) || !validText(resolution.Failure) || !validText(resolution.CacheWarning) {
		return fmt.Errorf("build model contains an oversized or invalid status field")
	}
	addStrings := func(values []string) bool {
		items += len(values)
		if items > maxModelItems {
			return false
		}
		for _, value := range values {
			if !validText(value) {
				return false
			}
		}
		return true
	}
	if len(resolution.Classpath) > 100_000 || !addStrings(resolution.Classpath) {
		return fmt.Errorf("build model exceeds its classpath/item safety limit")
	}
	addFlat := func(values map[string][]string) bool {
		items += len(values)
		if len(values) > 4096 || items > maxModelItems {
			return false
		}
		for key, list := range values {
			if !validText(key) || len(list) > 100_000 || !addStrings(list) {
				return false
			}
		}
		return true
	}
	addNested := func(values map[string]map[string][]string) bool {
		items += len(values)
		if len(values) > 4096 || items > maxModelItems {
			return false
		}
		for key, nested := range values {
			if !validText(key) || len(nested) > 4096 || !addFlat(nested) {
				return false
			}
		}
		return true
	}
	if !addFlat(resolution.ModuleClasspath) || !addFlat(resolution.Dependencies) ||
		!addNested(resolution.SourceSetClasspath) || !addNested(resolution.RuntimeSourceSetClasspath) ||
		!addNested(resolution.SourceSetDependencies) || !addNested(resolution.RuntimeSourceSetDependencies) || !addNested(resolution.SourceSetExported) || !addNested(resolution.DependencyExclusions) || !addNested(resolution.ExternalDependencyExclusions) ||
		!addNested(resolution.SourceSetDependsOn) || !addNested(resolution.SourceSetRoots) {
		return fmt.Errorf("build model exceeds its module/source-set/item safety limit")
	}
	if len(resolution.CompilerSettings) > 4096 {
		return fmt.Errorf("build model exceeds its compiler-settings module limit")
	}
	for module, bySourceSet := range resolution.CompilerSettings {
		items += 1 + len(bySourceSet)
		if !validText(module) || len(bySourceSet) > 4096 || items > maxModelItems {
			return fmt.Errorf("build model contains an oversized compiler-settings key")
		}
		for sourceSet, settings := range bySourceSet {
			if !validText(sourceSet) || !validText(settings.JavaHome) || !validText(settings.JavaRelease) ||
				!validText(settings.JavaSource) || !validText(settings.JavaTarget) || !validText(settings.KotlinVersion) ||
				!validText(settings.KotlinLanguageVersion) || !validText(settings.KotlinAPIVersion) ||
				!validText(settings.KotlinJVMTarget) || !validText(settings.IncompleteReason) ||
				!addStrings(settings.JavaArguments) || !addStrings(settings.KotlinArguments) {
				return fmt.Errorf("build model compiler settings exceed their item safety limit")
			}
		}
	}
	return nil
}

func gradleLauncher(root string) string {
	for _, name := range []string{"gradlew", "gradlew.bat"} {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath("gradle")
	return path
}

func gradleClasspath(parent context.Context, root, gradle string) []string {
	return gradleClasspathModel(parent, root, gradle).Classpath
}

func gradleClasspathModel(parent context.Context, root, gradle string) classpathResolution {
	resolution := newClasspathResolution()
	resolution.Importer = "gradle"
	if parent == nil {
		parent = context.Background()
	}
	toolContext, cancelTool := context.WithTimeout(parent, 5*time.Minute)
	defer cancelTool()
	tmp, err := os.CreateTemp("", "kotlsp-*.init.gradle")
	if err != nil {
		resolution.Failure = err.Error()
		return resolution
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = io.Copy(tmp, bytes.NewBufferString(gradleInitScript)); err != nil {
		_ = tmp.Close()
		resolution.Failure = err.Error()
		return resolution
	}
	_ = tmp.Close()
	// Model import is a bounded, infrequent query. Reusing a Gradle daemon leaves
	// a 512 MiB-heap JVM resident after kotlsp has finished with it, and repeated
	// editor sessions can accumulate several such daemons. A single-use daemon
	// may still be created when Gradle needs JVM isolation, but --no-daemon makes
	// it exit with this request. One worker is sufficient for the synthetic model
	// task and prevents dependency resolution from competing with foreground LSP
	// work across every core.
	cmd := exec.CommandContext(toolContext, gradle, "--no-daemon", "--no-parallel", "--max-workers=1", "--quiet", "--init-script", name, "kotlspClasspath")
	cmd.Dir = root
	cmd.Env = withToolHeapOption(os.Environ(), "GRADLE_OPTS", "-Xmx512m -XX:+ExitOnOutOfMemoryError")
	release, reserveErr := resourcebudget.Acquire(toolContext, "gradle-import", resourcebudget.BuildToolBytes)
	if reserveErr != nil {
		resolution.Failure = reserveErr.Error()
		return resolution
	}
	stdout := &boundedBuildOutput{limit: 32 << 20}
	stderr := &boundedBuildOutput{limit: 4 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	release()
	if stdout.truncated || stderr.truncated {
		resolution.Failure = "Gradle model output exceeded its 32 MiB stdout/4 MiB stderr safety limit"
		return resolution
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "kotlsp: Gradle classpath resolution failed in %s: %v: %s\n", root, err, strings.TrimSpace(string(stderr.data)))
		resolution.Failure = strings.TrimSpace(err.Error())
		if len(stderr.data) > 0 {
			resolution.Failure += ": " + strings.TrimSpace(string(stderr.data))
		}
		return resolution
	}
	output := stdout.data
	var paths []string
	exactSourceSets := make(map[string]bool)
	exactDependencySets := make(map[string]bool)
	exactRuntimeDependencySets := make(map[string]bool)
	configurationFallbacks := make(map[string]bool)
	fallbackDependencies := make(map[string]map[string][]string)
	fallbackRuntimeDependencies := make(map[string]map[string][]string)
	fallbackExported := make(map[string]map[string][]string)
	gradleModulesByGA := make(map[string][]string)
	type exclusionRecord struct {
		module, sourceSet, target, group, artifact string
	}
	var exclusionRecords []exclusionRecord
	for lineIndex, line := range strings.Split(string(output), "\n") {
		if lineIndex >= 250_000 {
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle model exceeds its 250000-record safety limit")
			break
		}
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "KOTLSP_MODEL_LIMITATION="); ok {
			parts := strings.SplitN(value, "\t", 2)
			if len(parts) == 2 {
				resolution.Failure = appendIncompleteReason(resolution.Failure, parts[0]+": "+parts[1])
			}
			continue
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_MODULE_COORDINATE="); ok {
			parts := strings.SplitN(value, "\t", 4)
			if len(parts) == 4 && parts[0] != "" && parts[1] != "" && parts[2] != "" {
				key := parts[1] + "\x00" + parts[2]
				if _, known := gradleModulesByGA[key]; known || len(gradleModulesByGA) < 4096 {
					gradleModulesByGA[key] = appendUniqueString(gradleModulesByGA[key], parts[0])
				} else {
					resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle reactor coordinate inventory exceeds its 4096-entry safety limit")
				}
			}
			continue
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_CLASSPATH="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if absolute, err := filepath.Abs(parts[2]); err == nil {
					paths = append(paths, absolute)
					resolution.ModuleClasspath[parts[0]] = append(resolution.ModuleClasspath[parts[0]], absolute)
					if resolution.SourceSetClasspath[parts[0]] == nil {
						resolution.SourceSetClasspath[parts[0]] = make(map[string][]string)
					}
					set := sourceSetFromConfiguration(parts[1])
					configurationFallbacks[parts[0]+"\x00"+set] = true
					resolution.SourceSetClasspath[parts[0]][set] = append(resolution.SourceSetClasspath[parts[0]][set], absolute)
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_RUNTIME="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if absolute, err := filepath.Abs(parts[2]); err == nil {
					if resolution.RuntimeSourceSetClasspath[parts[0]] == nil {
						resolution.RuntimeSourceSetClasspath[parts[0]] = make(map[string][]string)
					}
					set := sourceSetFromConfiguration(parts[1])
					configurationFallbacks[parts[0]+"\x00"+set] = true
					resolution.RuntimeSourceSetClasspath[parts[0]][set] = append(resolution.RuntimeSourceSetClasspath[parts[0]][set], absolute)
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_CLASSPATH="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if absolute, absoluteErr := filepath.Abs(parts[2]); absoluteErr == nil {
					paths = append(paths, absolute)
					resolution.ModuleClasspath[parts[0]] = append(resolution.ModuleClasspath[parts[0]], absolute)
					if resolution.SourceSetClasspath[parts[0]] == nil {
						resolution.SourceSetClasspath[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetClasspath[parts[0]][parts[1]] = append(resolution.SourceSetClasspath[parts[0]][parts[1]], absolute)
					exactSourceSets[parts[0]+"\x00"+parts[1]] = true
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_RUNTIME="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if absolute, absoluteErr := filepath.Abs(parts[2]); absoluteErr == nil {
					if resolution.RuntimeSourceSetClasspath[parts[0]] == nil {
						resolution.RuntimeSourceSetClasspath[parts[0]] = make(map[string][]string)
					}
					resolution.RuntimeSourceSetClasspath[parts[0]][parts[1]] = append(resolution.RuntimeSourceSetClasspath[parts[0]][parts[1]], absolute)
					exactSourceSets[parts[0]+"\x00"+parts[1]] = true
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_PROJECT_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 4)
			if len(parts) == 4 {
				if resolution.SourceSetDependencies[parts[0]] == nil {
					resolution.SourceSetDependencies[parts[0]] = make(map[string][]string)
				}
				resolution.SourceSetDependencies[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetDependencies[parts[0]][parts[1]], parts[3])
				resolution.Dependencies[parts[0]] = appendUniqueString(resolution.Dependencies[parts[0]], parts[3])
				if parts[2] == "true" {
					if resolution.SourceSetExported[parts[0]] == nil {
						resolution.SourceSetExported[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetExported[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetExported[parts[0]][parts[1]], parts[3])
				}
				exactSourceSets[parts[0]+"\x00"+parts[1]] = true
				exactDependencySets[parts[0]+"\x00"+parts[1]] = true
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_RUNTIME_PROJECT_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if resolution.RuntimeSourceSetDependencies[parts[0]] == nil {
					resolution.RuntimeSourceSetDependencies[parts[0]] = make(map[string][]string)
				}
				resolution.RuntimeSourceSetDependencies[parts[0]][parts[1]] = appendUniqueString(resolution.RuntimeSourceSetDependencies[parts[0]][parts[1]], parts[2])
				exactRuntimeDependencySets[parts[0]+"\x00"+parts[1]] = true
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				set, compileVisible, runtimeVisible, exported := gradleDependencyConfiguration(parts[1])
				if compileVisible {
					if fallbackDependencies[parts[0]] == nil {
						fallbackDependencies[parts[0]] = make(map[string][]string)
					}
					fallbackDependencies[parts[0]][set] = appendUniqueString(fallbackDependencies[parts[0]][set], parts[2])
				}
				if runtimeVisible {
					if fallbackRuntimeDependencies[parts[0]] == nil {
						fallbackRuntimeDependencies[parts[0]] = make(map[string][]string)
					}
					fallbackRuntimeDependencies[parts[0]][set] = appendUniqueString(fallbackRuntimeDependencies[parts[0]][set], parts[2])
				}
				if compileVisible && exported {
					if fallbackExported[parts[0]] == nil {
						fallbackExported[parts[0]] = make(map[string][]string)
					}
					fallbackExported[parts[0]][set] = appendUniqueString(fallbackExported[parts[0]][set], parts[2])
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_DEPENDENCY_EXCLUSION="); ok {
			parts := strings.SplitN(value, "\t", 5)
			if len(parts) == 5 {
				exclusionRecords = append(exclusionRecords, exclusionRecord{module: parts[0], sourceSet: parts[1], target: parts[2], group: parts[3], artifact: parts[4]})
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_DEPENDENCY_EXCLUSION="); ok {
			parts := strings.SplitN(value, "\t", 5)
			if len(parts) == 5 {
				set, compileVisible, runtimeVisible, _ := gradleDependencyConfiguration(parts[1])
				if compileVisible || runtimeVisible {
					exclusionRecords = append(exclusionRecords, exclusionRecord{module: parts[0], sourceSet: set, target: parts[2], group: parts[3], artifact: parts[4]})
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if resolution.SourceSetDependsOn[parts[0]] == nil {
					resolution.SourceSetDependsOn[parts[0]] = make(map[string][]string)
				}
				resolution.SourceSetDependsOn[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetDependsOn[parts[0]][parts[1]], parts[2])
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCE_ROOT="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				absolute, absoluteErr := filepath.Abs(parts[2])
				if absoluteErr == nil {
					if resolution.SourceSetRoots[parts[0]] == nil {
						resolution.SourceSetRoots[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetRoots[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetRoots[parts[0]][parts[1]], absolute)
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_COMPILER_SETTING="); ok {
			parts := strings.SplitN(value, "\t", 4)
			if len(parts) == 4 {
				decoded, decodeErr := base64.StdEncoding.DecodeString(parts[3])
				if decodeErr == nil && len(decoded) <= 1<<20 {
					if resolution.CompilerSettings[parts[0]] == nil {
						resolution.CompilerSettings[parts[0]] = make(map[string]CompilerSettings)
					}
					settings := resolution.CompilerSettings[parts[0]][parts[1]]
					setting := string(decoded)
					switch parts[2] {
					case "java.home":
						settings.JavaHome = setting
					case "java.release":
						settings.JavaRelease = setting
					case "java.source":
						settings.JavaSource = setting
					case "java.target":
						settings.JavaTarget = setting
					case "java.arg":
						settings.JavaArguments = append(settings.JavaArguments, setting)
					case "kotlin.version":
						settings.KotlinVersion = setting
					case "kotlin.languageVersion":
						settings.KotlinLanguageVersion = setting
					case "kotlin.apiVersion":
						settings.KotlinAPIVersion = setting
					case "kotlin.jvmTarget":
						settings.KotlinJVMTarget = setting
					case "kotlin.arg":
						settings.KotlinArguments = append(settings.KotlinArguments, setting)
					}
					resolution.CompilerSettings[parts[0]][parts[1]] = settings
				} else if decodeErr == nil {
					resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle compiler setting exceeds its 1 MiB safety limit")
				}
			}
		}
		if len(paths) > 100_000 {
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle classpath exceeds its 100000-path safety limit")
			paths = paths[:100_000]
			break
		}
	}
	// A module whose source sets Gradle identified exactly needs no
	// configuration-name guesses: a suffix-derived set that matches none of
	// its real source sets is a plain configuration (Spring Boot's
	// productionRuntimeClasspath, for example), not a source set, and is
	// dropped. Only a module without any exact identity falls back, and that
	// fallback is the reported limitation.
	moduleIdentified := func(module string) bool {
		for key := range exactSourceSets {
			if owner, _, _ := strings.Cut(key, "\x00"); owner == module {
				return true
			}
		}
		return false
	}
	for module, bySourceSet := range fallbackDependencies {
		for sourceSet, dependencies := range bySourceSet {
			if exactDependencySets[module+"\x00"+sourceSet] {
				continue
			}
			if moduleIdentified(module) {
				continue
			}
			resolution.UsedConfigurationFallback = true
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle project dependency classification required a configuration-name fallback")
			if resolution.SourceSetDependencies[module] == nil {
				resolution.SourceSetDependencies[module] = make(map[string][]string)
			}
			resolution.SourceSetDependencies[module][sourceSet] = uniqueSortedStrings(append(resolution.SourceSetDependencies[module][sourceSet], dependencies...))
			resolution.Dependencies[module] = uniqueSortedStrings(append(resolution.Dependencies[module], dependencies...))
			if exported := fallbackExported[module][sourceSet]; len(exported) > 0 {
				if resolution.SourceSetExported[module] == nil {
					resolution.SourceSetExported[module] = make(map[string][]string)
				}
				resolution.SourceSetExported[module][sourceSet] = uniqueSortedStrings(append(resolution.SourceSetExported[module][sourceSet], exported...))
			}
		}
	}
	for module, bySourceSet := range fallbackRuntimeDependencies {
		for sourceSet, dependencies := range bySourceSet {
			if exactRuntimeDependencySets[module+"\x00"+sourceSet] {
				continue
			}
			if moduleIdentified(module) {
				continue
			}
			resolution.UsedConfigurationFallback = true
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle runtime project dependency classification required a configuration-name fallback")
			if resolution.RuntimeSourceSetDependencies[module] == nil {
				resolution.RuntimeSourceSetDependencies[module] = make(map[string][]string)
			}
			resolution.RuntimeSourceSetDependencies[module][sourceSet] = uniqueSortedStrings(append(resolution.RuntimeSourceSetDependencies[module][sourceSet], dependencies...))
		}
	}
	for _, record := range exclusionRecords {
		if record.module == "" || record.sourceSet == "" || record.target == "" || record.group == "" || record.artifact == "" {
			continue
		}
		key := dependencyExclusionKey(record.sourceSet, record.target)
		matches := append([]string(nil), gradleModulesByGA[record.group+"\x00"+record.artifact]...)
		wildcard := record.group == "*" || record.artifact == "*"
		if wildcard {
			matches = matches[:0]
			for coordinate, modules := range gradleModulesByGA {
				group, artifact, _ := strings.Cut(coordinate, "\x00")
				if (record.group == "*" || record.group == group) && (record.artifact == "*" || record.artifact == artifact) {
					for _, module := range modules {
						matches = appendUniqueString(matches, module)
					}
				}
			}
		}
		if len(matches) > 0 {
			if resolution.DependencyExclusions[record.module] == nil {
				resolution.DependencyExclusions[record.module] = make(map[string][]string)
			}
			for _, match := range matches {
				resolution.DependencyExclusions[record.module][key] = appendUniqueString(resolution.DependencyExclusions[record.module][key], match)
			}
			if !wildcard {
				continue
			}
		}
		if resolution.ExternalDependencyExclusions[record.module] == nil {
			resolution.ExternalDependencyExclusions[record.module] = make(map[string][]string)
		}
		coordinate := record.group + ":" + record.artifact
		resolution.ExternalDependencyExclusions[record.module][key] = appendUniqueString(resolution.ExternalDependencyExclusions[record.module][key], coordinate)
	}
	for key := range configurationFallbacks {
		if exactSourceSets[key] {
			continue
		}
		module, sourceSet, _ := strings.Cut(key, "\x00")
		if moduleIdentified(module) {
			delete(resolution.SourceSetClasspath[module], sourceSet)
			delete(resolution.RuntimeSourceSetClasspath[module], sourceSet)
			continue
		}
		if !resolution.UsedConfigurationFallback {
			resolution.UsedConfigurationFallback = true
			resolution.Failure = appendIncompleteReason(resolution.Failure, "Gradle configuration classification required a suffix fallback")
		}
	}
	resolution.Classpath = paths
	resolution.Authoritative = len(paths) > 0 && resolution.Failure == "" && !resolution.UsedConfigurationFallback
	return resolution
}

func gradleDependencyConfiguration(configuration string) (sourceSet string, compileVisible, runtimeVisible, exported bool) {
	lower := strings.ToLower(configuration)
	for _, suffix := range []string{"runtimeonly", "runtime", "developmentonly"} {
		if strings.HasSuffix(lower, suffix) {
			set := configuration[:len(configuration)-len(suffix)]
			if set == "" {
				set = "main"
			}
			return set, false, true, false
		}
	}
	for _, suffix := range []struct {
		name     string
		exported bool
	}{
		{"implementation", false}, {"compileonly", false}, {"api", true}, {"compile", true},
	} {
		if strings.HasSuffix(lower, suffix.name) {
			set := configuration[:len(configuration)-len(suffix.name)]
			if set == "" {
				set = "main"
			}
			return set, true, suffix.name != "compileonly", suffix.exported
		}
	}
	return "main", false, false, false
}

func mavenLauncher(root string) string {
	for _, name := range []string{"mvnw", "mvnw.cmd"} {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath("mvn")
	return path
}

// mavenClasspaths obtains compile and test views in one Maven process. The
// dependency:list record carries the effective scope and absolute artifact
// path, so separating compile/provided/system from runtime/test does not need a
// second JVM or a hand-built repository-path guess.
func mavenClasspaths(parent context.Context, root, maven string) (compile, test, runtime []string, settings CompilerSettings, effective mavenPOM, resultErr error) {
	if parent == nil {
		parent = context.Background()
	}
	toolContext, cancelTool := context.WithTimeout(parent, 5*time.Minute)
	defer cancelTool()
	tmp, err := os.CreateTemp("", "kotlsp-maven-dependencies-*.txt")
	if err != nil {
		return nil, nil, nil, settings, effective, err
	}
	name := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(name)
	effectiveFile, effectiveErr := os.CreateTemp("", "kotlsp-maven-effective-*.xml")
	if effectiveErr != nil {
		return nil, nil, nil, settings, effective, effectiveErr
	}
	effectiveName := effectiveFile.Name()
	_ = effectiveFile.Close()
	defer os.Remove(effectiveName)
	cmd := exec.CommandContext(toolContext, maven, "-q", "help:effective-pom", "dependency:list", "-Doutput="+effectiveName, "-DincludeScope=test", "-DoutputAbsoluteArtifactFilename=true", "-DoutputFile="+name, "-DappendOutput=false")
	cmd.Dir = root
	cmd.Env = withToolHeapOption(os.Environ(), "MAVEN_OPTS", "-Xmx512m -XX:+ExitOnOutOfMemoryError")
	release, reserveErr := resourcebudget.Acquire(toolContext, "maven-import", resourcebudget.BuildToolBytes)
	if reserveErr != nil {
		return nil, nil, nil, settings, effective, reserveErr
	}
	runErr := cmd.Run()
	release()
	if runErr != nil {
		return nil, nil, nil, settings, effective, runErr
	}
	data, err := readBoundedBuildFile(name, 16<<20)
	if err != nil {
		return nil, nil, nil, settings, effective, err
	}
	if effectiveData, readErr := readBoundedBuildFile(effectiveName, 32<<20); readErr == nil {
		if decodeErr := xml.Unmarshal(effectiveData, &effective); decodeErr != nil {
			return nil, nil, nil, settings, effective, fmt.Errorf("parse Maven effective model: %w", decodeErr)
		}
		if validateErr := validateMavenModel(effective); validateErr != nil {
			return nil, nil, nil, settings, effective, validateErr
		}
		settings = mavenCompilerSettings(effective)
	} else {
		return nil, nil, nil, settings, effective, fmt.Errorf("read Maven effective model: %w", readErr)
	}
	knownScopes := map[string]bool{"compile": true, "provided": true, "system": true, "runtime": true, "test": true}
	for lineIndex, line := range strings.Split(string(data), "\n") {
		if lineIndex >= 250_000 {
			return nil, nil, nil, settings, effective, fmt.Errorf("Maven dependency output exceeds its 250000-record safety limit")
		}
		parts := strings.Split(strings.TrimSpace(line), ":")
		for field := 4; field+1 < len(parts); field++ {
			scope := strings.TrimSpace(parts[field])
			if !knownScopes[scope] {
				continue
			}
			path := strings.TrimSpace(strings.Join(parts[field+1:], ":"))
			if path == "" {
				break
			}
			test = append(test, path)
			if len(test) > 100_000 {
				return nil, nil, nil, settings, effective, fmt.Errorf("Maven dependency output exceeds its 100000-path safety limit")
			}
			if scope == "compile" || scope == "provided" || scope == "system" {
				compile = append(compile, path)
			}
			if scope == "compile" || scope == "runtime" {
				runtime = append(runtime, path)
			}
			break
		}
	}
	compile, test, runtime = uniqueSortedStrings(compile), uniqueSortedStrings(test), uniqueSortedStrings(runtime)
	if len(test) == 0 && strings.TrimSpace(string(data)) != "" {
		return nil, nil, nil, settings, effective, fmt.Errorf("Maven dependency output contained no parseable absolute artifacts")
	}
	return compile, test, runtime, settings, effective, nil
}

func readBoundedBuildFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("build-tool model file exceeds its %d-byte safety limit", limit)
	}
	return data, nil
}

func resolveMavenModelPath(moduleDir, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(moduleDir, value)
	}
	absolute, err := filepath.Abs(value)
	if err == nil {
		value = absolute
	}
	return filepath.Clean(value)
}

func withToolHeapOption(environment []string, name, option string) []string {
	out := append([]string(nil), environment...)
	prefix := name + "="
	for index, value := range out {
		if strings.HasPrefix(value, prefix) {
			out[index] = value + " " + option
			return out
		}
	}
	return append(out, prefix+option)
}

func conventionalOutputDirectories(root string) []string {
	candidates := []string{
		"build/classes/java/main", "build/classes/java/test",
		"build/classes/kotlin/main", "build/classes/kotlin/test",
		"build/resources/main", "build/resources/test",
		"target/classes", "target/test-classes", "out/production", "out/test",
	}
	paths := make([]string, 0, len(candidates))
	for _, relative := range candidates {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			paths = append(paths, path)
		}
	}
	return paths
}

func conventionalOutputDirectoriesForSourceSet(root, sourceSet string) []string {
	if sourceSet == "" {
		sourceSet = "main"
	}
	candidates := []string{
		filepath.Join("build", "classes", "java", sourceSet),
		filepath.Join("build", "classes", "kotlin", sourceSet),
		filepath.Join("build", "resources", sourceSet),
	}
	if sourceSet == "main" {
		candidates = append(candidates, "target/classes", "out/production")
	}
	if sourceSet == "test" {
		candidates = append(candidates, "target/test-classes", "target/classes", "out/test", "out/production")
	}
	var paths []string
	for _, relative := range candidates {
		path := filepath.Join(root, relative)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			paths = append(paths, path)
		}
	}
	return uniqueSortedStrings(paths)
}

func directJarReferences(root string) ([]string, bool) {
	const maxVisitedEntries = 20000
	const maxArchives = 4096
	var paths []string
	visited := 0
	exhausted := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		visited++
		if visited > maxVisitedEntries || len(paths) >= maxArchives {
			exhausted = true
			return filepath.SkipAll
		}
		if entry.IsDir() {
			if path != root && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, "-sources.jar") && !strings.HasSuffix(lower, "-javadoc.jar") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, exhausted
}

func sourceJarsFor(binary string) ([]string, bool) {
	if strings.HasSuffix(binary, "-sources.jar") {
		return []string{binary}, false
	}
	versionDir := filepath.Dir(filepath.Dir(binary))
	var sources []string
	visited := 0
	exhausted := false
	_ = filepath.WalkDir(versionDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		visited++
		if visited > 4096 || len(sources) >= 64 {
			exhausted = true
			return filepath.SkipAll
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), "-sources.jar") {
			sources = append(sources, path)
		}
		return nil
	})
	return sources, exhausted
}

func jdkSources() string {
	return jdkSourcesForHome("")
}

func jdkSourcesForHome(configuredHome string) string {
	candidates := make([]string, 0, 5)
	if configuredHome != "" {
		candidates = append(candidates, filepath.Join(configuredHome, "lib", "src.zip"), filepath.Join(configuredHome, "src.zip"))
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
		return ""
	}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, "lib", "src.zip"))
	}
	if java, err := exec.LookPath("java"); err == nil {
		if real, err := filepath.EvalSymlinks(java); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Dir(real)), "lib", "src.zip"))
		}
	}
	candidates = append(candidates, "/usr/lib/jvm/default/lib/src.zip", "/usr/lib/jvm/java-21-openjdk/lib/src.zip")
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func jdkBinaryArchives(configuredHome string) ([]sourceArchive, bool) {
	home := configuredHome
	if home == "" {
		home = os.Getenv("JAVA_HOME")
	}
	if home == "" {
		if java, err := exec.LookPath("java"); err == nil {
			if resolved, resolveErr := filepath.EvalSymlinks(java); resolveErr == nil {
				home = filepath.Dir(filepath.Dir(resolved))
			}
		}
	}
	if home == "" {
		return nil, true
	}
	paths, complete := boundedGlob(filepath.Join(home, "jmods", "*.jmod"), 4096, 512)
	if !complete {
		return nil, false
	}
	sort.Strings(paths)
	release := javaHomeRelease(home)
	archives := make([]sourceArchive, 0, len(paths))
	for _, path := range paths {
		module := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		archive := sourceArchive{path: path, jdk: true, binary: true, module: module, release: release}
		if module == "java.base" {
			archives = append([]sourceArchive{archive}, archives...)
		} else {
			archives = append(archives, archive)
		}
	}
	return archives, true
}

func sourceEntry(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "/module-info.java") || strings.HasSuffix(lower, "/package-info.java") {
		return false
	}
	return strings.HasSuffix(lower, ".java") || strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")
}

func archiveAccepts(archive sourceArchive, file *zip.File) bool {
	if archive.binary {
		name := strings.ToLower(file.Name)
		return strings.HasSuffix(name, ".class") && !strings.HasSuffix(name, "module-info.class")
	}
	return sourceEntry(file.Name)
}

// JMODs are ZIP containers for classes and native runtime payloads. Some
// perfectly valid native members (notably lib/server/libjvm.so) are hundreds
// of megabytes, while the index will never open them. Validate and account the
// semantic entries we can actually consume; validating unrelated payloads
// made java.base disappear entirely under the per-entry safety limit.
func archiveSemanticBudgetFiles(archive sourceArchive, files []*zip.File) []*zip.File {
	selected := make([]*zip.File, 0, len(files))
	for _, file := range files {
		if file == nil {
			continue
		}
		name := filepath.ToSlash(file.Name)
		lower := strings.ToLower(name)
		metadata := strings.EqualFold(name, "META-INF/MANIFEST.MF") || lower == "module-info.class" || strings.HasSuffix(lower, "/module-info.class")
		if archiveAccepts(archive, file) || metadata {
			selected = append(selected, file)
		}
	}
	return selected
}

func selectedArchiveFiles(archive sourceArchive, files []*zip.File) []*zip.File {
	budget, err := archiveio.NewBudget(archiveSemanticBudgetFiles(archive, files))
	if err != nil {
		return nil
	}
	selected, _ := selectedArchiveFilesWithBudget(archive, files, budget)
	return selected
}

func selectedArchiveFilesWithBudget(archive sourceArchive, files []*zip.File, budget *archiveio.Budget) ([]*zip.File, error) {
	return selectedArchiveFilesWithBudgetContext(context.Background(), archive, files, budget)
}

func selectedArchiveFilesWithBudgetContext(ctx context.Context, archive sourceArchive, files []*zip.File, budget *archiveio.Budget) ([]*zip.File, error) {
	if !archive.binary {
		// ZIPs can legally contain duplicate directory records. Index one
		// deterministic entry per normalized source name so cache manifests,
		// mirrors, and semantic URIs all describe the same generation.
		choices := make(map[string]*zip.File)
		for _, file := range files {
			if file == nil || !archiveAccepts(archive, file) {
				continue
			}
			name := filepath.ToSlash(file.Name)
			if name != file.Name || !safeArchiveEntryName(name) {
				continue
			}
			if _, exists := choices[name]; !exists {
				choices[name] = file
			}
		}
		names := make([]string, 0, len(choices))
		for name := range choices {
			names = append(names, name)
		}
		sort.Strings(names)
		selected := make([]*zip.File, 0, len(names))
		for _, name := range names {
			selected = append(selected, choices[name])
		}
		return selected, nil
	}
	multiRelease := false
	for _, file := range files {
		if strings.EqualFold(filepath.ToSlash(file.Name), "META-INF/MANIFEST.MF") {
			manifest, readErr := budget.ReadContext(ctx, file, archiveio.MaxMetadataBytes)
			if readErr != nil {
				return nil, readErr
			}
			unfolded := strings.ReplaceAll(strings.ReplaceAll(string(manifest), "\r\n ", ""), "\n ", "")
			for _, line := range strings.Split(unfolded, "\n") {
				name, value, found := strings.Cut(line, ":")
				if found && strings.EqualFold(strings.TrimSpace(name), "Multi-Release") && strings.EqualFold(strings.TrimSpace(value), "true") {
					multiRelease = true
					break
				}
			}
			break
		}
	}
	type choice struct {
		version int
		file    *zip.File
	}
	choices := make(map[string]choice)
	for _, file := range files {
		if file == nil || !archiveAccepts(archive, file) {
			continue
		}
		name := filepath.ToSlash(file.Name)
		if name != file.Name || !safeArchiveEntryName(name) {
			continue
		}
		logical, version := name, 0
		if strings.HasPrefix(strings.ToLower(name), "meta-inf/versions/") {
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
		if previous, ok := choices[logical]; !ok || version > previous.version {
			choices[logical] = choice{version: version, file: file}
		}
	}
	names := make([]string, 0, len(choices))
	for name := range choices {
		names = append(names, name)
	}
	sort.Strings(names)
	selected := make([]*zip.File, 0, len(names))
	for _, name := range names {
		selected = append(selected, choices[name].file)
	}
	return selected, nil
}

func safeArchiveEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.IndexByte(name, 0) >= 0 {
		return false
	}
	components := strings.Split(name, "/")
	if strings.ContainsRune(components[0], ':') {
		return false
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

var defaultJavaReleaseCache struct {
	sync.Once
	value int
}

func defaultJavaRelease() int {
	defaultJavaReleaseCache.Do(func() {
		if executable, err := exec.LookPath("java"); err == nil {
			if executable, err = filepath.EvalSymlinks(executable); err == nil {
				defaultJavaReleaseCache.value = javaHomeRelease(filepath.Dir(filepath.Dir(executable)))
			}
		}
		if defaultJavaReleaseCache.value == 0 {
			defaultJavaReleaseCache.value = 8
		}
	})
	return defaultJavaReleaseCache.value
}

func javaHomeRelease(home string) int {
	if home == "" {
		return 0
	}
	data, err := readFileBounded(filepath.Join(home, "release"), 1<<20, "JDK release metadata")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "JAVA_VERSION" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		majorText := value
		if strings.HasPrefix(value, "1.") {
			majorText = strings.TrimPrefix(value, "1.")
		}
		if dot := strings.IndexByte(majorText, '.'); dot >= 0 {
			majorText = majorText[:dot]
		}
		major, _ := strconv.Atoi(majorText)
		return major
	}
	return 0
}

func (i *Index) javaReleaseForLibrary(path string) int {
	path = filepath.Clean(path)
	i.mu.RLock()
	defer i.mu.RUnlock()
	release := 0
	access := i.libraryAccess[path]
	for index := range i.modules {
		module := &i.modules[index]
		if len(access) > 0 && !access[module.Dir] {
			matched := false
			for key := range access {
				if strings.HasPrefix(key, filepath.Clean(module.Dir)+"\x00") {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if value := javaHomeRelease(module.JavaHome); value > release {
			release = value
		}
	}
	if release == 0 {
		release = javaHomeRelease(i.defaultJavaHome)
	}
	if release == 0 {
		release = defaultJavaRelease()
	}
	return release
}

func languageForEntry(name string) string {
	if strings.HasSuffix(strings.ToLower(name), ".java") {
		return "java"
	}
	return "kotlin"
}
