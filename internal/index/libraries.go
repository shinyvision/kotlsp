package index

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

const gradleInitScript = `
gradle.projectsEvaluated {
    rootProject.tasks.register("kotlspClasspath") {
        doLast {
            rootProject.allprojects.each { project ->
				println("KOTLSP_MODULE=" + project.path + "\t" + project.projectDir.absolutePath)
                project.configurations.findAll {
					it.canBeResolved && (it.name.endsWith("CompileClasspath") || it.name == "compileClasspath")
                }.each { configuration ->
					configuration.resolve().each { println("KOTLSP_CLASSPATH=" + project.path + "\t" + configuration.name + "\t" + it.absolutePath) }
				}
				project.configurations.each { configuration ->
					configuration.allDependencies.each { dependency ->
						if (dependency instanceof org.gradle.api.artifacts.ProjectDependency) {
							println("KOTLSP_DEPENDENCY=" + project.path + "\t" + configuration.name + "\t" + dependency.dependencyProject.path)
						}
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
				}
				def javaSourceSets = project.extensions.findByName("sourceSets")
				if (javaSourceSets != null) {
					javaSourceSets.each { sourceSet ->
						if (sourceSet.hasProperty("java")) {
							sourceSet.java.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
						if (sourceSet.hasProperty("kotlin")) {
							sourceSet.kotlin.srcDirs.each { directory -> println("KOTLSP_SOURCE_ROOT=" + project.path + "\t" + sourceSet.name + "\t" + directory.absolutePath) }
						}
					}
				}
				def androidExtension = project.extensions.findByName("android")
				if (androidExtension != null && androidExtension.hasProperty("sourceSets")) {
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

// scanDeclarationsCompleteHook lets a test hold the scan at the point where
// declarations are complete but sources are not yet attached.
var scanDeclarationsCompleteHook func()

func (i *Index) scanLibraries(ctx context.Context, roots []string, generation uint64, declarationsComplete func()) {
	// Not complete until this pass finishes; a rescan starts incomplete again.
	i.librariesScanned.Store(false)
	if skipLibraryScan {
		return
	}
	binaryArchives := make([]sourceArchive, 0)
	sourceArchives := make([]sourceArchive, 0)
	deferredSources := make([]sourceArchive, 0, 1)
	jdkBinaries := jdkBinaryArchives(i.DefaultJavaHome())
	if len(jdkBinaries) > 0 {
		// java.base covers the implicit language surface and is deliberately
		// first. Vendor dependencies come next; less common JDK modules must not
		// postpone Spring/Jakarta/etc. availability.
		binaryArchives = append(binaryArchives, jdkBinaries[0])
	}
	if jdk := jdkSourcesForHome(i.DefaultJavaHome()); jdk != "" {
		deferredSources = append(deferredSources, sourceArchive{path: jdk, jdk: true})
	}
	seen := map[string]bool{}
	classpathSeen := map[string]bool{}
	classpath := make([]string, 0)
	for _, root := range roots {
		resolution := resolveClasspathModel(ctx, root)
		i.mergeModuleBuildResolution(root, resolution)
		for _, binary := range resolution.Classpath {
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
			for _, source := range sourceJarsFor(binary) {
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
	for _, binary := range defaultKotlinLibraries() {
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
		for _, source := range sourceJarsFor(binary) {
			i.copyLibraryAccess(binary, source)
			if !seen[source] {
				seen[source] = true
				sourceArchives = append(sourceArchives, sourceArchive{path: source})
			}
		}
	}
	wantedImports := i.workspaceLibraryImports()
	wantedTargets := i.workspaceLibraryTargets(wantedImports)
	prioritizeLibraryArchives(binaryArchives, wantedImports)
	prioritizeLibraryArchives(sourceArchives, wantedImports)
	if len(jdkBinaries) > 1 {
		prioritizeLibraryArchives(jdkBinaries[1:], wantedImports)
	}
	if libraryArchiveFilter != nil {
		binaryArchives = filterArchives(binaryArchives)
		sourceArchives = filterArchives(sourceArchives)
		jdkBinaries = filterArchives(jdkBinaries)
		deferredSources = filterArchives(deferredSources)
	}
	archives := make([]sourceArchive, 0, len(binaryArchives)+len(sourceArchives)+len(jdkBinaries)+len(deferredSources))
	archives = append(archives, binaryArchives...)
	archives = append(archives, sourceArchives...)
	if len(jdkBinaries) > 1 {
		archives = append(archives, jdkBinaries[1:]...)
	}
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
		reader, err := zip.OpenReader(archive.path)
		if err != nil {
			continue
		}
		total += int64(len(selectedArchiveFiles(archive, reader.File)))
		_ = reader.Close()
	}
	p := i.Progress()
	p.LibrariesTotal = total
	i.progress.Store(&p)
	i.mu.Lock()
	i.reserveLibraryCapacityLocked(total)
	i.mu.Unlock()
	// Parsing an archive from its jar holds whole entries and parse trees in
	// memory, so at most two run at once. Loading one from the snapshot
	// cache is a stream of small decodes and can use most of the machine;
	// on a 16-core laptop the scan was two-core-bound while the other
	// fourteen idled.
	parseWorkers := runtime.GOMAXPROCS(0) / 2
	if parseWorkers < 1 {
		parseWorkers = 1
	}
	if parseWorkers > 2 {
		parseWorkers = 2
	}
	cachedWorkers := runtime.GOMAXPROCS(0) - 2
	if cachedWorkers < parseWorkers {
		cachedWorkers = parseWorkers
	}
	if cachedWorkers > 8 {
		cachedWorkers = 8
	}
	// The scan allocates in bursts that the collector would otherwise chase
	// continuously; give it room, within the process memory limit.
	previousGC := debug.SetGCPercent(400)
	defer debug.SetGCPercent(previousGC)
	var parsed atomic.Int64
	scanStart := time.Now()
	indexPhase := func(phase []sourceArchive, countProgress bool) bool {
		workers := parseWorkers
		if archivesAreCached(phase) {
			workers = cachedWorkers
		}
		if scanTiming {
			defer func(started time.Time, count int, workers int) {
				fmt.Fprintf(os.Stderr, "kotlsp scan: %d archives on %d workers in %s (t+%s)\n", count, workers, time.Since(started).Round(time.Millisecond), time.Since(scanStart).Round(time.Millisecond))
			}(time.Now(), len(phase), workers)
		}
		jobs := make(chan sourceArchive, 8)
		var wg sync.WaitGroup
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
					i.indexSourceArchive(ctx, archive, generation, func(delta int64) {
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
		return !cancelled
	}
	// Materialize declarations which the workspace already imports (plus
	// implicit java.lang/Kotlin default types) before bulk archive traversal.
	// These small targeted passes never create partial cache snapshots; the full
	// phases below remain authoritative and complete.
	allBinaries := append(append([]sourceArchive(nil), binaryArchives...), jdkBinaries[1:]...)
	allSources := append(append([]sourceArchive(nil), sourceArchives...), deferredSources...)
	if !indexPhase(targetedLibraryArchives(allBinaries, wantedTargets), false) {
		return
	}
	if !indexPhase(targetedLibraryArchives(allSources, wantedTargets), false) {
		return
	}
	// Finish vendor bytecode before its sources. This makes the complete
	// compiled API available deterministically and lets the source phase collapse
	// matching declarations into navigation attachments instead of duplicates.
	if !indexPhase(binaryArchives, true) {
		return
	}
	if len(jdkBinaries) > 1 && !indexPhase(jdkBinaries[1:], true) {
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
	// Every declaration on the classpath is now indexed. What follows attaches
	// sources for navigation and hover; nothing it adds is a new name, so the
	// index is complete for the purpose of deciding what is unresolved.
	i.librariesScanned.Store(true)
	if declarationsComplete != nil {
		declarationsComplete()
	}
	if scanDeclarationsCompleteHook != nil {
		scanDeclarationsCompleteHook()
	}
	if !indexPhase(otherSources, true) {
		return
	}
	// The monolithic JDK source ZIP is deferred so it cannot postpone vendor
	// source attachment.
	indexPhase(deferredSources, true)
}

func (i *Index) workspaceLibraryImports() []string {
	i.mu.RLock()
	seen := make(map[string]bool)
	for uri, file := range i.files {
		if _, library := i.librarySources[uri]; library || file == nil {
			continue
		}
		for _, imported := range file.Imports {
			path := strings.TrimSuffix(imported.Path, ".*")
			if path != "" {
				seen[path] = true
			}
		}
	}
	i.mu.RUnlock()
	imports := make([]string, 0, len(seen))
	for imported := range seen {
		imports = append(imports, imported)
	}
	sort.Strings(imports)
	return imports
}

func (i *Index) workspaceLibraryTargets(imports []string) []string {
	seen := make(map[string]bool, len(imports)*2)
	for _, imported := range imports {
		if !strings.HasSuffix(imported, ".*") {
			seen[strings.ReplaceAll(imported, ".", "/")] = true
		}
	}
	i.mu.RLock()
	for uri, file := range i.files {
		if _, library := i.librarySources[uri]; library || file == nil {
			continue
		}
		for _, reference := range file.References {
			if reference.Qualifier != "" || reference.Name == "" || reference.Name[0] < 'A' || reference.Name[0] > 'Z' {
				continue
			}
			for _, packageName := range []string{"java/lang/", "java/util/", "kotlin/"} {
				seen[packageName+reference.Name] = true
			}
		}
	}
	i.mu.RUnlock()
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func targetedLibraryArchives(archives []sourceArchive, targets []string) []sourceArchive {
	if len(targets) == 0 {
		return nil
	}
	targeted := make([]sourceArchive, 0, len(archives))
	for _, archive := range archives {
		reader, err := zip.OpenReader(archive.path)
		if err != nil {
			continue
		}
		matched := false
		for _, file := range reader.File {
			if archiveAccepts(archive, file) && archiveEntryMatchesTargets(archive, file.Name, targets) {
				matched = true
				break
			}
		}
		_ = reader.Close()
		if matched {
			copy := archive
			copy.onlyTargets = targets
			copy.noCache = true
			targeted = append(targeted, copy)
		}
	}
	return targeted
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

func prioritizeLibraryArchives(archives []sourceArchive, imports []string) {
	if len(archives) < 2 || len(imports) == 0 {
		return
	}
	scores := make(map[string]int, len(archives))
	for _, archive := range archives {
		scores[archive.path] = libraryArchiveImportScore(archive, imports)
	}
	sort.SliceStable(archives, func(left, right int) bool {
		if archives[left].jdk && archives[left].module == "java.base" {
			return true
		}
		if archives[right].jdk && archives[right].module == "java.base" {
			return false
		}
		return scores[archives[left].path] > scores[archives[right].path]
	})
}

func libraryArchiveImportScore(archive sourceArchive, imports []string) int {
	reader, err := zip.OpenReader(archive.path)
	if err != nil {
		return 0
	}
	defer reader.Close()
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
	for _, file := range reader.File {
		name := strings.TrimPrefix(filepath.ToSlash(file.Name), "classes/")
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
func archivesAreCached(phase []sourceArchive) bool {
	for _, archive := range phase {
		if archive.noCache {
			return false
		}
		path, ok := archiveCachePath(archive)
		if !ok {
			return false
		}
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return len(phase) > 0
}

func defaultKotlinLibraries() []string {
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
	if compiler, ok := findKotlinCompiler(); ok {
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

const libraryCacheVersion = 29

type cachedArchive struct {
	Version int
}

type cachedSourceFile struct {
	Source LibrarySource
	Parsed analysis.ParsedFile
}

func (i *Index) indexSourceArchive(ctx context.Context, archive sourceArchive, generation uint64, progress func(int64)) {
	mirror := i.newArchiveMirror(archive)
	// Entries are prepared on this worker and inserted a few at a time: one
	// lock per file made eight decoders queue behind a lock taken a hundred
	// thousand times.
	const batchSize = 16
	var batch []LibraryFile
	flush := func() {
		if len(batch) == 0 {
			return
		}
		i.backgroundMu.RLock()
		i.addLibraryBatch(batch, generation)
		i.backgroundMu.RUnlock()
		progress(int64(len(batch)))
		batch = nil
	}
	if !archive.noCache && loadArchiveCache(ctx, archive, func(entry cachedSourceFile) bool {
		if i.generation.Load() != generation {
			return false
		}
		i.backgroundMu.RLock()
		i.canonicalizeLibraryFile(&entry.Parsed)
		i.backgroundMu.RUnlock()
		for symbol := range entry.Parsed.Symbols {
			entry.Parsed.Symbols[symbol].Library = true
		}
		prepareInterop(&entry.Parsed)
		batch = append(batch, LibraryFile{Source: entry.Source, Parsed: entry.Parsed})
		if len(batch) >= batchSize {
			flush()
		}
		return true
	}) {
		flush()
		// The parse came from the snapshot cache, so the loop below never ran
		// and never produced entry content. Mirror the archive separately when
		// its files are missing; a complete mirror makes this a no-op.
		i.mirrorArchive(ctx, archive, mirror)
		return
	}
	reader, err := zip.OpenReader(archive.path)
	if err != nil {
		return
	}
	defer reader.Close()
	var cacheWriter *archiveCacheWriter
	if !archive.noCache {
		cacheWriter, _ = newArchiveCacheWriter(archive)
	}
	if cacheWriter != nil {
		defer cacheWriter.Abort()
	}
	for _, file := range selectedArchiveFiles(archive, reader.File) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !archiveAccepts(archive, file) {
			continue
		}
		if len(archive.onlyTargets) > 0 && !archiveEntryMatchesTargets(archive, file.Name, archive.onlyTargets) {
			continue
		}
		i.backgroundMu.RLock()
		r, err := file.Open()
		if err != nil {
			i.backgroundMu.RUnlock()
			continue
		}
		// The entry is local build input. An arbitrary size ceiling silently
		// omitted valid generated sources and classfiles, leaving navigation
		// incomplete. Read the complete requested entry; cancellation remains
		// checked between entries and archive I/O errors are handled normally.
		data, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			i.backgroundMu.RUnlock()
			continue
		}
		entry := archiveEntry{archive: archive, name: file.Name}
		languageID := languageForEntry(file.Name)
		content := string(data)
		if archive.binary {
			parsedClass, parseErr := classfile.Parse(data)
			if parseErr != nil {
				i.backgroundMu.RUnlock()
				continue
			}
			content = classfile.RenderJava(parsedClass)
			languageID = "java"
			doc := textdoc.NewDocument(entry.URI(), languageID, 0, content)
			parsed := analysis.Parse(ctx, doc)
			applyClassfileAnnotations(parsed, parsedClass)
			applyKotlinBinaryMetadata(parsed, parsedClass)
			markBinaryWrapperSymbols(parsed, parsedClass.InternalName)
			mirror.write(file.Name, content, true)
			summarizeLibraryFile(parsed)
			parsed.References = nil
			parsed.Tokens = nil
			parsed.Diagnostics = nil
			parsed.Folds = nil
			i.canonicalizeLibraryFile(parsed)
			source := LibrarySource{Archive: archive.path, Entry: file.Name, LanguageID: languageID, Binary: true}
			i.addLibraryBatch([]LibraryFile{{Source: source, Parsed: *parsed}}, generation)
			if cacheWriter != nil {
				if writeErr := cacheWriter.Write(cachedSourceFile{Source: source, Parsed: *parsed}); writeErr != nil {
					cacheWriter.Abort()
					cacheWriter = nil
				}
			}
			progress(1)
			i.backgroundMu.RUnlock()
			continue
		}
		doc := textdoc.NewDocument(entry.URI(), languageID, 0, content)
		mirror.write(file.Name, content, false)
		parsed := analysis.Parse(ctx, doc)
		summarizeLibraryFile(parsed)
		parsed.References = nil
		parsed.Tokens = nil
		parsed.Diagnostics = nil
		parsed.Folds = nil
		i.canonicalizeLibraryFile(parsed)
		source := LibrarySource{Archive: archive.path, Entry: file.Name, LanguageID: languageID, Binary: archive.binary}
		i.addLibraryBatch([]LibraryFile{{Source: source, Parsed: *parsed}}, generation)
		if cacheWriter != nil {
			if writeErr := cacheWriter.Write(cachedSourceFile{Source: source, Parsed: *parsed}); writeErr != nil {
				cacheWriter.Abort()
				cacheWriter = nil
			}
		}
		progress(1)
		i.backgroundMu.RUnlock()
	}
	if cacheWriter != nil {
		_ = cacheWriter.Commit()
	}
	mirror.finish()
}

func (i *Index) canonicalizeLibraryFile(parsed *analysis.ParsedFile) {
	if parsed == nil {
		return
	}
	parsed.Package = i.internLibraryString(parsed.Package)
	canonicalIDs := make(map[string]string, len(parsed.Symbols))
	ownerNames := make(map[string]string)
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		oldID := symbol.ID
		newID := "L" + strconv.FormatUint(i.librarySymbolSeq.Add(1), 36)
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
	info, err := os.Stat(archive.path)
	if err != nil {
		return "", false
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	keyInput := strings.Join([]string{archive.path, info.ModTime().UTC().Format(time.RFC3339Nano), itoa64(info.Size()), itoa64(libraryCacheVersion), itoa64(int64(archive.release))}, "\x00")
	sum := sha256.Sum256([]byte(keyInput))
	base := filepath.Join(cacheRoot, "kotlsp", "libraries")
	versionDir := "v" + strconv.Itoa(libraryCacheVersion)
	libraryCacheCleanupOnce.Do(func() { cleanupObsoleteLibraryCaches(base, versionDir) })
	dir := filepath.Join(base, versionDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".gob.gz"), true
}

var libraryCacheCleanupOnce sync.Once

func cleanupObsoleteLibraryCaches(base, currentVersion string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(base, entry.Name())
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), "v") && entry.Name() != currentVersion {
				_ = os.RemoveAll(path)
			}
			continue
		}
		// Cache versions before v28 used a flat directory. These snapshots are
		// fully reproducible and structurally incompatible with compact IDs.
		if strings.HasSuffix(entry.Name(), ".gob.gz") || strings.HasPrefix(entry.Name(), ".library-") {
			_ = os.Remove(path)
		}
	}
}

func loadArchiveCache(ctx context.Context, archive sourceArchive, consume func(cachedSourceFile) bool) bool {
	path, ok := archiveCachePath(archive)
	if !ok {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		return false
	}
	defer zr.Close()
	decoder := gob.NewDecoder(zr)
	var header cachedArchive
	if err := decoder.Decode(&header); err != nil || header.Version != libraryCacheVersion {
		return false
	}
	for {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		var entry cachedSourceFile
		if err := decoder.Decode(&entry); err == io.EOF {
			return true
		} else if err != nil {
			return false
		}
		if !consume(entry) {
			return true
		}
	}
}

type archiveCacheWriter struct {
	path      string
	tmpPath   string
	file      *os.File
	zip       *gzip.Writer
	encoder   *gob.Encoder
	committed bool
}

func newArchiveCacheWriter(archive sourceArchive) (*archiveCacheWriter, error) {
	path, ok := archiveCachePath(archive)
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
	encoder := gob.NewEncoder(zw)
	if err = encoder.Encode(cachedArchive{Version: libraryCacheVersion}); err != nil {
		_ = zw.Close()
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, err
	}
	return &archiveCacheWriter{path: path, tmpPath: tmp.Name(), file: tmp, zip: zw, encoder: encoder}, nil
}

func (w *archiveCacheWriter) Write(entry cachedSourceFile) error {
	if w == nil || w.encoder == nil || w.committed {
		return os.ErrInvalid
	}
	return w.encoder.Encode(&entry)
}

func (w *archiveCacheWriter) Commit() error {
	if w == nil || w.file == nil || w.zip == nil || w.committed {
		return os.ErrInvalid
	}
	if err := w.zip.Close(); err != nil {
		return err
	}
	w.zip = nil
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
	path    string
	jdk     bool
	binary  bool
	module  string
	release int
	// onlyTargets/noCache describe a short priority pass and never participate
	// in a persistent archive-cache identity.
	onlyTargets []string
	noCache     bool
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
		entry, openErr := file.Open()
		if openErr != nil {
			return nil, openErr
		}
		data, readErr := io.ReadAll(entry)
		_ = entry.Close()
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

func resolveClasspath(ctx context.Context, root string) []string {
	return resolveClasspathModel(ctx, root).Classpath
}

type classpathResolution struct {
	Classpath             []string
	ModuleClasspath       map[string][]string
	Dependencies          map[string][]string
	SourceSetClasspath    map[string]map[string][]string
	SourceSetDependencies map[string]map[string][]string
	SourceSetExported     map[string]map[string][]string
	SourceSetDependsOn    map[string]map[string][]string
	SourceSetRoots        map[string]map[string][]string
}

const buildModelCacheVersion = 4

type cachedBuildModel struct {
	Version     int
	Fingerprint [sha256.Size]byte
	Resolution  classpathResolution
}

var modularPathCache sync.Map

func isModularPath(path string) bool {
	path = filepath.Clean(path)
	if cached, ok := modularPathCache.Load(path); ok {
		return cached.(bool)
	}
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
				for _, file := range archive.File {
					name := filepath.ToSlash(file.Name)
					if name == "module-info.class" || strings.HasPrefix(name, "META-INF/versions/") && strings.HasSuffix(name, "/module-info.class") {
						modular = true
						break
					}
					if strings.EqualFold(name, "META-INF/MANIFEST.MF") {
						reader, readErr := file.Open()
						if readErr == nil {
							manifest, _ := io.ReadAll(reader)
							_ = reader.Close()
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
	modularPathCache.Store(path, modular)
	return modular
}

func newClasspathResolution() classpathResolution {
	return classpathResolution{
		ModuleClasspath:       make(map[string][]string),
		Dependencies:          make(map[string][]string),
		SourceSetClasspath:    make(map[string]map[string][]string),
		SourceSetDependencies: make(map[string]map[string][]string),
		SourceSetExported:     make(map[string]map[string][]string),
		SourceSetDependsOn:    make(map[string]map[string][]string),
		SourceSetRoots:        make(map[string]map[string][]string),
	}
}

func resolveClasspathModel(ctx context.Context, root string) classpathResolution {
	fingerprint := buildModelFingerprint(root)
	if cached, ok := loadBuildModelCache(root, fingerprint); ok {
		cached.Classpath = uniqueSortedStrings(append(cached.Classpath, conventionalOutputDirectories(root)...))
		return cached
	}
	resolution := newClasspathResolution()
	paths := make([]string, 0)
	resolvedByBuildTool := false
	if gradle := gradleLauncher(root); gradle != "" {
		gradleResolution := gradleClasspathModel(ctx, root, gradle)
		paths = append(paths, gradleResolution.Classpath...)
		resolvedByBuildTool = len(gradleResolution.Classpath) > 0
		resolution.ModuleClasspath = gradleResolution.ModuleClasspath
		resolution.Dependencies = gradleResolution.Dependencies
		resolution.SourceSetClasspath = gradleResolution.SourceSetClasspath
		resolution.SourceSetDependencies = gradleResolution.SourceSetDependencies
		resolution.SourceSetExported = gradleResolution.SourceSetExported
		resolution.SourceSetDependsOn = gradleResolution.SourceSetDependsOn
		resolution.SourceSetRoots = gradleResolution.SourceSetRoots
	}
	if len(paths) == 0 {
		if maven := mavenLauncher(root); maven != "" {
			for _, module := range discoverModules([]string{root}) {
				if _, err := os.Stat(filepath.Join(module.Dir, "pom.xml")); err != nil {
					continue
				}
				mainPaths := mavenClasspathForScope(ctx, module.Dir, maven, "compile")
				testPaths := mavenClasspathForScope(ctx, module.Dir, maven, "test")
				modulePaths := uniqueSortedStrings(append(append([]string(nil), mainPaths...), testPaths...))
				resolution.ModuleClasspath[module.Name] = uniqueSortedStrings(append(resolution.ModuleClasspath[module.Name], modulePaths...))
				if resolution.SourceSetClasspath[module.Name] == nil {
					resolution.SourceSetClasspath[module.Name] = make(map[string][]string)
				}
				resolution.SourceSetClasspath[module.Name]["main"] = mainPaths
				resolution.SourceSetClasspath[module.Name]["test"] = testPaths
				paths = append(paths, modulePaths...)
				if len(modulePaths) > 0 {
					resolvedByBuildTool = true
				}
			}
			if len(paths) == 0 {
				paths = append(paths, mavenClasspath(ctx, root, maven)...)
				resolvedByBuildTool = len(paths) > 0
			}
		}
	}
	if len(paths) == 0 {
		paths = append(paths, directJarReferences(root)...)
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
	if len(out) > 0 && resolvedByBuildTool {
		_ = saveBuildModelCache(root, fingerprint, resolution)
	}
	return resolution
}

func buildModelFingerprint(root string) [sha256.Size]byte {
	hash := sha256.New()
	root, _ = filepath.Abs(root)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != root && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		buildInput := name == "build.gradle" || name == "build.gradle.kts" || name == "settings.gradle" || name == "settings.gradle.kts" || name == "pom.xml" || name == "gradle.properties" || name == "libs.versions.toml" || name == "gradle-wrapper.properties"
		lowerPath := strings.ToLower(path)
		libraryInput := strings.HasSuffix(name, ".jar") && !strings.HasSuffix(name, "-sources.jar") && !strings.HasSuffix(name, "-javadoc.jar") && !strings.Contains(lowerPath, string(filepath.Separator)+"build"+string(filepath.Separator))
		if !buildInput && !libraryInput {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write([]byte{0})
		if buildInput {
			if data, readErr := os.ReadFile(path); readErr == nil {
				_, _ = hash.Write(data)
			}
		} else if info, statErr := entry.Info(); statErr == nil {
			_, _ = io.WriteString(hash, itoa64(info.Size()))
			_, _ = io.WriteString(hash, info.ModTime().UTC().Format(time.RFC3339Nano))
		}
		_, _ = hash.Write([]byte{0})
		return nil
	})
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint
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
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".gob"), true
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
	var cached cachedBuildModel
	if err := gob.NewDecoder(file).Decode(&cached); err != nil || cached.Version != buildModelCacheVersion || cached.Fingerprint != fingerprint {
		return classpathResolution{}, false
	}
	for _, path := range cached.Resolution.Classpath {
		if _, err := os.Stat(path); err != nil {
			return classpathResolution{}, false
		}
	}
	return cached.Resolution, true
}

func saveBuildModelCache(root string, fingerprint [sha256.Size]byte, resolution classpathResolution) error {
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
	if err := gob.NewEncoder(tmp).Encode(cachedBuildModel{Version: buildModelCacheVersion, Fingerprint: fingerprint, Resolution: resolution}); err != nil {
		return err
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
	tmp, err := os.CreateTemp("", "kotlsp-*.init.gradle")
	if err != nil {
		return resolution
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = io.Copy(tmp, bytes.NewBufferString(gradleInitScript)); err != nil {
		_ = tmp.Close()
		return resolution
	}
	_ = tmp.Close()
	cmd := exec.CommandContext(parent, gradle, "--quiet", "--no-daemon", "--init-script", name, "kotlspClasspath")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GRADLE_OPTS=-Dorg.gradle.daemon=false")
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "kotlsp: Gradle classpath resolution failed in %s: %v: %s\n", root, err, strings.TrimSpace(string(exit.Stderr)))
		} else {
			fmt.Fprintf(os.Stderr, "kotlsp: Gradle classpath resolution failed in %s: %v\n", root, err)
		}
		return resolution
	}
	var paths []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
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
					resolution.SourceSetClasspath[parts[0]][set] = append(resolution.SourceSetClasspath[parts[0]][set], absolute)
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				resolution.Dependencies[parts[0]] = appendUniqueString(resolution.Dependencies[parts[0]], parts[2])
				set, compileVisible, exported := gradleDependencyConfiguration(parts[1])
				if !compileVisible {
					continue
				}
				if resolution.SourceSetDependencies[parts[0]] == nil {
					resolution.SourceSetDependencies[parts[0]] = make(map[string][]string)
				}
				resolution.SourceSetDependencies[parts[0]][set] = appendUniqueString(resolution.SourceSetDependencies[parts[0]][set], parts[2])
				if exported {
					if resolution.SourceSetExported[parts[0]] == nil {
						resolution.SourceSetExported[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetExported[parts[0]][set] = appendUniqueString(resolution.SourceSetExported[parts[0]][set], parts[2])
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
	}
	resolution.Classpath = paths
	return resolution
}

func gradleDependencyConfiguration(configuration string) (sourceSet string, compileVisible, exported bool) {
	lower := strings.ToLower(configuration)
	for _, suffix := range []string{"runtimeonly", "runtime", "developmentonly"} {
		if strings.HasSuffix(lower, suffix) {
			set := configuration[:len(configuration)-len(suffix)]
			if set == "" {
				set = "main"
			}
			return set, false, false
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
			return set, true, suffix.exported
		}
	}
	return "main", false, false
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

func mavenClasspath(parent context.Context, root, maven string) []string {
	return mavenClasspathForScope(parent, root, maven, "test")
}

func mavenClasspathForScope(parent context.Context, root, maven, scope string) []string {
	tmp, err := os.CreateTemp("", "kotlsp-maven-classpath-*.txt")
	if err != nil {
		return nil
	}
	name := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(name)
	cmd := exec.CommandContext(parent, maven, "-q", "dependency:build-classpath", "-Dmdep.includeScope="+scope, "-Dmdep.outputAbsoluteArtifactFilename=true", "-Dmdep.outputFile="+name)
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		return nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil
	}
	var paths []string
	for _, path := range filepath.SplitList(strings.TrimSpace(string(data))) {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
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

func directJarReferences(root string) []string {
	var paths []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
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
	return paths
}

func sourceJarsFor(binary string) []string {
	if strings.HasSuffix(binary, "-sources.jar") {
		return []string{binary}
	}
	versionDir := filepath.Dir(filepath.Dir(binary))
	var sources []string
	_ = filepath.WalkDir(versionDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), "-sources.jar") {
			sources = append(sources, path)
		}
		return nil
	})
	return sources
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

func jdkBinaryArchives(configuredHome string) []sourceArchive {
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
		return nil
	}
	paths, _ := filepath.Glob(filepath.Join(home, "jmods", "*.jmod"))
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
	return archives
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

func selectedArchiveFiles(archive sourceArchive, files []*zip.File) []*zip.File {
	if !archive.binary {
		selected := make([]*zip.File, 0, len(files))
		for _, file := range files {
			if archiveAccepts(archive, file) {
				selected = append(selected, file)
			}
		}
		return selected
	}
	multiRelease := false
	for _, file := range files {
		if strings.EqualFold(filepath.ToSlash(file.Name), "META-INF/MANIFEST.MF") {
			reader, err := file.Open()
			if err != nil {
				break
			}
			manifest, readErr := io.ReadAll(reader)
			_ = reader.Close()
			if readErr == nil {
				unfolded := strings.ReplaceAll(strings.ReplaceAll(string(manifest), "\r\n ", ""), "\n ", "")
				for _, line := range strings.Split(unfolded, "\n") {
					name, value, found := strings.Cut(line, ":")
					if found && strings.EqualFold(strings.TrimSpace(name), "Multi-Release") && strings.EqualFold(strings.TrimSpace(value), "true") {
						multiRelease = true
						break
					}
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
		if !archiveAccepts(archive, file) {
			continue
		}
		name := filepath.ToSlash(file.Name)
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
	return selected
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
	data, err := os.ReadFile(filepath.Join(home, "release"))
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
