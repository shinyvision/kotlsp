package index

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) Start(ctx context.Context, roots []protocol.URI) {
	i.lifecycleMu.Lock()
	defer i.lifecycleMu.Unlock()
	if i.closed.Load() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if i.cancel != nil {
		i.cancel()
	}
	generation := i.generation.Add(1)
	i.compilerRun.Add(1)
	scanCtx, cancel := context.WithCancel(ctx)
	i.cancel = cancel
	paths := make([]string, 0, len(roots))
	for _, root := range roots {
		if p, ok := uriutil.Path(root); ok {
			paths = append(paths, p)
		}
	}
	i.mu.Lock()
	for uri := range i.docs {
		i.fileGeneration[uri] = generation
	}
	i.roots = paths
	i.mu.Unlock()
	// Completion belongs to a scan generation. Retaining the previous
	// generation's flag while its replacement is still being assembled would
	// let fast unresolved diagnostics mistake a partial model for a complete
	// one.
	i.setLibrariesScanned(false)
	i.setRefreshIncomplete(true)
	i.generatedSources.mu.Lock()
	generatedStateChanged := i.generatedSources.complete
	i.generatedSources.complete = false
	i.generatedSources.mu.Unlock()
	if generatedStateChanged {
		i.diagnosticStateVersion.Add(1)
	}
	i.progress.Store(&Progress{})
	i.scanWG.Add(1)
	go func() {
		defer i.scanWG.Done()
		i.scan(scanCtx, paths, generation)
	}()
}

func (i *Index) scan(ctx context.Context, roots []string, generation uint64) {
	const maxWorkspaceEntries = 2000000
	const maxWorkspaceSources = 100000
	const maxWorkspaceSourceBytes int64 = 1 << 30
	modules, moduleErr := discoverModulesContext(ctx, roots)
	if moduleErr != nil {
		i.recordHealth("build-model", strings.Join(roots, string(os.PathListSeparator)), moduleErr.Error()+"; previous generation retained")
		return
	}
	defaultJavaHome := i.DefaultJavaHome()
	if defaultJavaHome != "" {
		for moduleIndex := range modules {
			if modules[moduleIndex].JavaHome == "" {
				modules[moduleIndex].JavaHome = defaultJavaHome
			}
		}
	}
	buildResolutions := make(map[string]classpathResolution, len(roots))
	stagedLibraryAccess := make(map[string]map[string]bool)
	for _, root := range roots {
		if ctx.Err() != nil || i.generation.Load() != generation {
			return
		}
		cleanRoot, _ := filepath.Abs(root)
		cleanRoot = filepath.Clean(cleanRoot)
		resolution := resolveClasspathModel(ctx, cleanRoot)
		i.recordModuleBuildResolutionHealth(cleanRoot, resolution)
		applyModuleBuildResolution(modules, cleanRoot, resolution, stagedLibraryAccess)
		buildResolutions[cleanRoot] = resolution
	}
	if ctx.Err() != nil || i.generation.Load() != generation {
		return
	}
	var paths []string
	visitedEntries := 0
	inventoryExhausted := false
	inventoryFailed := false
	seenPaths := make(map[string]bool)
	addPath := func(path string) {
		path = filepath.Clean(path)
		if !seenPaths[path] {
			seenPaths[path] = true
			paths = append(paths, path)
		}
	}
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if err != nil {
				i.recordHealth("index", path, err.Error())
				inventoryFailed = true
				return fs.SkipAll
			}
			visitedEntries++
			if visitedEntries > maxWorkspaceEntries || len(paths) >= maxWorkspaceSources {
				inventoryExhausted = true
				return fs.SkipAll
			}
			if d.IsDir() {
				if path != root && ignoredDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if isSource(path) {
				addPath(path)
			}
			return nil
		})
		if walkErr != nil {
			i.recordHealth("index", root, walkErr.Error())
			inventoryFailed = true
		}
		if inventoryExhausted || inventoryFailed {
			break
		}
	}
	// Generated roots are explicit module inputs, not arbitrary build output.
	// Scan them separately after the broad walk skips build/target trees.
	for _, module := range modules {
		if inventoryExhausted || inventoryFailed {
			break
		}
		for _, sourceRoot := range module.SourceRoots {
			walkErr := filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, err error) error {
				if ctx.Err() != nil {
					return fs.SkipAll
				}
				if err != nil {
					if path == sourceRoot && os.IsNotExist(err) {
						return nil
					}
					i.recordHealth("index", path, err.Error())
					inventoryFailed = true
					return fs.SkipAll
				}
				visitedEntries++
				if visitedEntries > maxWorkspaceEntries || len(paths) >= maxWorkspaceSources {
					inventoryExhausted = true
					return fs.SkipAll
				}
				if entry.IsDir() {
					if path != sourceRoot && ignoredDir(entry.Name()) {
						return filepath.SkipDir
					}
					return nil
				}
				if isSource(path) {
					addPath(path)
				}
				return nil
			})
			if walkErr != nil {
				i.recordHealth("index", sourceRoot, walkErr.Error())
				inventoryFailed = true
			}
			if inventoryExhausted || inventoryFailed {
				break
			}
		}
	}
	if inventoryExhausted {
		i.recordHealth("index", strings.Join(roots, string(os.PathListSeparator)), "workspace source inventory exceeded its 2000000-entry/100000-source safety limit; previous generation retained")
		return
	}
	if inventoryFailed {
		i.recordHealth("index", strings.Join(roots, string(os.PathListSeparator)), "workspace source inventory was incomplete; previous generation retained")
		return
	}
	p := Progress{FilesTotal: int64(len(paths))}
	if i.generation.Load() != generation {
		return
	}
	i.progress.Store(&p)
	// parsedFiles is the running counter; p itself is published above and must
	// never be mutated again, or Progress() readers race with the workers.
	var parsedFiles int64
	var sourceBytes atomic.Int64
	var sourceFailed atomic.Bool
	sourceCtx, sourceCancel := context.WithCancel(ctx)
	defer sourceCancel()
	type parsedResult struct {
		uri    protocol.URI
		doc    *textdoc.Document
		parsed *analysis.ParsedFile
	}
	var resultsMu sync.Mutex
	results := make([]parsedResult, 0, len(paths))
	jobs := make(chan string, 64)
	var wg sync.WaitGroup
	workers := 4
	if len(paths) < workers {
		workers = len(paths)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				if i.generation.Load() != generation {
					return
				}
				select {
				case <-sourceCtx.Done():
					return
				default:
				}
				data, err := readWorkspaceSource(path)
				if err != nil {
					i.recordHealth("index", path, err.Error())
					sourceFailed.Store(true)
					sourceCancel()
					return
				}
				if sourceBytes.Add(int64(len(data))) > maxWorkspaceSourceBytes {
					i.recordHealth("index", strings.Join(roots, string(os.PathListSeparator)), "workspace source text exceeds its 1 GiB transactional indexing safety limit")
					sourceFailed.Store(true)
					sourceCancel()
					return
				}
				u := uriutil.File(path)
				doc := textdoc.NewDocument(u, uriutil.LanguageID(path), 0, string(data))
				parsed := analysis.Parse(sourceCtx, doc)
				if sourceCtx.Err() != nil {
					return
				}
				if len(parsed.Symbols)+len(parsed.References) > maxPublishedFileOccurrences {
					i.recordHealth("index", path, "semantic occurrences exceed the 32768-per-file publication safety limit; previous generation retained")
					sourceFailed.Store(true)
					sourceCancel()
					return
				}
				resultsMu.Lock()
				results = append(results, parsedResult{uri: u, doc: doc, parsed: parsed})
				resultsMu.Unlock()
				count := atomic.AddInt64(&parsedFiles, 1)
				if i.generation.Load() == generation {
					i.progress.Store(&Progress{FilesParsed: count, FilesTotal: p.FilesTotal})
				}
			}
		}()
	}
	for _, path := range paths {
		select {
		case jobs <- path:
		case <-sourceCtx.Done():
			close(jobs)
			wg.Wait()
			if sourceFailed.Load() {
				i.recordHealth("index", strings.Join(roots, string(os.PathListSeparator)), "workspace source generation was incomplete; previous generation retained")
			}
			return
		}
	}
	close(jobs)
	wg.Wait()
	if i.generation.Load() != generation {
		return
	}
	if sourceFailed.Load() {
		i.recordHealth("index", strings.Join(roots, string(os.PathListSeparator)), "workspace source generation was incomplete; previous generation retained")
		return
	}
	sort.Slice(results, func(left, right int) bool { return results[left].uri < results[right].uri })
	// A publication generation is serialized separately from foreground reads.
	// Supersession may prevent a commit from starting, but once the first slice
	// lands the fully staged, infallible generation is completed. That invariant
	// prevents a subsequently failing scan from exposing a durable mix of two
	// source inventories.
	i.workspaceCommitMu.Lock()
	i.mu.Lock()
	if i.closed.Load() || i.generation.Load() != generation || ctx.Err() != nil {
		i.mu.Unlock()
		i.workspaceCommitMu.Unlock()
		return
	}
	i.modules = append([]ModuleInfo(nil), modules...)
	i.libraryAccess = stagedLibraryAccess
	i.semanticEnvironmentVersion++
	i.mu.Unlock()
	const publicationChunkWork = maxPublishedFileOccurrences
	for start := 0; start < len(results); {
		end, work := start, 0
		for end < len(results) {
			weight := max(1, len(results[end].parsed.Symbols)+len(results[end].parsed.References))
			if end > start && work+weight > publicationChunkWork {
				break
			}
			work += weight
			end++
		}
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			i.workspaceCommitMu.Unlock()
			return
		}
		for _, result := range results[start:end] {
			if _, open := i.docs[result.uri]; open {
				continue
			}
			i.indexedDocs[result.uri] = result.doc
			i.dropCompilerDiagnosticsLocked(result.parsed.URI)
			i.replaceLocked(result.parsed)
			i.fileGeneration[result.uri] = generation
		}
		i.mu.Unlock()
		runtime.Gosched()
		start = end
	}
	// Pruning is part of the same logical source-generation commit. It is not
	// deferred until libraries finish, because a superseding scan may fail
	// before reaching publication and must still leave this generation whole.
	i.mu.RLock()
	var staleSources []protocol.URI
	for uri := range i.files {
		if i.docs[uri] == nil && i.librarySources[uri].Archive == "" && i.fileGeneration[uri] != generation {
			staleSources = append(staleSources, uri)
		}
	}
	i.mu.RUnlock()
	for start := 0; start < len(staleSources); start += 32 {
		end := min(start+32, len(staleSources))
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			i.workspaceCommitMu.Unlock()
			return
		}
		for _, uri := range staleSources[start:end] {
			if i.docs[uri] == nil && i.librarySources[uri].Archive == "" && i.fileGeneration[uri] != generation {
				i.removeLocked(uri)
			}
		}
		i.mu.Unlock()
		runtime.Gosched()
	}
	i.workspaceCommitMu.Unlock()
	// Let the first editor document claim foreground priority before a cold
	// cache decoder starts allocating. Headless workspace-symbol sessions still
	// begin library indexing after the bounded fallback.
	select {
	case <-i.interactiveStarted:
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return
	}
	// Ready means every declaration-bearing input is indexed. Source archives
	// usually attach navigation text, but source-only aliases and generated APIs
	// make them part of the same correctness barrier.
	var readyOnce sync.Once
	markReady := func() {
		if i.closed.Load() || i.generation.Load() != generation {
			return
		}
		readyOnce.Do(func() {
			if i.closed.Load() || ctx.Err() != nil || i.generation.Load() != generation {
				return
			}
			i.pruneOlderGeneration(generation)
			if i.closed.Load() || ctx.Err() != nil || i.generation.Load() != generation {
				return
			}
			// Decided here, in the background, so the foreground never walks the
			// disk or takes a lock it already holds to find out.
			if err := i.computeGeneratedSourceStateContext(ctx); err != nil {
				i.recordHealth("generated-sources", strings.Join(roots, string(os.PathListSeparator)), err.Error()+"; previous uncertainty state retained")
			}
			if i.closed.Load() || ctx.Err() != nil || i.generation.Load() != generation {
				return
			}
			done := i.Progress()
			done.Ready = true
			i.progress.Store(&done)
			i.setRefreshIncomplete(false)
			i.signalSemanticProgress()
		})
	}
	i.scanLibraries(ctx, roots, generation, markReady, buildResolutions)
	if ctx.Err() != nil || i.generation.Load() != generation {
		return
	}
	markReady()
	// Initial validation uses the same run/cancellation/transaction machinery
	// as edit-triggered validation. A document edit can therefore supersede it
	// even though the workspace scan generation itself did not change.
	i.scheduleCompilerDiagnosticsNow(ctx)
}

func readWorkspaceSource(path string) ([]byte, error) {
	return readFileBounded(path, 64<<20, "workspace source")
}

func (i *Index) pruneOlderGeneration(generation uint64) {
	const chunkSize = 32
	i.mu.RLock()
	var stale []protocol.URI
	for uri := range i.files {
		if i.docs[uri] == nil && i.fileGeneration[uri] != generation {
			stale = append(stale, uri)
		}
	}
	i.mu.RUnlock()
	for start := 0; start < len(stale); start += chunkSize {
		end := min(start+chunkSize, len(stale))
		i.mu.Lock()
		if i.closed.Load() || i.generation.Load() != generation {
			i.mu.Unlock()
			return
		}
		for _, uri := range stale[start:end] {
			if i.docs[uri] == nil && i.fileGeneration[uri] != generation {
				i.removeLocked(uri)
			}
		}
		i.mu.Unlock()
		runtime.Gosched()
	}
}

func ignoredDir(name string) bool {
	switch name {
	case ".git", ".gradle", ".idea", "bin", "build", "out", "target", "node_modules", "vendor", ".kotlin", ".kotlsp":
		return true
	default:
		return strings.HasPrefix(name, ".") && name != "."
	}
}

func isSource(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".kt") || strings.HasSuffix(p, ".kts") || strings.HasSuffix(p, ".java")
}
