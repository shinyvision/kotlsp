package index

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
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
	openFiles := make([]*analysis.ParsedFile, 0, len(i.docs))
	for uri := range i.docs {
		if parsed := i.files[uri]; parsed != nil {
			openFiles = append(openFiles, parsed)
		}
	}
	i.clearIndexLocked()
	i.roots = paths
	i.classpath = nil
	i.modules = nil
	for _, parsed := range openFiles {
		i.replaceLocked(parsed)
	}
	i.mu.Unlock()
	go i.scan(scanCtx, paths, generation)
}

func (i *Index) scan(ctx context.Context, roots []string, generation uint64) {
	modules := discoverModules(roots)
	defaultJavaHome := i.DefaultJavaHome()
	if defaultJavaHome != "" {
		for moduleIndex := range modules {
			if modules[moduleIndex].JavaHome == "" {
				modules[moduleIndex].JavaHome = defaultJavaHome
			}
		}
	}
	i.setModules(modules)
	var paths []string
	seenPaths := make(map[string]bool)
	addPath := func(path string) {
		path = filepath.Clean(path)
		if !seenPaths[path] {
			seenPaths[path] = true
			paths = append(paths, path)
		}
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
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
	}
	// Generated roots are explicit module inputs, not arbitrary build output.
	// Scan them separately after the broad walk skips build/target trees.
	for _, module := range modules {
		for _, sourceRoot := range module.SourceRoots {
			_ = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return nil
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
		}
	}
	p := Progress{FilesTotal: int64(len(paths))}
	if i.generation.Load() != generation {
		return
	}
	i.progress.Store(&p)
	// parsedFiles is the running counter; p itself is published above and must
	// never be mutated again, or Progress() readers race with the workers.
	var parsedFiles int64
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
				case <-ctx.Done():
					return
				default:
				}
				i.backgroundMu.RLock()
				data, err := os.ReadFile(path)
				if err != nil {
					i.backgroundMu.RUnlock()
					continue
				}
				u := uriutil.File(path)
				doc := textdoc.NewDocument(u, uriutil.LanguageID(path), 0, string(data))
				parsed := analysis.Parse(ctx, doc)
				i.mu.Lock()
				if i.generation.Load() != generation {
					i.mu.Unlock()
					i.backgroundMu.RUnlock()
					return
				}
				if _, open := i.docs[u]; !open {
					i.indexedDocs[u] = doc
					i.dropCompilerDiagnosticsLocked(parsed.URI)
					i.replaceLocked(parsed)
				}
				i.mu.Unlock()
				i.backgroundMu.RUnlock()
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
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
	if i.generation.Load() != generation {
		return
	}
	// Let the first editor document claim foreground priority before a cold
	// cache decoder starts allocating. Headless workspace-symbol sessions still
	// begin library indexing after the bounded fallback.
	select {
	case <-i.interactiveStarted:
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return
	}
	// Ready means every declaration is indexed. That is true once the
	// workspace and every binary archive are in; the source archives that
	// follow only attach navigation text to declarations already present, and
	// on a large classpath they take as long again. Predictions and
	// navigation start at the earlier point; attachment finishes behind them.
	markReady := func() {
		if i.generation.Load() != generation {
			return
		}
		// Decided here, in the background, so the foreground never walks the
		// disk or takes a lock it already holds to find out.
		i.computeGeneratedSourceState()
		done := i.Progress()
		done.Ready = true
		i.progress.Store(&done)
	}
	i.scanLibraries(ctx, roots, generation, markReady)
	if i.generation.Load() != generation {
		return
	}
	markReady()
	go func() {
		if disableCompilerPasses {
			return
		}
		func() {
			i.compilerMu.Lock()
			defer i.compilerMu.Unlock()
			i.scanJavaCompilerDiagnostics(ctx, generation)
			i.scanKotlinCompilerDiagnostics(ctx, generation)
		}()
		i.notifyDiagnosticsChanged()
	}()
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
