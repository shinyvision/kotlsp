package index

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/archiveio"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// SourceFileStamp is the bounded identity used only by the polling fallback
// when a client cannot register watched files.
type SourceFileStamp struct {
	Size             int64
	ModifiedUnixNano int64
	ContentHash      uint64
}

// WorkspaceSourceSnapshot walks declared source roots, never dependency or
// build-output roots, and stops at limit. The boolean is true when the result
// is incomplete; callers must then retain their previous snapshot rather than
// infer deletions from partial data.
func (i *Index) WorkspaceSourceSnapshot(ctx context.Context, limit int, verifyContent ...bool) (map[protocol.URI]SourceFileStamp, bool) {
	i.mu.RLock()
	modules := append([]ModuleInfo(nil), i.modules...)
	roots := append([]string(nil), i.roots...)
	i.mu.RUnlock()
	forceContent := len(verifyContent) > 0 && verifyContent[0]
	const maxVerifiedSourceBytes int64 = 2 << 30
	var verifiedBytes int64
	rootSet := make(map[string]bool)
	for _, module := range modules {
		for _, root := range module.SourceRoots {
			if len(rootSet) >= 100_000 && !rootSet[filepath.Clean(root)] {
				return nil, true
			}
			rootSet[filepath.Clean(root)] = true
		}
	}
	if len(rootSet) == 0 {
		for _, root := range roots {
			rootSet[filepath.Clean(root)] = true
		}
	}
	snapshot := make(map[protocol.URI]SourceFileStamp)
	exhausted := false
	for root := range rootSet {
		if ctx.Err() != nil || exhausted {
			return snapshot, true
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				exhausted = true
				return fs.SkipAll
			}
			if walkErr != nil {
				if path == root && os.IsNotExist(walkErr) {
					return nil
				}
				exhausted = true
				return fs.SkipAll
			}
			if entry.IsDir() {
				if path != root && ignoredDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !isSource(path) {
				return nil
			}
			if limit > 0 && len(snapshot) >= limit {
				exhausted = true
				return fs.SkipAll
			}
			info, err := entry.Info()
			if err == nil {
				uri := uriutil.File(path)
				var hash uint64
				if forceContent {
					if info.Size() > 64<<20 || info.Size() > maxVerifiedSourceBytes-verifiedBytes {
						exhausted = true
						return fs.SkipAll
					}
					contentHash, hashErr := hashSourceFile(ctx, path)
					if hashErr != nil {
						exhausted = true
						return fs.SkipAll
					}
					hash = contentHash
					verifiedBytes += info.Size()
				}
				snapshot[uri] = SourceFileStamp{Size: info.Size(), ModifiedUnixNano: info.ModTime().UnixNano(), ContentHash: hash}
			}
			return nil
		})
	}
	if !forceContent && !exhausted && ctx.Err() == nil {
		uris := make([]protocol.URI, 0, len(snapshot))
		for uri := range snapshot {
			uris = append(uris, uri)
		}
		for start := 0; start < len(uris); start += 256 {
			if ctx.Err() != nil {
				return snapshot, true
			}
			end := min(start+256, len(uris))
			i.mu.RLock()
			for _, uri := range uris[start:end] {
				if file := i.files[uri]; file != nil {
					stamp := snapshot[uri]
					stamp.ContentHash = file.TextHash
					snapshot[uri] = stamp
				}
			}
			i.mu.RUnlock()
		}
	}
	return snapshot, exhausted || ctx.Err() != nil
}

func hashSourceFile(ctx context.Context, path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 256<<10)
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
		}
		if readErr == io.EOF {
			digest := hash.Sum(nil)
			return binary.LittleEndian.Uint64(digest[:8]), nil
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}

// RefreshBuildChanges applies watched build/archive changes without advancing
// the workspace generation or discarding usable source state. Build models are
// replaced per owning root, new generated source roots are discovered, and
// archives preserve their previous semantic snapshot unless a complete
// replacement is available.
func (i *Index) RefreshBuildChanges(ctx context.Context, changes []protocol.URI) <-chan struct{} {
	done := make(chan struct{})
	result := i.RefreshBuildChangesResult(ctx, changes)
	waitCtx, finish, started := i.beginBackground(ctx)
	if !started {
		close(done)
		return done
	}
	go func() {
		defer finish()
		defer close(done)
		select {
		case <-result:
		case <-waitCtx.Done():
		}
	}()
	return done
}

// RefreshBuildChangesResult reports whether every requested model/archive
// stage reached a usable publication. Polling callers retain their old
// fingerprint after false and therefore retry an unchanged on-disk failure.
func (i *Index) RefreshBuildChangesResult(ctx context.Context, changes []protocol.URI) <-chan bool {
	done := make(chan bool, 1)
	refreshCtx, finish, started := i.beginBackground(ctx)
	if !started {
		done <- false
		close(done)
		return done
	}
	go func() {
		defer finish()
		done <- i.refreshBuildChanges(refreshCtx, changes)
		close(done)
	}()
	return done
}

func (i *Index) refreshBuildChanges(ctx context.Context, changes []protocol.URI) (succeeded bool) {
	i.buildRefreshMu.Lock()
	if ctx.Err() != nil || i.closed.Load() {
		i.buildRefreshMu.Unlock()
		return false
	}
	i.setModelRefreshing(true)
	i.setRefreshIncomplete(true)
	i.cancelCompilerDiagnostics()
	defer func() {
		if succeeded {
			i.setRefreshIncomplete(false)
		}
		if !i.closed.Load() {
			i.setModelRefreshing(false)
		}
		i.buildRefreshMu.Unlock()
		if !i.closed.Load() && ctx.Err() == nil {
			i.ScheduleCompilerDiagnostics(ctx)
		}
	}()
	generation := i.generation.Load()
	i.mu.RLock()
	roots := append([]string(nil), i.roots...)
	previousModules := append([]ModuleInfo(nil), i.modules...)
	i.mu.RUnlock()
	affectedRoots := make(map[string]bool)
	archives := make(map[string]bool)
	refreshAllArchives := len(changes) == 0
	if len(changes) == 0 {
		for _, root := range roots {
			affectedRoots[filepath.Clean(root)] = true
		}
	}
	for _, uri := range changes {
		path, ok := uriutil.Path(uri)
		if !ok {
			continue
		}
		path = filepath.Clean(path)
		if strings.HasSuffix(strings.ToLower(path), ".jar") {
			archives[path] = true
			continue
		}
		if root := buildImportRoot(path, roots, previousModules); root != "" {
			affectedRoots[root] = true
		}
	}
	if refreshAllArchives {
		// Classpath replacement below covers binary JARs. Locally indexed source
		// attachments are not classpath entries, so include those explicitly or
		// a fallback watcher would detect their fingerprint and then refresh
		// nothing which could change navigation text.
		i.mu.RLock()
		for _, source := range i.librarySources {
			archivePath := filepath.Clean(source.Archive)
			if strings.HasSuffix(strings.ToLower(archivePath), "-sources.jar") && pathInAnyRoot(archivePath, affectedRoots) {
				archives[archivePath] = true
			}
		}
		i.mu.RUnlock()
	}
	if len(affectedRoots) == 0 || ctx.Err() != nil {
		for archive := range archives {
			if ctx.Err() != nil || !i.refreshLibraryArchive(ctx, archive) {
				return false
			}
		}
		succeeded = ctx.Err() == nil
		return succeeded
	}
	rootNames := make([]string, 0, len(affectedRoots))
	for root := range affectedRoots {
		rootNames = append(rootNames, root)
	}
	sort.Strings(rootNames)
	i.invalidateBuildModelRoots(rootNames)

	replacementModules := make([]ModuleInfo, 0, len(previousModules))
	for _, module := range previousModules {
		if !pathInAnyRoot(module.Dir, affectedRoots) {
			replacementModules = append(replacementModules, module)
		}
	}
	for _, root := range rootNames {
		modules, discoverErr := discoverModulesContext(ctx, []string{root})
		if discoverErr != nil {
			i.recordHealth("build-model", root, discoverErr.Error()+"; previous module snapshot retained")
			return false
		}
		defaultJavaHome := i.DefaultJavaHome()
		for index := range modules {
			if modules[index].JavaHome == "" {
				modules[index].JavaHome = defaultJavaHome
			}
		}
		replacementModules = append(replacementModules, modules...)
	}
	oldPaths := modulePathsWithinRoots(previousModules, affectedRoots)
	newPaths := make(map[string]bool)
	stagedAccess := make(map[string]map[string]bool)
	for _, root := range rootNames {
		if ctx.Err() != nil {
			return false
		}
		resolution := resolveClasspathModel(ctx, root)
		i.recordModuleBuildResolutionHealth(root, resolution)
		applyModuleBuildResolution(replacementModules, root, resolution, stagedAccess)
		compileClasspath, complete := compileClasspathEntries(resolution)
		if !complete {
			i.recordHealth("build-model", root, "compile classpath exceeds its 100000-path safety limit; previous module snapshot retained")
			return false
		}
		for _, path := range compileClasspath {
			newPaths[filepath.Clean(path)] = true
		}
	}
	stagedSources, wantedSources, sourceScope, stageErr := i.stageModuleSourceRefresh(ctx, replacementModules, previousModules, affectedRoots)
	if stageErr != nil {
		i.recordHealth("index-refresh", strings.Join(rootNames, string(os.PathListSeparator)), stageErr.Error()+"; previous module snapshot retained")
		return false
	}
	// Archive refresh is still fallible, so finish it before publishing the new
	// module/source model. Each archive transaction is itself all-or-complete;
	// a failure here therefore retains the previous build/source snapshot.
	refreshedArchives := make(map[string]bool)
	stagingAccess := func(path string, newlyAdded bool) (map[string]bool, bool) {
		path = filepath.Clean(path)
		i.mu.RLock()
		current, exists := i.libraryAccess[path]
		snapshot := make(map[string]bool, len(current)+1)
		for key := range current {
			snapshot[key] = true
		}
		i.mu.RUnlock()
		if exists {
			return snapshot, true
		}
		if newlyAdded {
			// An archive can become query-visible before the surrounding build
			// model transaction commits. Deny it during that interval instead of
			// publishing access from a model which may still be rolled back.
			snapshot[pendingLibraryAccessKey] = true
			return snapshot, true
		}
		return nil, false
	}
	for path := range newPaths {
		if strings.HasSuffix(strings.ToLower(path), ".jar") && (refreshAllArchives || !oldPaths[path] || archives[path]) {
			access, restricted := stagingAccess(path, !oldPaths[path])
			refreshed := false
			if restricted {
				refreshed = i.refreshLibraryArchive(ctx, path, access)
			} else {
				refreshed = i.refreshLibraryArchive(ctx, path)
			}
			if !refreshed {
				return false
			}
			refreshedArchives[path] = true
		}
	}
	for path := range archives {
		if refreshedArchives[path] {
			continue
		}
		if ctx.Err() != nil || !i.refreshLibraryArchive(ctx, path) {
			return false
		}
	}
	// Determine deletions before the write phase. Foreground opens and revision
	// changes are rechecked in each slice, so this snapshot cannot delete a
	// newly opened or edited document.
	i.mu.RLock()
	staleSources := make([]protocol.URI, 0)
	for uri := range i.files {
		if i.docs[uri] != nil || i.librarySources[uri].Archive != "" || wantedSources[uri] {
			continue
		}
		if path, ok := uriutil.Path(uri); ok && pathInAnyRoot(path, sourceScope) {
			staleSources = append(staleSources, uri)
		}
	}
	i.mu.RUnlock()
	i.workspaceCommitMu.Lock()
	i.mu.Lock()
	if ctx.Err() != nil || i.closed.Load() || i.generation.Load() != generation {
		i.mu.Unlock()
		i.workspaceCommitMu.Unlock()
		return false
	}
	i.clearLibraryAccessForRootsLocked(previousModules, affectedRoots)
	for path := range newPaths {
		path = filepath.Clean(path)
		if access := i.libraryAccess[path]; access != nil {
			delete(access, pendingLibraryAccessKey)
			if len(access) == 0 {
				delete(i.libraryAccess, path)
			}
		}
	}
	for archive, access := range stagedAccess {
		if i.libraryAccess[archive] == nil {
			i.libraryAccess[archive] = make(map[string]bool)
		}
		for key := range access {
			i.libraryAccess[archive][key] = true
		}
	}
	i.replaceWorkspaceClasspathSliceLocked(oldPaths, newPaths)
	i.modules = append([]ModuleInfo(nil), replacementModules...)
	i.semanticEnvironmentVersion++
	i.mu.Unlock()
	for start := 0; start < len(staleSources); start += 32 {
		end := min(start+32, len(staleSources))
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			i.workspaceCommitMu.Unlock()
			return false
		}
		for _, uri := range staleSources[start:end] {
			if i.docs[uri] != nil || i.librarySources[uri].Archive != "" || wantedSources[uri] {
				continue
			}
			if path, ok := uriutil.Path(uri); ok && pathInAnyRoot(path, sourceScope) {
				i.removeLocked(uri)
			}
		}
		i.mu.Unlock()
	}
	for start := 0; start < len(stagedSources); {
		end, work := start, 0
		for end < len(stagedSources) {
			weight := max(1, len(stagedSources[end].parsed.Symbols)+len(stagedSources[end].parsed.References))
			if end > start && work+weight > maxPublishedFileOccurrences {
				break
			}
			work += weight
			end++
		}
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			i.workspaceCommitMu.Unlock()
			return false
		}
		for _, source := range stagedSources[start:end] {
			if i.docs[source.uri] != nil || i.documentRevision[source.uri] != source.revision {
				continue
			}
			i.indexedDocs[source.uri] = source.document
			i.dropCompilerDiagnosticsLocked(source.uri)
			i.replaceLocked(source.parsed)
			i.fileGeneration[source.uri] = generation
		}
		i.mu.Unlock()
		start = end
	}
	i.workspaceCommitMu.Unlock()
	for path := range oldPaths {
		if !newPaths[path] && strings.HasSuffix(strings.ToLower(path), ".jar") {
			i.pruneLibraryArchive(path, nil)
		}
	}
	i.generatedSources.mu.Lock()
	generatedStateChanged := i.generatedSources.complete
	i.generatedSources.complete = false
	i.generatedSources.mu.Unlock()
	if generatedStateChanged {
		i.diagnosticStateVersion.Add(1)
	}
	if err := i.computeGeneratedSourceStateContext(ctx); err != nil {
		i.recordHealth("generated-sources", "refresh", err.Error()+"; previous uncertainty state retained")
		return false
	}
	succeeded = ctx.Err() == nil && !i.closed.Load() && i.generation.Load() == generation
	return succeeded
}

func (i *Index) recordModuleBuildResolutionHealth(root string, resolution classpathResolution) {
	root, _ = filepath.Abs(root)
	if resolution.Failure != "" {
		i.recordHealth("build-model", root, resolution.Importer+": "+resolution.Failure)
	}
	if resolution.CacheWarning != "" {
		i.recordHealth("build-model-cache", root, resolution.CacheWarning)
	}
	if resolution.UsedConfigurationFallback {
		i.recordHealth("build-model", root, "Gradle source-set identity was unavailable for part of the model; configuration-name fallback was used")
	}
}

type stagedWorkspaceSource struct {
	uri      protocol.URI
	document *textdoc.Document
	parsed   *analysis.ParsedFile
	revision uint64
}

// stageModuleSourceRefresh inventories and parses every newly visible source
// before the module model is published. A failed or oversized inventory leaves
// the previous model and all of its sources intact.
func (i *Index) stageModuleSourceRefresh(ctx context.Context, modules, previous []ModuleInfo, affected map[string]bool) ([]stagedWorkspaceSource, map[protocol.URI]bool, map[string]bool, error) {
	const maxRefreshEntries = 2_000_000
	const maxRefreshSources = 100_000
	const maxRefreshBytes int64 = 1 << 30
	newRoots := make(map[string]bool)
	scope := make(map[string]bool)
	for _, module := range previous {
		if pathInAnyRoot(module.Dir, affected) {
			for _, root := range module.SourceRoots {
				scope[filepath.Clean(root)] = true
			}
		}
	}
	for _, module := range modules {
		if pathInAnyRoot(module.Dir, affected) {
			for _, root := range module.SourceRoots {
				root = filepath.Clean(root)
				newRoots[root] = true
				scope[root] = true
			}
		}
	}
	i.mu.RLock()
	indexed := make(map[protocol.URI]bool, len(i.files))
	revisions := make(map[protocol.URI]uint64, len(i.documentRevision))
	for uri := range i.files {
		indexed[uri] = true
	}
	for uri, revision := range i.documentRevision {
		revisions[uri] = revision
	}
	i.mu.RUnlock()
	wanted := make(map[protocol.URI]bool)
	seenEntries := make(map[string]bool)
	staged := make([]stagedWorkspaceSource, 0)
	visited := 0
	var sourceBytes int64
	for _, root := range minimalRefreshRoots(newRoots) {
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if walkErr != nil {
				return walkErr
			}
			path = filepath.Clean(path)
			if seenEntries[path] {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			seenEntries[path] = true
			visited++
			if visited > maxRefreshEntries {
				return fmt.Errorf("module source refresh exceeds its %d-entry safety limit", maxRefreshEntries)
			}
			if entry.IsDir() {
				if path != root && ignoredDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !isSource(path) {
				return nil
			}
			uri := uriutil.File(path)
			if !wanted[uri] && len(wanted) >= maxRefreshSources {
				return fmt.Errorf("module source refresh exceeds its %d-source safety limit", maxRefreshSources)
			}
			wanted[uri] = true
			if indexed[uri] {
				return nil
			}
			data, err := readWorkspaceSource(path)
			if err != nil {
				return err
			}
			if int64(len(data)) > maxRefreshBytes-sourceBytes {
				return fmt.Errorf("module source refresh exceeds its 1 GiB text safety limit")
			}
			sourceBytes += int64(len(data))
			document := textdoc.NewDocument(uri, uriutil.LanguageID(path), 0, string(data))
			parsed := analysis.Parse(ctx, document)
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if len(parsed.Symbols)+len(parsed.References) > maxPublishedFileOccurrences {
				return fmt.Errorf("%s exceeds the 32768-occurrence publication safety limit", path)
			}
			staged = append(staged, stagedWorkspaceSource{uri: uri, document: document, parsed: parsed, revision: revisions[uri]})
			return nil
		})
		if walkErr != nil {
			return nil, nil, nil, walkErr
		}
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
	}
	return staged, wanted, scope, nil
}

func minimalRefreshRoots(set map[string]bool) []string {
	roots := make([]string, 0, len(set))
	for root := range set {
		if root != "" {
			roots = append(roots, filepath.Clean(root))
		}
	}
	sort.Slice(roots, func(left, right int) bool {
		if len(roots[left]) == len(roots[right]) {
			return roots[left] < roots[right]
		}
		return len(roots[left]) < len(roots[right])
	})
	minimal := make([]string, 0, len(roots))
	for _, root := range roots {
		contained := false
		for _, parent := range minimal {
			if pathWithin(root, parent) {
				contained = true
				break
			}
		}
		if !contained {
			minimal = append(minimal, root)
		}
	}
	return minimal
}

func (i *Index) clearLibraryAccessForRoots(modules []ModuleInfo, roots map[string]bool) {
	i.mu.Lock()
	i.clearLibraryAccessForRootsLocked(modules, roots)
	i.semanticEnvironmentVersion++
	i.mu.Unlock()
}

func (i *Index) clearLibraryAccessForRootsLocked(modules []ModuleInfo, roots map[string]bool) {
	directories := make(map[string]bool)
	for _, module := range modules {
		if pathInAnyRoot(module.Dir, roots) {
			directories[filepath.Clean(module.Dir)] = true
		}
	}
	for archive, access := range i.libraryAccess {
		for key := range access {
			directory := key
			if separator := strings.IndexByte(key, '\x00'); separator >= 0 {
				directory = key[:separator]
			}
			if directories[filepath.Clean(directory)] {
				delete(access, key)
			}
		}
		if len(access) == 0 {
			delete(i.libraryAccess, archive)
		}
	}
}

func longestContainingRoot(path string, roots []string) string {
	best := ""
	for _, root := range roots {
		root = filepath.Clean(root)
		if pathWithin(path, root) && len(root) > len(best) {
			best = root
		}
	}
	return best
}

// buildImportRoot maps a changed manifest to the smallest build invocation
// that owns it. Maven modules can be re-imported from their own directory;
// Gradle catalogs and subproject scripts belong to the nearest settings file.
// Only an unidentifiable build input falls back to the workspace root.
func buildImportRoot(path string, roots []string, modules []ModuleInfo) string {
	workspaceRoot := longestContainingRoot(path, roots)
	if workspaceRoot == "" {
		return ""
	}
	directory := filepath.Dir(path)
	if strings.EqualFold(filepath.Base(path), "pom.xml") {
		return directory
	}
	for current := directory; pathWithin(current, workspaceRoot); current = filepath.Dir(current) {
		for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
			if info, err := os.Stat(filepath.Join(current, name)); err == nil && !info.IsDir() {
				return current
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	best := ""
	for _, module := range modules {
		clean := filepath.Clean(module.Dir)
		if pathWithin(path, clean) && len(clean) > len(best) {
			best = clean
		}
	}
	if best != "" {
		return best
	}
	return workspaceRoot
}

func pathInAnyRoot(path string, roots map[string]bool) bool {
	for root := range roots {
		if pathWithin(path, root) {
			return true
		}
	}
	return false
}

func (i *Index) invalidateBuildModelRoots(roots []string) {
	buildInputManifestCache.Lock()
	for _, root := range roots {
		absolute, _ := filepath.Abs(root)
		delete(buildInputManifestCache.byRoot, filepath.Clean(absolute))
	}
	buildInputManifestCache.Unlock()
}

func modulePathsWithinRoots(modules []ModuleInfo, roots map[string]bool) map[string]bool {
	paths := make(map[string]bool)
	for _, module := range modules {
		if !pathInAnyRoot(module.Dir, roots) {
			continue
		}
		for _, path := range module.Classpath {
			paths[filepath.Clean(path)] = true
		}
		for _, path := range module.ModulePath {
			paths[filepath.Clean(path)] = true
		}
		for _, values := range module.ClasspathBySourceSet {
			for _, path := range values {
				paths[filepath.Clean(path)] = true
			}
		}
		for _, values := range module.ModulePathBySourceSet {
			for _, path := range values {
				paths[filepath.Clean(path)] = true
			}
		}
	}
	return paths
}

func (i *Index) replaceWorkspaceClasspathSlice(oldPaths, newPaths map[string]bool) {
	i.mu.Lock()
	i.replaceWorkspaceClasspathSliceLocked(oldPaths, newPaths)
	i.semanticEnvironmentVersion++
	i.mu.Unlock()
}

func (i *Index) replaceWorkspaceClasspathSliceLocked(oldPaths, newPaths map[string]bool) {
	kept := i.classpath[:0]
	for _, path := range i.classpath {
		clean := filepath.Clean(path)
		if !oldPaths[clean] || newPaths[clean] {
			kept = append(kept, path)
		}
	}
	for path := range newPaths {
		if !containsPath(kept, path) {
			kept = append(kept, path)
		}
	}
	sort.Strings(kept)
	i.classpath = kept
}

func containsPath(paths []string, wanted string) bool {
	wanted = filepath.Clean(wanted)
	for _, path := range paths {
		if filepath.Clean(path) == wanted {
			return true
		}
	}
	return false
}

func (i *Index) refreshLibraryArchive(ctx context.Context, path string, requestedAccess ...map[string]bool) bool {
	if ctx.Err() != nil || i.closed.Load() {
		return false
	}
	path = filepath.Clean(path)
	archive := sourceArchive{path: path, binary: !strings.HasSuffix(strings.ToLower(path), "-sources.jar"), release: i.javaReleaseForLibrary(path)}
	i.mu.RLock()
	for _, source := range i.librarySources {
		if filepath.Clean(source.Archive) == path {
			archive.binary = source.Binary
			break
		}
	}
	i.mu.RUnlock()
	wanted := make(map[string]bool)
	reader, err := zip.OpenReader(path)
	if err == nil {
		if budget, budgetErr := archiveio.NewBudget(archiveSemanticBudgetFiles(archive, reader.File)); budgetErr != nil {
			err = budgetErr
		} else {
			var selected []*zip.File
			selected, err = selectedArchiveFilesWithBudgetContext(ctx, archive, reader.File, budget)
			for _, entry := range selected {
				if archiveAccepts(archive, entry) {
					wanted[filepath.ToSlash(entry.Name)] = true
				}
			}
		}
		_ = reader.Close()
	}
	if err != nil {
		if os.IsNotExist(err) {
			if ctx.Err() != nil || i.closed.Load() {
				return false
			}
			i.pruneLibraryArchive(path, nil)
			return true
		} else {
			// A transiently truncated/replaced archive must not erase the last
			// usable semantic generation. The next watcher poll retries it.
			i.recordHealth("library-refresh", path, err.Error())
		}
		return false
	}
	archives := []sourceArchive{archive}
	i.populateArchiveMetadata(ctx, archives)
	if ctx.Err() != nil {
		return false
	}
	archive = archives[0]
	generation := i.generation.Load()
	var access map[string]bool
	hasAccess := len(requestedAccess) > 0
	if hasAccess {
		access = requestedAccess[0]
	} else {
		i.mu.RLock()
		access, hasAccess = i.libraryAccess[path]
		i.mu.RUnlock()
	}
	var accessSnapshots []map[string]bool
	if hasAccess {
		accessSnapshots = append(accessSnapshots, access)
	}
	complete := i.indexSourceArchive(ctx, archive, generation, func(int64) {}, accessSnapshots...)
	if !complete || ctx.Err() != nil || i.generation.Load() != generation {
		// A canceled/superseded refresh never publishes its staged archive. Keep
		// the prior generation live so the next watcher poll can retry it.
		i.retainLibraryArchiveGeneration(path, generation)
		return false
	}
	// The archive transaction has already removed entries absent from the new
	// selected snapshot. This is a defensive no-op for callers which computed
	// the inventory independently before staging.
	i.pruneLibraryArchive(path, wanted)
	return true
}

func (i *Index) pruneLibraryArchive(path string, wanted map[string]bool) {
	if i.closed.Load() {
		return
	}
	path = filepath.Clean(path)
	i.mu.Lock()
	var stale []protocol.URI
	for uri, source := range i.librarySources {
		if filepath.Clean(source.Archive) == path && (wanted == nil || !wanted[filepath.ToSlash(source.Entry)]) {
			stale = append(stale, uri)
		}
	}
	for _, uri := range stale {
		i.removeLocked(uri)
	}
	if wanted == nil || len(wanted) == 0 {
		delete(i.libraryModules, path)
		delete(i.libraryModuleAliases, path)
		delete(i.libraryAccess, path)
		delete(i.archiveDigests, path)
		i.semanticEnvironmentVersion++
	}
	i.mu.Unlock()
}
