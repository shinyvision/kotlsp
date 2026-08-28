package index

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/archiveio"
	"github.com/shinyvision/kotlsp/internal/classfile"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// Library navigation targets live inside jars and the JDK image, so the index
// identifies them by jar:// and jrt:// URIs. No editor can open those on its
// own: a client asked to jump into one creates an empty buffer and then fails
// to place the cursor. Every archive entry that carries a navigable position is
// therefore mirrored into the user cache directory, and only the mirrored
// file:// URI is handed to the client. The jar://jrt:// URI stays the index
// identity, so incoming requests against a mirrored path are mapped back before
// anything else looks at them.
const librarySourceCacheVersion = 2

// LibrarySourceMarker appears in every mirrored file URI. It exists so the LSP
// layer can reject the overwhelming majority of request payloads with one byte
// scan instead of decoding them twice.
const LibrarySourceMarker = "kotlsp/sources/v2/"

// LibrarySourceBaseMarker matches a mirror path from any layout version.
const LibrarySourceBaseMarker = "kotlsp/sources/"

// Keep the marker literal in sync with librarySourceCacheVersion: clients use
// the stable substring as a cheap pre-decode filter for mirrored URIs.

// librarySourceTTL drops mirrors for archives that no longer participate in any
// build. Dependency upgrades would otherwise retain every superseded version.
const librarySourceTTL = 14 * 24 * time.Hour

const (
	sourceOriginName   = ".kotlsp-origin.json"
	sourceCompleteName = ".kotlsp-complete"
)

// archiveOrigin records everything archiveEntry.URI needs, so a mirrored path
// can be turned back into the index URI without consulting live index state.
type archiveOrigin struct {
	Archive string `json:"archive"`
	JDK     bool   `json:"jdk"`
	Module  string `json:"module"`
	Binary  bool   `json:"binary"`
}

func cleanupObsoleteSourceMirrors(base, currentVersion string) {
	forEachBoundedDirectoryEntry(base, 10_000, func(entry os.DirEntry) {
		path := filepath.Join(base, entry.Name())
		if !entry.IsDir() {
			_ = os.Remove(path)
			return
		}
		if entry.Name() != currentVersion {
			_ = os.RemoveAll(path)
		}
	})
	deadline := time.Now().Add(-librarySourceTTL)
	forEachBoundedDirectoryEntry(filepath.Join(base, currentVersion), 10_000, func(entry os.DirEntry) {
		path := filepath.Join(base, currentVersion, entry.Name())
		marker := filepath.Join(path, sourceCompleteName)
		info, statErr := os.Lstat(marker)
		if statErr != nil {
			// An interrupted extraction is resumable but never authoritative,
			// so it is only discarded once it is older than the retention
			// window rather than while another process may still be writing.
			if dirInfo, dirErr := entry.Info(); dirErr == nil && dirInfo.ModTime().Before(deadline) {
				_ = os.RemoveAll(path)
			}
			return
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return
		}
		if info.ModTime().Before(deadline) {
			_ = os.RemoveAll(path)
		}
	})
}

func forEachBoundedDirectoryEntry(path string, limit int, visit func(os.DirEntry)) bool {
	directory, err := os.Open(path)
	if err != nil {
		return false
	}
	defer directory.Close()
	seen := 0
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			seen++
			if seen > limit {
				return false
			}
			visit(entry)
		}
		if readErr == io.EOF {
			return true
		}
		if readErr != nil {
			return false
		}
	}
}

func archiveMirrorName(archivePath string, known ...[sha256.Size]byte) (string, bool) {
	var digest [sha256.Size]byte
	if len(known) > 0 {
		digest = known[0]
	} else {
		var err error
		digest, err = digestArchive(archivePath)
		if err != nil {
			return "", false
		}
	}
	key := archivePath + "\x00" + hex.EncodeToString(digest[:])
	sum := sha256.Sum256([]byte(key))
	return sanitizeMirrorBase(filepath.Base(archivePath)) + "-" + hex.EncodeToString(sum[:6]), true
}

// archiveDigest reuses the content identity established by archive metadata
// scanning. A library is hashed at most once per observed archive generation;
// watched replacement refreshes overwrite this entry before materialization.
func (i *Index) archiveDigest(archivePath string) ([sha256.Size]byte, bool) {
	return i.archiveDigestContext(context.Background(), archivePath)
}

func (i *Index) archiveDigestContext(ctx context.Context, archivePath string) ([sha256.Size]byte, bool) {
	clean := filepath.Clean(archivePath)
	i.mu.RLock()
	digest, ok := i.archiveDigests[clean]
	i.mu.RUnlock()
	if ok {
		return digest, true
	}
	computed, err := digestArchiveContext(ctx, clean)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	i.mu.Lock()
	if existing, exists := i.archiveDigests[clean]; exists {
		computed = existing
	} else {
		i.storeArchiveDigestLocked(clean, computed)
	}
	i.mu.Unlock()
	return computed, true
}

func (i *Index) storeArchiveDigestLocked(path string, digest [sha256.Size]byte) {
	path = filepath.Clean(path)
	if _, exists := i.archiveDigests[path]; !exists && len(i.archiveDigests) >= 8192 {
		for victim := range i.archiveDigests {
			delete(i.archiveDigests, victim)
			break
		}
	}
	i.archiveDigests[path] = digest
}

func sanitizeMirrorBase(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "archive"
	}
	return b.String()
}

// mirrorEntryName maps an archive entry onto its mirrored file name. Class
// files are mirrored as the rendered Java stub the index already parses, so the
// editor opens them with a Java file type instead of a binary buffer.
func mirrorEntryName(entry string, binary bool) string {
	name := strings.ReplaceAll(entry, "\\", "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsRune(name, 0) {
		return ""
	}
	if first := strings.SplitN(name, "/", 2)[0]; strings.Contains(first, ":") {
		return ""
	}
	name = pathpkg.Clean(name)
	if name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return ""
	}
	if binary && strings.HasSuffix(name, ".class") {
		name = strings.TrimSuffix(name, ".class") + ".java"
	}
	return name
}

// mirrorEntryPath resolves one archive member below root and proves the
// canonical result remains contained. Name validation and post-join
// containment are both required: filepath rules differ across platforms.
func mirrorEntryPath(root, entry string, binary bool) (string, bool) {
	name := mirrorEntryName(entry, binary)
	if root == "" || name == "" {
		return "", false
	}
	candidate := filepath.Join(root, filepath.FromSlash(name))
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", false
	}
	return candidate, true
}

// secureMirrorDirectory validates every component below a known cache root.
// ZIP names are checked lexically as well, but a stale cache containing a
// symlink must not turn a later safe-looking entry into an out-of-root write or
// metadata read. The cache is user-owned, so this is a fail-closed integrity
// check; it does not claim to be a cross-process openat-style sandbox.
func secureMirrorDirectory(root, directory string, create bool) error {
	root, directory = filepath.Clean(root), filepath.Clean(directory)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("mirror directory escapes cache root")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		if err != nil {
			return err
		}
		return fmt.Errorf("mirror root is not a real directory")
	}
	current := root
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid mirror directory component")
		}
		current = filepath.Join(current, filepath.FromSlash(component))
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) && create {
			if makeErr := os.Mkdir(current, 0o700); makeErr != nil && !os.IsExist(makeErr) {
				return makeErr
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("mirror path contains a non-directory or symlink")
		}
	}
	return nil
}

// secureMirrorLeaf rejects planted symlinks and non-regular leaf nodes after
// the full parent chain has been validated. Callers use allowMissing only
// immediately before an atomic create; existing leaves are never followed or
// silently replaced.
func secureMirrorLeaf(root, path string, allowMissing bool) error {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if err := secureMirrorDirectory(root, filepath.Dir(path), false); err != nil {
		return err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("mirror leaf escapes cache root")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && allowMissing {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("mirror leaf is not a regular file")
	}
	return nil
}

func archiveEntryName(mirrored string, binary bool) string {
	name := strings.TrimPrefix(filepath.ToSlash(mirrored), "/")
	if binary && strings.HasSuffix(name, ".java") {
		name = strings.TrimSuffix(name, ".java") + ".class"
	}
	return name
}

func isArchiveURI(uri protocol.URI) bool {
	return strings.HasPrefix(string(uri), "jar://") || strings.HasPrefix(string(uri), "jrt://")
}

type librarySourceMirror struct {
	rootOnce sync.Once
	rootDir  string
	mu       sync.Mutex
	dirs     map[string]string
	origins  map[string]*archiveOrigin
}

// root resolves the mirror directory once per index. Superseded layouts are
// swept at the same time, so an upgrade never leaves an unreadable mirror
// behind and abandoned dependency versions do not accumulate forever.
func (m *librarySourceMirror) root() string {
	m.rootOnce.Do(func() {
		cacheRoot, err := os.UserCacheDir()
		if err != nil {
			return
		}
		base := filepath.Join(cacheRoot, "kotlsp", "sources")
		version := "v" + strconv.Itoa(librarySourceCacheVersion)
		dir := filepath.Join(base, version)
		if err := secureMirrorDirectory(cacheRoot, dir, true); err != nil {
			return
		}
		cleanupObsoleteSourceMirrors(base, version)
		m.rootDir = dir
	})
	return m.rootDir
}

func (m *librarySourceMirror) dir(archivePath string, digest ...[sha256.Size]byte) (string, bool) {
	root := m.root()
	if root == "" || archivePath == "" {
		return "", false
	}
	name, ok := archiveMirrorName(archivePath, digest...)
	dir := ""
	if ok {
		dir = filepath.Join(root, name)
	}
	key := archivePath + "\x00" + name
	m.mu.Lock()
	if m.dirs == nil {
		m.dirs = make(map[string]string)
	}
	if cached, exists := m.dirs[key]; exists {
		m.mu.Unlock()
		return cached, cached != ""
	}
	m.dirs[key] = dir
	m.mu.Unlock()
	return dir, dir != ""
}

// complete reports whether the whole archive has already been mirrored. It
// deliberately revalidates the marker leaf on every call: caching a positive
// answer would allow a later symlink replacement to bypass the leaf check.
func (m *librarySourceMirror) complete(dir string) bool {
	if secureMirrorDirectory(filepath.Dir(dir), dir, false) != nil {
		return false
	}
	marker := filepath.Join(dir, sourceCompleteName)
	if err := secureMirrorLeaf(dir, marker, false); err != nil {
		return false
	}
	return true
}

func (m *librarySourceMirror) origin(dir string) (archiveOrigin, bool) {
	m.mu.Lock()
	cached, ok := m.origins[dir]
	m.mu.Unlock()
	if ok {
		if cached == nil {
			return archiveOrigin{}, false
		}
		return *cached, true
	}
	var origin archiveOrigin
	loaded := false
	originPath := filepath.Join(dir, sourceOriginName)
	if leafErr := secureMirrorLeaf(dir, originPath, false); leafErr == nil {
		data, err := readFileBounded(originPath, 1<<20, "source mirror origin")
		if err == nil {
			loaded = json.Unmarshal(data, &origin) == nil
		}
	}
	m.mu.Lock()
	if m.origins == nil {
		m.origins = make(map[string]*archiveOrigin)
	}
	if loaded {
		stored := origin
		m.origins[dir] = &stored
	} else {
		m.origins[dir] = nil
	}
	m.mu.Unlock()
	return origin, loaded
}

// ensureOrigin records the archive metadata a mirrored path needs to be mapped
// back, for mirrors that were written one entry at a time rather than by a full
// archive pass.
func (m *librarySourceMirror) ensureOrigin(dir string, origin archiveOrigin) {
	if err := secureMirrorDirectory(filepath.Dir(dir), dir, true); err != nil {
		return
	}
	if _, ok := m.origin(dir); ok {
		return
	}
	encoded, err := json.Marshal(origin)
	if err != nil {
		return
	}
	if err := writeMirrorMetadata(dir, filepath.Join(dir, sourceOriginName), encoded, 0o600); err != nil {
		return
	}
	m.mu.Lock()
	if m.origins == nil {
		m.origins = make(map[string]*archiveOrigin)
	}
	stored := origin
	m.origins[dir] = &stored
	m.mu.Unlock()
}

// originForURI recovers the archive shape from the library URI itself, which is
// the only description available when a single entry is mirrored on demand.
func originForURI(uri protocol.URI, source LibrarySource) archiveOrigin {
	origin := archiveOrigin{Archive: source.Archive, Binary: source.Binary}
	if !strings.HasPrefix(string(uri), "jrt://") {
		return origin
	}
	origin.JDK = true
	if source.Binary {
		rest := strings.TrimPrefix(string(uri), "jrt://")
		if cut := strings.IndexByte(rest, '/'); cut > 0 {
			origin.Module = rest[:cut]
		}
	}
	return origin
}

// LibraryFileURI returns the mirrored file:// URI for a library URI, writing
// the single entry on demand when the archive has not finished mirroring yet.
func (i *Index) LibraryFileURI(uri protocol.URI) (protocol.URI, bool) {
	return i.LibraryFileURIContext(context.Background(), uri)
}

func (i *Index) LibraryFileURIContext(ctx context.Context, uri protocol.URI) (protocol.URI, bool) {
	if !isArchiveURI(uri) {
		return "", false
	}
	i.mu.RLock()
	source, known := i.librarySources[uri]
	i.mu.RUnlock()
	if !known || source.Archive == "" || source.Entry == "" {
		return "", false
	}
	digest, digestOK := i.archiveDigestContext(ctx, source.Archive)
	if !digestOK {
		return "", false
	}
	dir, ok := i.sourceMirror.dir(source.Archive, digest)
	if !ok {
		return "", false
	}
	path, ok := mirrorEntryPath(dir, source.Entry, source.Binary)
	if !ok {
		return "", false
	}
	if !i.sourceMirror.complete(dir) {
		i.sourceMirror.ensureOrigin(dir, originForURI(uri, source))
		// A cold, on-demand mirror has no package directories yet. Validate and
		// create that parent chain before checking the leaf; secureMirrorLeaf is
		// deliberately read-only and therefore rejects a missing parent.
		if dirErr := secureMirrorDirectory(dir, filepath.Dir(path), true); dirErr != nil {
			return "", false
		}
		if leafErr := secureMirrorLeaf(dir, path, true); leafErr != nil {
			return "", false
		} else if _, err := os.Lstat(path); os.IsNotExist(err) {
			document, found := i.DocumentContext(ctx, uri)
			if !found {
				return "", false
			}
			if writeMirroredFile(dir, path, document.Text) != nil {
				return "", false
			}
		}
	}
	if secureMirrorLeaf(dir, path, false) != nil {
		return "", false
	}
	return uriutil.File(path), true
}

// DebugSourcePath maps a loaded JVM class to the same exact workspace or
// attached-library source used by definition navigation.
func (i *Index) DebugSourcePath(ctx context.Context, classPaths []string, className, sourceName string) (string, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	className = strings.TrimSuffix(className, ".")
	if dollar := strings.IndexByte(className, '$'); dollar >= 0 {
		className = className[:dollar]
	}
	type sourceCandidate struct {
		uri           protocol.URI
		binaryArchive string
		moduleDir     string
	}
	i.mu.RLock()
	ids := i.byFQN[className]
	if len(ids) > maxResolutionCandidates {
		i.mu.RUnlock()
		i.recordHealth("debug-source", className, "exact source candidate inventory exceeded its 512-symbol safety limit and was withheld")
		return "", false
	}
	candidates := make([]sourceCandidate, 0, len(ids))
	for _, id := range ids {
		symbol := i.symbols[id]
		if symbol == nil || !analysis.IsTypeKind(symbol.Kind) || symbol.Synthetic {
			continue
		}
		candidate := sourceCandidate{uri: symbol.URI}
		if symbol.SourceURI != "" {
			candidate.uri = symbol.SourceURI
		}
		if source, ok := i.librarySources[symbol.URI]; ok && source.Binary {
			candidate.binaryArchive = filepath.Clean(source.Archive)
		} else if module, unique := moduleForURIInModules(symbol.URI, i.modules); unique {
			candidate.moduleDir = filepath.Clean(module.Dir)
		}
		candidates = append(candidates, candidate)
	}
	i.mu.RUnlock()
	bestRank := len(classPaths) + 1
	paths := make(map[string]bool)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return "", false
		}
		rank := len(classPaths)
		matchedIdentity := len(classPaths) == 0
		for index, classPath := range classPaths {
			clean := filepath.Clean(classPath)
			if candidate.binaryArchive != "" && clean == candidate.binaryArchive {
				rank, matchedIdentity = index, true
				break
			}
			if candidate.binaryArchive == "" && candidate.moduleDir != "" && pathWithin(clean, candidate.moduleDir) {
				if info, err := os.Stat(clean); err == nil && info.IsDir() {
					rank, matchedIdentity = index, true
					break
				}
			}
		}
		if !matchedIdentity || rank > bestRank {
			continue
		}
		uri := candidate.uri
		if mirrored, ok := i.LibraryFileURIContext(ctx, uri); ok {
			uri = mirrored
		}
		path, ok := uriutil.Path(uri)
		if !ok || sourceName != "" && filepath.Base(path) != sourceName {
			continue
		}
		path = filepath.Clean(path)
		if rank < bestRank {
			bestRank = rank
			paths = make(map[string]bool)
		}
		paths[path] = true
	}
	if len(paths) != 1 {
		return "", false
	}
	for path := range paths {
		return path, true
	}
	return "", false
}

// LibraryURIForFile maps a mirrored file:// URI back onto the jar://jrt:// URI
// the index is keyed by. It reads the mirror's own metadata rather than live
// index state so buffers left open across a server restart keep working.
// base is the version-independent mirror directory. A path beneath it that
// the current layout cannot map (a mirror written by an earlier build that the
// editor still has open) is still a library view, never project source.
func (m *librarySourceMirror) base() string {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(cacheRoot, "kotlsp", "sources")
}

// IsLibraryMirrorFile reports whether a file URI lies under the library
// source mirror, whichever layout version wrote it.
func (i *Index) IsLibraryMirrorFile(uri protocol.URI) bool {
	if !strings.Contains(string(uri), LibrarySourceBaseMarker) {
		return false
	}
	base := i.sourceMirror.base()
	path, ok := uriutil.Path(uri)
	if base == "" || !ok {
		return false
	}
	relative, err := filepath.Rel(base, filepath.Clean(path))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func (i *Index) LibraryURIForFile(uri protocol.URI) (protocol.URI, bool) {
	root := i.sourceMirror.root()
	if root == "" || !strings.Contains(string(uri), LibrarySourceMarker) {
		return "", false
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		return "", false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	slashed := filepath.ToSlash(relative)
	cut := strings.IndexByte(slashed, '/')
	if cut <= 0 {
		return "", false
	}
	dir := filepath.Join(root, slashed[:cut])
	if secureMirrorDirectory(root, dir, false) != nil {
		return "", false
	}
	if secureMirrorLeaf(dir, path, false) != nil || secureMirrorLeaf(dir, filepath.Join(dir, sourceOriginName), false) != nil {
		return "", false
	}
	origin, ok := i.sourceMirror.origin(dir)
	if !ok {
		return "", false
	}
	entry := archiveEntry{
		archive: sourceArchive{path: origin.Archive, jdk: origin.JDK, module: origin.Module, binary: origin.Binary},
		name:    archiveEntryName(slashed[cut+1:], origin.Binary),
	}
	return entry.URI(), true
}

func writeMirroredFile(root, path, content string) error {
	return writeMirrorMetadata(root, path, []byte(content), 0o444)
}

func writeMirrorMetadata(root, path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := secureMirrorDirectory(root, dir, true); err != nil {
		return err
	}
	if err := secureMirrorLeaf(root, path, true); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".kotlsp-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return secureMirrorLeaf(root, path, false)
}

// archiveMirror writes one archive's mirror during background indexing, where
// the rendered content of every entry is already in hand.
type archiveMirror struct {
	dir  string
	dirs map[string]bool
}

// newArchiveMirror returns nil when the archive is already mirrored.
func (i *Index) newArchiveMirror(archive sourceArchive) *archiveMirror {
	digest := archive.digest
	if !archive.digestOK {
		var ok bool
		digest, ok = i.archiveDigest(archive.path)
		if !ok {
			return nil
		}
	}
	dir, ok := i.sourceMirror.dir(archive.path, digest)
	if !ok || i.sourceMirror.complete(dir) {
		return nil
	}
	if err := secureMirrorDirectory(filepath.Dir(dir), dir, true); err != nil {
		return nil
	}
	origin, err := json.Marshal(archiveOrigin{Archive: archive.path, JDK: archive.jdk, Module: archive.module, Binary: archive.binary})
	if err != nil {
		return nil
	}
	if err := writeMirrorMetadata(dir, filepath.Join(dir, sourceOriginName), origin, 0o600); err != nil {
		return nil
	}
	return &archiveMirror{dir: dir, dirs: make(map[string]bool)}
}

func (m *archiveMirror) write(entry, content string, binary bool) bool {
	if m == nil {
		return true
	}
	path, ok := mirrorEntryPath(m.dir, entry, binary)
	if !ok {
		return false
	}
	if dir := filepath.Dir(path); !m.dirs[dir] {
		if err := secureMirrorDirectory(m.dir, dir, true); err != nil {
			return false
		}
		m.dirs[dir] = true
	}
	return writeMirroredFile(m.dir, path, content) == nil
}

func (m *archiveMirror) finish() {
	if m == nil {
		return
	}
	if secureMirrorDirectory(filepath.Dir(m.dir), m.dir, false) != nil {
		return
	}
	if err := writeMirrorMetadata(m.dir, filepath.Join(m.dir, sourceCompleteName), nil, 0o600); err != nil {
		return
	}
}

// mirrorArchive writes a mirror for an archive whose parse came from the
// snapshot cache, so the indexing pass that normally produces the content never
// ran. It repeats the selection rules of indexSourceArchive exactly.
func (i *Index) mirrorArchive(ctx context.Context, archive sourceArchive, mirror *archiveMirror) {
	if mirror == nil {
		return
	}
	reader, err := zip.OpenReader(archive.path)
	if err != nil {
		return
	}
	defer reader.Close()
	budget, err := archiveio.NewBudget(archiveSemanticBudgetFiles(archive, reader.File))
	if err != nil {
		i.recordHealth("library-mirror", archive.path, err.Error())
		return
	}
	selected, err := selectedArchiveFilesWithBudgetContext(ctx, archive, reader.File, budget)
	if err != nil {
		i.recordHealth("library-mirror", archive.path, err.Error())
		return
	}
	complete := true
	for _, file := range selected {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !archiveAccepts(archive, file) {
			continue
		}
		if kotlinBuiltinSourceArchive(archive) && !kotlinBuiltinSourceEntry(file.Name) {
			continue
		}
		data, readErr := budget.ReadContext(ctx, file, archiveio.MaxEntryBytes)
		if readErr != nil {
			complete = false
			if errors.Is(readErr, archiveio.ErrArchiveBudget) {
				break
			}
			continue
		}
		content := string(data)
		if archive.binary {
			parsed, parseErr := classfile.Parse(data)
			if parseErr != nil {
				complete = false
				continue
			}
			content = classfile.RenderJava(parsed)
		}
		if !mirror.write(file.Name, content, archive.binary) {
			complete = false
		}
	}
	if complete && ctx.Err() == nil {
		mirror.finish()
	}
}
