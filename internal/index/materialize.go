package index

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
const librarySourceCacheVersion = 1

// LibrarySourceMarker appears in every mirrored file URI. It exists so the LSP
// layer can reject the overwhelming majority of request payloads with one byte
// scan instead of decoding them twice.
const LibrarySourceMarker = "kotlsp/sources/v1/"

// The marker spells the version out so it stays a constant. This fails to
// compile if librarySourceCacheVersion moves without the marker following it.
const _ = uint(librarySourceCacheVersion - 1)

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
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(base, entry.Name())
		if !entry.IsDir() {
			_ = os.Remove(path)
			continue
		}
		if entry.Name() != currentVersion {
			_ = os.RemoveAll(path)
		}
	}
	current, err := os.ReadDir(filepath.Join(base, currentVersion))
	if err != nil {
		return
	}
	deadline := time.Now().Add(-librarySourceTTL)
	for _, entry := range current {
		path := filepath.Join(base, currentVersion, entry.Name())
		info, statErr := os.Stat(filepath.Join(path, sourceCompleteName))
		if statErr != nil {
			// An interrupted extraction is resumable but never authoritative,
			// so it is only discarded once it is older than the retention
			// window rather than while another process may still be writing.
			if dirInfo, dirErr := entry.Info(); dirErr == nil && dirInfo.ModTime().Before(deadline) {
				_ = os.RemoveAll(path)
			}
			continue
		}
		if info.ModTime().Before(deadline) {
			_ = os.RemoveAll(path)
		}
	}
}

func archiveMirrorName(archivePath string) (string, bool) {
	info, err := os.Stat(archivePath)
	if err != nil {
		return "", false
	}
	key := strings.Join([]string{archivePath, info.ModTime().UTC().Format(time.RFC3339Nano), itoa64(info.Size())}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return sanitizeMirrorBase(filepath.Base(archivePath)) + "-" + hex.EncodeToString(sum[:6]), true
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
	name := strings.TrimPrefix(filepath.ToSlash(entry), "/")
	if binary && strings.HasSuffix(name, ".class") {
		name = strings.TrimSuffix(name, ".class") + ".java"
	}
	return name
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
	rootOnce  sync.Once
	rootDir   string
	mu        sync.Mutex
	dirs      map[string]string
	extracted map[string]bool
	origins   map[string]*archiveOrigin
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
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}
		cleanupObsoleteSourceMirrors(base, version)
		m.rootDir = dir
	})
	return m.rootDir
}

func (m *librarySourceMirror) dir(archivePath string) (string, bool) {
	root := m.root()
	if root == "" || archivePath == "" {
		return "", false
	}
	m.mu.Lock()
	if dir, ok := m.dirs[archivePath]; ok {
		m.mu.Unlock()
		return dir, dir != ""
	}
	m.mu.Unlock()
	name, ok := archiveMirrorName(archivePath)
	dir := ""
	if ok {
		dir = filepath.Join(root, name)
	}
	m.mu.Lock()
	if m.dirs == nil {
		m.dirs = make(map[string]string)
	}
	m.dirs[archivePath] = dir
	m.mu.Unlock()
	return dir, dir != ""
}

// complete reports whether the whole archive has already been mirrored. Only a
// positive answer is cached: a mirror that is still being written must be
// re-checked, while a finished one must never cost a syscall again.
func (m *librarySourceMirror) complete(dir string) bool {
	m.mu.Lock()
	done := m.extracted[dir]
	m.mu.Unlock()
	if done {
		return true
	}
	marker := filepath.Join(dir, sourceCompleteName)
	if _, err := os.Stat(marker); err != nil {
		return false
	}
	// Touching the marker keeps an archive that is still in use outside the
	// retention sweep even when its mirror was written long ago.
	now := time.Now()
	_ = os.Chtimes(marker, now, now)
	m.markComplete(dir)
	return true
}

func (m *librarySourceMirror) markComplete(dir string) {
	m.mu.Lock()
	if m.extracted == nil {
		m.extracted = make(map[string]bool)
	}
	m.extracted[dir] = true
	m.mu.Unlock()
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
	if data, err := os.ReadFile(filepath.Join(dir, sourceOriginName)); err == nil {
		loaded = json.Unmarshal(data, &origin) == nil
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
	if _, ok := m.origin(dir); ok {
		return
	}
	encoded, err := json.Marshal(origin)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, sourceOriginName), encoded, 0o600); err != nil {
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
	if !isArchiveURI(uri) {
		return "", false
	}
	i.mu.RLock()
	source, known := i.librarySources[uri]
	i.mu.RUnlock()
	if !known || source.Archive == "" || source.Entry == "" {
		return "", false
	}
	dir, ok := i.sourceMirror.dir(source.Archive)
	if !ok {
		return "", false
	}
	path := filepath.Join(dir, filepath.FromSlash(mirrorEntryName(source.Entry, source.Binary)))
	if !i.sourceMirror.complete(dir) {
		i.sourceMirror.ensureOrigin(dir, originForURI(uri, source))
		if _, err := os.Stat(path); err != nil {
			document, found := i.Document(uri)
			if !found {
				return "", false
			}
			if writeMirroredFile(path, document.Text) != nil {
				return "", false
			}
		}
	}
	return uriutil.File(path), true
}

// LibraryURIForFile maps a mirrored file:// URI back onto the jar://jrt:// URI
// the index is keyed by. It reads the mirror's own metadata rather than live
// index state so buffers left open across a server restart keep working.
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

func writeMirroredFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".kotlsp-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if _, err := io.WriteString(temp, content); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	// Library sources are navigation targets, never edit targets. A read-only
	// mode keeps an accidental editor write from diverging the mirror from the
	// archive it represents.
	if err := os.Chmod(name, 0o444); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// archiveMirror writes one archive's mirror during background indexing, where
// the rendered content of every entry is already in hand.
type archiveMirror struct {
	index *Index
	dir   string
	dirs  map[string]bool
}

// newArchiveMirror returns nil when the archive needs no mirroring: either it
// is already complete, or the pass is a partial one whose coverage must never
// be recorded as authoritative.
func (i *Index) newArchiveMirror(archive sourceArchive) *archiveMirror {
	if archive.noCache || len(archive.onlyTargets) > 0 {
		return nil
	}
	dir, ok := i.sourceMirror.dir(archive.path)
	if !ok || i.sourceMirror.complete(dir) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	origin, err := json.Marshal(archiveOrigin{Archive: archive.path, JDK: archive.jdk, Module: archive.module, Binary: archive.binary})
	if err != nil {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, sourceOriginName), origin, 0o600); err != nil {
		return nil
	}
	return &archiveMirror{index: i, dir: dir, dirs: make(map[string]bool)}
}

func (m *archiveMirror) write(entry, content string, binary bool) {
	if m == nil {
		return
	}
	path := filepath.Join(m.dir, filepath.FromSlash(mirrorEntryName(entry, binary)))
	if dir := filepath.Dir(path); !m.dirs[dir] {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}
		m.dirs[dir] = true
	}
	_ = writeMirroredFile(path, content)
}

func (m *archiveMirror) finish() {
	if m == nil {
		return
	}
	if err := os.WriteFile(filepath.Join(m.dir, sourceCompleteName), nil, 0o600); err != nil {
		return
	}
	m.index.sourceMirror.markComplete(m.dir)
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
	for _, file := range selectedArchiveFiles(archive, reader.File) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !archiveAccepts(archive, file) {
			continue
		}
		entry, openErr := file.Open()
		if openErr != nil {
			continue
		}
		data, readErr := io.ReadAll(entry)
		_ = entry.Close()
		if readErr != nil {
			continue
		}
		content := string(data)
		if archive.binary {
			parsed, parseErr := classfile.Parse(data)
			if parseErr != nil {
				continue
			}
			content = classfile.RenderJava(parsed)
		}
		mirror.write(file.Name, content, archive.binary)
	}
	mirror.finish()
}
