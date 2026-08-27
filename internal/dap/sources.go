package dap

// Library source serving for stack frames whose classes live in dependency
// jars. pathForSource only finds files that sit on disk under a source root,
// so without this store every framework frame would surface to the client as
// a bare name with no way to view it. The store maps such frames to DAP
// source references backed by the -sources.jar that Gradle or Maven placed
// next to the binary jar in the dependency cache, and the source request
// handler streams the matching entry out of that jar.

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type jarSourceRef struct {
	jarPath string
	entry   string
	origin  string
}

type sourceStore struct {
	mu        sync.Mutex
	next      int
	refs      map[int]jarSourceRef
	classJars map[string]string // class entry path -> binary jar that contains it ("" = known absent)
}

func newSourceStore() *sourceStore {
	return &sourceStore{next: 1, refs: make(map[int]jarSourceRef), classJars: make(map[string]string)}
}

// reset drops every cached lookup: the classpath changes between launches on
// the same connection, and stale jar associations would outlive it.
func (store *sourceStore) reset() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.next = 1
	store.refs = make(map[int]jarSourceRef)
	store.classJars = make(map[string]string)
}

// referenceFor resolves a jdb frame to a DAP source reference backed by a
// sources jar. frameName is the method FQN jdb prints in `where` output,
// sourceName the file name reported for the frame. It returns 0 when the
// class cannot be found in any classpath jar or no sources jar is available.
func (store *sourceStore) referenceFor(classPaths []string, frameName, sourceName string) (int, string) {
	className := frameClassName(frameName)
	if className == "" || sourceName == "" {
		return 0, ""
	}
	classEntry := strings.ReplaceAll(className, ".", "/") + ".class"
	packageDir := ""
	if slash := strings.LastIndexByte(classEntry, '/'); slash >= 0 {
		packageDir = classEntry[:slash]
	}
	sourceEntry := sourceName
	if packageDir != "" {
		sourceEntry = packageDir + "/" + sourceName
	}

	binaryJar := store.locateClass(classPaths, classEntry)
	if binaryJar == "" {
		return 0, ""
	}
	sourcesJar := findSourcesJar(binaryJar)
	if sourcesJar == "" || !zipHasEntry(sourcesJar, sourceEntry) {
		return 0, ""
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	id := store.next
	store.next++
	origin := filepath.Base(sourcesJar)
	store.refs[id] = jarSourceRef{jarPath: sourcesJar, entry: sourceEntry, origin: origin}
	return id, origin
}

// contentFor streams the source text registered under id.
func (store *sourceStore) contentFor(id int) (string, bool) {
	store.mu.Lock()
	ref, ok := store.refs[id]
	store.mu.Unlock()
	if !ok {
		return "", false
	}
	reader, err := zip.OpenReader(ref.jarPath)
	if err != nil {
		return "", false
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Name != ref.entry {
			continue
		}
		contents, err := file.Open()
		if err != nil {
			return "", false
		}
		defer contents.Close()
		data, err := io.ReadAll(contents)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
	return "", false
}

// frameClassName extracts the top-level class FQN from a jdb frame name:
// drops the trailing method segment and any nested/lambda suffix.
func frameClassName(frameName string) string {
	className := frameName
	if dot := strings.LastIndexByte(className, '.'); dot >= 0 {
		className = className[:dot]
	}
	if dollar := strings.IndexByte(className, '$'); dollar >= 0 {
		className = className[:dollar]
	}
	return className
}

// locateClass finds the first classpath jar containing the class entry,
// caching both hits and misses so a hot path through framework frames does
// not rescan the whole classpath per stack trace.
func (store *sourceStore) locateClass(classPaths []string, classEntry string) string {
	store.mu.Lock()
	if jar, searched := store.classJars[classEntry]; searched {
		store.mu.Unlock()
		return jar
	}
	store.mu.Unlock()

	found := ""
	for _, path := range classPaths {
		if !strings.HasSuffix(path, ".jar") {
			continue
		}
		if zipHasEntry(path, classEntry) {
			found = path
			break
		}
	}
	store.mu.Lock()
	store.classJars[classEntry] = found
	store.mu.Unlock()
	return found
}

// findSourcesJar locates the sources companion of a binary jar. Maven keeps
// it beside the binary; the Gradle cache hashes each artifact into its own
// directory, so the sources jar sits in a sibling hash directory of the same
// artifact version.
func findSourcesJar(binaryJar string) string {
	base := strings.TrimSuffix(filepath.Base(binaryJar), ".jar")
	sibling := filepath.Join(filepath.Dir(binaryJar), base+"-sources.jar")
	if fileExists(sibling) {
		return sibling
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(binaryJar)), "*", base+"-sources.jar"))
	if err == nil {
		for _, match := range matches {
			if fileExists(match) {
				return match
			}
		}
	}
	return ""
}

func zipHasEntry(jarPath, entry string) bool {
	reader, err := zip.OpenReader(jarPath)
	if err != nil {
		return false
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Name == entry {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
