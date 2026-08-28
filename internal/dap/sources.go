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
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/archiveio"
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
	refIDs    map[string]int
	classJars map[string]string // class entry path -> binary jar that contains it ("" = known absent)
}

const (
	maxSourceClasspathArchives = 512
	maxSourceArchiveEntries    = 250000
	maxSourceJarSiblings       = 512
	maxSourceReferences        = 8192
	maxSourceClassCache        = 4096
	maxSourceClasspathRoots    = 4096
)

func newSourceStore() *sourceStore {
	return &sourceStore{next: 1, refs: make(map[int]jarSourceRef), refIDs: make(map[string]int), classJars: make(map[string]string)}
}

// reset drops every cached lookup: the classpath changes between launches on
// the same connection, and stale jar associations would outlive it.
func (store *sourceStore) reset() {
	store.mu.Lock()
	defer store.mu.Unlock()
	// IDs remain monotonic for the connection. A delayed source request from a
	// prior launch must fail, never alias a different source in the new launch.
	store.refs = make(map[int]jarSourceRef)
	store.refIDs = make(map[string]int)
	store.classJars = make(map[string]string)
}

// referenceFor resolves a JDI frame to a DAP source reference backed by a
// sources jar. frameName is the declaring-type and method identity,
// sourceName the file name reported for the frame. It returns 0 when the
// class cannot be found in any classpath jar or no sources jar is available.
func (store *sourceStore) referenceFor(classPaths []string, frameName, sourceName string, contexts ...context.Context) (int, string) {
	ctx := requestContext(contexts)
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

	binaryJar := store.locateClass(classPaths, classEntry, ctx)
	if binaryJar == "" {
		return 0, ""
	}
	sourcesJar := findSourcesJar(binaryJar, ctx)
	if sourcesJar == "" || !zipHasEntry(sourcesJar, sourceEntry, ctx) {
		return 0, ""
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	key := sourcesJar + "\x00" + sourceEntry
	if id := store.refIDs[key]; id != 0 {
		return id, filepath.Base(sourcesJar)
	}
	if len(store.refs) >= maxSourceReferences {
		return 0, ""
	}
	id := store.next
	store.next++
	origin := filepath.Base(sourcesJar)
	store.refs[id] = jarSourceRef{jarPath: sourcesJar, entry: sourceEntry, origin: origin}
	store.refIDs[key] = id
	return id, origin
}

// contentFor streams the source text registered under id.
func (store *sourceStore) contentFor(id int, contexts ...context.Context) (string, bool) {
	ctx := requestContext(contexts)
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
	budget, budgetErr := archiveio.NewBudget(reader.File)
	if budgetErr != nil {
		return "", false
	}
	if len(reader.File) > maxSourceArchiveEntries {
		return "", false
	}
	for index, file := range reader.File {
		if index&255 == 0 && ctx.Err() != nil {
			return "", false
		}
		if file.Name != ref.entry {
			continue
		}
		data, err := budget.ReadContext(ctx, file, 16<<20)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
	return "", false
}

// frameClassName extracts the top-level class FQN from a JDI frame name:
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
func (store *sourceStore) locateClass(classPaths []string, classEntry string, contexts ...context.Context) string {
	ctx := requestContext(contexts)
	store.mu.Lock()
	if jar, searched := store.classJars[classEntry]; searched {
		store.mu.Unlock()
		return jar
	}
	store.mu.Unlock()

	found := ""
	archives := 0
	complete := true
	if len(classPaths) > maxSourceClasspathRoots {
		classPaths = classPaths[:maxSourceClasspathRoots]
		complete = false
	}
	for _, path := range classPaths {
		if ctx.Err() != nil {
			complete = false
			break
		}
		if !strings.HasSuffix(path, ".jar") {
			continue
		}
		archives++
		if archives > maxSourceClasspathArchives {
			complete = false
			break
		}
		if zipHasEntry(path, classEntry, ctx) {
			found = path
			break
		}
	}
	store.mu.Lock()
	if found != "" || complete {
		if len(store.classJars) >= maxSourceClassCache {
			store.classJars = make(map[string]string)
		}
		store.classJars[classEntry] = found
	}
	store.mu.Unlock()
	return found
}

// findSourcesJar locates the sources companion of a binary jar. Maven keeps
// it beside the binary; the Gradle cache hashes each artifact into its own
// directory, so the sources jar sits in a sibling hash directory of the same
// artifact version.
func findSourcesJar(binaryJar string, contexts ...context.Context) string {
	ctx := requestContext(contexts)
	base := strings.TrimSuffix(filepath.Base(binaryJar), ".jar")
	sibling := filepath.Join(filepath.Dir(binaryJar), base+"-sources.jar")
	if fileExists(sibling) {
		return sibling
	}
	parent := filepath.Dir(filepath.Dir(binaryJar))
	directory, err := os.Open(parent)
	if err != nil {
		return ""
	}
	defer directory.Close()
	visited := 0
	for {
		if ctx.Err() != nil {
			return ""
		}
		entries, readErr := directory.ReadDir(64)
		for _, entry := range entries {
			visited++
			if visited > maxSourceJarSiblings {
				return ""
			}
			if !entry.IsDir() {
				continue
			}
			match := filepath.Join(parent, entry.Name(), base+"-sources.jar")
			if fileExists(match) {
				return match
			}
		}
		if readErr != nil {
			return ""
		}
	}
}

func zipHasEntry(jarPath, entry string, contexts ...context.Context) bool {
	ctx := requestContext(contexts)
	reader, err := zip.OpenReader(jarPath)
	if err != nil {
		return false
	}
	defer reader.Close()
	if archiveio.ValidateZipFiles(reader.File) != nil {
		return false
	}
	if len(reader.File) > maxSourceArchiveEntries {
		return false
	}
	for index, file := range reader.File {
		if index&255 == 0 && ctx.Err() != nil {
			return false
		}
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
