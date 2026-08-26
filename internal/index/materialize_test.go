package index

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// compileTestClass produces real class bytes, since the mirror stores whatever
// the class-file renderer produced for the index.
func compileTestClass(t *testing.T, pkg, name, source string) string {
	t.Helper()
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, name+".java")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, compileErr := exec.Command(javac, "-parameters", "-d", dir, sourcePath).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, pkg, name+".class"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeTestArchive(t *testing.T, name string, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for entryName, content := range entries {
		entry, createErr := writer.Create(entryName)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write([]byte(content)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// A jar:// target is meaningless to an editor: it opens an empty buffer and
// then fails to place the cursor. Navigation must name a file that exists on
// disk with exactly the content the index positions were computed against.
func TestLibraryDefinitionTargetsAnExistingFileWithIndexedContent(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	source := "package demo;\npublic class Service {\n    public String run() {\n        return \"ok\";\n    }\n}\n"
	archive := writeTestArchive(t, "library-sources.jar", map[string]string{"demo/Service.java": source})
	idx := New(nil)
	defer idx.Close()
	idx.indexSourceArchive(context.Background(), sourceArchive{path: archive}, idx.generation.Load(), func(int64) {})

	libraryURI := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/demo/Service.java")
	if _, ok := idx.Document(libraryURI); !ok {
		t.Fatalf("archive entry was not indexed under %s", libraryURI)
	}
	mirrored, ok := idx.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatalf("library URI %s produced no mirrored file", libraryURI)
	}
	if !strings.HasPrefix(string(mirrored), "file://") {
		t.Fatalf("mirrored URI must use a scheme the editor can open, got %s", mirrored)
	}
	path, ok := uriutil.Path(mirrored)
	if !ok {
		t.Fatalf("mirrored URI is not a file path: %s", mirrored)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mirrored file is not readable: %v", err)
	}
	if string(content) != source {
		t.Fatalf("mirrored content diverged from the indexed document:\n%q\n%q", string(content), source)
	}
	back, ok := idx.LibraryURIForFile(mirrored)
	if !ok || back != libraryURI {
		t.Fatalf("mirrored path did not map back to the index URI: %q %v", back, ok)
	}
}

// Class files carry no source, so the mirror stores the rendered Java stub the
// index parsed. The rendered name must round-trip back to the .class entry.
func TestBinaryLibraryMirrorsRenderedStubAndRoundTrips(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	class := compileTestClass(t, "fixtures", "Sample", "package fixtures;\npublic class Sample {\n    public String run(String input) { return input; }\n}\n")
	archive := writeTestArchive(t, "library.jar", map[string]string{"fixtures/Sample.class": class})
	idx := New(nil)
	defer idx.Close()
	idx.indexSourceArchive(context.Background(), sourceArchive{path: archive, binary: true}, idx.generation.Load(), func(int64) {})

	libraryURI := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/fixtures/Sample.class")
	document, ok := idx.Document(libraryURI)
	if !ok {
		t.Fatalf("class entry was not indexed under %s", libraryURI)
	}
	mirrored, ok := idx.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatalf("binary library URI produced no mirrored file")
	}
	path, _ := uriutil.Path(mirrored)
	if filepath.Ext(path) != ".java" {
		t.Fatalf("rendered stub must be mirrored as Java so the editor sets a usable file type, got %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mirrored stub is not readable: %v", err)
	}
	if string(content) != document.Text {
		t.Fatalf("mirrored stub diverged from the parsed document")
	}
	back, ok := idx.LibraryURIForFile(mirrored)
	if !ok || back != libraryURI {
		t.Fatalf("rendered stub did not map back to the class entry: %q %v", back, ok)
	}
}

// A cached parse skips the indexing loop entirely. The mirror must still exist,
// or navigation would break on every run after the first.
func TestMirrorIsRebuiltWhenTheParseComesFromCache(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	source := "package demo;\npublic class Cached {}\n"
	archive := writeTestArchive(t, "cached-sources.jar", map[string]string{"demo/Cached.java": source})
	libraryURI := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/demo/Cached.java")

	first := New(nil)
	first.indexSourceArchive(context.Background(), sourceArchive{path: archive}, first.generation.Load(), func(int64) {})
	mirrored, ok := first.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatal("first pass produced no mirrored file")
	}
	first.Close()

	path, _ := uriutil.Path(mirrored)
	if err := os.RemoveAll(filepath.Dir(filepath.Dir(path))); err != nil {
		t.Fatal(err)
	}

	second := New(nil)
	defer second.Close()
	second.indexSourceArchive(context.Background(), sourceArchive{path: archive}, second.generation.Load(), func(int64) {})
	rebuilt, ok := second.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatal("cached pass produced no mirrored file")
	}
	rebuiltPath, _ := uriutil.Path(rebuilt)
	content, err := os.ReadFile(rebuiltPath)
	if err != nil {
		t.Fatalf("mirror was not rebuilt after the snapshot cache took over: %v", err)
	}
	if string(content) != source {
		t.Fatalf("rebuilt mirror content = %q", string(content))
	}
}

func TestMirroredPathsOutsideTheCacheAreNotRewritten(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	idx := New(nil)
	defer idx.Close()
	if _, ok := idx.LibraryURIForFile(uriutil.File(filepath.Join(t.TempDir(), "Main.kt"))); ok {
		t.Fatal("a workspace file must never be treated as a library mirror")
	}
	uri := protocol.URI("jar:///cache/library-sources.jar!/demo/Service.java")
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, "java", 0, "package demo; class Service {}"))
	idx.AddLibraryBatch([]LibraryFile{{Source: LibrarySource{Archive: "/cache/library-sources.jar", Entry: "demo/Service.java", LanguageID: "java"}, Parsed: *parsed}})
	if _, ok := idx.LibraryFileURI(uri); ok {
		t.Fatal("an archive that does not exist on disk must not yield a mirrored path")
	}
}
