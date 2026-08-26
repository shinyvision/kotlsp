package index

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Navigation from inside a library file must reach the declaration whether the
// name arrives through an import or through the file's own package. Library
// files are indexed without a reference table, so this only works if the table
// is rebuilt on demand.
func TestDefinitionInsideLibraryFileResolvesReferences(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	requestMapping := "package demo.ann;\n\npublic @interface RequestMapping {\n\tString name() default \"\";\n}\n"
	aliasFor := "package demo.core;\n\npublic @interface AliasFor {\n\tClass<?> annotation();\n}\n"
	getMapping := "package demo.ann;\n\nimport demo.core.AliasFor;\n\n@RequestMapping(method = 1)\npublic @interface GetMapping {\n\t@AliasFor(annotation = RequestMapping.class)\n\tString name() default \"\";\n}\n"
	archive := writeTestArchive(t, "demo-sources.jar", map[string]string{
		"demo/ann/RequestMapping.java": requestMapping,
		"demo/core/AliasFor.java":      aliasFor,
		"demo/ann/GetMapping.java":     getMapping,
	})
	idx := New(nil)
	defer idx.Close()
	idx.indexSourceArchive(context.Background(), sourceArchive{path: archive}, idx.generation.Load(), func(int64) {})

	uri := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/demo/ann/GetMapping.java")
	document, ok := idx.Document(uri)
	if !ok {
		t.Fatal("library entry was not indexed")
	}
	for _, probe := range []struct{ label, needle, want string }{
		{"same-package annotation", "@RequestMapping(method", "demo/ann/RequestMapping.java"},
		{"same-package class literal", "RequestMapping.class", "demo/ann/RequestMapping.java"},
		{"imported annotation", "@AliasFor(annotation", "demo/core/AliasFor.java"},
	} {
		at := strings.Index(getMapping, probe.needle)
		if at < 0 {
			t.Fatalf("%s: fixture does not contain %q", probe.label, probe.needle)
		}
		if strings.HasPrefix(probe.needle, "@") {
			at++
		}
		found := idx.Definitions(uri, document.Position(at+2))
		if len(found) == 0 {
			t.Fatalf("%s: go-to-definition inside a library file found nothing", probe.label)
		}
		if !strings.HasSuffix(string(found[0].Location().URI), probe.want) {
			t.Fatalf("%s: resolved to %s, want %s", probe.label, found[0].Location().URI, probe.want)
		}
	}
}

// The rebuilt tables are a bounded working set, not a second index.
func TestLibraryReferenceWorkingSetIsBounded(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	entries := make(map[string]string, libraryReferenceWorkingSet+4)
	names := make([]string, 0, libraryReferenceWorkingSet+4)
	for n := 0; n < libraryReferenceWorkingSet+4; n++ {
		name := "demo/Type" + string(rune('A'+n%26)) + string(rune('a'+n/26)) + ".java"
		entries[name] = "package demo;\n\npublic class Type" + string(rune('A'+n%26)) + string(rune('a'+n/26)) + " {\n\tString value = Shared.NAME;\n}\n"
		names = append(names, name)
	}
	entries["demo/Shared.java"] = "package demo;\n\npublic class Shared {\n\tpublic static final String NAME = \"x\";\n}\n"
	archive := writeTestArchive(t, "bounded-sources.jar", entries)
	idx := New(nil)
	defer idx.Close()
	idx.indexSourceArchive(context.Background(), sourceArchive{path: archive}, idx.generation.Load(), func(int64) {})

	for _, name := range names {
		uri := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/" + name)
		document, ok := idx.Document(uri)
		if !ok {
			t.Fatalf("%s was not indexed", name)
		}
		idx.ensureLibraryReferences(uri, document)
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	loaded := 0
	for _, name := range names {
		if file := idx.files[protocol.URI("jar://"+filepath.ToSlash(archive)+"!/"+name)]; file != nil && len(file.References) > 0 {
			loaded++
		}
	}
	if loaded > libraryReferenceWorkingSet {
		t.Fatalf("%d library files retained reference tables, cap is %d", loaded, libraryReferenceWorkingSet)
	}
	if len(idx.libraryReferenceOrder) > libraryReferenceWorkingSet {
		t.Fatalf("working set tracker grew to %d", len(idx.libraryReferenceOrder))
	}
}
