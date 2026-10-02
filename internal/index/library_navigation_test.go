package index

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// Navigation into compiled libraries with no sources attached: a member
// declared on the type itself, one inherited from a Java supertype, and one
// inherited through a generic supertype (`CrudRepository<User, Long>.save`).
// The jars are built here, so the test needs nothing from the machine but a
// JDK.
func TestDefinitionsResolveIntoBinaryOnlyLibraries(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	classes := compileTestClasses(t, map[string]string{
		"validation/Errors":        "package validation; public interface Errors { boolean hasErrors(); }",
		"validation/BindingResult": "package validation; public interface BindingResult extends Errors { Object getTarget(); }",
		"data/Repository":          "package data; public interface Repository<T, ID> {}",
		"data/CrudRepository":      "package data; public interface CrudRepository<T, ID> extends Repository<T, ID> { <S extends T> S save(S entity); }",
		"data/ListCrudRepository":  "package data; public interface ListCrudRepository<T, ID> extends CrudRepository<T, ID> {}",
	})
	jar := func(name, pkg string) string {
		entries := map[string]string{}
		for path, class := range classes {
			if strings.HasPrefix(path, pkg+"/") {
				entries[path] = class
			}
		}
		return writeTestArchive(t, name, entries)
	}
	validation, data := jar("validation.jar", "validation"), jar("data.jar", "data")
	root, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolution := newClasspathResolution()
	resolution.SourceSetClasspath[":"] = map[string][]string{"main": {validation, data}}

	previousSkip, previousFilter := skipLibraryScan, libraryArchiveFilter
	skipLibraryScan = false
	libraryArchiveFilter = func(candidate sourceArchive) bool {
		path := filepath.Clean(candidate.path)
		return path == filepath.Clean(validation) || path == filepath.Clean(data)
	}
	t.Cleanup(func() { skipLibraryScan, libraryArchiveFilter = previousSkip, previousFilter })

	idx := New(nil)
	defer idx.Close()
	uri := uriutil.File(filepath.Join(root, "src", "main", "kotlin", "Probe.kt"))
	source := `package probe
import validation.BindingResult
import data.ListCrudRepository
class User
fun probe(bindingResult: BindingResult, users: ListCrudRepository<User, Long>, user: User) {
    bindingResult.getTarget()
    bindingResult.hasErrors()
    users.save(user)
}
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.scanLibraries(context.Background(), []string{root}, idx.generation.Load(), nil, map[string]classpathResolution{filepath.Clean(root): resolution})
	document, ok := idx.Document(uri)
	if !ok {
		t.Fatal("probe document was not indexed")
	}
	for name, want := range map[string]string{
		"getTarget": "validation.BindingResult.getTarget",
		"hasErrors": "validation.Errors.hasErrors",
		"save":      "data.CrudRepository.save",
	} {
		definitions := idx.DefinitionsContext(context.Background(), uri, document.Position(strings.LastIndex(source, name)+1))
		if len(definitions) != 1 || definitions[0].FQN != want {
			t.Errorf("%s: definitions = %v, want %s", name, definitions, want)
		}
	}
}

// compileTestClasses compiles Java sources keyed by class path
// (`pkg/Name`) together, so they may refer to each other, and returns each
// class file's bytes under `pkg/Name.class`.
func compileTestClasses(t *testing.T, sources map[string]string) map[string]string {
	t.Helper()
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	arguments := []string{"-parameters", "-d", filepath.Join(dir, "out")}
	for path, source := range sources {
		file := filepath.Join(dir, "src", filepath.FromSlash(path)+".java")
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, file)
	}
	if output, err := exec.Command(javac, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	classes := make(map[string]string, len(sources))
	for path := range sources {
		data, err := os.ReadFile(filepath.Join(dir, "out", filepath.FromSlash(path)+".class"))
		if err != nil {
			t.Fatal(err)
		}
		classes[path+".class"] = string(data)
	}
	return classes
}
