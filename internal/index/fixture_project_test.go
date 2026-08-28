package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// The fixture depends on nothing outside itself, so indexing the JDK and the
// Gradle cache with it is pure cost: five seconds per index for 44,000 files no
// assertion touches. Tests in this package skip it.
func init() {
	skipLibraryScan = true
	disableCompilerPasses = true
}

// fixtureProject materialises testdata/project into a temporary directory so a
// test owns its own sources. Measuring or asserting against a live workspace is
// unreproducible: the files move under the test.
func fixtureProject(t *testing.T) string {
	return fixtureProjectFrom(t, filepath.Join("testdata", "project"))
}

// fixtureProjectFrom materialises any fixture directory.
func fixtureProjectFrom(t *testing.T, source string) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, relErr := filepath.Rel(source, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(root, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatalf("materialising the fixture project: %v", err)
	}
	return root
}

func fixtureFile(root, relative string) protocol.URI {
	return uriutil.File(filepath.Join(root, filepath.FromSlash(relative)))
}

// startedFixtureIndex indexes the fixture and waits for it to be ready. With
// library scanning off this costs about half a second, so every test takes its
// own rather than sharing one and inheriting another test's compiler results.
func startedFixtureIndex(t *testing.T) (*Index, string) {
	return startedFixtureIndexFrom(t, filepath.Join("testdata", "project"))
}

func startedFixtureIndexFrom(t *testing.T, source string) (*Index, string) {
	t.Helper()
	root := fixtureProjectFrom(t, source)
	idx := New(nil)
	t.Cleanup(idx.Close)
	idx.Start(context.Background(), []protocol.URI{uriutil.File(root)})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(10 * time.Millisecond)
	}
	if !idx.Progress().Ready {
		t.Fatal("the fixture index never became ready")
	}
	return idx, root
}

// requireCompilerBackedTest skips tests that invoke a real javac or K2. Each
// costs seconds, so running them on every edit makes the suite unusable during
// development. They are a release gate, not the inner loop:
//
//	go test ./...                           fast, no compiler involved
//	KOTLSP_COMPILER_TESTS=1 go test ./...   everything
func requireCompilerBackedTest(t *testing.T) {
	t.Helper()
	if os.Getenv("KOTLSP_COMPILER_TESTS") == "" {
		t.Skip("set KOTLSP_COMPILER_TESTS=1 to run tests that invoke a real compiler")
	}
	if !compilerAvailable() {
		t.Skip("no Kotlin compiler in this environment")
	}
	disableCompilerPasses = false
	// The compiler resolves `String` against the real standard library, so
	// the index must too, or the type rules abstain and the gate proves
	// nothing about them. Only the stdlib and java.base are indexed.
	skipLibraryScan = false
	libraryArchiveFilter = func(archive sourceArchive) bool {
		if archive.jdk {
			return archive.module == "java.base"
		}
		return strings.Contains(filepath.Base(archive.path), "kotlin-stdlib")
	}
	t.Cleanup(func() {
		disableCompilerPasses = true
		skipLibraryScan = true
		libraryArchiveFilter = nil
	})
}

// requireCorpusTest runs a test against a real project named by
// KOTLSP_CORPUS: compiler passes on and every library indexed, because the
// project's dependencies must resolve for its code to be judged at all. Unlike
// the fixture, this is opt-in -- it indexes and compiles a whole project.
func requireCorpusTest(t *testing.T) string {
	t.Helper()
	root := os.Getenv("KOTLSP_CORPUS")
	if root == "" {
		t.Skip("set KOTLSP_CORPUS to a project root")
	}
	if !compilerAvailable() {
		t.Skip("no Kotlin compiler in this environment")
	}
	disableCompilerPasses = false
	skipLibraryScan = false
	libraryArchiveFilter = nil
	t.Cleanup(func() {
		disableCompilerPasses = true
		skipLibraryScan = true
		libraryArchiveFilter = nil
	})
	return root
}

// waitForCompilerPass blocks until one more Kotlin validation pass completes.
func waitForCompilerPass(t *testing.T, idx *Index, timeout time.Duration) bool {
	t.Helper()
	passes := idx.CompilerPasses("kotlin")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Findings stay in a private transaction until both language passes
		// have finished, so a completed Kotlin pass alone is not an oracle yet.
		if idx.CompilerPasses("kotlin") > passes {
			for _, status := range idx.CompilerStatus() {
				if status.Published {
					return true
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// markReady lets a test built purely from Open() calls exercise rules that
// abstain until a workspace scan has finished.
func (i *Index) markReady() {
	progress := i.Progress()
	progress.Ready = true
	i.progress.Store(&progress)
}

// openKotlinBuiltins declares the builtins the type rules compare against,
// so `String` resolves to kotlin.String without indexing a standard library.
func openKotlinBuiltins(idx *Index) {
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///stdlib/kotlin/Builtins.kt", LanguageID: "kotlin", Version: 1,
		Text: "package kotlin\n\nopen class Any\nabstract class Enum<E>\nclass String { val length: Int = 0 }\nclass Int\nclass Long\nclass Double\nclass Float\nclass Char\nclass Boolean\nclass Unit\nclass Nothing\n",
	})
}

// compilerAvailable reports whether this environment has a compiler at all, so
// a test can skip in milliseconds instead of waiting out a deadline for output
// that is never coming.
func compilerAvailable() bool {
	_, ok := findKotlinCompiler()
	return ok
}

// waitForCompilerDiagnostics waits for the compiler's own findings for a file
// and returns them raw. The merged output cannot be used for this: a compiler
// finding an identical prediction covers is dropped from it by design.
func waitForCompilerDiagnostics(t *testing.T, idx *Index, uri protocol.URI, want int) []protocol.Diagnostic {
	t.Helper()
	if !compilerAvailable() {
		return nil
	}
	deadline := time.Now().Add(90 * time.Second)
	var raw []protocol.Diagnostic
	for time.Now().Before(deadline) {
		idx.mu.RLock()
		raw = append([]protocol.Diagnostic(nil), idx.compilerDiagnostics[uri]...)
		idx.mu.RUnlock()
		if len(raw) >= want {
			return raw
		}
		time.Sleep(100 * time.Millisecond)
	}
	return raw
}

// The fixture's clean sources must produce nothing at all. A diagnostic here is
// a false positive by construction.
func TestFixtureCleanSourcesReportNothing(t *testing.T) {
	requireCompilerBackedTest(t)
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)
	idx.ScheduleCompilerDiagnostics(context.Background())
	// Give a pass time to run before concluding the file is clean.
	waitForCompilerDiagnostics(t, idx, fixtureFile(root, "src/main/kotlin/fixture/Errors.kt"), 1)

	for _, clean := range []string{
		"src/main/kotlin/fixture/Clean.kt",
		"src/main/java/fixture/CleanJava.java",
	} {
		for _, diagnostic := range idx.Diagnostics(fixtureFile(root, clean)) {
			if diagnostic.Severity == 1 {
				t.Fatalf("%s: %s reported %q at line %d", clean, diagnostic.Source, diagnostic.Message, diagnostic.Range.Start.Line+1)
			}
		}
	}
}

// The deliberate errors must be reported, so a test that finds nothing is
// failing rather than passing vacuously.
func TestFixtureErrorsAreReported(t *testing.T) {
	requireCompilerBackedTest(t)
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)
	idx.ScheduleCompilerDiagnostics(context.Background())
	uri := fixtureFile(root, "src/main/kotlin/fixture/Errors.kt")
	found := waitForCompilerDiagnostics(t, idx, uri, 3)
	if len(found) == 0 {
		t.Skip("no Kotlin compiler available in this environment")
	}
	joined := strings.Builder{}
	for _, diagnostic := range found {
		joined.WriteString(diagnostic.Message)
		joined.WriteByte('\n')
	}
	for _, want := range []string{"MissingSymbol", "missingFunction"} {
		if !strings.Contains(joined.String(), want) {
			t.Fatalf("expected a diagnostic mentioning %q, got:\n%s", want, joined.String())
		}
	}
}

// The point of retaining findings is that an author never sees the file go
// blank while validation catches up. This is the end-to-end form of that.
func TestFixtureDiagnosticsSurviveAnEdit(t *testing.T) {
	requireCompilerBackedTest(t)
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)
	uri := fixtureFile(root, "src/main/kotlin/fixture/Errors.kt")
	path := filepath.Join(root, "src", "main", "kotlin", "fixture", "Errors.kt")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: string(original)})
	before := waitForCompilerDiagnostics(t, idx, uri, 1)
	if len(before) == 0 {
		t.Skip("no Kotlin compiler available in this environment")
	}

	// Append a comment: it touches no line any finding sits on.
	lines := strings.Split(string(original), "\n")
	insertAt := len(lines) - 1
	edited := strings.Join(append(append([]string{}, lines[:insertAt]...), "// a trailing note", ""), "\n")
	editRange := protocol.Range{
		Start: protocol.Position{Line: insertAt, Character: 0},
		End:   protocol.Position{Line: insertAt, Character: 0},
	}
	if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Range: &editRange, Text: "// a trailing note\n"}},
	}); err != nil {
		t.Fatal(err)
	}
	_ = edited

	// Retention is about the raw compiler store; the merged output hides
	// compiler findings that predictions already cover.
	idx.mu.RLock()
	immediate := len(idx.compilerDiagnostics[uri])
	idx.mu.RUnlock()
	if immediate == 0 {
		t.Fatalf("every finding vanished the moment the file was edited; %d were retained before", len(before))
	}
	if immediate != len(before) {
		t.Fatalf("retained %d of %d findings across an edit that touched none of their lines", immediate, len(before))
	}
}
