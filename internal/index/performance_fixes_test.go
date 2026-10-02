package index

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// moduleForURIReference is the straightforward algorithm moduleForURIInModules
// replaced: clean every root on every call.
func moduleForURIReference(uri protocol.URI, modules []ModuleInfo) (*ModuleInfo, bool) {
	path := strings.TrimPrefix(string(uri), "file://")
	path = filepath.Clean(path)
	best, bestSpecificity, ambiguous := -1, -1, false
	for index := range modules {
		module := &modules[index]
		specificity := -1
		for _, sourceRoot := range module.SourceRoots {
			if clean := filepath.Clean(sourceRoot); pathWithin(path, clean) && len(clean) > specificity {
				specificity = len(clean)
			}
		}
		if clean := filepath.Clean(module.Dir); pathWithin(path, clean) && len(clean) > specificity {
			specificity = len(clean)
		}
		if specificity < 0 {
			continue
		}
		if specificity > bestSpecificity {
			best, bestSpecificity, ambiguous = index, specificity, false
		} else if specificity == bestSpecificity && best != index {
			ambiguous = true
		}
	}
	if best < 0 || ambiguous {
		return nil, false
	}
	return &modules[best], true
}

func TestModuleLocatorAgreesWithTheStraightforwardAlgorithm(t *testing.T) {
	modules := []ModuleInfo{
		{Name: ":a", Dir: "/w/a", SourceRoots: []string{"/w/a/src/main/kotlin", "/w/a/src/test/kotlin/"}},
		{Name: ":a:b", Dir: "/w/a/b", SourceRoots: []string{"/w/a/b/src/main/kotlin"}},
		{Name: ":c", Dir: "/w/c//", SourceRoots: []string{"/w/c/./src"}},
		{Name: ":dup1", Dir: "/w/dup", SourceRoots: []string{"/w/dup/src"}},
		{Name: ":dup2", Dir: "/w/dup", SourceRoots: []string{"/w/dup/src"}},
	}
	for _, path := range []string{
		"/w/a/src/main/kotlin/X.kt", "/w/a/src/test/kotlin/X.kt", "/w/a/b/src/main/kotlin/Y.kt", "/w/a/b/README",
		"/w/a/other/Z.kt", "/w/c/src/Q.kt", "/w/c", "/w/dup/src/D.kt", "/w/elsewhere/E.kt", "/w/ab/F.kt", "/",
	} {
		uri := protocol.URI("file://" + path)
		gotModule, gotOK := moduleForURIInModules(uri, modules)
		wantModule, wantOK := moduleForURIReference(uri, modules)
		if gotOK != wantOK || (gotModule == nil) != (wantModule == nil) || gotModule != nil && gotModule.Name != wantModule.Name {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", path, gotModule, gotOK, wantModule, wantOK)
		}
	}
	// A module list edited in place must never be answered from a stale locator.
	modules[0].Dir = "/w/moved"
	modules[0].SourceRoots = []string{"/w/moved/src"}
	uri := protocol.URI("file:///w/moved/src/X.kt")
	gotModule, gotOK := moduleForURIInModules(uri, modules)
	if !gotOK || gotModule.Name != ":a" {
		t.Errorf("in-place edit not seen: got (%v, %v)", gotModule, gotOK)
	}
}

func TestPathWithinNeedsASeparatorBoundary(t *testing.T) {
	for _, c := range []struct {
		path, dir string
		want      bool
	}{
		{"/w/a/b", "/w/a", true}, {"/w/a", "/w/a", true}, {"/w/ab", "/w/a", false}, {"/w/a/", "/w/a", true}, {"/x", "/w", false},
	} {
		if got := pathWithin(c.path, c.dir); got != c.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", c.path, c.dir, got, c.want)
		}
	}
}

func TestPreferSourceDeclarationsDropsLibraryCopies(t *testing.T) {
	source := analysis.Symbol{ID: "s", FQN: "app.Color", Kind: analysis.KindEnum}
	copy := analysis.Symbol{ID: "l", FQN: "app.Color", Kind: analysis.KindEnum, Library: true}
	other := analysis.Symbol{ID: "o", FQN: "other.Color", Kind: analysis.KindEnum, Library: true}

	if got := uniqueTypeResolution([]analysis.Symbol{copy, source}); len(got) != 1 || got[0].ID != "s" {
		t.Errorf("source declaration plus its library copy should resolve to the source, got %+v", got)
	}
	if got := uniqueTypeResolution([]analysis.Symbol{source, other}); len(got) != 0 {
		t.Errorf("two genuinely different types must stay ambiguous, got %+v", got)
	}
	if got := uniqueTypeResolution([]analysis.Symbol{copy}); len(got) != 1 {
		t.Errorf("a lone library type resolves to itself, got %+v", got)
	}
}

func TestWorkspaceBuildOutputJarIsRecognisedButVendoredJarsAreNot(t *testing.T) {
	for _, c := range []struct {
		jar  string
		want bool
	}{
		{"/w/dtos/models/build/libs/dtos-models.jar", true},
		{"/w/service/target/service-1.0.jar", true},
		{"/w/lib/vendor.jar", false},
		{"/home/u/.gradle/caches/modules-2/files-2.1/g/a/1/a-1.jar", false},
		{"/elsewhere/build/libs/x.jar", false},
	} {
		if got := workspaceBuildOutputJar(c.jar, "/w"); got != c.want {
			t.Errorf("workspaceBuildOutputJar(%q) = %v, want %v", c.jar, got, c.want)
		}
	}
}

func TestBuiltinSourcesArchiveDeclaresTheLanguageBuiltins(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	path, err := builtinSourcesArchive()
	if err != nil {
		t.Fatal(err)
	}
	again, err := builtinSourcesArchive()
	if err != nil || again != path {
		t.Fatalf("the archive must be reused, got %q then %q (%v)", path, again, err)
	}
	if !strings.Contains(filepath.Base(path), "kotlin-stdlib") || !strings.HasSuffix(path, "-sources.jar") {
		t.Fatalf("name %q would not be routed through the stdlib builtin selection", filepath.Base(path))
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var entries []string
	for _, file := range reader.File {
		entries = append(entries, file.Name)
	}
	if selected := kotlinBuiltinSourceSelection(entries); len(selected) != len(entries) {
		t.Fatalf("builtin selection keeps %d of %d entries: %v", len(selected), len(entries), entries)
	}
	declared := map[string]bool{}
	for _, file := range reader.File {
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, file.UncompressedSize64)
		n, _ := stream.Read(data)
		stream.Close()
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(protocol.URI("file:///b/"+file.Name), "kotlin", 0, string(data[:n])))
		for _, symbol := range parsed.Symbols {
			if analysis.IsTypeKind(symbol.Kind) && symbol.FQN != "" {
				declared[symbol.FQN] = true
			}
		}
	}
	for _, want := range []string{
		"kotlin.Any", "kotlin.Enum", "kotlin.String", "kotlin.Int", "kotlin.Long", "kotlin.Double", "kotlin.Boolean", "kotlin.Char",
		"kotlin.Array", "kotlin.IntArray", "kotlin.CharSequence", "kotlin.Comparable", "kotlin.Number", "kotlin.Unit",
		"kotlin.collections.List", "kotlin.collections.MutableList", "kotlin.collections.Set", "kotlin.collections.Map",
		"kotlin.collections.Iterable", "kotlin.collections.Collection", "kotlin.collections.Iterator",
	} {
		if !declared[want] {
			t.Errorf("builtin declarations do not declare %s", want)
		}
	}
}

func TestReferencesAreRememberedAndForgottenWhenTheirFileOrDeclarationsChange(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	open := func(uri, text string, version int) {
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI(uri), LanguageID: "kotlin", Version: version, Text: text})
	}
	open("file:///w/Color.kt", "package app\nenum class Color { RED }\n", 1)
	open("file:///w/Use.kt", "package app\nfun use(c: Color) = Color.RED\n", 1)

	position := protocol.Position{Line: 1, Character: len("fun use(c: ")}
	first := idx.ReferencesContext(context.Background(), "file:///w/Use.kt", position, false)
	if len(first) == 0 {
		t.Fatal("no references to Color")
	}
	idx.mu.RLock()
	remembered := len(idx.late.byKey)
	idx.mu.RUnlock()
	if remembered == 0 {
		t.Fatal("the references resolved by the request were not remembered")
	}
	if again := idx.ReferencesContext(context.Background(), "file:///w/Use.kt", position, false); len(again) != len(first) {
		t.Fatalf("a repeated request changed its answer: %d then %d", len(first), len(again))
	}

	// A new declaration that could capture the name must not be answered from memory.
	before := idx.late.declarations.Load()
	open("file:///w/Other.kt", "package app\nclass Extra\n", 1)
	if idx.late.declarations.Load() == before {
		t.Fatal("adding a declaration did not move the declaration version")
	}
	// Editing the referencing file drops its entries.
	open("file:///w/Use.kt", "package app\nfun use(c: Color) = Color.RED\nfun more(c: Color) = c\n", 2)
	if after := idx.ReferencesContext(context.Background(), "file:///w/Use.kt", position, false); len(after) <= len(first) {
		t.Fatalf("a reference added by an edit was missed: %d then %d", len(first), len(after))
	}
}

func conflictingDiagnostics(t *testing.T, source string) int {
	t.Helper()
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///w/Overloads.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	count := 0
	for _, diagnostic := range idx.declarationDiagnosticsLocked(idx.files[uri]) {
		if diagnostic.Code == "CONFLICTING_OVERLOADS" {
			count++
		}
	}
	return count
}

// Extension functions with the same name and parameters but different
// receivers are different functions.
func TestExtensionFunctionsWithDifferentReceiversDoNotConflict(t *testing.T) {
	source := "package app\nclass A\nclass B\nprivate fun A.toDto(x: Int): String = \"a\"\nprivate fun B.toDto(x: Int): String = \"b\"\n"
	if got := conflictingDiagnostics(t, source); got != 0 {
		t.Errorf("different receivers reported %d conflicts", got)
	}
}

func TestExtensionFunctionsWithTheSameReceiverStillConflict(t *testing.T) {
	source := "package app\nclass A\nprivate fun A.toDto(x: Int): String = \"a\"\nprivate fun A.toDto(x: Int): String = \"b\"\n"
	if got := conflictingDiagnostics(t, source); got == 0 {
		t.Error("two identical extension functions must still conflict")
	}
}

func TestCompoundAssignmentIsNotAValReassignment(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///w/Vals.kt")
	source := "package app\nfun use() {\n    val ids = mutableListOf<Int>()\n    ids += 1\n    val n = 1\n    n = 2\n    n++\n}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	lines := map[int]bool{}
	for _, diagnostic := range valReassignments(ctx, idx, idx.files[uri]) {
		lines[int(diagnostic.Range.Start.Line)+1] = true
	}
	if lines[4] {
		t.Error("`ids += 1` on a val collection is plusAssign, not a reassignment")
	}
	if !lines[6] {
		t.Error("`n = 2` on a val must still be reported")
	}
}

func TestCompoundAssignmentRecognition(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{{" += 1", true}, {"-= 1", true}, {" *= 2", true}, {" = 2", false}, {" == 2", false}, {" ++", false}, {"+==", false}, {"", false}} {
		if got := compoundAssignmentAfter(c.text, 0); got != c.want {
			t.Errorf("compoundAssignmentAfter(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

// Status is polled by clients waiting for readiness; it must not re-evaluate
// the rules on every call.
func TestFastDiagnosticStatusIsAnsweredFromMemoryWhileNothingChanges(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/A.kt", LanguageID: "kotlin", Version: 1, Text: "package app\nclass A\n"})
	first := idx.FastDiagnosticStatus()
	idx.fastStatusMu.Lock()
	computedAt := idx.fastStatusAt
	idx.fastStatusMu.Unlock()
	second := idx.FastDiagnosticStatus()
	idx.fastStatusMu.Lock()
	unchanged := idx.fastStatusAt.Equal(computedAt)
	idx.fastStatusMu.Unlock()
	if !unchanged {
		t.Error("a second status call recomputed instead of answering from memory")
	}
	if first.Files != second.Files || len(first.Codes) != len(second.Codes) {
		t.Errorf("cached status differs: %+v vs %+v", first, second)
	}
	// An edit moves the index and so must drop the memory.
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/B.kt", LanguageID: "kotlin", Version: 1, Text: "package app\nclass B\n"})
	if third := idx.FastDiagnosticStatus(); third.Files == first.Files {
		t.Errorf("status did not notice a new file: %d then %d", first.Files, third.Files)
	}
}

// Typing inside a function body must not invalidate what the index knows about
// everyone else: the declaration version moves only when declarations do.
func TestEditingABodyKeepsTheDeclarationVersionAndTheResolvedReferences(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	open := func(uri, text string, version int) {
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI(uri), LanguageID: "kotlin", Version: version, Text: text})
	}
	change := func(uri, text string, version int) {
		if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: protocol.URI(uri), Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	open("file:///w/Color.kt", "package app\nenum class Color { RED }\n", 1)
	open("file:///w/Use.kt", "package app\nfun use(c: Color): Int {\n    val a = 1\n    return a\n}\n", 1)
	open("file:///w/Elsewhere.kt", "package app\nfun other(c: Color) = c\n", 1)

	position := protocol.Position{Line: 1, Character: len("fun other(c: ")}
	if len(idx.ReferencesContext(context.Background(), "file:///w/Elsewhere.kt", position, false)) == 0 {
		t.Fatal("no references to Color")
	}
	idx.mu.RLock()
	remembered := len(idx.late.byKey)
	idx.mu.RUnlock()
	before := idx.late.declarations.Load()

	for version := 2; version < 8; version++ {
		change("file:///w/Use.kt", "package app\nfun use(c: Color): Int {\n    val a = "+string(rune('0'+version))+"\n    val b = a + 1 // typing\n    return b\n}\n", version)
	}
	if after := idx.late.declarations.Load(); after != before {
		t.Errorf("editing a function body moved the declaration version: %d -> %d", before, after)
	}
	idx.mu.RLock()
	kept := len(idx.late.byKey)
	idx.mu.RUnlock()
	if kept < remembered {
		t.Errorf("an edit in one file dropped resolved references of others: %d -> %d", remembered, kept)
	}

	// Changing a signature, however, is a declaration change.
	change("file:///w/Use.kt", "package app\nfun use(c: Color, extra: Int): Int = extra\n", 9)
	if idx.late.declarations.Load() == before {
		t.Error("changing a function signature did not move the declaration version")
	}
}

func TestDocumentHighlightsFindEveryOccurrenceOfAProperty(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///w/Service.kt")
	source := "package app\n\ninterface Repo { fun find(id: Int): String }\n\nclass Service(private val repo: Repo) {\n    fun a() = repo.find(1)\n    fun b() = repo.find(2)\n    fun c(other: Int) = other + 1\n    fun d() = repo.find(3)\n}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.markReady()
	offset := strings.Index(source, "repo.find(1)")
	doc, _ := idx.Document(uri)
	highlights := idx.DocumentHighlightsContext(context.Background(), uri, doc.Position(offset))
	if len(highlights) != 4 { // the declaration plus three uses; `other` and `find` are different names
		t.Fatalf("want 4 highlights of repo, got %d: %+v", len(highlights), highlights)
	}
}

func TestIncomingCallsFindCallersThatWereNeverResolved(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/Repo.kt", LanguageID: "kotlin", Version: 1, Text: "package app\n\ninterface Repo { fun find(id: Int): String }\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/A.kt", LanguageID: "kotlin", Version: 1, Text: "package app\n\nclass A(private val repo: Repo) {\n    fun one() = repo.find(1)\n    fun two() = repo.find(2)\n}\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/B.kt", LanguageID: "kotlin", Version: 1, Text: "package app\n\nclass B(private val repo: Repo) {\n    fun three() = repo.find(3)\n}\n"})
	idx.markReady()
	idx.mu.RLock()
	var target analysis.Symbol
	for _, id := range idx.byName["find"] {
		if symbol := idx.symbols[id]; symbol != nil && symbol.Kind == analysis.KindMethod && !symbol.Library {
			target = *symbol
		}
	}
	idx.mu.RUnlock()
	if target.ID == "" {
		t.Fatal("fixture method not indexed")
	}
	calls := idx.CallsToContext(context.Background(), target)
	callers := 0
	for _, references := range calls {
		callers += len(references)
	}
	if callers != 3 {
		t.Fatalf("want 3 calls to find, got %d: %v", callers, calls)
	}
}

// Publishing an edited document's diagnostics is off the edit's path and
// coalesced: a burst of edits costs one computation, and the last version wins.
func TestDiagnosticsAreCoalescedAndPublishedAfterTheEdit(t *testing.T) {
	var mu sync.Mutex
	published := map[protocol.URI][]int{}
	idx := New(func(uri protocol.URI, diagnostics []protocol.Diagnostic) {
		mu.Lock()
		published[uri] = append(published[uri], len(diagnostics))
		mu.Unlock()
	})
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///w/Edited.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: "package app\nfun ok() = 1\n"})
	const edits = 30
	for version := 2; version < 2+edits; version++ {
		text := "package app\nfun ok() = 1\n"
		if version == 1+edits {
			text = "package app\nfun broken(\n" // the final version has a syntax error
		}
		if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		results := append([]int(nil), published[uri]...)
		mu.Unlock()
		if len(results) > 0 && results[len(results)-1] > 0 {
			if len(results) > edits {
				t.Fatalf("%d publications for %d edits: nothing was coalesced", len(results), edits+1)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the last version's diagnostics were never published: %v", results)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Remembered resolutions are keyed on the declaration around a reference, so an
// edit in one function must neither disturb another function's memory nor leave
// the edited function answering from it.
func TestResolutionMemorySurvivesEditsElsewhereAndNotInTheEditedDeclaration(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	open := func(uri, text string, version int) {
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI(uri), LanguageID: "kotlin", Version: version, Text: text})
	}
	change := func(uri, text string, version int) {
		if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: protocol.URI(uri), Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	open("file:///w/Repos.kt", "package app\n\ninterface Repo { fun find(id: Int): String }\nclass Other { fun find(id: Int): Int = id }\n", 1)
	original := "package app\n\nclass Service(private val repo: Repo) {\n    fun a() = repo.find(1)\n\n    fun b() = repo.find(2)\n}\n"
	open("file:///w/Service.kt", original, 1)
	idx.markReady()

	findCalls := func() map[int]string { // line -> FQN of what `.find` resolves to
		idx.mu.RLock()
		defer idx.mu.RUnlock()
		file := idx.files["file:///w/Service.kt"]
		out := map[int]string{}
		for _, reference := range file.References {
			if reference.Name != "find" {
				continue
			}
			resolved := idx.resolveContextLocked(context.Background(), file, reference)
			if len(resolved) == 1 {
				out[int(reference.Range.Start.Line)] = resolved[0].FQN
			} else {
				out[int(reference.Range.Start.Line)] = "?"
			}
		}
		return out
	}
	before := findCalls()
	if before[3] != "app.Repo.find" || before[5] != "app.Repo.find" {
		t.Fatalf("both calls should resolve to Repo.find: %v", before)
	}
	idx.mu.RLock()
	remembered := len(idx.late.byKey)
	idx.mu.RUnlock()
	if remembered == 0 {
		t.Fatal("resolutions were not remembered")
	}

	// 1. A harmless edit in function b (a comment) must not disturb a's memory.
	change("file:///w/Service.kt", strings.Replace(original, "fun b() = repo.find(2)", "fun b() = repo.find(2) // note", 1), 2)
	idx.mu.RLock()
	afterComment := len(idx.late.byKey)
	idx.mu.RUnlock()
	if afterComment < remembered {
		t.Errorf("an edit dropped remembered resolutions: %d -> %d", remembered, afterComment)
	}
	if got := findCalls(); got[3] != "app.Repo.find" || got[5] != "app.Repo.find" {
		t.Fatalf("resolutions changed after a comment: %v", got)
	}

	// 2. Shadowing `repo` inside b changes what b's call means; a's must not change.
	shadowed := strings.Replace(original, "fun b() = repo.find(2)", "fun b(): Int {\n        val repo = Other()\n        return repo.find(2)\n    }", 1)
	change("file:///w/Service.kt", shadowed, 3)
	got := findCalls()
	if got[3] != "app.Repo.find" {
		t.Errorf("function a's call was disturbed by an edit in b: %v", got)
	}
	var shadowedLine int
	for line := range got {
		if line > 3 {
			shadowedLine = line
		}
	}
	if got[shadowedLine] != "app.Other.find" {
		t.Errorf("b's call must now resolve through the local `repo` to Other.find, got %q (%v) -- served from stale memory?", got[shadowedLine], got)
	}
}

// A client that pulls diagnostics ignores pushed ones, so none may be computed.
func TestNoDiagnosticsAreComputedForPushWhenTheClientPulls(t *testing.T) {
	for _, push := range []bool{true, false} {
		var calls atomic.Int64
		idx := New(func(protocol.URI, []protocol.Diagnostic) { calls.Add(1) })
		idx.SetDiagnosticsPush(push)
		uri := protocol.URI("file:///w/Pull.kt")
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: "package app\nfun a() = 1\n"})
		for version := 2; version < 6; version++ {
			if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
				TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: version},
				ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: "package app\nfun a() = 1 // edit\n"}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(2 * time.Second)
		for push && calls.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		got := calls.Load()
		idx.Close()
		if push && got == 0 {
			t.Error("a push client received no diagnostics")
		}
		if !push && got != 0 {
			t.Errorf("a pull client had %d diagnostic sets computed for push", got)
		}
	}
}

// An edit to an initializer changes what other code means when the declaration's
// type is inferred from it, so remembered resolutions must not survive it.
func TestChangingAnInferredInitializerInvalidatesRememberedResolutions(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	change := func(uri, text string, version int) {
		if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: protocol.URI(uri), Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/Repos.kt", LanguageID: "kotlin", Version: 1, Text: "package app\n\nclass Foo { fun find(id: Int): String = \"\" }\nclass Bar { fun find(id: Int): Int = id }\n"})
	holder := "package app\n\nfun make() = Foo()\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/Holder.kt", LanguageID: "kotlin", Version: 1, Text: holder})
	user := "package app\n\nfun use() = make().find(1)\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/Use.kt", LanguageID: "kotlin", Version: 1, Text: user})
	idx.markReady()

	resolveFind := func() string {
		idx.mu.RLock()
		defer idx.mu.RUnlock()
		file := idx.files["file:///w/Use.kt"]
		for _, reference := range file.References {
			if reference.Name == "find" {
				resolved := idx.resolveContextLocked(context.Background(), file, reference)
				if len(resolved) == 1 {
					return resolved[0].FQN
				}
				return "?"
			}
		}
		return "none"
	}
	if got := resolveFind(); got != "app.Foo.find" {
		t.Fatalf("before the edit .find should resolve through Foo, got %q", got)
	}
	change("file:///w/Holder.kt", strings.Replace(holder, "Foo()", "Bar()", 1), 2)
	if got := resolveFind(); got != "app.Bar.find" {
		t.Fatalf("after the initializer changed .find must resolve through Bar, got %q (stale memory)", got)
	}
}

// Declarations with identical text in different classes mean different things;
// a remembered resolution must not be shared between them.
func TestIdenticalDeclarationsInDifferentClassesDoNotShareRememberedResolutions(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	source := "package app\n\nclass A {\n    fun helper(): Int = 1\n    fun run() = helper()\n}\n\nclass B {\n    fun helper(): String = \"\"\n    fun run() = helper()\n}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///w/Twins.kt", LanguageID: "kotlin", Version: 1, Text: source})
	idx.markReady()
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files["file:///w/Twins.kt"]
	got := map[int]string{}
	for pass := 0; pass < 2; pass++ { // the second pass is answered from memory
		for _, reference := range file.References {
			if reference.Name != "helper" || reference.Role != analysis.RoleCall {
				continue
			}
			resolved := idx.resolveContextLocked(context.Background(), file, reference)
			if len(resolved) != 1 {
				t.Fatalf("helper() should resolve uniquely, got %d", len(resolved))
			}
			got[int(reference.Range.Start.Line)] = resolved[0].FQN
		}
	}
	if got[4] != "app.A.helper" || got[9] != "app.B.helper" {
		t.Fatalf("identical bodies in different classes were confused: %v", got)
	}
}

func TestJVMArrayTypesAreSpelledTheKotlinWay(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"T[]", "Array<T>"}, {"int[]", "IntArray"}, {"java.lang.String[]", "Array<String>"},
		{"char[]", "CharArray"}, {"T[][]", "Array<Array<T>>"}, {"java.util.List<java.lang.String[]>", "List<Array<String>>"},
		{"java.lang.Object", "Any"}, {"List<T>", "List<T>"},
	} {
		if got := kotlinizeBinaryType(c.in); got != c.want {
			t.Errorf("kotlinizeBinaryType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Kotlin 2.3 and 2.4 libraries -- the project's own standard library among
// them -- carry metadata schema 2.3/2.4. The decoder rejected everything past
// 2.2, so none of their top-level Kotlin functions was understood. The layout is
// unchanged: every signature the supported 2.1 stdlib yields is identical in 2.4.
func TestKotlinMetadataSchemasUpToTwoFourAreDecoded(t *testing.T) {
	for _, version := range [][]int{{1, 9, 0}, {2, 0, 0}, {2, 2, 0}, {2, 3, 0}, {2, 4, 0}} {
		if !supportedKotlinMetadataVersion(version) {
			t.Errorf("schema %v should be supported", version)
		}
	}
	for _, version := range [][]int{{2, 9, 0}, {3, 0, 0}, {0, 9, 0}} {
		if supportedKotlinMetadataVersion(version) {
			t.Errorf("schema %v should still be rejected", version)
		}
	}
}

// The real fixture behind accepting schemas 2.3 and 2.4: the same standard
// library classes decoded from a supported (2.1) and a newer (2.4) release must
// yield identical signatures for everything they share. The class files are
// copied from kotlin-stdlib 2.1.0 and 2.4.10 into testdata/kotlin-stdlib.
func TestStdlib24MetadataDecodesLikeStdlib21(t *testing.T) {
	classes := []string{
		"kotlin/Pair.class", "kotlin/TuplesKt.class", "kotlin/PreconditionsKt__PreconditionsKt.class",
		"kotlin/StandardKt__StandardKt.class", "kotlin/collections/ArraysKt__ArraysKt.class",
		"kotlin/collections/CollectionsKt__CollectionsKt.class", "kotlin/collections/CollectionsKt__IterablesKt.class",
	}
	decode := func(version string) map[string]bool {
		out := map[string]bool{}
		for _, name := range classes {
			data, err := os.ReadFile(filepath.Join("testdata", "kotlin-stdlib", version, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			class, err := classfile.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			parsed := parsedBinaryClassfile(textdoc.NewDocument("file:///libs/X.class", "java", 0, classfile.RenderJava(class)), class)
			if err := applyKotlinBinaryMetadata(parsed, class); err != nil {
				t.Fatalf("%s %s: %v", version, name, err)
			}
			for _, symbol := range parsed.Symbols {
				if symbol.Kind == analysis.KindProperty && symbol.OriginID != "" {
					out["val "+symbol.FQN+" recv="+symbol.ReceiverType+" : "+symbol.Type] = true
					continue
				}
				if symbol.Kind != analysis.KindFunction || symbol.OriginID == "" {
					continue
				}
				var parameters []string
				for _, parameter := range symbol.Parameters {
					parameters = append(parameters, parameter.Type)
				}
				out[symbol.FQN+" recv="+symbol.ReceiverType+" ("+strings.Join(parameters, ",")+") -> "+symbol.Type] = true
			}
		}
		return out
	}
	old, current := decode("2.1.0"), decode("2.4.10")
	if len(old) < 50 {
		t.Fatalf("only %d Kotlin-level functions decoded from the 2.1 stdlib", len(old))
	}
	for signature := range old {
		if !current[signature] {
			t.Errorf("a signature from 2.1 is missing or different in 2.4: %s", signature)
		}
	}
	found := false
	for signature := range current {
		found = found || strings.HasPrefix(signature, "kotlin.collections.flatten recv=Array<out Array<out T>> ()")
	}
	if !found {
		t.Error("the Array extension `flatten` has no Array<out Array<out T>> receiver")
	}
	for _, property := range []string{
		"val kotlin.collections.indices recv=Collection<*> : kotlin.ranges.IntRange",
		"val kotlin.collections.lastIndex recv=List<T> : Int",
		"val kotlin.Pair.second recv= : B",
	} {
		if !current[property] {
			t.Errorf("the 2.4 stdlib decodes no %s", property)
		}
	}
}

func TestLibraryArtifactNameIgnoresTheVersion(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"/c/kotlin-stdlib-2.4.10.jar", "kotlin-stdlib"},
		{"/c/kotlin-stdlib-jdk8-2.4.10.jar", "kotlin-stdlib-jdk8"},
		{"/k/lib/kotlin-stdlib.jar", "kotlin-stdlib"},
		{"/k/lib/kotlin-stdlib-jdk7.jar", "kotlin-stdlib-jdk7"},
		{"/c/kotlin-script-runtime-2.0.21.jar", "kotlin-script-runtime"},
		{"/c/jackson-core-2.17.1-SNAPSHOT.jar", "jackson-core"},
		{"/c/commons.jar", "commons"},
	} {
		if got := libraryArtifactName(c.path); got != c.want {
			t.Errorf("libraryArtifactName(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
