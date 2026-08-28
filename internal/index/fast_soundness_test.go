package index

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// The contract of a fast diagnostic is that the compiler may add findings we
// did not report, but must never contradict one we did. This asserts exactly
// that, using the compiler as the oracle: every fast finding must be confirmed
// by a compiler finding on the same line.
//
// A violation is a soundness bug and fails the build. That is what converts
// "we are sure this rule is right" from an intention into something checked.
func assertFastDiagnosticsAreSound(t *testing.T, idx *Index, uri protocol.URI) []string {
	t.Helper()
	// Raw sets, not the reconciled output: reconciliation drops a compiler
	// finding an identical prediction already covers, which is the very
	// agreement being checked here.
	idx.mu.RLock()
	file := idx.files[uri]
	var predictions []protocol.Diagnostic
	if file != nil {
		predictions = append(predictions, idx.declarationDiagnosticsLocked(file)...)
		predictions = append(predictions, idx.referenceDiagnosticsLocked(file)...)
		predictions = append(predictions, idx.fastDiagnosticsLocked(file)...)
	}
	compiler := append([]protocol.Diagnostic(nil), idx.compilerDiagnostics[uri]...)
	idx.mu.RUnlock()

	type key struct {
		line    int
		code    string
		message string
	}
	confirmed := make(map[key]bool, len(compiler))
	for _, diagnostic := range compiler {
		code, _ := diagnostic.Code.(string)
		confirmed[key{diagnostic.Range.Start.Line, code, diagnostic.Message}] = true
	}
	type position struct {
		line, character int
		code, message   string
	}
	var codes []string
	unique := make(map[position]bool, len(predictions))
	for _, prediction := range predictions {
		if prediction.Source != "kotlsp" || !isFastDiagnostic(prediction) {
			continue
		}
		code, _ := prediction.Code.(string)
		if code == "compiler" {
			codes = append(codes, "compiler:"+javaMessagePrefix(prediction.Message))
		} else {
			codes = append(codes, code)
		}
		// Two occurrences on one line at different columns are two findings,
		// as they are for the compiler; the same column twice is a double.
		if at := (position{prediction.Range.Start.Line, prediction.Range.Start.Character, code, prediction.Message}); unique[at] {
			t.Errorf("duplicate prediction: %s %q twice at %s:%d:%d", code, prediction.Message, filepath.Base(string(uri)), at.line+1, at.character+1)
		} else {
			unique[at] = true
		}
		// The bar is exact agreement. A prediction on the right line with
		// different wording would still change on screen when the compiler
		// arrived, which is the thing this exists to prevent.
		if !confirmed[key{prediction.Range.Start.Line, code, prediction.Message}] {
			t.Errorf("unsound fast diagnostic: %s reported %q at %s:%d; the compiler reports no such finding there",
				code, prediction.Message, filepath.Base(string(uri)), prediction.Range.Start.Line+1)
		}
	}
	return codes
}

// isFastDiagnostic identifies findings produced by a predictive rule, as
// opposed to the index's own lint (unused imports and the like). The aligned
// pre-existing checks share codes with the rules and count as predictions.
func isFastDiagnostic(diagnostic protocol.Diagnostic) bool {
	code, _ := diagnostic.Code.(string)
	if code == "compiler" {
		return javaMessagePrefix(diagnostic.Message) != ""
	}
	for _, rule := range fastRules {
		for _, candidate := range rule.codes {
			if candidate == code {
				return true
			}
		}
	}
	return false
}

// corpusFiles collects the sources the soundness gate runs over.
func corpusFiles(root string) []string {
	var out []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if isJavaOrKotlinSource(path) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// TestFastDiagnosticsAreSoundOnTheFixture is the fail-closed gate. It runs on
// every build, over sources whose compiler findings are known.
func TestFastDiagnosticsAreSoundOnTheFixture(t *testing.T) {
	requireCompilerBackedTest(t)
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	fired := make(map[string]bool)
	// Two fixtures: the main one, and a Java one with nothing but flow
	// errors, because javac runs flow analysis only over a compilation whose
	// attribution succeeded.
	for _, fixture := range []struct{ dir, oracle string }{
		{filepath.Join("testdata", "project"), "src/main/kotlin/fixture/Errors.kt"},
		{filepath.Join("testdata", "flow"), "src/main/java/flow/FlowJava.java"},
	} {
		idx, root := startedFixtureIndexFrom(t, fixture.dir)
		idx.ScheduleCompilerDiagnostics(context.Background())
		if len(waitForCompilerDiagnostics(t, idx, fixtureFile(root, fixture.oracle), 1)) == 0 {
			t.Fatalf("%s: the compiler reported nothing for %s, so there is no oracle", fixture.dir, fixture.oracle)
		}
		soundnessOverFixture(t, idx, root, fired)
	}
	// A gate that passes because nothing fired proves nothing. Every rule
	// must have produced at least one confirmed prediction on the fixture.
	for _, rule := range fastRules {
		for _, code := range rule.codes {
			if code == "compiler" {
				continue
			}
			if !fired[code] {
				t.Errorf("rule %s never fired on the fixture, so its soundness is untested", code)
			}
		}
		for _, prefix := range rule.javaMessages {
			if !fired["compiler:"+prefix] {
				t.Errorf("Java rule %q never fired on the fixture, so its soundness is untested", prefix)
			}
		}
	}
}

func soundnessOverFixture(t *testing.T, idx *Index, root string, fired map[string]bool) {
	t.Helper()
	for _, path := range corpusFiles(root) {
		relative, _ := filepath.Rel(root, path)
		uri := fixtureFile(root, filepath.ToSlash(relative))
		// Every rule abstains on a file with a syntax error. A fixture file
		// that fails to parse would make this gate vacuous for that file
		// without failing it, so parsing clean is asserted first.
		idx.mu.RLock()
		if file := idx.files[uri]; file != nil {
			for _, diagnostic := range file.Diagnostics {
				if diagnostic.Code == "syntax" {
					t.Errorf("%s does not parse (%s at line %d); the gate cannot cover it", relative, diagnostic.Message, diagnostic.Range.Start.Line+1)
				}
			}
		}
		idx.mu.RUnlock()
		for _, code := range assertFastDiagnosticsAreSound(t, idx, uri) {
			fired[code] = true
		}
	}
}

// TestFastDiagnosticsAreSoundOnAWorkspace widens the corpus to a real project
// when one is named, so the gate can be run against code nobody wrote for it.
//
//	KOTLSP_CORPUS=~/Projects/some-project go test ./internal/index/ -run Sound -v
func TestFastDiagnosticsAreSoundOnAWorkspace(t *testing.T) {
	root := requireCorpusTest(t)
	idx := New(nil)
	defer idx.Close()
	idx.Start(context.Background(), []protocol.URI{fileURI(root)})
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(200 * time.Millisecond)
	}
	idx.ScheduleCompilerDiagnostics(context.Background())
	if !waitForCompilerPass(t, idx, 3*time.Minute) {
		t.Fatal("the compiler never finished a pass over the corpus, so there is no oracle")
	}

	files := corpusFiles(root)
	predictions := 0
	for _, path := range files {
		uri := fileURI(path)
		for _, diagnostic := range idx.Diagnostics(uri) {
			if diagnostic.Source == "kotlsp" && isFastDiagnostic(diagnostic) {
				predictions++
			}
		}
		assertFastDiagnosticsAreSound(t, idx, uri)
	}
	t.Logf("corpus: %d files, %d fast diagnostics", len(files), predictions)
}

func fileURI(path string) protocol.URI {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return protocol.URI("file://" + filepath.ToSlash(absolute))
}

var _ = fmt.Sprintf
var _ = strings.TrimSpace

// The promise made to the author: what a prediction shows is what stays. The
// full diagnostic set for a file is taken before the compiler has run and again
// after, and every prediction must be present in both, unchanged.
func TestPredictionsSurviveTheCompilerLanding(t *testing.T) {
	requireCompilerBackedTest(t)
	idx, root := startedFixtureIndex(t)
	uri := fixtureFile(root, "src/main/kotlin/fixture/Errors.kt")
	type shown struct {
		line    int
		code    string
		message string
	}
	snapshot := func() map[shown]bool {
		out := make(map[shown]bool)
		for _, diagnostic := range idx.Diagnostics(uri) {
			if diagnostic.Source != "kotlsp" || !isFastDiagnostic(diagnostic) {
				continue
			}
			code, _ := diagnostic.Code.(string)
			out[shown{diagnostic.Range.Start.Line, code, diagnostic.Message}] = true
		}
		return out
	}
	before := snapshot()
	if len(before) == 0 {
		t.Fatal("no predictions before the compiler ran, so this proves nothing")
	}
	idx.ScheduleCompilerDiagnostics(context.Background())
	if len(waitForCompilerDiagnostics(t, idx, uri, 1)) == 0 {
		t.Skip("the compiler produced nothing to reconcile against")
	}
	after := snapshot()
	for finding := range before {
		if !after[finding] {
			t.Errorf("prediction changed when the compiler landed: %s %q at line %d", finding.code, finding.message, finding.line+1)
		}
	}
	for finding := range after {
		if !before[finding] {
			t.Errorf("a prediction appeared only after the compiler landed: %s %q at line %d", finding.code, finding.message, finding.line+1)
		}
	}
}

func TestPredictionReconciliationUsesExactRange(t *testing.T) {
	first := protocol.Diagnostic{
		Range: protocol.Range{Start: protocol.Position{Line: 1, Character: 2}, End: protocol.Position{Line: 1, Character: 3}},
		Code:  "UNRESOLVED_REFERENCE", Message: "Unresolved reference 'T'.",
	}
	second := first
	second.Range.Start.Character = 8
	second.Range.End.Character = 9
	compiler := second
	compiler.Message = "Unresolved reference: T"
	remainingPredictions, remainingCompiler := reconcilePredictions([]protocol.Diagnostic{first, second}, []protocol.Diagnostic{compiler})
	if len(remainingPredictions) != 1 || remainingPredictions[0].Range != first.Range {
		t.Fatalf("predictions after range-local wording drift = %#v", remainingPredictions)
	}
	if len(remainingCompiler) != 1 || remainingCompiler[0].Range != second.Range {
		t.Fatalf("compiler findings after range-local wording drift = %#v", remainingCompiler)
	}
}
