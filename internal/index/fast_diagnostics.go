package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Fast diagnostics are the findings the index can prove without running a
// compiler, so an author sees them immediately rather than after a validation
// pass. They exist under one rule: the compiler may add findings we did not
// report, but must never contradict one we did.
//
// The first attempt at index-backed diagnostics failed that rule badly, at a
// 98% false-positive rate, because it reported "I could not resolve this,
// therefore it is an error". Failure to prove something correct is not proof
// that it is wrong. Every rule here must instead establish that no legal
// interpretation of the program exists.
//
// The subtle part is that soundness of a rule requires completeness of its
// opposite. Reporting an unguarded nullable access, for instance, means knowing
// every way Kotlin can establish non-nullness; missing one turns correct code
// into an error. Where a rule cannot be complete about that, it abstains.
type fastRule struct {
	// codes are the compiler's own diagnostic names this rule can emit. A
	// prediction carries the same code and message the compiler will, so the
	// finding that later confirms it is indistinguishable from it.
	codes []string
	// languages the rule understands. A rule never runs on a language it was
	// not written for.
	languages []analysis.Language
	// javaMessages lists the message markers a Java rule emits. javac has one
	// code for everything, so a Java prediction is identified by a fixed part
	// of its message, and the soundness gate checks each marker fired rather
	// than the code.
	javaMessages []string
	// apply returns findings that are provably errors.
	apply func(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic
}

// fastRules is the registry. Order is irrelevant: every rule sees the same
// immutable snapshot.
var fastRules []fastRule

func registerFastRule(rule fastRule) { fastRules = append(fastRules, rule) }

// The redeclaration check predates this registry and stays outside its
// preconditions: a second declaration of the same name needs no library and no
// finished scan to prove, so it must not wait for either. It is registered
// here without a body so its codes count as predictions.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"CLASSIFIER_REDECLARATION", "CONFLICTING_OVERLOADS", "REDECLARATION"},
		languages: []analysis.Language{analysis.LanguageKotlin},
	})
}

func (r fastRule) handles(language analysis.Language) bool {
	for _, candidate := range r.languages {
		if candidate == language {
			return true
		}
	}
	return false
}

// fastDiagnosticsLocked runs every rule whose preconditions hold.
//
// The global preconditions are the ones no rule can be sound without:
//
//   - Indexing must have finished. A name that is merely not indexed yet is not
//     an unknown name, and the refresh mechanism re-runs this once it is.
//   - The file must have parsed. Findings recovered from source the parser
//     could not read are not evidence of anything, and the Kotlin grammar has
//     gaps in constructs that are perfectly legal.
//   - The workspace must not contain generated sources this index cannot see.
//     An annotation processor produces symbols with no source, and reporting
//     their absence would be confidently wrong.
func (i *Index) fastDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	if file == nil || !i.fastDiagnosticsEligibleLocked(file) {
		return nil
	}
	var out []protocol.Diagnostic
	for _, rule := range fastRules {
		if rule.apply == nil || !rule.handles(file.Language) {
			continue
		}
		out = append(out, rule.apply(i, file)...)
	}
	return out
}

// predictionsApplyTo excludes scripts. A build script resolves its names
// against Gradle's own classpath, which the index never sees, and the compiler
// pass never compiles it, so nothing about its names can be confirmed.
func predictionsApplyTo(file *analysis.ParsedFile) bool {
	return !strings.HasSuffix(strings.ToLower(string(file.URI)), ".kts")
}

func (i *Index) fastDiagnosticsEligibleLocked(file *analysis.ParsedFile) bool {
	if !predictionsApplyTo(file) || !i.Progress().Ready {
		return false
	}
	for _, diagnostic := range file.Diagnostics {
		if diagnostic.Severity == 1 && diagnostic.Code == "syntax" {
			return false
		}
	}
	return !i.hasUnmodelledGeneratedSources()
}

// reconcilePredictionsLocked decides what an author sees when both a
// prediction and a compiler finding exist for one place. Identical code and
// message: the prediction stands and the compiler's copy is dropped, so nothing
// changes on screen when the compiler arrives. Same code, different wording:
// the compiler's wins, because it is authoritative and the wording has drifted.
// Otherwise both are real findings and both are shown.
func reconcilePredictions(predictions, compiler []protocol.Diagnostic) ([]protocol.Diagnostic, []protocol.Diagnostic) {
	if len(predictions) == 0 || len(compiler) == 0 {
		return predictions, compiler
	}
	type key struct {
		line    int
		code    string
		message string
	}
	// Counted, not merely noted: the same finding can legitimately occur
	// twice on one line (`fun f(a: T): T` with T unresolved), and a compiler
	// copy cancels one prediction, never all of them.
	predicted := make(map[key]int, len(predictions))
	for _, diagnostic := range predictions {
		code, _ := diagnostic.Code.(string)
		predicted[key{diagnostic.Range.Start.Line, code, diagnostic.Message}]++
	}
	drifted := make(map[[2]any]bool)
	keptCompiler := compiler[:0:0]
	for _, diagnostic := range compiler {
		code, _ := diagnostic.Code.(string)
		if k := (key{diagnostic.Range.Start.Line, code, diagnostic.Message}); predicted[k] > 0 {
			predicted[k]--
			continue
		}
		drifted[[2]any{diagnostic.Range.Start.Line, code}] = true
		keptCompiler = append(keptCompiler, diagnostic)
	}
	keptPredictions := predictions[:0:0]
	for _, diagnostic := range predictions {
		code, _ := diagnostic.Code.(string)
		if drifted[[2]any{diagnostic.Range.Start.Line, code}] {
			continue
		}
		keptPredictions = append(keptPredictions, diagnostic)
	}
	return keptPredictions, keptCompiler
}

// javaMessagePrefix returns the registered marker a Java prediction's message
// contains, or "" when it is not a prediction of any rule.
func javaMessagePrefix(message string) string {
	longest := ""
	for _, rule := range fastRules {
		for _, marker := range rule.javaMessages {
			if strings.Contains(message, marker) && len(marker) > len(longest) {
				longest = marker
			}
		}
	}
	return longest
}
