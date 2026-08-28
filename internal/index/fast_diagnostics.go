package index

import (
	"sort"
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
	// usesWorkspaceIndex is set only when a rule can turn an absent or
	// currently-unique workspace symbol into a finding. Pure declaration and
	// local-flow rules remain useful during the initial scan; workspace rules
	// wait until the symbol universe they reason about is complete.
	usesWorkspaceIndex bool
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
// Preconditions are rule-specific. Local declaration/flow rules run during a
// cold scan. Rules whose proof depends on absence or uniqueness in the symbol
// universe wait for a complete index and modelled generated sources. Syntax
// damage is declaration-local: independent declarations on either side survive.
func (i *Index) fastDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	if file == nil || !predictionsApplyTo(file) {
		return nil
	}
	var out []protocol.Diagnostic
	for _, rule := range fastRules {
		if rule.apply == nil || !rule.handles(file.Language) || !i.fastRuleEligibleLocked(file, rule) {
			continue
		}
		findings := rule.apply(i, file)
		remaining := maxCompilerDiagnosticsPerFile - len(out)
		if remaining <= 0 {
			break
		}
		out = append(out, findings[:min(remaining, len(findings))]...)
	}
	return predictionsOutsideSyntaxDamage(out, file)
}

// predictionsApplyTo excludes scripts. A build script resolves its names
// against Gradle's own classpath, which the index never sees, and the compiler
// pass never compiles it, so nothing about its names can be confirmed.
func predictionsApplyTo(file *analysis.ParsedFile) bool {
	return !strings.HasSuffix(strings.ToLower(string(file.URI)), ".kts")
}

func (i *Index) fastDiagnosticsEligibleLocked(file *analysis.ParsedFile) bool {
	if !predictionsApplyTo(file) || !i.semanticUniverseCompleteLocked(file) {
		return false
	}
	return !i.hasUnmodelledGeneratedSourcesFor(file)
}

func (i *Index) semanticUniverseCompleteLocked(file *analysis.ParsedFile) bool {
	if !i.Progress().Ready {
		return false
	}
	// Directly opened fragments have no build model or archive scan. Once their
	// caller explicitly marks the fragment ready, its in-memory symbol universe
	// is complete by construction.
	if i.generation.Load() == 0 {
		return true
	}
	if i.modelRefreshing.Load() || i.refreshIncomplete.Load() || !i.librariesScanned.Load() {
		return false
	}
	module, unique := moduleForURIInModules(file.URI, i.modules)
	if !unique {
		return false
	}
	_, sourceSetUnique := sourceSetForURIInModule(file.URI, module)
	// skipLibraryScan is an explicit test/embedding declaration that the empty
	// archive universe is complete. A self-contained workspace (no build tool
	// at all) is complete by construction. Conventional discovery that stands
	// in for a build script whose import failed remains non-authoritative and
	// therefore abstains from absence-based predictions.
	return sourceSetUnique && (module.BuildModelAuthoritative || module.BuildModelSelfContained || skipLibraryScan)
}

func (i *Index) fastRuleEligibleLocked(file *analysis.ParsedFile, rule fastRule) bool {
	if file == nil || file.ParseMode == "large" || !predictionsApplyTo(file) {
		return false
	}
	if !rule.usesWorkspaceIndex {
		return true
	}
	return i.fastDiagnosticsEligibleLocked(file)
}

// FastDiagnosticStatus is the bounded, auditable description exposed by
// kotlsp/status. Coverage is deliberately honest: these are conservative
// predictions backed by a compiler pass, not a replacement compiler.
type FastDiagnosticStatus struct {
	RuleCount                int
	LocalRuleCount           int
	WorkspaceRuleCount       int
	Codes                    []string
	CompilerBackstop         bool
	Files                    int
	LocalEligibleFiles       int
	WorkspaceEligibleFiles   int
	WorkspaceAbstainedFiles  int
	CurrentPredictions       int
	StatusTruncated          bool
	UnavailableFilesByReason map[string]int
}

// FastDiagnosticStatus reports both the advertised rule surface and why some
// workspace-dependent predictions currently abstain. It never returns file
// names or an unbounded per-document list.
func (i *Index) FastDiagnosticStatus() FastDiagnosticStatus {
	i.mu.RLock()
	defer i.mu.RUnlock()
	status := FastDiagnosticStatus{UnavailableFilesByReason: make(map[string]int)}
	codeSet := make(map[string]bool)
	for _, rule := range fastRules {
		if rule.apply == nil {
			continue
		}
		status.RuleCount++
		if rule.usesWorkspaceIndex {
			status.WorkspaceRuleCount++
		} else {
			status.LocalRuleCount++
		}
		for _, code := range rule.codes {
			codeSet[code] = true
		}
	}
	for code := range codeSet {
		status.Codes = append(status.Codes, code)
	}
	sort.Strings(status.Codes)
	progress := i.Progress()
	// Status is a foreground request. Rule evaluation is intentionally sampled
	// over a bounded file set; StatusTruncated makes the aggregate explicitly a
	// lower bound instead of monopolizing the global read lock on a large tree.
	const maxStatusFiles = 256
	for _, file := range i.files {
		if file == nil {
			continue
		}
		if status.Files >= maxStatusFiles {
			status.StatusTruncated = true
			break
		}
		status.Files++
		if predictionsApplyTo(file) {
			status.LocalEligibleFiles++
		}
		workspaceEligible := predictionsApplyTo(file) && i.semanticUniverseCompleteLocked(file) && !i.hasUnmodelledGeneratedSourcesFor(file)
		if workspaceEligible {
			status.WorkspaceEligibleFiles++
		} else if predictionsApplyTo(file) {
			status.WorkspaceAbstainedFiles++
		}
		status.CurrentPredictions += len(i.fastDiagnosticsLocked(file))
		switch {
		case !predictionsApplyTo(file):
			status.UnavailableFilesByReason["script classpath is owned by the build tool"]++
		case file.ParseMode == "large":
			status.UnavailableFilesByReason["large-file parsing is navigation-only; compiler diagnostics own semantic errors"]++
		case !progress.Ready:
			status.UnavailableFilesByReason["workspace-dependent rules are waiting for a complete index"]++
		case !i.librariesScanned.Load():
			status.UnavailableFilesByReason["library inventory is incomplete"]++
		case i.modelRefreshing.Load() || i.refreshIncomplete.Load():
			status.UnavailableFilesByReason["a watched build-model refresh is incomplete"]++
		case func() bool {
			module := i.moduleForURILocked(file.URI)
			return module != nil && !module.BuildModelAuthoritative && !module.BuildModelSelfContained
		}():
			status.UnavailableFilesByReason["build model is not authoritative"]++
		case i.hasUnmodelledGeneratedSourcesFor(file):
			status.UnavailableFilesByReason["generated declarations have not been indexed in the source-set dependency closure"]++
		}
		for _, diagnostic := range file.Diagnostics {
			if diagnostic.Severity == 1 && diagnostic.Code == "syntax" {
				status.UnavailableFilesByReason["predictions inside a syntax-damaged declaration abstain"]++
				break
			}
		}
	}
	for _, compiler := range i.compilerStatus.snapshot() {
		if compiler.Passes > 0 || compiler.Running || compiler.LastOutcome != "" {
			status.CompilerBackstop = true
			break
		}
	}
	return status
}

func predictionsOutsideSyntaxDamage(predictions []protocol.Diagnostic, file *analysis.ParsedFile) []protocol.Diagnostic {
	if file == nil || len(file.Diagnostics) == 0 {
		return predictions
	}
	var damaged []protocol.Range
	for _, diagnostic := range file.Diagnostics {
		if diagnostic.Severity == 1 && diagnostic.Code == "syntax" {
			damaged = append(damaged, diagnostic.Range)
		}
	}
	if len(damaged) == 0 {
		return predictions
	}
	// A recovered declaration is uncertain only when the syntax damage is in
	// that declaration. Independent declarations on either side remain useful;
	// an early unfinished function no longer suppresses the rest of the file.
	kept := predictions[:0:0]
	for _, prediction := range predictions {
		owner := protocol.Range{}
		hasOwner := false
		for _, symbol := range file.Symbols {
			if symbol.Synthetic || !rangeContains(symbol.Range, prediction.Range) {
				continue
			}
			if !hasOwner || rangeContains(owner, symbol.Range) {
				owner, hasOwner = symbol.Range, true
			}
		}
		uncertain := false
		for _, syntaxRange := range damaged {
			if rangesOverlap(syntaxRange, prediction.Range) || hasOwner && rangesOverlap(syntaxRange, owner) {
				uncertain = true
				break
			}
		}
		if !uncertain {
			kept = append(kept, prediction)
		}
	}
	return kept
}

func rangeContains(outer, inner protocol.Range) bool {
	return !positionBefore(inner.Start, outer.Start) && !positionBefore(outer.End, inner.End)
}

func positionBefore(left, right protocol.Position) bool {
	return left.Line < right.Line || left.Line == right.Line && left.Character < right.Character
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
	type confirmationKey struct {
		line    int
		code    string
		message string
	}
	type locationKey struct {
		start protocol.Position
		end   protocol.Position
		code  string
	}
	type lineKey struct {
		line int
		code string
	}
	// Compilers often underline a larger syntax node than the fast rule, even
	// when code and wording are identical. Confirmation is therefore line-local
	// and counted: one compiler copy cancels one prediction, never every equal
	// spelling on the line. Wording drift remains range-local whenever an exact
	// range exists; the line fallback is safe only when that line has one fast
	// finding for the code.
	predicted := make(map[confirmationKey]int, len(predictions))
	predictionsAt := make(map[locationKey]int, len(predictions))
	predictionsOnLine := make(map[lineKey]int, len(predictions))
	for _, diagnostic := range predictions {
		code, _ := diagnostic.Code.(string)
		predicted[confirmationKey{diagnostic.Range.Start.Line, code, diagnostic.Message}]++
		predictionsAt[locationKey{diagnostic.Range.Start, diagnostic.Range.End, code}]++
		predictionsOnLine[lineKey{diagnostic.Range.Start.Line, code}]++
	}
	drifted := make(map[locationKey]bool)
	driftedLine := make(map[lineKey]bool)
	keptCompiler := compiler[:0:0]
	for _, diagnostic := range compiler {
		code, _ := diagnostic.Code.(string)
		if k := (confirmationKey{diagnostic.Range.Start.Line, code, diagnostic.Message}); predicted[k] > 0 {
			predicted[k]--
			continue
		}
		location := locationKey{diagnostic.Range.Start, diagnostic.Range.End, code}
		if predictionsAt[location] > 0 {
			drifted[location] = true
		} else if line := (lineKey{diagnostic.Range.Start.Line, code}); predictionsOnLine[line] == 1 {
			driftedLine[line] = true
		}
		keptCompiler = append(keptCompiler, diagnostic)
	}
	keptPredictions := predictions[:0:0]
	for _, diagnostic := range predictions {
		code, _ := diagnostic.Code.(string)
		if drifted[locationKey{diagnostic.Range.Start, diagnostic.Range.End, code}] || driftedLine[lineKey{diagnostic.Range.Start.Line, code}] {
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
