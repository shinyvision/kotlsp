package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A call to a callee the index can pin down exactly -- one candidate, in the
// workspace, no varargs, no named arguments in play -- has a fixed shape: each
// required parameter needs a value, and a literal argument has a type the
// compiler will compare with the parameter's. Both are provable without
// inference. Any ambiguity at all, and the rule abstains.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"NO_VALUE_FOR_PARAMETER", "ARGUMENT_TYPE_MISMATCH"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     callShapeMismatches,
	})
}

func callShapeMismatches(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.documentLocked(file.URI)
	if document == nil {
		return nil
	}
	text := document.Text
	var out []protocol.Diagnostic
	for index := range file.References {
		reference := &file.References[index]
		if reference.Role != analysis.RoleCall || reference.Qualifier != "" || reference.ArgumentLabel || reference.Arity < 0 || reference.Name == "invoke" {
			continue
		}
		callee, ok := i.uniqueWorkspaceCalleeLocked(file, reference)
		if !ok {
			continue
		}
		if i.callUsesNamedArgumentsLocked(file, document, reference) {
			continue
		}
		parameters := callee.Parameters
		for _, parameter := range parameters {
			if parameter.Variadic {
				ok = false
			}
		}
		if !ok || reference.Arity > len(parameters) {
			continue
		}
		for position := reference.Arity; position < len(parameters); position++ {
			if parameters[position].Default != "" {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: reference.Range, Severity: 1, Source: "kotlsp",
				Code:    "NO_VALUE_FOR_PARAMETER",
				Message: "No value passed for parameter '" + parameters[position].Name + "'.",
			})
		}
		for position := 0; position < reference.Arity && position < len(reference.Arguments) && position < len(parameters); position++ {
			expected := i.builtinExpectedTypeLocked(file, parameters[position].Type)
			if expected == "" {
				continue
			}
			start, end := document.Offset(reference.Arguments[position].Start), document.Offset(reference.Arguments[position].End)
			if start < 0 || end > len(text) || start >= end {
				continue
			}
			actual := literalKind(text[start:end])
			if literalAcceptedBy(expected, actual) {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: reference.Arguments[position], Severity: 1, Source: "kotlsp",
				Code:    "ARGUMENT_TYPE_MISMATCH",
				Message: "Argument type mismatch: actual type is '" + actual + "', but '" + expected + "' was expected.",
			})
		}
	}
	return out
}

// uniqueWorkspaceCalleeLocked resolves a call by name alone and accepts the
// result only when exactly one workspace callable answers.
func (i *Index) uniqueWorkspaceCalleeLocked(file *analysis.ParsedFile, reference *analysis.Reference) (analysis.Symbol, bool) {
	byName := *reference
	byName.Arity = -1
	byName.ResolvedID = ""
	candidates := i.resolveLocked(file, byName)
	var callee analysis.Symbol
	found := 0
	for _, candidate := range candidates {
		if !analysis.IsCallableKind(candidate.Kind) {
			if analysis.IsTypeKind(candidate.Kind) {
				continue
			}
			return analysis.Symbol{}, false
		}
		callee = candidate
		found++
	}
	if found != 1 || callee.Library || callee.Synthetic || callee.Language != analysis.LanguageKotlin {
		return analysis.Symbol{}, false
	}
	return callee, true
}

// callUsesNamedArgumentsLocked reports whether any argument is passed by name,
// in which case positions no longer say which parameter is missing.
func (i *Index) callUsesNamedArgumentsLocked(file *analysis.ParsedFile, document interface {
	Offset(protocol.Position) int
}, call *analysis.Reference) bool {
	if len(call.Arguments) == 0 {
		return false
	}
	first := document.Offset(call.Arguments[0].Start)
	last := document.Offset(call.Arguments[len(call.Arguments)-1].End)
	for index := range file.References {
		label := &file.References[index]
		if label.ArgumentLabel && label.StartByte >= first && label.EndByte <= last {
			return true
		}
	}
	text := i.documentTextLocked(file.URI)
	for _, argument := range call.Arguments {
		start, end := document.Offset(argument.Start), document.Offset(argument.End)
		if start >= 0 && end <= len(text) && start < end && strings.Contains(text[start:end], "=") && !strings.Contains(text[start:end], "==") {
			return true
		}
	}
	return false
}
