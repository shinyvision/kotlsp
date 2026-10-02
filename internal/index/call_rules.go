package index

import (
	"context"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A call to a callee the index can pin down exactly -- one candidate, in the
// workspace, no varargs, no named arguments in play -- has a fixed shape: each
// required parameter needs a value. Argument expressions are accepted only
// when the index proves a unique builtin type (a literal, declared local,
// constructor, or uniquely resolved call); unknown and flow-sensitive shapes
// still abstain. Any callee ambiguity at all also abstains.
func init() {
	registerFastRule(fastRule{
		codes:              []string{"NO_VALUE_FOR_PARAMETER", "ARGUMENT_TYPE_MISMATCH"},
		languages:          []analysis.Language{analysis.LanguageKotlin},
		usesWorkspaceIndex: true,
		apply:              callShapeMismatches,
	})
}

func callShapeMismatches(ctx context.Context, i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
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
		callee, ok := i.uniqueWorkspaceCalleeLocked(ctx, file, reference)
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
		// A trailing lambda is passed to the last parameter, whatever sits
		// between it and the arguments in parentheses: `Failure(code) { "why" }`
		// leaves a defaulted `cause` out and supplies `lazyMessage`.
		positional := reference.Arity
		trailing := trailingLambdaArgument(text, document, reference)
		if trailing {
			positional--
		}
		for position := positional; position < len(parameters); position++ {
			if trailing && position == len(parameters)-1 {
				continue
			}
			if parameters[position].Default != "" {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: reference.Range, Severity: 1, Source: "kotlsp",
				Code:    "NO_VALUE_FOR_PARAMETER",
				Message: "No value passed for parameter '" + parameters[position].Name + "'.",
			})
		}
		for position := 0; position < positional && position < len(reference.Arguments) && position < len(parameters); position++ {
			expected := i.builtinExpectedTypeLocked(file, parameters[position].Type)
			if expected == "" {
				continue
			}
			start, end := document.Offset(reference.Arguments[position].Start), document.Offset(reference.Arguments[position].End)
			if start < 0 || end > len(text) || start >= end {
				continue
			}
			expression := strings.TrimSpace(text[start:end])
			actual := literalKind(expression)
			if actual == "" {
				actual = i.builtinExpectedTypeLocked(file, i.inferExpressionTypeLocked(ctx, file, expression, reference.StartByte))
			}
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
func (i *Index) uniqueWorkspaceCalleeLocked(ctx context.Context, file *analysis.ParsedFile, reference *analysis.Reference) (analysis.Symbol, bool) {
	byName := *reference
	byName.Arity = -1
	byName.ResolvedID = ""
	// This lookup identifies the declaration whose shape will be diagnosed. It
	// must not run overload applicability against the very missing or mistyped
	// arguments the rule is trying to report, or every erroneous call appears
	// to have no callee and the rule can never fire.
	byName.Role = analysis.RoleRead
	candidates := i.resolveLocked(ctx, file, byName)
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
	// An override takes its default values from the declaration it
	// overrides -- Kotlin forbids restating them -- so its own parameter list
	// says nothing about which arguments may be left out.
	if containsString(callee.Modifiers, "override") || containsString(callee.Modifiers, "actual") {
		return analysis.Symbol{}, false
	}
	// Ranking may have kept one constructor of several: a call that matches a
	// secondary constructor was diagnosed against the primary one. Any other
	// overload in the same declaration makes the shape ambiguous.
	if callee.ContainerID != "" {
		for _, id := range i.byContainerName[callee.ContainerID] {
			sibling := i.symbols[id]
			if sibling == nil || sibling.ID == callee.ID || sibling.Kind != callee.Kind {
				continue
			}
			if callee.Kind == analysis.KindConstructor || sibling.Name == callee.Name {
				return analysis.Symbol{}, false
			}
		}
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

// trailingLambdaArgument reports whether the call's last argument is a lambda
// written after the parentheses (or with none at all).
func trailingLambdaArgument(text string, document interface {
	Offset(protocol.Position) int
}, call *analysis.Reference) bool {
	if len(call.Arguments) == 0 {
		return false
	}
	start := document.Offset(call.Arguments[len(call.Arguments)-1].Start)
	if start <= 0 || start >= len(text) || text[start] != '{' {
		return false
	}
	before := start - 1
	for before >= 0 && (text[before] == ' ' || text[before] == '\t' || text[before] == '\n' || text[before] == '\r') {
		before--
	}
	return before >= 0 && (text[before] == ')' || before == call.EndByte-1)
}
