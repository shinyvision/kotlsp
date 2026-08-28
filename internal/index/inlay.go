package index

import (
	"context"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

type ParameterHint struct {
	Position       protocol.Position
	Label          string
	Callable       analysis.Symbol
	ParameterIndex int
}

// ParameterHints resolves already-parsed call arguments against the symbol
// index. No parsing or file I/O occurs while the index lock is held.
func (i *Index) ParameterHints(uri protocol.URI, requested protocol.Range) []ParameterHint {
	return i.ParameterHintsContext(context.Background(), uri, requested)
}

func (i *Index) ParameterHintsContext(ctx context.Context, uri protocol.URI, requested protocol.Range) []ParameterHint {
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	var out []ParameterHint
	for _, ref := range file.References {
		if ctx.Err() != nil {
			return nil
		}
		if ref.Role != analysis.RoleCall || len(ref.Arguments) == 0 {
			continue
		}
		resolved := i.resolveContextLocked(ctx, file, ref)
		var callable analysis.Symbol
		bestScore := -1 << 30
		bestCount := 0
		for _, candidate := range resolved {
			if ctx.Err() != nil {
				return nil
			}
			if !analysis.IsCallableKind(candidate.Kind) || !matchesArityForLanguage(candidate, len(ref.Arguments), file.Language) {
				continue
			}
			score, typed := i.callCompatibilityLocked(file, ref, candidate)
			if typed && score <= -1<<19 {
				continue
			}
			if !typed {
				// Equal-arity overloads without enough argument type evidence are
				// intentionally ambiguous: a wrong parameter label is worse than
				// withholding the hint.
				score = 0
			}
			if score > bestScore {
				callable, bestScore, bestCount = candidate, score, 1
			} else if score == bestScore {
				bestCount++
			}
		}
		if bestCount != 1 {
			callable = analysis.Symbol{}
		}
		if callable.ID == "" {
			continue
		}
		positional := 0
		for _, argumentRange := range ref.Arguments {
			argument := strings.TrimSpace(doc.Slice(argumentRange))
			parameterIndex := -1
			name, _, isNamed := namedArgument(argument)
			if isNamed {
				for index, parameter := range callable.Parameters {
					if parameter.Name == name {
						parameterIndex = index
						break
					}
				}
			} else if positional < len(callable.Parameters) {
				parameterIndex = positional
				if !callable.Parameters[positional].Variadic {
					positional++
				}
			}
			if parameterIndex < 0 || parameterIndex >= len(callable.Parameters) {
				continue
			}
			if beforeRange(argumentRange.End, requested.Start) || beforeRange(requested.End, argumentRange.Start) {
				continue
			}
			parameter := callable.Parameters[parameterIndex]
			if argument == parameter.Name || isNamed {
				continue
			}
			out = append(out, ParameterHint{Position: argumentRange.Start, Label: parameter.Name + ":", Callable: callable, ParameterIndex: parameterIndex})
		}
	}
	return out
}

// JavaLambdaParameterHints target-types lambdas passed as call arguments using
// the same overload applicability and generic substitution used by resolution.
// It deliberately abstains when more than one overload remains equally good.
func (i *Index) JavaLambdaParameterHints(uri protocol.URI, requested protocol.Range) []ParameterHint {
	return i.JavaLambdaParameterHintsContext(context.Background(), uri, requested)
}

func (i *Index) JavaLambdaParameterHintsContext(ctx context.Context, uri protocol.URI, requested protocol.Range) []ParameterHint {
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil || file.Language != analysis.LanguageJava {
		return nil
	}
	var out []ParameterHint
	for _, ref := range file.References {
		if ctx.Err() != nil {
			return nil
		}
		if ref.Role != analysis.RoleCall || len(ref.Arguments) == 0 {
			continue
		}
		callable, unique := i.uniqueApplicableCallableContextLocked(ctx, file, ref)
		if !unique {
			continue
		}
		for argumentIndex, argumentRange := range ref.Arguments {
			start, end := doc.Offset(argumentRange.Start), doc.Offset(argumentRange.End)
			if start < 0 || end <= start || end > len(doc.Text) {
				continue
			}
			expressionStart := start
			for expressionStart < end && strings.ContainsRune(" \t\r\n", rune(doc.Text[expressionStart])) {
				expressionStart++
			}
			expression := strings.TrimSpace(doc.Text[expressionStart:end])
			arrow := topLevelExpressionOperator(expression, "->")
			if arrow < 0 {
				continue
			}
			parameterIndex := argumentIndex
			if parameterIndex >= len(callable.Parameters) {
				parameterIndex = len(callable.Parameters) - 1
			}
			if parameterIndex < 0 {
				continue
			}
			target := i.contextualCallableParameterTypeLocked(file, ref, callable, parameterIndex, doc)
			out = i.appendLambdaParameterHintsLocked(out, file, doc, requested, expressionStart, expression, arrow, target, callable)
		}
	}
	// A lambda initializing a declaration with an explicit type is
	// target-typed by that declared type alone; no overload choice is
	// involved, so the declared functional interface is the whole proof.
	for _, symbol := range file.Symbols {
		if ctx.Err() != nil {
			return nil
		}
		if symbol.Kind != analysis.KindField && symbol.Kind != analysis.KindVariable && symbol.Kind != analysis.KindProperty {
			continue
		}
		if symbol.Type == "" || symbol.Type == "var" || symbol.Initializer == "" {
			continue
		}
		initializer := strings.TrimSpace(symbol.Initializer)
		arrow := topLevelExpressionOperator(initializer, "->")
		if arrow < 0 {
			continue
		}
		declarationEnd := symbol.EndByte
		if declarationEnd > len(doc.Text) {
			declarationEnd = len(doc.Text)
		}
		if symbol.NameEndByte < 0 || symbol.NameEndByte > declarationEnd {
			continue
		}
		relative := strings.Index(doc.Text[symbol.NameEndByte:declarationEnd], initializer)
		if relative < 0 {
			continue
		}
		out = i.appendLambdaParameterHintsLocked(out, file, doc, requested, symbol.NameEndByte+relative, initializer, arrow, symbol.Type, analysis.Symbol{})
	}
	return out
}

// appendLambdaParameterHintsLocked emits one hint per implicitly typed lambda
// parameter whose target functional interface has exactly one abstract method.
func (i *Index) appendLambdaParameterHintsLocked(out []ParameterHint, file *analysis.ParsedFile, doc *textdoc.Document, requested protocol.Range, expressionStart int, expression string, arrow int, target string, callable analysis.Symbol) []ParameterHint {
	types := i.functionalParameterTypesLocked(file, target)
	prefix := strings.TrimSpace(expression[:arrow])
	prefix = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(prefix, "("), ")"))
	names := splitTopLevelCallArguments(prefix)
	if len(names) != len(types) || len(names) == 0 {
		return out
	}
	search := expressionStart
	prefixEnd := expressionStart + arrow
	for index, name := range names {
		name = strings.TrimSpace(name)
		if !isSimpleIdentifier(name) {
			continue // explicitly typed or destructuring parameter
		}
		if search > prefixEnd || prefixEnd > len(doc.Text) {
			continue
		}
		relative := strings.Index(doc.Text[search:prefixEnd], name)
		if relative < 0 {
			continue
		}
		nameStart := search + relative
		nameEnd := nameStart + len(name)
		search = nameEnd
		nameRange := doc.Range(nameStart, nameEnd)
		if beforeRange(nameRange.End, requested.Start) || beforeRange(requested.End, nameRange.Start) {
			continue
		}
		out = append(out, ParameterHint{Position: nameRange.End, Label: ": " + types[index], Callable: callable, ParameterIndex: index})
	}
	return out
}

func (i *Index) uniqueApplicableCallableContextLocked(ctx context.Context, file *analysis.ParsedFile, ref analysis.Reference) (analysis.Symbol, bool) {
	bestScore, bestCount := -1<<30, 0
	var best analysis.Symbol
	for _, candidate := range i.resolveContextLocked(ctx, file, ref) {
		if ctx.Err() != nil {
			return analysis.Symbol{}, false
		}
		if !analysis.IsCallableKind(candidate.Kind) || !matchesArityForLanguage(candidate, len(ref.Arguments), file.Language) {
			continue
		}
		score, typed := i.callCompatibilityLocked(file, ref, candidate)
		if typed && score <= -1<<19 {
			continue
		}
		if score > bestScore {
			best, bestScore, bestCount = candidate, score, 1
		} else if score == bestScore {
			bestCount++
		}
	}
	return best, best.ID != "" && bestCount == 1
}

func beforeRange(a, b protocol.Position) bool {
	return a.Line < b.Line || a.Line == b.Line && a.Character < b.Character
}
