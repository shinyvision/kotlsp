package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Errors about how a body is written rather than what it declares: a missing
// return, an 'if' used as an expression without 'else', a call on a nullable
// receiver, a 'break' outside a loop, a class that cannot be instantiated.
// Each rule below is the conservative form of the compiler's check: it fires
// only in shapes where no analysis could rescue the code.
func init() {
	registerFastRule(fastRule{
		codes: []string{
			"NO_RETURN_IN_FUNCTION_WITH_BLOCK_BODY", "INVALID_IF_AS_EXPRESSION", "UNSAFE_CALL",
			"CONDITION_TYPE_MISMATCH", "BREAK_OR_CONTINUE_OUTSIDE_A_LOOP",
			"CREATING_AN_INSTANCE_OF_ABSTRACT_CLASS", "ENUM_CLASS_CONSTRUCTOR_CALL", "INTERFACE_AS_FUNCTION",
		},
		languages:          []analysis.Language{analysis.LanguageKotlin},
		usesWorkspaceIndex: true,
		apply:              kotlinBodyShapes,
	})
}

func kotlinBodyShapes(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.documentLocked(file.URI)
	if document == nil || document.Text == "" {
		return nil
	}
	c := newUnresolvedNameContext(file)
	c.prepare(i)
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || symbol.URI != file.URI {
			continue
		}
		switch symbol.Kind {
		case analysis.KindFunction, analysis.KindMethod:
			out = append(out, i.missingReturn(c, document, symbol)...)
			out = append(out, ifWithoutElse(c, document, symbol, true)...)
		case analysis.KindProperty, analysis.KindVariable:
			out = append(out, ifWithoutElse(c, document, symbol, false)...)
		}
	}
	out = append(out, i.unsafeCalls(c, document)...)
	out = append(out, i.conditionMismatches(c, document)...)
	out = append(out, i.jumpsOutsideLoops(c, document)...)
	out = append(out, i.impossibleInstantiations(c, document)...)
	return out
}

// Names of standard functions that never return. A call to any of these ends
// the flow, so a body containing one may legally end without a return.
var neverReturns = map[string]bool{"TODO": true, "error": true, "exitProcess": true, "fail": true, "throwUninitializedPropertyAccessException": true}

// blockBody returns the byte range strictly inside the braces of a function
// with a block body, and false for an expression body or no body.
func blockBody(c *unresolvedNameContext, symbol *analysis.Symbol) (int, int, bool) {
	tail, hasBody := functionTail(c.text, symbol)
	if !hasBody {
		return 0, 0, false
	}
	tailStart := symbol.EndByte - len(tail)
	brace := indexTopLevel(c.text, c.mask, tailStart, '{')
	if brace < 0 || brace >= symbol.EndByte {
		return 0, 0, false
	}
	if eq := strings.IndexByte(c.text[tailStart:brace], '='); eq >= 0 {
		return 0, 0, false
	}
	end := matchingBrace(c.text, c.mask, brace)
	if end < 0 || end != symbol.EndByte-1 {
		return 0, 0, false
	}
	return brace + 1, end, true
}

func (i *Index) missingReturn(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, symbol *analysis.Symbol) []protocol.Diagnostic {
	declared := strings.TrimSpace(symbol.Type)
	if declared == "" || hasAnyModifier(symbol, "expect", "actual", "external", "abstract") {
		return nil
	}
	base, _ := splitInstantiatedType(declared)
	base = strings.TrimSpace(strings.TrimSuffix(base, "?"))
	if containsString(symbol.TypeParameters, base) {
		return nil
	}
	if owner := i.symbols[symbol.ContainerID]; owner != nil && containsString(owner.TypeParameters, base) {
		return nil
	}
	resolved, ok := i.resolveOneTypeLocked(c.file, declared)
	if !ok || resolved[0].FQN == "kotlin.Unit" || resolved[0].FQN == "kotlin.Nothing" {
		return nil
	}
	start, end, ok := blockBody(c, symbol)
	if !ok {
		return nil
	}
	body, mask := c.text[start:end], c.mask[start:end]
	for _, keyword := range []string{"return", "throw", "while", "do"} {
		if len(keywordPositions(body, mask, keyword)) > 0 {
			return nil
		}
	}
	// A call to something that never returns ends the flow too. Any callee
	// declared anywhere with a Nothing result counts, by name alone.
	for at := 0; at < len(body); at++ {
		if !mask[at] || !isIdentifierByteFast(body[at]) || at > 0 && isIdentifierByteFast(body[at-1]) {
			continue
		}
		nameEnd := at
		for nameEnd < len(body) && isIdentifierByteFast(body[nameEnd]) {
			nameEnd++
		}
		name := body[at:nameEnd]
		at = nameEnd
		next := skipForwardCode(body, mask, nameEnd)
		if next < 0 || body[next] != '(' {
			continue
		}
		if neverReturns[name] {
			return nil
		}
		for _, id := range i.byName[name] {
			if callee := i.symbols[id]; callee != nil && analysis.IsCallableKind(callee.Kind) && strings.TrimSpace(strings.TrimSuffix(callee.Type, "?")) == "Nothing" {
				return nil
			}
		}
	}
	return []protocol.Diagnostic{{
		Range: document.Range(end, end+1), Severity: 1, Source: "kotlsp",
		Code:    "NO_RETURN_IN_FUNCTION_WITH_BLOCK_BODY",
		Message: "Missing return statement.",
	}}
}

// ifWithoutElse reports an 'if' that is the whole initialiser or expression
// body and has no top-level 'else'.
func ifWithoutElse(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, symbol *analysis.Symbol, function bool) []protocol.Diagnostic {
	var start, end int
	if function {
		tail, hasBody := functionTail(c.text, symbol)
		if !hasBody {
			return nil
		}
		tailStart := symbol.EndByte - len(tail)
		eq := strings.IndexByte(tail, '=')
		brace := strings.IndexByte(tail, '{')
		if eq < 0 || brace >= 0 && brace < eq {
			return nil
		}
		start, end = tailStart+eq+1, symbol.EndByte
	} else {
		if symbol.Initializer == "" {
			return nil
		}
		var ok bool
		start, end, ok = initializerSpan(c.text, symbol)
		if !ok {
			return nil
		}
	}
	first := skipForwardCode(c.text, c.mask, start)
	if first < 0 || first+2 > end || c.text[first:first+2] != "if" || first+2 < len(c.text) && isIdentifierByteFast(c.text[first+2]) {
		return nil
	}
	// An 'else' at nesting depth zero anywhere in the span belongs to this
	// 'if' or to a nested one; either way the shape is not provably wrong.
	depth := 0
	for at := first; at < end; at++ {
		if !c.mask[at] {
			continue
		}
		switch c.text[at] {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
		}
		if depth == 0 && strings.HasPrefix(c.text[at:], "else") && (at == 0 || !isIdentifierByteFast(c.text[at-1])) && (at+4 >= len(c.text) || !isIdentifierByteFast(c.text[at+4])) {
			return nil
		}
	}
	return []protocol.Diagnostic{{
		Range: document.Range(first, first+2), Severity: 1, Source: "kotlsp",
		Code:    "INVALID_IF_AS_EXPRESSION",
		Message: "'if' must have both main and 'else' branches when used as an expression.",
	}}
}

// countWord counts whole-word occurrences of name in code within a range.
func countWord(c *unresolvedNameContext, from, to int, name string) int {
	if from < 0 || to > len(c.text) || from >= to {
		return 0
	}
	return len(keywordPositions(c.text[from:to], c.mask[from:to], name))
}

// unsafeCalls reports `x.member` where x is a parameter or local declared with
// a nullable type that is used exactly once, so no smart cast can apply, and
// member is something the non-null type has while no nullable-receiver
// extension of that name exists anywhere.
func (i *Index) unsafeCalls(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, ref := range c.file.References {
		if ref.Qualifier == "" || !isSimpleIdentifier(ref.Qualifier) || ref.ArgumentLabel || ref.Role == analysis.RoleType || ref.Role == analysis.RoleImport {
			continue
		}
		dot := ref.StartByte - 1
		if dot < 1 || c.text[dot] != '.' || c.text[dot-1] == '?' || c.text[dot-1] == '!' {
			continue
		}
		// The qualifier must be written directly before the dot.
		if qualifierStart := dot - len(ref.Qualifier); qualifierStart < 0 || c.text[qualifierStart:dot] != ref.Qualifier || qualifierStart > 0 && isIdentifierByteFast(c.text[qualifierStart-1]) {
			continue
		}
		var binding *analysis.Symbol
		for _, symbol := range i.fileSymbolsByName[c.file.URI][ref.Qualifier] {
			if !isLexicalSymbol(*symbol) || symbol.Kind != analysis.KindParameter && symbol.Kind != analysis.KindVariable || symbol.StartByte > ref.StartByte || !symbolInScopeAt(*symbol, ref.StartByte) {
				continue
			}
			if binding == nil || symbol.StartByte > binding.StartByte {
				binding = symbol
			}
		}
		if binding == nil || containsString(binding.Modifiers, "constructor-property") {
			continue
		}
		declared := strings.TrimSpace(binding.Type)
		if !strings.HasSuffix(declared, "?") || !isSimpleIdentifier(declared[:len(declared)-1]) {
			continue
		}
		base := declared[:len(declared)-1]
		resolved, ok := i.resolveOneTypeLocked(c.file, base)
		if !ok || !isKotlinClassLike(resolved[0].Kind) {
			continue
		}
		// Exactly one use inside the binding's scope: this one.
		scopeEnd := binding.ScopeEndByte
		if scopeEnd <= 0 || scopeEnd > len(c.text) {
			continue
		}
		if countWord(c, binding.ScopeStartByte, scopeEnd, ref.Qualifier) != 1 {
			continue
		}
		hierarchy := i.completeHierarchyLocked(c, resolved[0])
		if !hierarchy.complete {
			continue
		}
		hasMember := false
		for _, owner := range hierarchy.types {
			for _, member := range i.typeMembersLocked(owner) {
				if member.Name == ref.Name {
					hasMember = true
				}
			}
		}
		nullableExtension := false
		for _, id := range i.byName[ref.Name] {
			candidate := i.symbols[id]
			if candidate == nil || candidate.ReceiverType == "" {
				continue
			}
			receiver := strings.TrimSpace(candidate.ReceiverType)
			receiverBase, _ := splitInstantiatedType(receiver)
			receiverBase = strings.TrimSpace(receiverBase)
			if strings.HasSuffix(receiver, "?") || containsString(candidate.TypeParameters, receiverBase) {
				nullableExtension = true
				break
			}
			if owner := i.symbols[candidate.ContainerID]; owner != nil && containsString(owner.TypeParameters, receiverBase) {
				nullableExtension = true
				break
			}
			if receiverBase == base {
				hasMember = true
			}
		}
		if nullableExtension || !hasMember {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: document.Range(dot, dot+1), Severity: 1, Source: "kotlsp",
			Code:    "UNSAFE_CALL",
			Message: "Only safe (?.) or non-null asserted (!!.) calls are allowed on a nullable receiver of type '" + declared + "'.",
		})
	}
	return out
}

// conditionMismatches reports `if (x)` and `while (x)` where x is a literal
// or a binding of a declared non-Boolean builtin type.
func (i *Index) conditionMismatches(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, keyword := range []string{"if", "while"} {
		for _, at := range keywordPositions(c.text, c.mask, keyword) {
			open := skipForwardCode(c.text, c.mask, at+len(keyword))
			if open < 0 || c.text[open] != '(' {
				continue
			}
			closing := matchingParen(c.text, open)
			if closing < 0 {
				continue
			}
			condition := strings.TrimSpace(c.text[open+1 : closing])
			start := open + 1 + strings.Index(c.text[open+1:closing], condition)
			inferred := ""
			if kind := literalKind(condition); kind != "" {
				if kind != "Boolean" {
					inferred = kind
				}
			} else if isSimpleIdentifier(condition) {
				var binding *analysis.Symbol
				for _, symbol := range i.fileSymbolsByName[c.file.URI][condition] {
					if !isLexicalSymbol(*symbol) || symbol.Kind != analysis.KindParameter && symbol.Kind != analysis.KindVariable || symbol.StartByte > start || !symbolInScopeAt(*symbol, start) {
						continue
					}
					if binding == nil || symbol.StartByte > binding.StartByte {
						binding = symbol
					}
				}
				if binding == nil {
					continue
				}
				if expected := i.builtinExpectedTypeLocked(c.file, binding.Type); expected != "" && expected != "Boolean" {
					inferred = expected
				}
			}
			if inferred == "" {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: document.Range(start, start+len(condition)), Severity: 1, Source: "kotlsp",
				Code:    "CONDITION_TYPE_MISMATCH",
				Message: "Condition type mismatch: inferred type is '" + inferred + "' but 'Boolean' was expected.",
			})
		}
	}
	return out
}

func (i *Index) jumpsOutsideLoops(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, keyword := range []string{"break", "continue"} {
		for _, at := range keywordPositions(c.text, c.mask, keyword) {
			if at+len(keyword) < len(c.text) && c.text[at+len(keyword)] == '@' {
				continue
			}
			callable := i.enclosingCallableLocked(c.file, at)
			if callable == nil || callable.Synthetic {
				continue
			}
			inNested := false
			for _, lambda := range c.lambdas {
				if lambda.start < at && at < lambda.end {
					inNested = true
				}
			}
			for _, anonymous := range c.anonymous {
				if anonymous.start < at && at < anonymous.end {
					inNested = true
				}
			}
			if inNested {
				continue
			}
			loop := false
			for _, loopKeyword := range []string{"for", "while", "do"} {
				if countWord(c, callable.StartByte, at, loopKeyword) > 0 {
					loop = true
				}
			}
			if loop {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: document.Range(at, at+len(keyword)), Severity: 1, Source: "kotlsp",
				Code:    "BREAK_OR_CONTINUE_OUTSIDE_A_LOOP",
				Message: "'break' and 'continue' are only allowed inside loops.",
			})
		}
	}
	return out
}

// impossibleInstantiations reports `Name(...)` where Name is an abstract
// class, an enum class, or a plain interface of the workspace and nothing
// else -- no function, no companion invoke -- could be what the call means.
func (i *Index) impossibleInstantiations(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, ref := range c.file.References {
		if ref.Role != analysis.RoleCall || ref.Qualifier != "" || ref.ArgumentLabel {
			continue
		}
		before := skipBackCode(c.text, c.mask, ref.StartByte-1)
		if before >= 0 && (c.text[before] == '.' || c.text[before] == ':' || c.text[before] == '@' || c.text[before] == '?') {
			continue
		}
		open := skipForwardCode(c.text, c.mask, ref.EndByte)
		if open < 0 || c.text[open] != '(' {
			continue
		}
		closing := matchingParen(c.text, open)
		if closing < 0 {
			continue
		}
		enclosing := i.symbols[i.containerIDAtLocked(c.file, ref.StartByte)]
		if enclosing == nil || !analysis.IsCallableKind(enclosing.Kind) && enclosing.Kind != analysis.KindProperty && enclosing.Kind != analysis.KindVariable {
			continue
		}
		target := i.workspaceKotlinClassLocked(c.file, ref.Name)
		if target == nil || hasAnyModifier(target, "expect", "actual", "external", "sealed") {
			continue
		}
		scope := i.scopeAtLocked(c, ref)
		if scope == nil || !scope.complete {
			continue
		}
		shadowed := false
		for _, id := range i.byName[ref.Name] {
			candidate := i.symbols[id]
			if candidate == nil || analysis.IsTypeKind(candidate.Kind) || candidate.Kind == analysis.KindConstructor {
				continue
			}
			if isLexicalSymbol(*candidate) && candidate.URI == c.file.URI || !isLexicalSymbol(*candidate) && i.callablePossiblyVisibleLocked(c, scope, *candidate) {
				shadowed = true
				break
			}
		}
		if shadowed {
			continue
		}
		// A companion 'invoke' makes Name(...) a call.
		companionInvoke := false
		for _, id := range i.byContainerName[target.ID] {
			nested := i.symbols[id]
			if nested == nil || nested.ContainerID != target.ID || nested.Kind != analysis.KindObject {
				continue
			}
			for _, member := range i.typeMembersLocked(*nested) {
				if member.Name == "invoke" {
					companionInvoke = true
				}
			}
			if hierarchy, ok := i.resolvedHierarchyLocked(*nested); !ok {
				companionInvoke = true
			} else {
				for _, supertype := range hierarchy {
					for _, member := range i.typeMembersLocked(supertype) {
						if member.Name == "invoke" {
							companionInvoke = true
						}
					}
				}
			}
		}
		if companionInvoke {
			continue
		}
		switch {
		case target.Kind == analysis.KindClass && containsString(target.Modifiers, "abstract"):
			out = append(out, protocol.Diagnostic{
				Range: document.Range(ref.StartByte, closing+1), Severity: 1, Source: "kotlsp",
				Code:    "CREATING_AN_INSTANCE_OF_ABSTRACT_CLASS",
				Message: "Cannot create an instance of an abstract class.",
			})
		case target.Kind == analysis.KindEnum:
			out = append(out, protocol.Diagnostic{
				Range: document.Range(ref.StartByte, closing+1), Severity: 1, Source: "kotlsp",
				Code:    "ENUM_CLASS_CONSTRUCTOR_CALL",
				Message: "Enum types cannot be instantiated.",
			})
		case target.Kind == analysis.KindInterface && len(target.Modifiers) == 0 && len(target.Supertypes) == 0 && len(target.TypeParameters) == 0:
			out = append(out, protocol.Diagnostic{
				Range: ref.Range, Severity: 1, Source: "kotlsp",
				Code:    "INTERFACE_AS_FUNCTION",
				Message: "Interface 'interface " + target.Name + " : Any' does not have constructors.",
			})
		}
	}
	return out
}
