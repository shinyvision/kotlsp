package index

import (
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
)

func (i *Index) typeOfNameLocked(file *analysis.ParsedFile, name string, at int) string {
	if name == "this" || name == "super" {
		if enclosing := i.enclosingTypeLocked(file, at); enclosing.ID != "" {
			if name == "super" {
				// An unqualified Kotlin super expression is ambiguous when the
				// declaration has more than one direct supertype. Java has one
				// superclass plus interfaces, but the syntax model does not retain
				// enough information to distinguish those here. Abstain rather than
				// choosing whichever declaration happened to be indexed first.
				if len(enclosing.Supertypes) != 1 {
					return ""
				}
				return simpleType(enclosing.Supertypes[0])
			}
			return enclosing.Name
		}
	}
	bestSmartCast := ""
	nonNullSmartCast := false
	seenSmartCasts := make(map[string]bool)
	for _, smartCast := range i.fileSmartCastsByName[file.URI][name] {
		if smartCast.Name == name && smartCast.StartByte <= at && at <= smartCast.EndByte {
			if smartCast.Type == "!" {
				nonNullSmartCast = true
			} else if !seenSmartCasts[smartCast.Type] {
				seenSmartCasts[smartCast.Type] = true
				if bestSmartCast == "" {
					bestSmartCast = smartCast.Type
				} else {
					// Every fact in scope holds at once: `value is A && value is B`
					// refines to the intersection, which the hierarchy walk
					// understands through splitIntersectionTypes.
					bestSmartCast += " & " + smartCast.Type
				}
			}
		}
	}
	best := ""
	var bestSymbol *analysis.Symbol
	candidates := i.fileSymbolsByName[file.URI][name]
	before := sort.Search(len(candidates), func(index int) bool { return candidates[index].StartByte > at })
	for index := before - 1; index >= 0; index-- {
		symbol := candidates[index]
		inScope := !isLexicalSymbol(*symbol) || symbolInScopeAt(*symbol, at)
		if !inScope {
			continue
		}
		bestSymbol = symbol
		best = symbol.Type
		if best == "" || best == "var" || best == "val" {
			best = i.inferredConventionBindingTypeLocked(file, *symbol)
			if best == "" && symbol.Initializer != "" {
				best = i.inferExpressionTypeLocked(file, symbol.Initializer, symbol.StartByte)
			}
		}
		break
	}
	stableSmartCast := bestSymbol != nil && i.kotlinSmartCastStableLocked(file, *bestSymbol, at)
	if stableSmartCast && bestSmartCast != "" {
		return bestSmartCast
	}
	if best != "" {
		if stableSmartCast && nonNullSmartCast {
			return strings.TrimSuffix(strings.TrimSpace(best), "?")
		}
		return best
	}
	if bestSymbol != nil {
		if contextual := i.contextualLambdaParameterTypeLocked(file, *bestSymbol); contextual != "" {
			return contextual
		}
	}
	if symbols := i.resolveTypeSymbolsAtLocked(file, name, at); len(symbols) == 1 {
		return symbols[0].FQN
	}
	return ""
}

// kotlinSmartCastStableLocked enforces the part of Kotlin's stability contract
// the fast model can prove. Parameters and local vals are immutable bindings;
// mutable locals, properties/getters, fields, and unresolved writes abstain.
// This deliberately narrows the optimization instead of pretending that a
// syntax span is a complete control-flow/stability proof.
func (i *Index) kotlinSmartCastStableLocked(file *analysis.ParsedFile, symbol analysis.Symbol, at int) bool {
	if file.Language != analysis.LanguageKotlin || symbol.URI != file.URI || at < symbol.StartByte {
		return false
	}
	stableBinding := symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindVariable && containsString(symbol.Modifiers, "val")
	if !stableBinding {
		return false
	}
	for _, reference := range file.References {
		if reference.Role != analysis.RoleWrite || reference.Name != symbol.Name || reference.StartByte <= symbol.StartByte || reference.StartByte >= at {
			continue
		}
		resolved := i.resolveLocked(file, reference)
		if len(resolved) != 1 || resolved[0].ID == symbol.ID {
			return false
		}
	}
	return true
}

func (i *Index) inferredConventionBindingTypeLocked(file *analysis.ParsedFile, symbol analysis.Symbol) string {
	text := i.documentTextLocked(file.URI)
	for _, reference := range file.References {
		if strings.HasPrefix(reference.Name, "component") && reference.StartByte <= symbol.NameStartByte && symbol.NameEndByte <= reference.EndByte {
			receiver := i.inferExpressionTypeLocked(file, reference.Qualifier, symbol.StartByte)
			if receiver != "" {
				return i.memberResultTypeLocked(file, receiver, reference.Name, symbol.StartByte)
			}
		}
		if reference.Name != "next" || reference.StartByte < symbol.NameEndByte || reference.StartByte > symbol.ScopeEndByte || symbol.NameEndByte > len(text) || reference.EndByte > len(text) {
			continue
		}
		between := strings.TrimSpace(text[symbol.NameEndByte:reference.EndByte])
		if between != "in" {
			continue
		}
		iteratorType := i.typeOfExpressionLocked(file, reference.Qualifier, reference.StartByte)
		if iteratorType != "" {
			return i.memberResultTypeLocked(file, iteratorType, "next", reference.StartByte)
		}
	}
	return ""
}

func (i *Index) inferExpressionTypeLocked(file *analysis.ParsedFile, expression string, at int) string {
	return i.inferExpressionResultLocked(file, expression, at).Type
}

// inferExpressionResultLocked exposes whether the measured syntax fast path
// proved a type or merely derived a conservative candidate. Callers which can
// mutate source or choose one overload may require inferenceExact; ordinary
// display features can use a conservative result. Unknown syntax remains an
// explicit abstention for the background compiler rather than fabricated Any.
func (i *Index) inferExpressionResultLocked(file *analysis.ParsedFile, expression string, at int) inferredExpressionType {
	return i.inferExpressionResultDepthLocked(file, expression, at, 0)
}

func (i *Index) inferExpressionResultDepthLocked(file *analysis.ParsedFile, expression string, at, depth int) inferredExpressionType {
	ir := parseExpressionIR(expression, file.Language)
	if (ir.Kind == expressionBinary || ir.Kind == expressionUnary) && operatorTypable(ir.Operator) {
		// Operator expressions are typed from their operands: the language's
		// numeric promotion and boolean/string rules are the proof, so the
		// textual fast paths (which would read `f(1) + 2` as `f(1)`) never see
		// them. Anything the rules do not cover abstains.
		return i.inferOperatorExpressionLocked(file, ir, at, depth)
	}
	typ := i.inferExpressionTypeValueLocked(file, expression, at)
	if typ == "" {
		return inferredExpressionType{Expression: ir}
	}
	confidence := inferenceConservative
	switch ir.Kind {
	case expressionLiteral, expressionCast:
		confidence = inferenceExact
	}
	return inferredExpressionType{Type: typ, Confidence: confidence, Expression: ir}
}

func (i *Index) inferExpressionTypeValueLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(strings.TrimSuffix(expression, ";"))
	expression = unwrapEnclosingParentheses(expression)
	if file.Language == analysis.LanguageKotlin {
		if strings.HasPrefix(expression, "by ") {
			delegate := strings.TrimSpace(strings.TrimPrefix(expression, "by "))
			if open := topLevelExpressionOperator(delegate, "{"); open >= 0 {
				if close := matchingDelimiter(delegate, open, '{', '}'); close > open {
					body := unwrapExpressionBlock(delegate[open : close+1])
					return i.inferExpressionTypeLocked(file, body, at)
				}
			}
			if delegateType := i.inferExpressionTypeLocked(file, delegate, at); delegateType != "" {
				return i.memberResultTypeLocked(file, delegateType, "getValue", at)
			}
		}
		if inferred := i.inferKotlinCompositeExpressionLocked(file, expression, at); inferred != "" {
			return inferred
		}
		if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
			body := strings.TrimSpace(expression[1 : len(expression)-1])
			parameters := ""
			if arrow := topLevelExpressionOperator(body, "->"); arrow >= 0 {
				parameters = strings.TrimSpace(body[:arrow])
				body = strings.TrimSpace(body[arrow+2:])
			}
			result := i.inferExpressionTypeLocked(file, unwrapExpressionBlock("{"+body+"}"), at)
			if result != "" {
				parameterTypes := make([]string, 0)
				for _, parameter := range splitTopLevelExpressions(parameters, ',') {
					if colon := strings.LastIndexByte(parameter, ':'); colon >= 0 {
						typ := strings.TrimSpace(parameter[colon+1:])
						if typ == "" {
							return ""
						}
						parameterTypes = append(parameterTypes, typ)
					} else if parameter != "" {
						// Untyped lambda parameters are contextual. Inventing Any here
						// poisons overload selection and refactoring evidence.
						return ""
					}
				}
				return "(" + strings.Join(parameterTypes, ", ") + ") -> " + result
			}
		}
		if strings.HasPrefix(expression, "::") {
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(expression, "::")), "`")
			var resolved string
			matches := 0
			for _, id := range i.byName[name] {
				callable := i.symbols[id]
				if !analysis.IsCallableKind(callable.Kind) || callable.Type == "" || !i.accessibleLocked(file, *callable, at) || !i.simpleNameInScopeLocked(file, *callable) {
					continue
				}
				parameterTypes := make([]string, 0, len(callable.Parameters))
				for _, parameter := range callable.Parameters {
					if parameter.Type == "" {
						parameterTypes = nil
						break
					}
					parameterTypes = append(parameterTypes, parameter.Type)
				}
				if parameterTypes == nil {
					continue
				}
				resolved = "(" + strings.Join(parameterTypes, ", ") + ") -> " + callable.Type
				matches++
				if matches > 1 {
					return ""
				}
			}
			return resolved
		}
	} else if inferred := i.inferJavaCompositeExpressionLocked(file, expression, at); inferred != "" {
		return inferred
	}
	if open := strings.IndexByte(expression, '('); open >= 0 {
		if close := callClosingParen(expression, open); close >= open && close < len(expression)-1 {
			remainder := strings.TrimSpace(expression[close+1:])
			if strings.HasPrefix(remainder, "(") {
				typ := i.inferExpressionTypeLocked(file, expression[:close+1], at)
				for strings.HasPrefix(remainder, "(") && typ != "" {
					end := callClosingParen(remainder, 0)
					if end < 0 || end >= len(remainder) {
						typ = i.invocationResultTypeLocked(file, typ, at)
						remainder = ""
						break
					}
					typ = i.invocationResultTypeLocked(file, typ, at)
					remainder = strings.TrimSpace(remainder[end+1:])
				}
				if remainder == "" {
					return typ
				}
			}
		}
	}
	switch {
	case expression == "true" || expression == "false":
		if file.Language == analysis.LanguageJava {
			return "boolean"
		}
		return "Boolean"
	case strings.HasPrefix(expression, "\"") || strings.HasPrefix(expression, "\"\"\""):
		return "String"
	case strings.HasPrefix(expression, "'"):
		if file.Language == analysis.LanguageJava {
			return "char"
		}
		return "Char"
	case numericExpression(expression, file.Language == analysis.LanguageKotlin):
		if strings.ContainsAny(expression, ".eEfFdD") {
			if file.Language == analysis.LanguageJava {
				return "double"
			}
			return "Double"
		}
		if strings.HasSuffix(strings.ToLower(expression), "l") {
			if file.Language == analysis.LanguageJava {
				return "long"
			}
			return "Long"
		}
		if file.Language == analysis.LanguageJava {
			return "int"
		}
		return "Int"
	}
	if strings.HasPrefix(expression, "new ") {
		expression = strings.TrimSpace(strings.TrimPrefix(expression, "new "))
	}
	if firstTopLevelIndexOpen(expression) > 0 && strings.HasSuffix(expression, "]") || file.Language == analysis.LanguageKotlin && strings.HasSuffix(expression, "::class") {
		// Indexed access and class literals are member-chain forms the
		// expression typer already proves through operator/get lookups.
		return i.typeOfExpressionLocked(file, expression, at)
	}
	open := strings.IndexByte(expression, '(')
	if open < 0 {
		if !strings.ContainsAny(expression, " +-*/%?:[]{}") {
			if !strings.Contains(expression, ".") {
				// A name can have an inferred type (for example `val repository =
				// factory()`). Qualified resolution uses this expression path, so
				// consulting only explicit declarations made completion understand
				// the receiver while go-to-definition silently lost it. The lexical
				// lookup excludes a declaration from its own initializer through its
				// scope bounds, which also prevents recursive self-inference.
				return i.typeOfNameLocked(file, expression, at)
			}
			return i.typeOfExpressionLocked(file, expression, at)
		}
		return ""
	}
	close := callClosingParen(expression, open)
	if close >= len(expression) {
		// callClosingParen intentionally returns len on malformed input so its
		// low-level callers can avoid negative slices. A type proof, however,
		// must not treat an unterminated invocation as a real call.
		return ""
	}
	if chain := splitTopLevelMemberChain(expression); len(chain) > 1 {
		return i.typeOfExpressionLocked(file, expression, at)
	}
	callee := strings.TrimSpace(expression[:open])
	calleeQualifier := ""
	if dot := strings.LastIndexByte(callee, '.'); dot >= 0 {
		// `Context().apply { }` names an extension or member through its
		// receiver; resolving the callee as an unqualified name would rank every
		// `apply` in the universe instead of the receiver's own candidates.
		calleeQualifier = strings.TrimSuffix(strings.TrimSpace(callee[:dot]), "?")
		callee = callee[dot+1:]
	}
	callee = strings.Trim(callee, "`")
	base, explicitArguments := splitInstantiatedType(callee)
	if declared := i.declaredTypeOfNameLocked(file, base, at); declared != "" {
		if result := i.invocationResultTypeLocked(file, declared, at); result != "" {
			return result
		}
	}
	for _, symbol := range i.fileSymbolsByName[file.URI][base] {
		if analysis.IsTypeKind(symbol.Kind) || symbol.StartByte > at || !symbolInScopeAt(*symbol, at) {
			continue
		}
		if valueType := i.typeOfNameLocked(file, base, at); valueType != "" {
			if result := i.invocationResultTypeLocked(file, valueType, at); result != "" {
				return result
			}
		}
		break
	}
	callValues := splitTopLevelCallArguments(expression[open+1 : close])
	callCandidates := i.resolveLocked(file, analysis.Reference{
		Name:        base,
		Qualifier:   calleeQualifier,
		URI:         file.URI,
		StartByte:   at,
		EndByte:     at + len(base),
		ContainerID: i.containerIDAtLocked(file, at),
		Role:        analysis.RoleCall,
		Arity:       len(callValues),
	})
	if i.kotlinCollectionFactoryAvailableLocked(base, callCandidates) {
		switch base {
		case "listOf", "emptyList":
			return kotlinCollectionFactoryType(i, file, "List", explicitArguments, callValues, at)
		case "mutableListOf":
			return kotlinCollectionFactoryType(i, file, "MutableList", explicitArguments, callValues, at)
		case "setOf", "emptySet":
			return kotlinCollectionFactoryType(i, file, "Set", explicitArguments, callValues, at)
		case "mutableSetOf":
			return kotlinCollectionFactoryType(i, file, "MutableSet", explicitArguments, callValues, at)
		case "mapOf", "emptyMap":
			return i.kotlinMapFactoryTypeLocked(file, "Map", explicitArguments, callValues, at)
		case "mutableMapOf":
			return i.kotlinMapFactoryTypeLocked(file, "MutableMap", explicitArguments, callValues, at)
		case "arrayOf":
			return kotlinCollectionFactoryType(i, file, "Array", explicitArguments, callValues, at)
		}
	}
	if types := i.resolveTypeSymbolsAtLocked(file, base, at); len(types) == 1 && constructibleTypeForInference(types[0], file.Language) && callCandidatesPermitConstructor(callCandidates) {
		owner := types[0]
		arguments := explicitArguments
		if len(arguments) == 0 && len(owner.TypeParameters) > 0 {
			callArguments := callValues
			constructorOwners := []analysis.Symbol{owner}
			if owner.Kind == analysis.KindTypeAlias && owner.Type != "" {
				underlying, _ := splitInstantiatedType(owner.Type)
				constructorOwners = append(constructorOwners, i.resolveTypeSymbolsAtLocked(file, underlying, at)...)
			}
			matchingConstructors := 0
			for _, constructorOwner := range constructorOwners {
				for _, id := range i.byContainerMember[memberKey(constructorOwner.ID, constructorOwner.Name)] {
					constructor := i.symbols[id]
					if constructor.Kind != analysis.KindConstructor || constructor.ContainerID != constructorOwner.ID || !i.accessibleLocked(file, *constructor, at) || !matchesArityForLanguage(*constructor, len(callArguments), file.Language) {
						continue
					}
					inferred := make(map[string]string)
					for index, parameter := range constructor.Parameters {
						if index >= len(callArguments) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, callArguments[index], at)
						i.inferTypeParameterBindingsLocked(file, parameter.Type, actual, owner.TypeParameters, inferred)
					}
					candidateArguments := make([]string, 0, len(owner.TypeParameters))
					for _, typeParameter := range owner.TypeParameters {
						if inferred[typeParameter] == "" {
							candidateArguments = nil
							break
						}
						candidateArguments = append(candidateArguments, inferred[typeParameter])
					}
					if len(candidateArguments) == 0 {
						continue
					}
					matchingConstructors++
					if matchingConstructors > 1 {
						return ""
					}
					arguments = candidateArguments
				}
			}
			if matchingConstructors != 1 {
				return ""
			}
		}
		if len(arguments) > 0 {
			return owner.Name + "<" + strings.Join(arguments, ", ") + ">"
		}
		return owner.Name
	}
	if len(callCandidates) != 1 || !analysis.IsCallableKind(callCandidates[0].Kind) || callCandidates[0].Type == "" {
		return ""
	}
	candidate := callCandidates[0]
	result := candidate.Type
	if len(candidate.TypeParameters) == 0 {
		return result
	}
	arguments := explicitArguments
	if len(arguments) == 0 {
		inferred := make(map[string]string, len(candidate.TypeParameters))
		for parameterIndex, parameter := range candidate.Parameters {
			if parameterIndex >= len(callValues) {
				break
			}
			actual := i.inferExpressionTypeLocked(file, callValues[parameterIndex], at)
			i.inferTypeParameterBindingsLocked(file, parameter.Type, actual, candidate.TypeParameters, inferred)
		}
		for _, parameter := range candidate.TypeParameters {
			if inferred[parameter] == "" {
				return ""
			}
			arguments = append(arguments, inferred[parameter])
		}
	}
	return substituteTypeParameters(result, candidate.TypeParameters, arguments)
}

func (i *Index) kotlinCollectionFactoryAvailableLocked(name string, candidates []analysis.Symbol) bool {
	switch name {
	case "listOf", "emptyList", "mutableListOf", "setOf", "emptySet", "mutableSetOf", "mapOf", "emptyMap", "mutableMapOf", "arrayOf":
	default:
		return false
	}
	// Keep useful built-in types when a small workspace has no indexed stdlib,
	// but never let the spelling shortcut override a visible user declaration.
	if len(candidates) == 0 {
		return true
	}
	if len(candidates) != 1 {
		return false
	}
	fqn := candidates[0].FQN
	return fqn == "kotlin."+name || fqn == "kotlin.collections."+name
}

func callCandidatesPermitConstructor(candidates []analysis.Symbol) bool {
	for _, candidate := range candidates {
		if analysis.IsCallableKind(candidate.Kind) && candidate.Kind != analysis.KindConstructor {
			return false
		}
	}
	return true
}

func constructibleTypeForInference(symbol analysis.Symbol, language analysis.Language) bool {
	switch symbol.Kind {
	case analysis.KindClass, analysis.KindRecord, analysis.KindTypeAlias:
		return true
	case analysis.KindAnnotation:
		return language == analysis.LanguageKotlin
	default:
		return false
	}
}

func kotlinCollectionFactoryType(i *Index, file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) > 1 {
		return ""
	}
	if len(arguments) == 0 {
		var element string
		for _, value := range values {
			inferred := i.inferExpressionTypeLocked(file, value, at)
			if inferred == "" {
				return ""
			}
			element = i.commonExpressionTypeLocked(file, element, inferred)
			if element == "" {
				return ""
			}
		}
		if element == "" {
			element = "Nothing"
		}
		arguments = []string{element}
	}
	return collection + "<" + strings.Join(arguments, ", ") + ">"
}

func (i *Index) kotlinMapFactoryTypeLocked(file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) != 0 && len(arguments) != 2 {
		return ""
	}
	if len(arguments) == 0 {
		keyType, valueType := "", ""
		for _, value := range values {
			separator := topLevelWordIndex(value, "to")
			if separator < 0 {
				return ""
			}
			key := i.inferExpressionTypeLocked(file, value[:separator], at)
			mapped := i.inferExpressionTypeLocked(file, value[separator+len("to"):], at)
			if key == "" || mapped == "" {
				return ""
			}
			keyType = i.commonExpressionTypeLocked(file, keyType, key)
			valueType = i.commonExpressionTypeLocked(file, valueType, mapped)
			if keyType == "" || valueType == "" {
				return ""
			}
		}
		if keyType == "" {
			keyType = "Nothing"
		}
		if valueType == "" {
			valueType = "Nothing"
		}
		arguments = []string{keyType, valueType}
	}
	return collection + "<" + strings.Join(arguments, ", ") + ">"
}

func (i *Index) inferJavaCompositeExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	if strings.HasPrefix(expression, "(") {
		if close := matchingDelimiter(expression, 0, '(', ')'); close > 1 && close < len(expression)-1 {
			candidate := strings.TrimSpace(expression[1:close])
			if isJavaPrimitiveType(candidate) || len(i.resolveTypeSymbolsLocked(file, candidate)) > 0 {
				return candidate
			}
		}
	}
	if question := topLevelExpressionOperator(expression, "?"); question >= 0 {
		remainder := expression[question+1:]
		if colon := topLevelExpressionOperator(remainder, ":"); colon >= 0 {
			left := i.inferExpressionTypeLocked(file, remainder[:colon], at)
			right := i.inferExpressionTypeLocked(file, remainder[colon+1:], at)
			return i.commonExpressionTypeLocked(file, left, right)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(expression), "switch") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			if close := matchingDelimiter(expression, open, '{', '}'); close > open {
				var inferred string
				for _, entry := range splitTopLevelExpressions(expression[open+1:close], ';') {
					if arrow := strings.Index(entry, "->"); arrow >= 0 {
						branch := strings.TrimSpace(entry[arrow+2:])
						branch = strings.TrimSpace(strings.TrimPrefix(branch, "yield "))
						inferred = i.commonExpressionTypeLocked(file, inferred, i.inferExpressionTypeLocked(file, unwrapExpressionBlock(branch), at))
					}
				}
				return inferred
			}
		}
	}
	return ""
}

func isJavaPrimitiveType(value string) bool {
	switch strings.TrimSpace(value) {
	case "boolean", "byte", "short", "int", "long", "float", "double", "char":
		return true
	default:
		return false
	}
}

func unwrapEnclosingParentheses(expression string) string {
	for strings.HasPrefix(expression, "(") {
		close := matchingDelimiter(expression, 0, '(', ')')
		if close != len(expression)-1 {
			break
		}
		expression = strings.TrimSpace(expression[1:close])
	}
	return expression
}

func (i *Index) inferKotlinCompositeExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	if operator := topLevelWordIndex(expression, "to"); operator >= 0 {
		left := i.inferExpressionTypeLocked(file, expression[:operator], at)
		right := i.inferExpressionTypeLocked(file, expression[operator+len("to"):], at)
		if left != "" && right != "" {
			return "Pair<" + left + ", " + right + ">"
		}
	}
	for _, name := range []string{"run", "with"} {
		trimmed := strings.TrimSpace(expression)
		if !strings.HasPrefix(trimmed, name) {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(trimmed, name))
		if name == "with" && !strings.HasPrefix(remainder, "(") || name == "run" && !strings.HasPrefix(remainder, "{") && !strings.HasPrefix(remainder, "(") {
			continue
		}
		brace := topLevelExpressionOperator(expression, "{")
		if brace < 0 {
			continue
		}
		close := matchingDelimiter(expression, brace, '{', '}')
		if close <= brace {
			continue
		}
		body := unwrapExpressionBlock(expression[brace : close+1])
		receiver := ""
		if name == "with" {
			if open := strings.IndexByte(expression, '('); open >= 0 {
				if end := callClosingParen(expression, open); end > open && end < len(expression) {
					receiver = i.inferExpressionTypeLocked(file, expression[open+1:end], at)
				}
			}
		}
		if (body == "this" || body == "it") && receiver != "" {
			return receiver
		}
		if inferred := i.inferExpressionTypeLocked(file, body, at); inferred != "" {
			return inferred
		}
	}
	if operator := topLevelExpressionOperator(expression, "?:"); operator >= 0 {
		left := strings.TrimSuffix(strings.TrimSpace(i.inferExpressionTypeLocked(file, expression[:operator], at)), "?")
		right := i.inferExpressionTypeLocked(file, expression[operator+2:], at)
		return i.commonExpressionTypeLocked(file, left, right)
	}
	for _, operator := range []string{" as? ", " as "} {
		if index := topLevelExpressionOperator(expression, operator); index >= 0 {
			typ := strings.TrimSpace(expression[index+len(operator):])
			if operator == " as? " && typ != "" && !strings.HasSuffix(typ, "?") {
				typ += "?"
			}
			return typ
		}
	}
	if strings.HasPrefix(expression, "if") {
		open := strings.IndexByte(expression, '(')
		if open >= 0 {
			if close := matchingDelimiter(expression, open, '(', ')'); close >= 0 {
				rest := strings.TrimSpace(expression[close+1:])
				if elseAt := topLevelWordIndex(rest, "else"); elseAt >= 0 {
					left := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(rest[:elseAt]), at)
					right := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(rest[elseAt+len("else"):]), at)
					return i.commonExpressionTypeLocked(file, left, right)
				}
			}
		}
	}
	if strings.HasPrefix(expression, "when") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			close := matchingDelimiter(expression, open, '{', '}')
			if close > open {
				var inferred string
				for _, entry := range splitTopLevelExpressions(expression[open+1:close], ';') {
					if arrow := strings.Index(entry, "->"); arrow >= 0 {
						branch := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(entry[arrow+2:]), at)
						inferred = i.commonExpressionTypeLocked(file, inferred, branch)
					}
				}
				return inferred
			}
		}
	}
	if strings.HasPrefix(expression, "try") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			var inferred string
			for cursor := open; cursor >= 0 && cursor < len(expression); {
				close := matchingDelimiter(expression, cursor, '{', '}')
				if close <= cursor {
					break
				}
				inferred = i.commonExpressionTypeLocked(file, inferred, i.inferExpressionTypeLocked(file, unwrapExpressionBlock(expression[cursor:close+1]), at))
				rest := strings.TrimSpace(expression[close+1:])
				if strings.HasPrefix(rest, "finally") {
					break
				}
				if !strings.HasPrefix(rest, "catch") {
					break
				}
				next := strings.IndexByte(rest, '{')
				if next < 0 {
					break
				}
				cursor = close + 1 + strings.Index(expression[close+1:], "{")
			}
			return inferred
		}
	}
	return ""
}

func (i *Index) commonExpressionTypeLocked(file *analysis.ParsedFile, left, right string) string {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	nullable := file.Language == analysis.LanguageKotlin && (strings.HasSuffix(left, "?") || strings.HasSuffix(right, "?"))
	leftBase, rightBase := strings.TrimSuffix(left, "?"), strings.TrimSuffix(right, "?")
	applyNullability := func(value string) string {
		value = strings.TrimSuffix(strings.TrimSpace(value), "?")
		if nullable && value != "" && value != "Nothing" {
			value += "?"
		}
		return value
	}
	if file.Language == analysis.LanguageKotlin {
		if simpleType(leftBase) == "Nothing" {
			return applyNullability(rightBase)
		}
		if simpleType(rightBase) == "Nothing" {
			return applyNullability(leftBase)
		}
	}
	if identical, known := i.typesIdenticalAtLocked(file, leftBase, rightBase, -1); known && identical {
		return applyNullability(leftBase)
	}
	leftOwners := i.instantiatedTypeHierarchyLocked(file, leftBase)
	rightOwners := i.instantiatedTypeHierarchyLocked(file, rightBase)
	type ownerAtDistance struct {
		owner    instantiatedTypeOwner
		distance int
	}
	rightByID := make(map[string][]ownerAtDistance, len(rightOwners))
	for _, owner := range rightOwners {
		previous := rightByID[owner.symbol.ID]
		if len(previous) == 0 || owner.distance < previous[0].distance {
			rightByID[owner.symbol.ID] = []ownerAtDistance{{owner: owner, distance: owner.distance}}
		} else if owner.distance == previous[0].distance {
			rightByID[owner.symbol.ID] = append(previous, ownerAtDistance{owner: owner, distance: owner.distance})
		}
	}
	bestScore := int(^uint(0) >> 1)
	bestName := ""
	bestOwnerID := ""
	bestAmbiguous := false
	for _, owner := range leftOwners {
		for _, rightOwner := range rightByID[owner.symbol.ID] {
			score := owner.distance + rightOwner.distance
			candidateName := commonInstantiatedOwnerName(file.Language, owner, rightOwner.owner)
			if score < bestScore {
				bestScore, bestName, bestOwnerID = score, candidateName, owner.symbol.ID
				bestAmbiguous = false
			} else if score == bestScore && (owner.symbol.ID != bestOwnerID || candidateName != bestName) {
				// Multiple unrelated owners or distinct instantiations at the
				// same graph distance require language variance/intersection
				// rules. Traversal order is not a LUB proof.
				bestAmbiguous = true
			}
		}
	}
	if bestScore != int(^uint(0)>>1) && !bestAmbiguous {
		return applyNullability(bestName)
	}
	// Missing dependency graph data is an unknown, not proof that Object/Any is
	// the least upper bound. Callers can abstain instead of exporting a broad,
	// falsely precise type.
	return ""
}

func commonInstantiatedOwnerName(language analysis.Language, left, right instantiatedTypeOwner) string {
	name := left.symbol.FQN
	if name == "" {
		name = left.symbol.Name
	}
	if len(left.arguments) != len(right.arguments) || len(left.arguments) == 0 {
		return name
	}
	arguments := make([]string, len(left.arguments))
	for index := range arguments {
		// Declaration-site variance is not available for every binary and
		// source owner. Recursively LUB-ing invariant arguments invents an
		// unsound List<Common>; preserve only exact arguments and otherwise use
		// the language's explicit unknown projection.
		if sameJvmType(left.arguments[index], right.arguments[index]) {
			arguments[index] = left.arguments[index]
		} else if language == analysis.LanguageKotlin {
			arguments[index] = "*"
		} else {
			arguments[index] = "?"
		}
	}
	return instantiatedTypeName(name, arguments)
}

func topLevelExpressionOperator(expression, operator string) int {
	if strings.TrimSpace(operator) == operator {
		if index := lexical.TopLevelTokenIndex(expression, operator, true); index >= 0 {
			return index
		}
	}
	parens, brackets, braces, angles := 0, 0, 0, 0
	for index := 0; index+len(operator) <= len(expression); index++ {
		if parens == 0 && brackets == 0 && braces == 0 && angles == 0 && strings.HasPrefix(expression[index:], operator) {
			return index
		}
		switch expression[index] {
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		}
	}
	return -1
}

func topLevelWordIndex(expression, word string) int {
	for search := 0; search < len(expression); {
		index := strings.Index(expression[search:], word)
		if index < 0 {
			return -1
		}
		index += search
		if topLevelExpressionOperator(expression, expression[index:index+len(word)]) == index && (index == 0 || !isIdentRune(rune(expression[index-1]))) && (index+len(word) == len(expression) || !isIdentRune(rune(expression[index+len(word)]))) {
			return index
		}
		search = index + len(word)
	}
	return -1
}

func splitTopLevelExpressions(expression string, separator byte) []string {
	return lexical.SplitTopLevel(expression, string(separator), true)
}

func unwrapExpressionBlock(expression string) string {
	expression = strings.TrimSpace(expression)
	if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
		expression = strings.TrimSpace(expression[1 : len(expression)-1])
		if statements := splitTopLevelExpressions(expression, ';'); len(statements) > 0 {
			return statements[len(statements)-1]
		}
	}
	return expression
}

func (i *Index) declaredTypeOfNameLocked(file *analysis.ParsedFile, name string, at int) string {
	best, bestStart := "", -1
	for _, symbol := range file.Symbols {
		inScope := !isLexicalSymbol(symbol) || symbolInScopeAt(symbol, at)
		if symbol.Name == name && symbol.Type != "" && symbol.StartByte <= at && symbol.StartByte >= bestStart && inScope {
			best, bestStart = symbol.Type, symbol.StartByte
		}
	}
	return best
}

func callClosingParen(expression string, open int) int {
	if close := lexical.MatchingDelimiter(expression, open, "(", ")", true); close >= 0 {
		return close
	}
	return len(expression)
}

func splitTopLevelCallArguments(value string) []string {
	return lexical.SplitTopLevel(value, ",", true)
}

func numericExpression(value string, kotlin bool) bool {
	tokens, complete := lexical.TokenizeBounded(value, kotlin, 2)
	return complete && len(tokens) == 1 && tokens[0].Kind == lexical.Number && tokens[0].Start == 0 && tokens[0].End == len(value)
}

func (i *Index) typeOfExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	nullableResult := false
	if file.Language == analysis.LanguageKotlin {
		nullableResult = strings.Contains(expression, "?.") && !strings.HasSuffix(expression, "!!")
		expression = strings.ReplaceAll(expression, "?.", ".")
		expression = strings.ReplaceAll(expression, "!!", "")
		if strings.HasSuffix(expression, "::class") {
			literal := strings.TrimSpace(strings.TrimSuffix(expression, "::class"))
			if literalType := i.typeOfExpressionLocked(file, literal, at); literalType != "" {
				return "KClass<" + literalType + ">"
			}
		}
	}
	if !strings.Contains(expression, ".") {
		if strings.Contains(expression, "[") {
			return i.indexedExpressionTypeLocked(file, expression, at)
		}
		if strings.Contains(expression, "(") {
			return i.inferExpressionTypeLocked(file, expression, at)
		}
		return i.typeOfNameLocked(file, expression, at)
	}
	parts := splitTopLevelMemberChain(expression)
	if len(parts) == 0 {
		return ""
	}
	typ := i.typeOfNameLocked(file, parts[0], at)
	if file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(parts[0]), "::class") {
		literal := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[0]), "::class"))
		if literalType := i.typeOfExpressionLocked(file, literal, at); literalType != "" {
			typ = "KClass<" + literalType + ">"
		}
	} else if strings.Contains(parts[0], "[") {
		typ = i.indexedExpressionTypeLocked(file, parts[0], at)
	} else if strings.Contains(parts[0], "(") {
		typ = i.inferExpressionTypeLocked(file, parts[0], at)
	}
	for _, member := range parts[1:] {
		if typ == "" {
			return ""
		}
		memberName := member
		callArguments := []string(nil)
		call := false
		if open := strings.IndexByte(member, '('); open >= 0 {
			call = true
			memberName = strings.TrimSpace(member[:open])
			close := callClosingParen(member, open)
			if close >= len(member) {
				return ""
			}
			callArguments = splitTopLevelCallArguments(member[open+1 : close])
			if callArguments == nil {
				callArguments = make([]string, 0)
			}
		} else if open := strings.IndexByte(member, '{'); open >= 0 && strings.HasSuffix(strings.TrimSpace(member), "}") {
			call = true
			memberName = strings.TrimSpace(member[:open])
			callArguments = []string{strings.TrimSpace(member[open:])}
		}
		next := ""
		if file.Language == analysis.LanguageJava && !call && memberName == "class" {
			next = "Class<" + typ + ">"
		}
		if file.Language == analysis.LanguageKotlin {
			base, arguments := splitInstantiatedType(typ)
			if len(arguments) > 1 && simpleType(base) == "Pair" {
				if memberName == "first" {
					next = arguments[0]
				} else if memberName == "second" {
					next = arguments[1]
				}
			}
			if call && len(arguments) > 0 && (simpleType(base) == "Set" || simpleType(base) == "MutableSet" || simpleType(base) == "List" || simpleType(base) == "MutableList" || simpleType(base) == "Collection" || simpleType(base) == "Iterable" || simpleType(base) == "Sequence") {
				switch memberName {
				case "first", "last", "single", "random":
					next = arguments[0]
				case "firstOrNull", "lastOrNull", "singleOrNull", "randomOrNull":
					next = strings.TrimSuffix(strings.TrimSpace(arguments[0]), "?") + "?"
				}
			}
			if call && len(callArguments) > 0 {
				body := unwrapExpressionBlock(callArguments[len(callArguments)-1])
				switch memberName {
				case "apply", "also":
					next = typ
				case "let", "run":
					if body == "it" || body == "this" {
						next = typ
					} else if inferred := i.inferExpressionTypeLocked(file, body, at); inferred != "" {
						next = inferred
					}
				}
			}
		}
		if next == "" {
			var found bool
			next, found = i.uniqueDirectMemberResultTypeLocked(file, typ, memberName, call, len(callArguments), at)
			if found && next == "" {
				return ""
			}
		}
		if next == "" && file.Language == analysis.LanguageKotlin {
			var ambiguous bool
			next, ambiguous = i.uniqueExtensionResultTypeLocked(file, typ, memberName, call, callArguments, at)
			if ambiguous {
				return ""
			}
		}
		typ = next
	}
	if nullableResult && typ != "" && !strings.HasSuffix(strings.TrimSpace(typ), "?") {
		return typ + "?"
	}
	return typ
}

func (i *Index) memberResultTypeLocked(file *analysis.ParsedFile, receiverType, name string, at int) string {
	if result, found := i.uniqueDirectMemberResultTypeLocked(file, receiverType, name, true, -1, at); found {
		return result
	}
	if file.Language == analysis.LanguageKotlin {
		if result, ambiguous := i.uniqueExtensionResultTypeLocked(file, receiverType, name, true, nil, at); !ambiguous {
			return result
		}
	}
	return ""
}

// uniqueDirectMemberResultTypeLocked returns the result from the nearest
// declaring type only when exactly one accessible member matches. found is
// true even for an ambiguous set so callers do not incorrectly fall through
// to an extension method when a real member shadows it.
func (i *Index) uniqueDirectMemberResultTypeLocked(file *analysis.ParsedFile, receiverType, name string, callable bool, arity, at int) (result string, found bool) {
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, receiverType) {
		owner, arguments := instantiated.symbol, instantiated.arguments
		matches := 0
		for _, id := range i.byContainerMember[memberKey(owner.ID, name)] {
			member := i.symbols[id]
			if member.ContainerID != owner.ID || member.Type == "" || callable != analysis.IsCallableKind(member.Kind) || !i.accessibleLocked(file, *member, at) {
				continue
			}
			if callable && arity >= 0 && !matchesArityForLanguage(*member, arity, file.Language) {
				continue
			}
			matches++
			if matches == 1 {
				result = substituteTypeParameters(member.Type, owner.TypeParameters, arguments)
			} else {
				result = ""
			}
		}
		if matches > 0 {
			return result, true
		}
	}
	return "", false
}

// uniqueExtensionResultTypeLocked applies the parts of extension overload
// filtering the source model can prove. The second result reports ambiguity;
// no result and no ambiguity means that no extension was applicable.
func (i *Index) uniqueExtensionResultTypeLocked(file *analysis.ParsedFile, receiverType, name string, callable bool, callArguments []string, at int) (result string, ambiguous bool) {
	seen := make(map[string]bool)
	matches := 0
	hierarchy := i.instantiatedTypeHierarchyLocked(file, receiverType)
	owners := make([]analysis.Symbol, 0, len(hierarchy))
	for _, instantiated := range hierarchy {
		owners = append(owners, instantiated.symbol)
	}
	if len(owners) == 0 {
		owners = spellingReceiverOwners(receiverType)
	}
	for _, owner := range owners {
		for _, id := range i.extensionMemberCandidatesLocked(owner, name) {
			if seen[id] {
				continue
			}
			seen[id] = true
			extension := i.symbols[id]
			if extension.Type == "" || callable != analysis.IsCallableKind(extension.Kind) || !i.accessibleLocked(file, *extension, at) || !i.extensionVisibleLocked(file, *extension, at) {
				continue
			}
			bindings, applicable := i.extensionReceiverBindingsLocked(file, *extension, receiverType)
			if !applicable || callable && callArguments != nil && !matchesArityForLanguage(*extension, len(callArguments), file.Language) {
				continue
			}
			parameters := make(map[string]bool, len(extension.TypeParameters))
			for _, parameter := range extension.TypeParameters {
				parameters[parameter] = true
			}
			for index, argument := range callArguments {
				if index >= len(extension.Parameters) {
					break
				}
				actual := i.inferExpressionTypeLocked(file, argument, at)
				if actual == "" || !matchTypePattern(extension.Parameters[index].Type, actual, parameters, bindings) {
					applicable = false
					break
				}
			}
			if !applicable {
				continue
			}
			matches++
			if matches == 1 {
				result = substituteTypeBindings(extension.Type, bindings)
			} else {
				return "", true
			}
		}
	}
	return result, false
}

func (i *Index) invocationResultTypeLocked(file *analysis.ParsedFile, receiverType string, at int) string {
	receiverType = strings.TrimSpace(strings.TrimSuffix(receiverType, "?"))
	if arrow := strings.LastIndex(receiverType, "->"); arrow >= 0 {
		return strings.TrimSpace(receiverType[arrow+2:])
	}
	return i.memberResultTypeLocked(file, receiverType, "invoke", at)
}

func (i *Index) indexedExpressionTypeLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	open := firstTopLevelIndexOpen(expression)
	if open <= 0 {
		return ""
	}
	typ := i.typeOfExpressionLocked(file, strings.TrimSpace(expression[:open]), at)
	for open >= 0 && open < len(expression) {
		close := matchingDelimiter(expression, open, '[', ']')
		if close < 0 || typ == "" {
			return ""
		}
		if strings.HasSuffix(strings.TrimSpace(typ), "[]") {
			typ = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(typ), "[]"))
		} else {
			next, found := i.uniqueDirectMemberResultTypeLocked(file, typ, "get", true, 1, at)
			if found && next == "" {
				return ""
			}
			if next == "" {
				base, arguments := splitInstantiatedType(typ)
				if (simpleType(base) == "Array" || simpleType(base) == "List" || simpleType(base) == "MutableList") && len(arguments) > 0 {
					next = arguments[0]
				} else if (simpleType(base) == "Map" || simpleType(base) == "MutableMap") && len(arguments) > 1 {
					next = arguments[1]
					if file.Language == analysis.LanguageKotlin && !strings.HasSuffix(strings.TrimSpace(next), "?") {
						next += "?"
					}
				}
			}
			typ = next
		}
		remainder := strings.TrimSpace(expression[close+1:])
		if remainder == "" {
			break
		}
		if remainder[0] != '[' {
			return ""
		}
		open = close + 1 + strings.Index(expression[close+1:], "[")
	}
	return typ
}

func firstTopLevelIndexOpen(expression string) int {
	parens, braces, angles := 0, 0, 0
	for index := 0; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		case '[':
			if parens == 0 && braces == 0 && angles == 0 {
				return index
			}
		}
	}
	return -1
}

func splitTopLevelMemberChain(expression string) []string {
	start, parens, brackets, braces, angles := 0, 0, 0, 0, 0
	var result []string
	for index := 0; index <= len(expression); index++ {
		if index == len(expression) || expression[index] == '.' && parens == 0 && brackets == 0 && braces == 0 && angles == 0 {
			if part := strings.TrimSpace(expression[start:index]); part != "" {
				result = append(result, part)
			}
			start = index + 1
			continue
		}
		switch expression[index] {
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		}
	}
	return result
}

func kotlinNullableMemberAccessAllowed(source string, memberStart int) bool {
	if memberStart >= 2 && memberStart <= len(source) && source[memberStart-1] == '.' && source[memberStart-2] == '?' {
		return true
	}
	return memberStart >= 3 && memberStart <= len(source) && source[memberStart-1] == '.' && source[memberStart-2] == '!' && source[memberStart-3] == '!'
}

// operatorTypable lists the operators whose result type follows from operand
// types alone. Elvis, `to`, casts and type tests keep their dedicated paths.
func operatorTypable(operator string) bool {
	switch operator {
	case "+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!":
		return true
	}
	return false
}

// inferOperatorExpressionLocked applies JLS 5.6.2 binary numeric promotion or
// Kotlin's numeric operator conventions to operand evidence. Confidence is
// exact only when every operand is exact; any operand without evidence, or
// any combination the rules do not define, abstains rather than guessing.
func (i *Index) inferOperatorExpressionLocked(file *analysis.ParsedFile, ir expressionIR, at, depth int) inferredExpressionType {
	result := inferredExpressionType{Expression: ir}
	if depth > 64 {
		return result
	}
	kotlin := file.Language == analysis.LanguageKotlin
	boolean := "Boolean"
	if !kotlin {
		boolean = "boolean"
	}
	operands := make([]inferredExpressionType, 0, len(ir.Children))
	confidence := inferenceExact
	for _, child := range ir.Children {
		operand := i.inferExpressionResultDepthLocked(file, child.Text, at, depth+1)
		if operand.Confidence == inferenceUnknown {
			confidence = inferenceUnknown
		} else if operand.Confidence < confidence {
			confidence = operand.Confidence
		}
		operands = append(operands, operand)
	}
	typed := func(typ string) inferredExpressionType {
		if typ == "" {
			return result
		}
		result.Type, result.Confidence = typ, confidence
		if result.Confidence == inferenceUnknown {
			result.Confidence = inferenceConservative
		}
		return result
	}
	switch ir.Kind {
	case expressionUnary:
		if len(operands) != 1 || operands[0].Type == "" {
			return result
		}
		operand := operands[0].Type
		switch ir.Operator {
		case "!":
			if isBooleanType(file.Language, operand) {
				return typed(boolean)
			}
			if kotlin {
				return typed(i.memberResultTypeLocked(file, operand, "not", at))
			}
		case "-", "+":
			if rank, ok := numericRank(file.Language, operand); ok {
				return typed(numericTypeForRank(file.Language, max(rank, numericRankInt)))
			}
			if kotlin {
				name := map[string]string{"-": "unaryMinus", "+": "unaryPlus"}[ir.Operator]
				return typed(i.memberResultTypeLocked(file, operand, name, at))
			}
		}
		return result
	case expressionBinary:
		if len(operands) != 2 {
			return result
		}
		left, right := operands[0].Type, operands[1].Type
		switch ir.Operator {
		case "==", "!=", "<", ">", "<=", ">=":
			// Equality and comparison always yield a boolean; operand
			// evidence only affects confidence.
			if confidence == inferenceUnknown {
				confidence = inferenceConservative
			}
			return typed(boolean)
		case "&&", "||":
			if confidence == inferenceUnknown {
				confidence = inferenceConservative
			}
			return typed(boolean)
		}
		if left == "" || right == "" {
			return result
		}
		if ir.Operator == "+" {
			if kotlin && isStringType(file.Language, left) || !kotlin && (isStringType(file.Language, left) || isStringType(file.Language, right)) {
				return typed("String")
			}
		}
		leftRank, leftNumeric := numericRank(file.Language, left)
		rightRank, rightNumeric := numericRank(file.Language, right)
		if leftNumeric && rightNumeric {
			return typed(numericTypeForRank(file.Language, max(leftRank, rightRank, numericRankInt)))
		}
		if kotlin {
			leftChar, rightChar := simpleType(strings.TrimSpace(left)) == "Char", simpleType(strings.TrimSpace(right)) == "Char"
			switch {
			case leftChar && rightChar && ir.Operator == "-":
				return typed("Int")
			case leftChar && rightNumeric && rightRank == numericRankInt && (ir.Operator == "+" || ir.Operator == "-"):
				return typed("Char")
			case !leftChar:
				name := map[string]string{"+": "plus", "-": "minus", "*": "times", "/": "div", "%": "rem"}[ir.Operator]
				if name != "" && !leftNumeric {
					return typed(i.memberResultTypeLocked(file, left, name, at))
				}
			}
		}
	}
	return result
}

const (
	numericRankByte = iota + 1
	numericRankShort
	numericRankInt
	numericRankLong
	numericRankFloat
	numericRankDouble
)

func numericRank(language analysis.Language, typ string) (int, bool) {
	name := simpleType(strings.TrimSpace(typ))
	if language == analysis.LanguageJava {
		switch name {
		case "byte", "Byte":
			return numericRankByte, true
		case "short", "Short":
			return numericRankShort, true
		case "char", "Character", "int", "Integer":
			return numericRankInt, true
		case "long", "Long":
			return numericRankLong, true
		case "float", "Float":
			return numericRankFloat, true
		case "double", "Double":
			return numericRankDouble, true
		}
		return 0, false
	}
	switch name {
	case "Byte":
		return numericRankByte, true
	case "Short":
		return numericRankShort, true
	case "Int":
		return numericRankInt, true
	case "Long":
		return numericRankLong, true
	case "Float":
		return numericRankFloat, true
	case "Double":
		return numericRankDouble, true
	}
	return 0, false
}

func numericTypeForRank(language analysis.Language, rank int) string {
	kotlin := []string{"", "Byte", "Short", "Int", "Long", "Float", "Double"}
	java := []string{"", "byte", "short", "int", "long", "float", "double"}
	if rank < numericRankByte || rank > numericRankDouble {
		return ""
	}
	if language == analysis.LanguageJava {
		return java[rank]
	}
	return kotlin[rank]
}

func isBooleanType(language analysis.Language, typ string) bool {
	name := simpleType(strings.TrimSpace(typ))
	if language == analysis.LanguageJava {
		return name == "boolean" || name == "Boolean"
	}
	return name == "Boolean"
}

func isStringType(language analysis.Language, typ string) bool {
	return simpleType(strings.TrimSpace(typ)) == "String"
}
