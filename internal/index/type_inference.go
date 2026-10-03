package index

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
)

func (i *Index) typeOfNameLocked(ctx context.Context, file *analysis.ParsedFile, name string, at int) string {
	if name == "this" && file.Language == analysis.LanguageKotlin {
		// The innermost receiver: a lambda with one, an extension function's,
		// then the class. Only the class was asked before, so `this` in a
		// top-level extension function had no type at all.
		best, bestStart := "", -1
		if enclosing := i.enclosingTypeLocked(file, at); enclosing.ID != "" {
			best, bestStart = enclosing.Name, enclosing.StartByte
		}
		if receiver, start := i.enclosingExtensionReceiverLocked(file, at); receiver != "" && start > bestStart {
			best, bestStart = receiver, start
		}
		if receiver, start := i.contextualLambdaReceiverLocked(ctx, file, at); receiver != "" && start > bestStart {
			best = receiver
		}
		if best == "" {
			// A build script's own `this` is its template, which is the Project.
			if receivers := gradleScriptReceiverTypes(file); len(receivers) > 0 {
				best = receivers[len(receivers)-1]
			}
		}
		if best != "" {
			return best
		}
	}
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
			best = i.inferredConventionBindingTypeLocked(ctx, file, *symbol)
			if best == "" && symbol.Initializer != "" {
				best = i.inferExpressionTypeLocked(ctx, file, symbol.Initializer, symbol.StartByte)
			}
		}
		break
	}
	stableSmartCast := bestSymbol != nil && i.kotlinSmartCastStableLocked(ctx, file, *bestSymbol, at)
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
		if contextual := i.contextualLambdaParameterTypeLocked(ctx, file, *bestSymbol); contextual != "" {
			return contextual
		}
	}
	if symbols := i.resolveTypeSymbolsAtLocked(file, name, at); len(symbols) == 1 {
		return symbols[0].FQN
	}
	// A value declared elsewhere -- an imported top-level property such as a
	// generated jOOQ table (`COLORS`), an object's constant, a member of the
	// enclosing class or of an implicit receiver -- has the type its
	// declaration states, spelled the way its own file spelled it.
	if bestSymbol == nil {
		return i.resolvedValueTypeLocked(ctx, file, name, at)
	}
	return ""
}

// resolvedValueTypeLocked resolves a bare name as a value at offset and
// returns the declared type of the one value it binds to, or "".
func (i *Index) resolvedValueTypeLocked(ctx context.Context, file *analysis.ParsedFile, name string, at int) string {
	if name == "" || strings.ContainsAny(name, " .()<>[]{}") {
		return ""
	}
	resolved := i.resolveLocked(ctx, file, analysis.Reference{
		Name: name, URI: file.URI, StartByte: at, EndByte: at + len(name),
		ContainerID: i.containerIDAtLocked(file, at), Role: analysis.RoleRead, Arity: -1, Synthetic: true,
	})
	if len(resolved) != 1 {
		return ""
	}
	symbol := resolved[0]
	switch symbol.Kind {
	case analysis.KindProperty, analysis.KindField, analysis.KindVariable, analysis.KindParameter, analysis.KindEnumMember:
	default:
		return ""
	}
	typ := symbol.Type
	if typ == "" || typ == "val" || typ == "var" {
		declaring := i.files[symbol.URI]
		if declaring == nil || symbol.Initializer == "" {
			return ""
		}
		typ = i.inferExpressionTypeLocked(ctx, declaring, symbol.Initializer, symbol.StartByte)
		if typ == "" {
			return ""
		}
	}
	if symbol.Kind == analysis.KindEnumMember && symbol.ContainerName != "" {
		typ = symbol.ContainerName
	}
	return i.respellDeclaredTypeLocked(file, symbol, typ)
}

// kotlinSmartCastStableLocked enforces the part of Kotlin's stability contract
// the fast model can prove. Parameters and local vals are immutable bindings;
// mutable locals, properties/getters, fields, and unresolved writes abstain.
// This deliberately narrows the optimization instead of pretending that a
// syntax span is a complete control-flow/stability proof.
func (i *Index) kotlinSmartCastStableLocked(ctx context.Context, file *analysis.ParsedFile, symbol analysis.Symbol, at int) bool {
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
		resolved := i.resolveLocked(ctx, file, reference)
		if len(resolved) != 1 || resolved[0].ID == symbol.ID {
			return false
		}
	}
	return true
}

func (i *Index) inferredConventionBindingTypeLocked(ctx context.Context, file *analysis.ParsedFile, symbol analysis.Symbol) string {
	text := i.documentTextLocked(file.URI)
	for _, reference := range file.References {
		if strings.HasPrefix(reference.Name, "component") && reference.StartByte <= symbol.NameStartByte && symbol.NameEndByte <= reference.EndByte {
			receiver := i.inferExpressionTypeLocked(ctx, file, reference.Qualifier, symbol.StartByte)
			if receiver != "" {
				return i.memberResultTypeLocked(ctx, file, receiver, reference.Name, symbol.StartByte)
			}
		}
		if reference.Name != "next" || reference.StartByte < symbol.NameEndByte || reference.StartByte > symbol.ScopeEndByte || symbol.NameEndByte > len(text) || reference.EndByte > len(text) {
			continue
		}
		between := strings.TrimSpace(text[symbol.NameEndByte:reference.EndByte])
		if between != "in" {
			continue
		}
		iteratorType := i.typeOfExpressionLocked(ctx, file, reference.Qualifier, reference.StartByte)
		if iteratorType != "" {
			return i.memberResultTypeLocked(ctx, file, iteratorType, "next", reference.StartByte)
		}
	}
	return ""
}

func (i *Index) inferExpressionTypeLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
	return i.inferExpressionResultLocked(ctx, file, expression, at).Type
}

// inferExpressionResultLocked exposes whether the measured syntax fast path
// proved a type or merely derived a conservative candidate. Callers which can
// mutate source or choose one overload may require inferenceExact; ordinary
// display features can use a conservative result. Unknown syntax remains an
// explicit abstention for the background compiler rather than fabricated Any.
func (i *Index) inferExpressionResultLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) inferredExpressionType {
	if ctx.Err() != nil || resolutionNestingExceeded(ctx) {
		return inferredExpressionType{}
	}
	return i.inferExpressionResultDepthLocked(withResolutionDepth(ctx, resolutionDepth(ctx)+1), file, expression, at, 0)
}

// inferExpressionResultContextLocked carries the caller's resolution nesting
// depth, so inference that re-enters resolution counts against the same bound
// rather than starting a fresh one each time around the cycle.
func (i *Index) inferExpressionResultContextLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) inferredExpressionType {
	return i.inferExpressionResultLocked(ctx, file, expression, at)
}

func (i *Index) inferExpressionResultDepthLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at, depth int) inferredExpressionType {
	ir := parseExpressionIR(expression, file.Language)
	if (ir.Kind == expressionBinary || ir.Kind == expressionUnary) && operatorTypable(ir.Operator) {
		// Operator expressions are typed from their operands: the language's
		// numeric promotion and boolean/string rules are the proof, so the
		// textual fast paths (which would read `f(1) + 2` as `f(1)`) never see
		// them. Anything the rules do not cover abstains.
		return i.inferOperatorExpressionLocked(ctx, file, ir, at, depth)
	}
	typ := i.inferExpressionTypeValueLocked(ctx, file, expression, at)
	if typ == "" {
		return inferredExpressionType{Expression: ir}
	}
	if file.Language == analysis.LanguageKotlin {
		typ = kotlinViewOfJavaType(typ)
	}
	confidence := inferenceConservative
	switch ir.Kind {
	case expressionLiteral, expressionCast:
		confidence = inferenceExact
	}
	return inferredExpressionType{Type: typ, Confidence: confidence, Expression: ir}
}

func (i *Index) inferExpressionTypeValueLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(strings.TrimSuffix(expression, ";"))
	expression = unwrapEnclosingParentheses(expression)
	if file.Language == analysis.LanguageKotlin {
		if strings.HasPrefix(expression, "by ") {
			delegate := strings.TrimSpace(strings.TrimPrefix(expression, "by "))
			if open := topLevelExpressionOperator(delegate, "{"); open >= 0 {
				if close := matchingDelimiter(delegate, open, '{', '}'); close > open {
					body := unwrapExpressionBlock(delegate[open : close+1])
					return i.inferExpressionTypeLocked(ctx, file, body, at)
				}
			}
			if delegateType := i.inferExpressionTypeLocked(ctx, file, delegate, at); delegateType != "" {
				return i.memberResultTypeLocked(ctx, file, delegateType, "getValue", at)
			}
		}
		if inferred := i.inferKotlinCompositeExpressionLocked(ctx, file, expression, at); inferred != "" {
			return inferred
		}
		if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
			body := strings.TrimSpace(expression[1 : len(expression)-1])
			parameters := ""
			if arrow := topLevelExpressionOperator(body, "->"); arrow >= 0 {
				parameters = strings.TrimSpace(body[:arrow])
				body = strings.TrimSpace(body[arrow+2:])
			}
			result := i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock("{"+body+"}"), at)
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
	} else if inferred := i.inferJavaCompositeExpressionLocked(ctx, file, expression, at); inferred != "" {
		return inferred
	}
	if open := strings.IndexByte(expression, '('); open >= 0 {
		if close := callClosingParen(expression, open); close >= open && close < len(expression)-1 {
			remainder := strings.TrimSpace(expression[close+1:])
			if strings.HasPrefix(remainder, "(") {
				typ := i.inferExpressionTypeLocked(ctx, file, expression[:close+1], at)
				for strings.HasPrefix(remainder, "(") && typ != "" {
					end := callClosingParen(remainder, 0)
					if end < 0 || end >= len(remainder) {
						typ = i.invocationResultTypeLocked(ctx, file, typ, at)
						remainder = ""
						break
					}
					typ = i.invocationResultTypeLocked(ctx, file, typ, at)
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
		return i.typeOfExpressionLocked(ctx, file, expression, at)
	}
	open := strings.IndexByte(expression, '(')
	if open < 0 {
		// A call written with a trailing lambda has no parentheses at all:
		// `token.let { it }`, `account?.takeIf { it.active }`. Those contain a
		// brace and a space, so the punctuation test below abandoned them here
		// even though the member-chain typer proves them -- which cost the type
		// of every value produced by a scope function.
		if parts := splitTopLevelMemberChain(expression); len(parts) > 1 && strings.HasSuffix(strings.TrimSpace(expression), "}") {
			return i.typeOfExpressionLocked(ctx, file, expression, at)
		}
		if !strings.ContainsAny(expression, " +-*/%?:[]{}") {
			if !strings.Contains(expression, ".") {
				// A name can have an inferred type (for example `val repository =
				// factory()`). Qualified resolution uses this expression path, so
				// consulting only explicit declarations made completion understand
				// the receiver while go-to-definition silently lost it. The lexical
				// lookup excludes a declaration from its own initializer through its
				// scope bounds, which also prevents recursive self-inference.
				return i.typeOfNameLocked(ctx, file, expression, at)
			}
			return i.typeOfExpressionLocked(ctx, file, expression, at)
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
		return i.typeOfExpressionLocked(ctx, file, expression, at)
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
		if result := i.invocationResultTypeLocked(ctx, file, declared, at); result != "" {
			return result
		}
	}
	for _, symbol := range i.fileSymbolsByName[file.URI][base] {
		if analysis.IsTypeKind(symbol.Kind) || symbol.StartByte > at || !symbolInScopeAt(*symbol, at) {
			continue
		}
		if valueType := i.typeOfNameLocked(ctx, file, base, at); valueType != "" {
			if result := i.invocationResultTypeLocked(ctx, file, valueType, at); result != "" {
				return result
			}
		}
		break
	}
	callValues := splitTopLevelCallArguments(expression[open+1 : close])
	// This reference names the callee of the expression being analysed, which
	// is spelled inside `expression` rather than at `at`. It borrows `at` only
	// for scope, so it is synthetic: resolution must not re-derive its
	// qualifier from the source text there.
	callCandidates := i.resolveContextLocked(withResolutionDepth(ctx, resolutionDepth(ctx)+1), file, analysis.Reference{
		Name:        base,
		Qualifier:   calleeQualifier,
		URI:         file.URI,
		StartByte:   at,
		EndByte:     at + len(base),
		ContainerID: i.containerIDAtLocked(file, at),
		Role:        analysis.RoleCall,
		Arity:       len(callValues),
		Synthetic:   true,
	})
	// A synthetic reference carries no argument ranges, so resolution cannot
	// weigh a callable reference argument; the argument text can.
	callCandidates = i.filterByCallableReferenceArityLocked(ctx, file, callCandidates, callValues, at)
	if i.kotlinCollectionFactoryAvailableLocked(base, callCandidates) {
		switch base {
		case "listOf", "emptyList":
			return kotlinCollectionFactoryType(ctx, i, file, "List", explicitArguments, callValues, at)
		case "mutableListOf":
			return kotlinCollectionFactoryType(ctx, i, file, "MutableList", explicitArguments, callValues, at)
		case "setOf", "emptySet":
			return kotlinCollectionFactoryType(ctx, i, file, "Set", explicitArguments, callValues, at)
		case "mutableSetOf":
			return kotlinCollectionFactoryType(ctx, i, file, "MutableSet", explicitArguments, callValues, at)
		case "mapOf", "emptyMap":
			return i.kotlinMapFactoryTypeLocked(ctx, file, "Map", explicitArguments, callValues, at)
		case "mutableMapOf":
			return i.kotlinMapFactoryTypeLocked(ctx, file, "MutableMap", explicitArguments, callValues, at)
		case "arrayOf":
			return kotlinCollectionFactoryType(ctx, i, file, "Array", explicitArguments, callValues, at)
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
						actual := i.inferExpressionTypeLocked(ctx, file, callArguments[index], at)
						i.inferTypeParameterBindingsLocked(ctx, file, parameter.Type, actual, owner.TypeParameters, inferred)
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
	if len(callCandidates) != 1 || !analysis.IsCallableKind(callCandidates[0].Kind) {
		return ""
	}
	candidate := callCandidates[0]
	result := candidate.Type
	if result == "" {
		result = i.kotlinExpressionBodyResultTypeLocked(ctx, candidate)
	}
	if result == "" {
		return ""
	}
	// The declaration's own imports name its result: a Java `RecordMapper`
	// is `org.jooq.RecordMapper` whether or not this file imports it.
	result = i.respellDeclaredTypeLocked(file, candidate, result)
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
			actual := i.inferExpressionTypeLocked(ctx, file, callValues[parameterIndex], at)
			i.inferTypeParameterBindingsLocked(ctx, file, parameter.Type, actual, candidate.TypeParameters, inferred)
		}
		for _, parameter := range candidate.TypeParameters {
			if inferred[parameter] == "" {
				// Not every parameter binds from argument types: jOOQ's
				// `mapping(ProductTypeRecord::create)` binds its result from
				// a callable reference. The call binder covers references and
				// lambdas, and reads what stays unbound as `*`.
				instantiated := i.instantiateCallResultLocked(ctx, file, candidate, result, nil, nil, callValues, at)
				if candidate.Language == analysis.LanguageJava && file.Language == analysis.LanguageKotlin {
					instantiated = kotlinViewOfJavaType(instantiated)
				}
				if typeContainsAnyParameter(instantiated, candidate.TypeParameters) {
					return ""
				}
				return instantiated
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
	// The standard library declares each factory several times (empty, one
	// element, vararg), so overloads are expected. What matters is that every
	// candidate is the library's own: a user declaration of the same name must
	// still win.
	for _, candidate := range candidates {
		if candidate.FQN != "kotlin."+name && candidate.FQN != "kotlin.collections."+name {
			return false
		}
	}
	return true
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

func kotlinCollectionFactoryType(ctx context.Context, i *Index, file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) > 1 {
		return ""
	}
	if len(arguments) == 0 {
		var element string
		for _, value := range values {
			inferred := i.inferExpressionTypeLocked(ctx, file, value, at)
			if inferred == "" {
				return ""
			}
			element = i.commonExpressionTypeLocked(ctx, file, element, inferred)
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

func (i *Index) kotlinMapFactoryTypeLocked(ctx context.Context, file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
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
			key := i.inferExpressionTypeLocked(ctx, file, value[:separator], at)
			mapped := i.inferExpressionTypeLocked(ctx, file, value[separator+len("to"):], at)
			if key == "" || mapped == "" {
				return ""
			}
			keyType = i.commonExpressionTypeLocked(ctx, file, keyType, key)
			valueType = i.commonExpressionTypeLocked(ctx, file, valueType, mapped)
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

func (i *Index) inferJavaCompositeExpressionLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
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
			left := i.inferExpressionTypeLocked(ctx, file, remainder[:colon], at)
			right := i.inferExpressionTypeLocked(ctx, file, remainder[colon+1:], at)
			return i.commonExpressionTypeLocked(ctx, file, left, right)
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
						inferred = i.commonExpressionTypeLocked(ctx, file, inferred, i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock(branch), at))
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

func (i *Index) inferKotlinCompositeExpressionLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
	if operator := topLevelWordIndex(expression, "to"); operator >= 0 {
		left := i.inferExpressionTypeLocked(ctx, file, expression[:operator], at)
		right := i.inferExpressionTypeLocked(ctx, file, expression[operator+len("to"):], at)
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
					receiver = i.inferExpressionTypeLocked(ctx, file, expression[open+1:end], at)
				}
			}
		}
		if (body == "this" || body == "it") && receiver != "" {
			return receiver
		}
		if inferred := i.inferExpressionTypeLocked(ctx, file, body, at); inferred != "" {
			return inferred
		}
	}
	if operator := topLevelExpressionOperator(expression, "?:"); operator >= 0 {
		left := strings.TrimSuffix(strings.TrimSpace(i.inferExpressionTypeLocked(ctx, file, expression[:operator], at)), "?")
		right := i.inferExpressionTypeLocked(ctx, file, expression[operator+2:], at)
		return i.commonExpressionTypeLocked(ctx, file, left, right)
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
					left := i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock(rest[:elseAt]), at)
					right := i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock(rest[elseAt+len("else"):]), at)
					return i.commonExpressionTypeLocked(ctx, file, left, right)
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
						branch := i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock(entry[arrow+2:]), at)
						inferred = i.commonExpressionTypeLocked(ctx, file, inferred, branch)
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
				inferred = i.commonExpressionTypeLocked(ctx, file, inferred, i.inferExpressionTypeLocked(ctx, file, unwrapExpressionBlock(expression[cursor:close+1]), at))
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

func (i *Index) commonExpressionTypeLocked(ctx context.Context, file *analysis.ParsedFile, left, right string) string {
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
	leftOwners := i.instantiatedTypeHierarchyLocked(ctx, file, leftBase)
	rightOwners := i.instantiatedTypeHierarchyLocked(ctx, file, rightBase)
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
		leftArgument, rightArgument := strings.TrimSpace(left.arguments[index]), strings.TrimSpace(right.arguments[index])
		if sameJvmType(leftArgument, rightArgument) {
			arguments[index] = leftArgument
		} else if language == analysis.LanguageKotlin && strings.TrimSuffix(leftArgument, "?") == strings.TrimSuffix(rightArgument, "?") {
			// `listOf(a?.id)` and `listOfNotNull(b)`: the same element, one
			// side nullable -- a list of the nullable element.
			arguments[index] = strings.TrimSuffix(leftArgument, "?") + "?"
		} else if language == analysis.LanguageKotlin {
			arguments[index] = "*"
		} else {
			arguments[index] = "?"
		}
	}
	return instantiatedTypeName(name, arguments)
}

func topLevelExpressionOperator(expression, operator string) int {
	// Pure in its two arguments, and asked about the same expressions over and
	// over while a project is resolved; tokenising them each time was a large
	// share of a project-wide query.
	if len(expression) > 2048 {
		return topLevelExpressionOperatorUncached(expression, operator)
	}
	key := topLevelOperatorKey{expression: expression, operator: operator}
	topLevelOperatorCache.RLock()
	index, ok := topLevelOperatorCache.values[key]
	topLevelOperatorCache.RUnlock()
	if ok {
		return index
	}
	index = topLevelExpressionOperatorUncached(expression, operator)
	key = topLevelOperatorKey{expression: strings.Clone(expression), operator: strings.Clone(operator)}
	topLevelOperatorCache.Lock()
	if topLevelOperatorCache.values == nil || len(topLevelOperatorCache.values) >= 100_000 {
		topLevelOperatorCache.values = make(map[topLevelOperatorKey]int)
	}
	topLevelOperatorCache.values[key] = index
	topLevelOperatorCache.Unlock()
	return index
}

type topLevelOperatorKey struct{ expression, operator string }

var topLevelOperatorCache struct {
	sync.RWMutex
	values map[topLevelOperatorKey]int
}

func topLevelExpressionOperatorUncached(expression, operator string) int {
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

func (i *Index) typeOfExpressionLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	nullableResult := false
	if file.Language == analysis.LanguageKotlin {
		// Only a safe call in the chain itself makes the result nullable;
		// `xs.flatMap { it?.ids }` is not a nullable list.
		nullableResult = topLevelSafeCall(expression) && !strings.HasSuffix(expression, "!!")
		expression = strings.ReplaceAll(expression, "?.", ".")
		expression = strings.ReplaceAll(expression, "!!", "")
		if strings.HasSuffix(expression, "::class") {
			literal := strings.TrimSpace(strings.TrimSuffix(expression, "::class"))
			if literalType := i.typeOfExpressionLocked(ctx, file, literal, at); literalType != "" {
				return "KClass<" + literalType + ">"
			}
		}
	}
	if !strings.Contains(expression, ".") {
		if strings.Contains(expression, "[") {
			return i.indexedExpressionTypeLocked(ctx, file, expression, at)
		}
		if strings.Contains(expression, "(") {
			return i.inferExpressionTypeLocked(ctx, file, expression, at)
		}
		return i.typeOfNameLocked(ctx, file, expression, at)
	}
	parts := splitTopLevelMemberChain(expression)
	if len(parts) == 0 {
		return ""
	}
	typ := i.typeOfNameLocked(ctx, file, parts[0], at)
	if file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(parts[0]), "::class") {
		literal := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[0]), "::class"))
		if literalType := i.typeOfExpressionLocked(ctx, file, literal, at); literalType != "" {
			typ = "KClass<" + literalType + ">"
		}
	} else if strings.Contains(parts[0], "[") {
		typ = i.indexedExpressionTypeLocked(ctx, file, parts[0], at)
	} else if strings.Contains(parts[0], "(") {
		typ = i.inferExpressionTypeLocked(ctx, file, parts[0], at)
	}
	// `Color.RED`, `Box.standard()` and `Outer.Nested.make()` start from a type
	// name, not a value: nothing above gave the head a type, but the type
	// itself says what its enum entries, companion members and nested types
	// produce.
	var qualifier *analysis.Symbol
	if file.Language == analysis.LanguageKotlin && !strings.ContainsAny(parts[0], "([{<") {
		head := strings.TrimSpace(parts[0])
		if owners := i.resolveTypeSymbolsAtLocked(file, head, at); len(owners) == 1 && !i.valueShadowsTypeLocked(file, head, at) {
			owner := owners[0]
			qualifier = &owner
		}
	}
	for position, member := range parts[1:] {
		if qualifier != nil {
			name, arguments, call, ok := memberCallShape(member)
			if !ok {
				return ""
			}
			resolved, nested, handled := i.typeQualifierMemberTypeLocked(ctx, file, *qualifier, name, call, len(arguments), at, arguments...)
			if handled {
				if nested != nil {
					if position == len(parts)-2 {
						// A nested object is a value of its own type
						// (`Authorities.Colors`); a nested class is not one.
						if nested.Kind == analysis.KindObject {
							return nested.FQN
						}
						return ""
					}
					qualifier = nested
					continue
				}
				qualifier, typ = nil, resolved
				continue
			}
			if position != 0 || typ == "" {
				return ""
			}
			// Not an entry, companion member or nested type: let the head be
			// the value of its own type, as for an object or a Java static.
			qualifier = nil
		}
		if typ == "" {
			return ""
		}
		memberName := member
		callArguments := []string(nil)
		call := false
		brace, paren := strings.IndexByte(member, '{'), strings.IndexByte(member, '(')
		// A trailing lambda whose body contains a call has both a brace and a
		// parenthesis: `takeIf { it.isNotEmpty() }`. Whichever opens first
		// decides the form. Reading that member as a parenthesised call named
		// it "takeIf { it.isNotEmpty", so it matched nothing and the value lost
		// its type -- while the same call with a literal body worked.
		if brace >= 0 && (paren < 0 || brace < paren) && strings.HasSuffix(strings.TrimSpace(member), "}") {
			call = true
			memberName = strings.TrimSpace(member[:brace])
			callArguments = []string{strings.TrimSpace(member[brace:])}
		} else if paren >= 0 {
			call = true
			memberName = strings.TrimSpace(member[:paren])
			close := callClosingParen(member, paren)
			if close >= len(member) {
				return ""
			}
			callArguments = splitTopLevelCallArguments(member[paren+1 : close])
			if callArguments == nil {
				callArguments = make([]string, 0)
			}
			// `getOrElse(1) { "" }`: a trailing lambda is the last argument.
			if rest := strings.TrimSpace(member[close+1:]); strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
				callArguments = append(callArguments, rest)
			}
		}
		// `filterIsInstance<ThresholdColorCellInput>()`: explicit type arguments
		// belong to the callee, not to its name.
		memberName, explicitTypeArguments := splitInstantiatedType(memberName)
		memberName = strings.Trim(memberName, "`")
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
				case "takeIf", "takeUnless":
					// `fun <T> T.takeIf(predicate: (T) -> Boolean): T?` answers
					// the receiver, made nullable: the value is returned or it
					// is not.
					next = strings.TrimSuffix(strings.TrimSpace(typ), "?") + "?"
				case "let", "run":
					if body == "it" || body == "this" {
						next = typ
					} else if inferred := i.inferExpressionTypeLocked(ctx, file, body, at); inferred != "" {
						next = inferred
					}
				}
			}
		}
		if next == "" {
			var found bool
			next, found = i.uniqueDirectMemberResultTypeLocked(ctx, file, typ, memberName, call, len(callArguments), at, callArguments...)
			if found && next == "" {
				return ""
			}
		}
		if next == "" && file.Language == analysis.LanguageKotlin {
			var ambiguous bool
			next, ambiguous = i.uniqueExtensionResultTypeLocked(ctx, file, typ, memberName, call, callArguments, at, explicitTypeArguments...)
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

func (i *Index) memberResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, receiverType, name string, at int) string {
	if result, found := i.uniqueDirectMemberResultTypeLocked(ctx, file, receiverType, name, true, -1, at); found {
		return result
	}
	if file.Language == analysis.LanguageKotlin {
		if result, ambiguous := i.uniqueExtensionResultTypeLocked(ctx, file, receiverType, name, true, nil, at); !ambiguous {
			return result
		}
	}
	return ""
}

// uniqueDirectMemberResultTypeLocked returns the result from the nearest
// declaring type only when exactly one accessible member matches. found is
// true even for an ambiguous set so callers do not incorrectly fall through
// to an extension method when a real member shadows it.
func (i *Index) uniqueDirectMemberResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, receiverType, name string, callable bool, arity, at int, callArguments ...string) (result string, found bool) {
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(ctx, file, receiverType) {
		owner, arguments := instantiated.symbol, instantiated.arguments
		matches := 0
		var overloadResults []overloadResult
		// Kotlin prefers an overload that takes the arguments without a vararg:
		// jOOQ's `insertInto(table)` is `insertInto(Table<R>)`, not
		// `insertInto(Table<R>, Field<?>...)` with nothing spread.
		preferFixed, overloads := false, 0
		if callable && arity >= 0 {
			for _, id := range i.byContainerMember[memberKey(owner.ID, name)] {
				if member := i.symbols[id]; member != nil && member.ContainerID == owner.ID && analysis.IsCallableKind(member.Kind) && matchesArityForLanguage(*member, arity, file.Language) {
					overloads++
					preferFixed = preferFixed || takesArityWithoutVararg(*member, arity, file.Language)
				}
			}
		}
		// Several overloads take this many arguments: jOOQ's
		// `orderBy(OrderField<T1>)` and `orderBy(Collection<...>)`. One whose
		// parameter an argument provably is not -- a SortField is no
		// Collection -- is out. Unknown stays in.
		var argumentTypes []string
		rejectsArguments := func(member analysis.Symbol) bool {
			if overloads < 2 || len(callArguments) == 0 {
				return false
			}
			if argumentTypes == nil {
				argumentTypes = make([]string, len(callArguments))
				for index, argument := range callArguments {
					if trimmed := strings.TrimSpace(argument); !strings.HasPrefix(trimmed, "{") && !strings.Contains(trimmed, "::") {
						if _, _, named := namedArgument(trimmed); !named {
							argumentTypes[index] = i.inferExpressionTypeLocked(ctx, file, trimmed, at)
						}
					}
				}
			}
			for index, actual := range argumentTypes {
				if actual == "" || index >= len(member.Parameters) {
					continue
				}
				parameter := member.Parameters[index]
				if parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg") {
					continue
				}
				expected := withoutVariance(strings.TrimSpace(parameter.Type))
				if member.Language == analysis.LanguageJava {
					expected = kotlinViewOfJavaType(expected)
				}
				if typeContainsAnyParameter(expected, member.TypeParameters) && !strings.Contains(expected, "<") {
					continue
				}
				if matched, known := i.subtypeRelationAtLocked(ctx, file, strings.TrimSuffix(actual, "?"), expected, at); known && !matched {
					return true
				}
			}
			return false
		}
		for _, id := range i.byContainerMember[memberKey(owner.ID, name)] {
			member := i.symbols[id]
			// `outer.Inner()` constructs an inner class through a value of the
			// class around it.
			if callable && member.ContainerID == owner.ID && analysis.IsTypeKind(member.Kind) && nestedTypeCapturesOuter(*member, owner) && member.FQN != "" && i.accessibleLocked(file, *member, at) {
				return member.FQN, true
			}
			if member.ContainerID != owner.ID || callable != analysis.IsCallableKind(member.Kind) || !i.accessibleLocked(file, *member, at) {
				continue
			}
			if callable && arity >= 0 && (!matchesArityForLanguage(*member, arity, file.Language) || preferFixed && !takesArityWithoutVararg(*member, arity, file.Language)) {
				continue
			}
			memberType := i.declaredOrInferredMemberTypeLocked(ctx, *member)
			if memberType == "" {
				continue
			}
			candidate := substituteTypeParameters(i.respellDeclaredTypeLocked(file, *member, memberType), owner.TypeParameters, arguments)
			// `flux.map { it.name }`: the method's own type parameters bind
			// from the call's arguments and lambdas.
			if callable {
				candidate = i.instantiateCallResultLocked(ctx, file, *member, candidate, owner.TypeParameters, arguments, callArguments, at)
			}
			if member.Language == analysis.LanguageJava && file.Language == analysis.LanguageKotlin {
				candidate = kotlinViewOfJavaType(candidate)
			}
			matches++
			overloadResults = append(overloadResults, overloadResult{*member, candidate})
		}
		if matches > 0 {
			return agreedOverloadResult(overloadResults, func(member analysis.Symbol) bool {
				return callable && arity >= 0 && rejectsArguments(member)
			}), true
		}
	}
	return "", false
}

type overloadResult struct {
	member analysis.Symbol
	result string
}

// agreedOverloadResult is the result every matching overload gives. The same
// declaration indexed twice -- from a library's sources and from its class
// files -- agrees with itself. Overloads that disagree are narrowed by their
// arguments, which costs argument inference and so happens only then; if
// they still disagree, the call is ambiguous and has no result.
func agreedOverloadResult(candidates []overloadResult, rejects func(analysis.Symbol) bool) string {
	agreed := func(values []overloadResult) string {
		if len(values) == 0 {
			return ""
		}
		for _, value := range values[1:] {
			if value.result != values[0].result {
				return ""
			}
		}
		return values[0].result
	}
	if result := agreed(candidates); result != "" || len(candidates) < 2 {
		return result
	}
	kept := candidates[:0:0]
	for _, candidate := range candidates {
		if !rejects(candidate.member) {
			kept = append(kept, candidate)
		}
	}
	return agreed(kept)
}

// uniqueExtensionResultTypeLocked applies the parts of extension overload
// filtering the source model can prove. The second result reports ambiguity;
// no result and no ambiguity means that no extension was applicable.
func (i *Index) uniqueExtensionResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, receiverType, name string, callable bool, callArguments []string, at int, explicitTypeArguments ...string) (result string, ambiguous bool) {
	seen := make(map[string]bool)
	matches := 0
	hierarchy := i.instantiatedTypeHierarchyLocked(ctx, file, receiverType)
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
			bindings, applicable := i.extensionReceiverBindingsLocked(ctx, file, *extension, receiverType)
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
				// A lambda's parameters come from the parameter it is passed
				// for: `{ true }` given to `filter` is a `(T) -> Boolean` with
				// an implicit `it`, though on its own it reads as
				// `() -> Boolean`. Lambdas bind below, against the parameter.
				if strings.HasPrefix(strings.TrimSpace(argument), "{") {
					continue
				}
				actual := i.inferExpressionTypeLocked(ctx, file, argument, at)
				if actual == "" {
					// A lambda has no type this engine can state, and every
					// scope function takes one. Requiring each argument to type
					// rejected `takeIf`, `let`, `filter` and their neighbours
					// outright, although the receiver binding -- the part that
					// decides the result -- was already proven. An argument that
					// cannot be typed is not evidence against a candidate; only
					// one that types to something contradictory is.
					continue
				}
				// A vararg parameter takes its element type, once per argument.
				expected := strings.TrimPrefix(strings.TrimSpace(extension.Parameters[index].Type), "vararg ")
				if !matchTypePattern(expected, actual, parameters, bindings) {
					applicable = false
					break
				}
			}
			if !applicable {
				continue
			}
			// Type arguments written at the call bind the extension's own type
			// parameters in order; the receiver binds the rest.
			if len(explicitTypeArguments) > 0 {
				if len(explicitTypeArguments) != len(extension.TypeParameters) {
					continue
				}
				if bindings == nil {
					bindings = make(map[string]string, len(explicitTypeArguments))
				}
				for index, parameter := range extension.TypeParameters {
					bindings[parameter] = explicitTypeArguments[index]
				}
			}
			if declared := i.respellDeclaredTypeLocked(file, *extension, extension.Type); typeContainsAnyParameter(substituteTypeBindings(declared, bindings), extension.TypeParameters) {
				bindings = i.bindLambdaResultsLocked(ctx, file, *extension, callArguments, parameters, bindings, at)
			}
			candidate := substituteTypeBindings(i.respellDeclaredTypeLocked(file, *extension, extension.Type), bindings)
			// `fun <T, R> T.let(block: (T) -> R): R` answers R, which only the
			// lambda's own result can bind. An unbound parameter is not a type:
			// naming one would invent a class called R.
			if parameters[strings.TrimSuffix(strings.TrimSpace(candidate), "?")] {
				continue
			}
			// As a type argument it is merely unknown: `List<R>` is a List of
			// something, `List<*>`.
			candidate = starUnboundTypeArguments(candidate, extension.TypeParameters, bindings)
			matches++
			if matches == 1 {
				result = candidate
				continue
			}
			// One declaration can reach the index several times: the standard
			// library ships `takeIf` and `let` as sources and again as the
			// binary facade members of their multifile class. Candidates that
			// answer identically are one answer, and treating them as an
			// ambiguity abstained from every scope function in the language.
			if candidate != result {
				return "", true
			}
		}
	}
	return result, false
}

func (i *Index) invocationResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, receiverType string, at int) string {
	receiverType = strings.TrimSpace(strings.TrimSuffix(receiverType, "?"))
	if arrow := strings.LastIndex(receiverType, "->"); arrow >= 0 {
		return strings.TrimSpace(receiverType[arrow+2:])
	}
	return i.memberResultTypeLocked(ctx, file, receiverType, "invoke", at)
}

func (i *Index) indexedExpressionTypeLocked(ctx context.Context, file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	open := firstTopLevelIndexOpen(expression)
	if open <= 0 {
		return ""
	}
	typ := i.typeOfExpressionLocked(ctx, file, strings.TrimSpace(expression[:open]), at)
	for open >= 0 && open < len(expression) {
		close := matchingDelimiter(expression, open, '[', ']')
		if close < 0 || typ == "" {
			return ""
		}
		if strings.HasSuffix(strings.TrimSpace(typ), "[]") {
			typ = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(typ), "[]"))
		} else {
			next, found := i.uniqueDirectMemberResultTypeLocked(ctx, file, typ, "get", true, 1, at)
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
func (i *Index) inferOperatorExpressionLocked(ctx context.Context, file *analysis.ParsedFile, ir expressionIR, at, depth int) inferredExpressionType {
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
		operand := i.inferExpressionResultDepthLocked(ctx, file, child.Text, at, depth+1)
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
				return typed(i.memberResultTypeLocked(ctx, file, operand, "not", at))
			}
		case "-", "+":
			if rank, ok := numericRank(file.Language, operand); ok {
				return typed(numericTypeForRank(file.Language, max(rank, numericRankInt)))
			}
			if kotlin {
				name := map[string]string{"-": "unaryMinus", "+": "unaryPlus"}[ir.Operator]
				return typed(i.memberResultTypeLocked(ctx, file, operand, name, at))
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
					return typed(i.memberResultTypeLocked(ctx, file, left, name, at))
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

// memberCallShape splits one link of a member chain into its name and, for a
// call, its arguments: `standard()` -> ("standard", [], true).
func memberCallShape(member string) (name string, arguments []string, call, ok bool) {
	member = strings.TrimSpace(member)
	brace, paren := strings.IndexByte(member, '{'), strings.IndexByte(member, '(')
	switch {
	case brace >= 0 && (paren < 0 || brace < paren):
		return strings.TrimSpace(member[:brace]), []string{strings.TrimSpace(member[brace:])}, true, true
	case paren >= 0:
		closing := callClosingParen(member, paren)
		if closing >= len(member) {
			return "", nil, false, false
		}
		arguments = splitTopLevelCallArguments(member[paren+1 : closing])
		if arguments == nil {
			arguments = []string{}
		}
		// `getOrElse(1) { "" }`: a trailing lambda is the last argument.
		if rest := strings.TrimSpace(member[closing+1:]); strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
			arguments = append(arguments, rest)
		}
		// `Mono.just<Foo>(x)`: explicit type arguments are not the name.
		name, _ := splitInstantiatedType(strings.TrimSpace(member[:paren]))
		return strings.Trim(name, "`"), arguments, true, true
	}
	return strings.Trim(member, "`"), nil, false, true
}

// typeQualifierMemberTypeLocked answers what `Owner.name` / `Owner.name(...)`
// evaluates to when Owner is a type name: an enum entry is the enum itself, a
// companion or static member has its declared result, and a nested type is the
// next qualifier. handled is false when the name is none of those, so the
// caller abstains instead of guessing.
func (i *Index) typeQualifierMemberTypeLocked(ctx context.Context, file *analysis.ParsedFile, owner analysis.Symbol, name string, call bool, arity, at int, callArguments ...string) (result string, nested *analysis.Symbol, handled bool) {
	if !call {
		for _, id := range i.byContainerMember[memberKey(owner.ID, name)] {
			if member := i.symbols[id]; member.ContainerID == owner.ID && member.Kind == analysis.KindEnumMember {
				return owner.Name, nil, true
			}
		}
	}
	containers := []analysis.Symbol{owner}
	for _, id := range i.byContainerName[owner.ID] {
		if inner := i.symbols[id]; inner.ContainerID == owner.ID && inner.Kind == analysis.KindObject && containsString(inner.Modifiers, "companion") {
			containers = append(containers, *inner)
		}
	}
	if !call {
		for _, id := range i.byContainerMember[memberKey(owner.ID, name)] {
			if inner := i.symbols[id]; inner.ContainerID == owner.ID && analysis.IsTypeKind(inner.Kind) {
				return "", inner, true
			}
		}
	} else {
		// `Outer.Nested(1)` constructs a Nested.
		nestedIDs := append(append([]string(nil), i.byContainerMember[memberKey(owner.ID, name)]...), i.binaryNestedTypeIDsLocked(owner, name)...)
		for _, id := range nestedIDs {
			if inner := i.symbols[id]; inner != nil && analysis.IsTypeKind(inner.Kind) && inner.Kind != analysis.KindObject && !nestedTypeCapturesOuter(*inner, owner) {
				if inner.FQN != "" {
					return inner.FQN, nil, true
				}
			}
		}
	}
	for _, container := range containers {
		matches, resolved := 0, ""
		for _, id := range i.byContainerMember[memberKey(container.ID, name)] {
			member := i.symbols[id]
			if member.ContainerID != container.ID || call != analysis.IsCallableKind(member.Kind) || !i.accessibleLocked(file, *member, at) {
				continue
			}
			if call && !matchesArityForLanguage(*member, arity, file.Language) {
				continue
			}
			memberType := i.declaredOrInferredMemberTypeLocked(ctx, *member)
			if memberType == "" {
				continue
			}
			candidate := i.respellDeclaredTypeLocked(file, *member, memberType)
			if call {
				candidate = i.instantiateCallResultLocked(ctx, file, *member, candidate, nil, nil, callArguments, at)
			}
			if member.Language == analysis.LanguageJava && file.Language == analysis.LanguageKotlin {
				candidate = kotlinViewOfJavaType(candidate)
			}
			if matches++; matches == 1 {
				resolved = candidate
			} else if candidate != resolved {
				resolved = ""
			}
		}
		if matches > 0 {
			return resolved, nil, resolved != ""
		}
	}
	return "", nil, false
}

// valueShadowsTypeLocked reports whether a local, parameter or property named
// like a type is in scope, in which case the name is that value.
func (i *Index) valueShadowsTypeLocked(file *analysis.ParsedFile, name string, at int) bool {
	for _, symbol := range i.fileSymbolsByName[file.URI][name] {
		if !analysis.IsTypeKind(symbol.Kind) && symbol.StartByte <= at && symbolInScopeAt(*symbol, at) {
			return true
		}
	}
	return false
}

// topLevelSafeCall reports whether a `?.` joins the links of the chain itself,
// outside any argument list or lambda.
func topLevelSafeCall(expression string) bool {
	depth := 0
	for index := 0; index+1 < len(expression); index++ {
		switch c := expression[index]; c {
		case '"', '\'':
			for index++; index < len(expression) && expression[index] != c; index++ {
				if expression[index] == '\\' {
					index++
				}
			}
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if depth == 0 && expression[index+1] == '.' {
				return true
			}
		}
	}
	return false
}

// starUnboundTypeArguments replaces type parameters no binding reached with a
// star projection where they stand as type arguments.
func starUnboundTypeArguments(value string, typeParameters []string, bindings map[string]string) string {
	unbound := make(map[string]bool, len(typeParameters))
	for _, parameter := range typeParameters {
		if bindings[parameter] == "" {
			unbound[parameter] = true
		}
	}
	if len(unbound) == 0 {
		return value
	}
	if ref, ok := parseTypeRef(value); ok {
		return ref.transform(func(t typeRef) typeRef {
			for index, argument := range t.Args {
				if !argument.Star && argument.Type.Function == nil && len(argument.Type.Args) == 0 && unbound[argument.Type.Name] {
					t.Args[index] = typeArgument{Star: true}
				}
			}
			return t
		}).String()
	}
	return starUnboundTypeArgumentsText(value, typeParameters, bindings)
}

// starUnboundTypeArgumentsText is the textual fallback for spellings the
// type parser does not take.
func starUnboundTypeArgumentsText(value string, typeParameters []string, bindings map[string]string) string {
	for _, parameter := range typeParameters {
		if bindings[parameter] != "" || !typeContainsAnyParameter(value, []string{parameter}) {
			continue
		}
		var out strings.Builder
		for index := 0; index < len(value); {
			if strings.HasPrefix(value[index:], parameter) && (index == 0 || !isIdentRune(rune(value[index-1]))) && (index+len(parameter) == len(value) || !isIdentRune(rune(value[index+len(parameter)]))) {
				previous := strings.TrimRight(value[:index], " ")
				for _, variance := range []string{"out", "in"} {
					if strings.HasSuffix(previous, variance) && (len(previous) == len(variance) || !isIdentRune(rune(previous[len(previous)-len(variance)-1]))) {
						previous = strings.TrimRight(strings.TrimSuffix(previous, variance), " ")
					}
				}
				if strings.HasSuffix(previous, "<") || strings.HasSuffix(previous, ",") {
					out.WriteString("*")
					index += len(parameter)
					// `R?` as an argument is still just unknown.
					if index < len(value) && value[index] == '?' {
						index++
					}
					continue
				}
			}
			out.WriteByte(value[index])
			index++
		}
		value = strings.ReplaceAll(strings.ReplaceAll(out.String(), "out *", "*"), "in *", "*")
	}
	return value
}
