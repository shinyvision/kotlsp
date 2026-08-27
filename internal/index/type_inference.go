package index

import (
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

func (i *Index) typeOfNameLocked(file *analysis.ParsedFile, name string, at int) string {
	if name == "this" || name == "super" {
		if enclosing := i.enclosingTypeLocked(file, at); enclosing.ID != "" {
			if name == "super" && len(enclosing.Supertypes) > 0 {
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
				if bestSmartCast != "" {
					bestSmartCast += " & "
				}
				bestSmartCast += smartCast.Type
			}
		}
	}
	if bestSmartCast != "" {
		if bestSmartCast != "!" {
			return bestSmartCast
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
	if best != "" {
		if nonNullSmartCast {
			return strings.TrimSuffix(strings.TrimSpace(best), "?")
		}
		return best
	}
	if bestSymbol != nil {
		if contextual := i.contextualLambdaParameterTypeLocked(file, *bestSymbol); contextual != "" {
			return contextual
		}
	}
	if symbols := i.resolveTypeSymbolsLocked(file, name); len(symbols) > 0 {
		return symbols[0].FQN
	}
	return ""
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
				for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, delegateType) {
					owner, arguments := instantiated.symbol, instantiated.arguments
					for _, id := range i.byContainerMember[memberKey(owner.Name, "getValue")] {
						getter := i.symbols[id]
						if getter.ContainerID == owner.ID && analysis.IsCallableKind(getter.Kind) && getter.Type != "" && i.accessibleLocked(file, *getter, at) {
							return substituteTypeParameters(getter.Type, owner.TypeParameters, arguments)
						}
					}
				}
				for _, container := range i.typeAndSupertypesLocked(file, delegateType) {
					for _, id := range i.byReceiverMember[memberKey(container, "getValue")] {
						getter := i.symbols[id]
						if getter.Type == "" || !analysis.IsCallableKind(getter.Kind) || !i.accessibleLocked(file, *getter, at) || !i.extensionVisibleLocked(file, *getter, at) {
							continue
						}
						if bindings, applicable := i.extensionReceiverBindingsLocked(file, *getter, delegateType); applicable {
							return substituteTypeBindings(getter.Type, bindings)
						}
					}
				}
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
						parameterTypes = append(parameterTypes, strings.TrimSpace(parameter[colon+1:]))
					} else if parameter != "" {
						parameterTypes = append(parameterTypes, "Any")
					}
				}
				return "(" + strings.Join(parameterTypes, ", ") + ") -> " + result
			}
		}
		if strings.HasPrefix(expression, "::") {
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(expression, "::")), "`")
			for _, id := range i.byName[name] {
				callable := i.symbols[id]
				if !analysis.IsCallableKind(callable.Kind) || callable.Type == "" || !i.accessibleLocked(file, *callable, at) {
					continue
				}
				parameterTypes := make([]string, 0, len(callable.Parameters))
				for _, parameter := range callable.Parameters {
					parameterTypes = append(parameterTypes, parameter.Type)
				}
				return "(" + strings.Join(parameterTypes, ", ") + ") -> " + callable.Type
			}
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
	case numericExpression(expression):
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
	open := strings.IndexByte(expression, '(')
	if open < 0 {
		if !strings.ContainsAny(expression, " +-*/%?:[]{}") {
			if !strings.Contains(expression, ".") {
				return i.declaredTypeOfNameLocked(file, expression, at)
			}
			return i.typeOfExpressionLocked(file, expression, at)
		}
		return ""
	}
	callee := strings.TrimSpace(expression[:open])
	if dot := strings.LastIndexByte(callee, '.'); dot >= 0 {
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
	callValues := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
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
	if types := i.resolveTypeSymbolsLocked(file, base); len(types) > 0 {
		owner := types[0]
		arguments := explicitArguments
		if len(arguments) == 0 && len(owner.TypeParameters) > 0 {
			callArguments := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
			constructorOwners := []analysis.Symbol{owner}
			if owner.Kind == analysis.KindTypeAlias && owner.Type != "" {
				underlying, _ := splitInstantiatedType(owner.Type)
				constructorOwners = append(constructorOwners, i.resolveTypeSymbolsLocked(file, underlying)...)
			}
			for _, constructorOwner := range constructorOwners {
				for _, id := range i.byContainerMember[memberKey(constructorOwner.Name, constructorOwner.Name)] {
					constructor := i.symbols[id]
					if constructor.Kind != analysis.KindConstructor || constructor.ContainerID != constructorOwner.ID {
						continue
					}
					inferred := make(map[string]string)
					for index, parameter := range constructor.Parameters {
						if index >= len(callArguments) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, callArguments[index], at)
						inferTypeParameterBindings(parameter.Type, actual, owner.TypeParameters, inferred)
					}
					for _, typeParameter := range owner.TypeParameters {
						if inferred[typeParameter] == "" {
							arguments = nil
							break
						}
						arguments = append(arguments, inferred[typeParameter])
					}
					if len(arguments) > 0 {
						break
					}
				}
				if len(arguments) > 0 {
					break
				}
			}
		}
		if len(arguments) > 0 {
			return owner.Name + "<" + strings.Join(arguments, ", ") + ">"
		}
		return owner.Name
	}
	for _, id := range i.byName[base] {
		candidate := i.symbols[id]
		if !i.accessibleLocked(file, *candidate, at) {
			continue
		}
		if analysis.IsTypeKind(candidate.Kind) {
			return candidate.Name
		}
		if analysis.IsCallableKind(candidate.Kind) && candidate.Type != "" {
			result := candidate.Type
			if len(candidate.TypeParameters) > 0 {
				arguments := explicitArguments
				if len(arguments) == 0 {
					values := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
					inferred := make(map[string]string, len(candidate.TypeParameters))
					for parameterIndex, parameter := range candidate.Parameters {
						if parameterIndex >= len(values) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, values[parameterIndex], at)
						inferTypeParameterBindings(parameter.Type, actual, candidate.TypeParameters, inferred)
					}
					for _, parameter := range candidate.TypeParameters {
						if inferred[parameter] == "" {
							arguments = nil
							break
						}
						arguments = append(arguments, inferred[parameter])
					}
				}
				result = substituteTypeParameters(result, candidate.TypeParameters, arguments)
			}
			return result
		}
	}
	return ""
}

func kotlinCollectionFactoryType(i *Index, file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) == 0 {
		var element string
		for _, value := range values {
			element = i.commonExpressionTypeLocked(file, element, i.inferExpressionTypeLocked(file, value, at))
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
	if len(arguments) < 2 {
		keyType, valueType := "", ""
		for _, value := range values {
			if separator := topLevelWordIndex(value, "to"); separator >= 0 {
				keyType = i.commonExpressionTypeLocked(file, keyType, i.inferExpressionTypeLocked(file, value[:separator], at))
				valueType = i.commonExpressionTypeLocked(file, valueType, i.inferExpressionTypeLocked(file, value[separator+len("to"):], at))
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
		if !strings.HasPrefix(strings.TrimSpace(expression), name) {
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
				if end := callClosingParen(expression, open); end > open {
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
	if sameJvmType(left, right) {
		if !strings.HasSuffix(left, "?") || !strings.HasSuffix(right, "?") {
			return strings.TrimSuffix(left, "?")
		}
		return left
	}
	if i.isSubtypeLocked(file, left, right) {
		return right
	}
	if i.isSubtypeLocked(file, right, left) {
		return left
	}
	if file.Language == analysis.LanguageJava {
		return "Object"
	}
	return "Any"
}

func topLevelExpressionOperator(expression, operator string) int {
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
	var out []string
	start, parens, brackets, braces := 0, 0, 0, 0
	for index := 0; index <= len(expression); index++ {
		if index == len(expression) || expression[index] == separator && parens == 0 && brackets == 0 && braces == 0 {
			if value := strings.TrimSpace(expression[start:index]); value != "" {
				out = append(out, value)
			}
			start = index + 1
			continue
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
		}
	}
	return out
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
	depth := 0
	for index := open; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return len(expression)
}

func splitTopLevelCallArguments(value string) []string {
	start, parens, brackets, braces, angles := 0, 0, 0, 0, 0
	var result []string
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' && parens == 0 && brackets == 0 && braces == 0 && angles == 0 {
			if argument := strings.TrimSpace(value[start:index]); argument != "" {
				result = append(result, argument)
			}
			start = index + 1
			continue
		}
		switch value[index] {
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
			angles--
		}
	}
	return result
}

func numericExpression(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if r >= '0' && r <= '9' || strings.ContainsRune("._xXbBeEfFdDlL+-", r) && index > 0 {
			continue
		}
		return false
	}
	return true
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
			callArguments = splitTopLevelCallArguments(member[open+1 : close])
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
		for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, typ) {
			if next != "" {
				break
			}
			owner, arguments := instantiated.symbol, instantiated.arguments
			for _, id := range i.byContainerMember[memberKey(owner.Name, memberName)] {
				symbol := i.symbols[id]
				if symbol.ContainerID == owner.ID && symbol.Type != "" && (call == analysis.IsCallableKind(symbol.Kind) || !call && !analysis.IsCallableKind(symbol.Kind)) && i.accessibleLocked(file, *symbol, at) {
					next = substituteTypeParameters(symbol.Type, owner.TypeParameters, arguments)
					break
				}
			}
			if next != "" {
				break
			}
		}
		if next == "" && file.Language == analysis.LanguageKotlin {
			for _, container := range i.typeAndSupertypesLocked(file, typ) {
				for _, id := range i.byReceiverMember[memberKey(container, memberName)] {
					extension := i.symbols[id]
					if extension.Type == "" || call != analysis.IsCallableKind(extension.Kind) || !i.accessibleLocked(file, *extension, at) || !i.extensionVisibleLocked(file, *extension, at) {
						continue
					}
					bindings, applicable := i.extensionReceiverBindingsLocked(file, *extension, typ)
					if !applicable || call && !matchesArityForLanguage(*extension, len(callArguments), file.Language) {
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
						if !matchTypePattern(extension.Parameters[index].Type, actual, parameters, bindings) {
							applicable = false
							break
						}
					}
					if applicable {
						next = substituteTypeBindings(extension.Type, bindings)
						break
					}
				}
				if next != "" {
					break
				}
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
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, receiverType) {
		owner, arguments := instantiated.symbol, instantiated.arguments
		for _, id := range i.byContainerMember[memberKey(owner.Name, name)] {
			member := i.symbols[id]
			if member.ContainerID == owner.ID && analysis.IsCallableKind(member.Kind) && member.Type != "" && i.accessibleLocked(file, *member, at) {
				return substituteTypeParameters(member.Type, owner.TypeParameters, arguments)
			}
		}
	}
	if file.Language == analysis.LanguageKotlin {
		for _, container := range i.typeAndSupertypesLocked(file, receiverType) {
			for _, id := range i.byReceiverMember[memberKey(container, name)] {
				member := i.symbols[id]
				if member.Type == "" || !analysis.IsCallableKind(member.Kind) || !i.accessibleLocked(file, *member, at) || !i.extensionVisibleLocked(file, *member, at) {
					continue
				}
				if bindings, applicable := i.extensionReceiverBindingsLocked(file, *member, receiverType); applicable {
					return substituteTypeBindings(member.Type, bindings)
				}
			}
		}
	}
	return ""
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
			next := ""
			for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, typ) {
				owner, arguments := instantiated.symbol, instantiated.arguments
				for _, id := range i.byContainerMember[memberKey(owner.Name, "get")] {
					symbol := i.symbols[id]
					if symbol.ContainerID == owner.ID && analysis.IsCallableKind(symbol.Kind) && symbol.Type != "" && i.accessibleLocked(file, *symbol, at) {
						next = substituteTypeParameters(symbol.Type, owner.TypeParameters, arguments)
						break
					}
				}
				if next != "" {
					break
				}
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
