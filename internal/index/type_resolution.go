package index

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func (i *Index) resolveTypeSymbolsLocked(file *analysis.ParsedFile, typeName string) []analysis.Symbol {
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, analysis.Symbol{}, newAccessibilityMemoLocked(i, file))
}

func (i *Index) resolveTypeSymbolsAtLocked(file *analysis.ParsedFile, typeName string, at int) []analysis.Symbol {
	var owner analysis.Symbol
	if ownerID := i.containerIDAtLocked(file, at); ownerID != "" {
		if candidate := i.symbols[ownerID]; candidate != nil {
			owner = *candidate
		}
	}
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, owner, newAccessibilityMemoLocked(i, file), at)
}

// resolveTypeSymbolsForOwnerLocked applies the same import/package precedence
// as ordinary type lookup, but can also prove which nested declaration is in
// lexical scope for an owning declaration. Equal-precedence collisions are
// ambiguity, never an invitation to select map or source order.
func (i *Index) resolveTypeSymbolsForOwnerLocked(file *analysis.ParsedFile, typeName string, lexicalOwner analysis.Symbol) []analysis.Symbol {
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, lexicalOwner, newAccessibilityMemoLocked(i, file), lexicalOwner.StartByte)
}

func (i *Index) resolveTypeSymbolsForOwnerMemoLocked(file *analysis.ParsedFile, typeName string, lexicalOwner analysis.Symbol, access *accessibilityMemo, positions ...int) []analysis.Symbol {
	base, _ := splitInstantiatedType(typeName)
	base = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(base, "out "), "in "))
	base = strings.TrimPrefix(base, "? extends ")
	base = strings.TrimPrefix(base, "? super ")
	base = strings.TrimSuffix(base, "?")
	for strings.HasSuffix(base, "[]") {
		base = strings.TrimSuffix(base, "[]")
	}
	if base == "" {
		return nil
	}
	// Import inspection and every symbol bucket share one work budget. Capping
	// buckets separately still allowed a file with thousands of repeated star
	// imports to allocate an equally large aggregate candidate slice while the
	// foreground index lock was held.
	filter := func(ids []string) []analysis.Symbol {
		if access.workExhausted || !access.consumeWork(len(ids)) {
			return nil
		}
		return i.symbolsForIDsLocked(ids, func(symbol analysis.Symbol) bool {
			return analysis.IsTypeKind(symbol.Kind) && i.accessibleWithMemoLocked(file, symbol, access, positions...)
		})
	}
	if strings.Contains(base, ".") {
		return filter(i.byFQN[base])
	}
	if !i.prepareResolutionImportsLocked(file, access) {
		i.recordHealth("type-resolution", base, "import inventory exceeded the query-wide type-resolution work limit and was withheld")
		return nil
	}
	// Lexically declared type parameters and nested/local types have priority.
	var local []string
	localSymbols := i.fileSymbolsByName[file.URI][base]
	if len(localSymbols) > maxResolutionCandidates || !access.consumeWork(len(localSymbols)) {
		i.recordHealth("type-resolution", base, "same-file type inventory exceeded its 512-symbol safety limit and was withheld")
		return nil
	}
	for _, symbol := range localSymbols {
		if analysis.IsTypeKind(symbol.Kind) && (len(positions) == 0 || i.typeDeclarationVisibleAtLocked(*symbol, positions[0])) {
			local = append(local, symbol.ID)
		}
	}
	if values := filter(local); len(values) > 0 {
		if lexicalOwner.ID != "" {
			values = nearestLexicalTypesLocked(values, lexicalOwner, i.symbols)
		} else {
			// Without a lexical owner (a type spelled by an inferred result such
			// as `Box<T>` returned from a nested declaration) a same-file nested
			// type is still the only declaration that name can mean, provided it
			// is unique. A top-level declaration outranks a nested homonym; two
			// nested homonyms remain an ambiguity rather than a guess.
			values = preferTopLevelTypes(values)
		}
		return uniqueTypeResolution(values)
	} else if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	var explicit []analysis.Symbol
	explicitImports := access.importsByLocal[base]
	if !access.consumeWork(len(explicitImports)) {
		return nil
	}
	for _, imported := range explicitImports {
		if !imported.Wildcard && imported.LocalName() == base {
			explicit = append(explicit, filter(i.byFQN[imported.Path])...)
		}
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(explicit); len(values) > 0 {
		return values
	} else if len(explicit) > 0 {
		return nil
	}
	if file.Package != "" {
		if values := filter(i.byFQN[file.Package+"."+base]); len(values) > 0 {
			return uniqueTypeResolution(values)
		}
	} else if values := filter(i.byFQN[base]); len(values) > 0 {
		// A file with no package declaration sits in the root package, where a
		// top-level declaration's qualified name is its simple name. Skipping
		// this left such files resolving nothing by scope at all.
		return uniqueTypeResolution(values)
	}
	// Every explicit star import has equal precedence. Preserve ambiguity across
	// them instead of returning whichever import happened to occur first.
	var wildcard []analysis.Symbol
	if !access.consumeWork(len(access.wildcardImports)) {
		return nil
	}
	for _, imported := range access.wildcardImports {
		if imported.Wildcard {
			wildcard = append(wildcard, filter(i.byFQN[imported.Path+"."+base])...)
		}
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(wildcard); len(values) > 0 {
		return values
	} else if len(wildcard) > 0 {
		return nil
	}
	// In a Kotlin file `String` is kotlin.String, never java.lang.String,
	// however both are on the classpath: Kotlin's own default imports shadow
	// the Java ones. Java files see only java.lang.
	defaults := []string{"java.lang." + base}
	if file.Language == analysis.LanguageKotlin {
		defaults = defaults[:0]
		for _, prefix := range []string{"kotlin.", "kotlin.annotation.", "kotlin.collections.", "kotlin.comparisons.", "kotlin.io.", "kotlin.ranges.", "kotlin.sequences.", "kotlin.text.", "kotlin.jvm."} {
			defaults = append(defaults, prefix+base)
		}
	}
	var defaultCandidates []analysis.Symbol
	for _, fqn := range defaults {
		defaultCandidates = append(defaultCandidates, filter(i.byFQN[fqn])...)
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(defaultCandidates); len(values) > 0 {
		return values
	} else if len(defaultCandidates) > 0 {
		return nil
	}
	if file.Language == analysis.LanguageKotlin {
		return uniqueTypeResolution(filter(i.byFQN["java.lang."+base]))
	}
	// No global by-name fallback. A simple name that is not declared here, not
	// imported, not in this package and not default-imported is not in scope,
	// and Kotlin will not compile it. Resolving it anyway made navigation jump
	// to a type the file cannot actually name.
	return nil
}

func (i *Index) typeDeclarationVisibleAtLocked(symbol analysis.Symbol, at int) bool {
	if symbol.Kind == analysis.KindTypeParameter {
		return symbolInScopeAt(symbol, at)
	}
	if symbol.ContainerID == "" {
		return true
	}
	container := i.symbols[symbol.ContainerID]
	if container == nil || !analysis.IsCallableKind(container.Kind) {
		// Member/nested types are in scope throughout their owning type.
		return true
	}
	// Java and Kotlin local classes enter scope at their declaration and never
	// leak to an earlier reference in the same callable.
	return symbol.NameEndByte <= at && symbolInScopeAt(symbol, at)
}

func preferTopLevelTypes(values []analysis.Symbol) []analysis.Symbol {
	var topLevel []analysis.Symbol
	for _, value := range values {
		if value.ContainerID == "" {
			topLevel = append(topLevel, value)
		}
	}
	if len(topLevel) > 0 {
		return topLevel
	}
	return values
}

func uniqueTypeResolution(values []analysis.Symbol) []analysis.Symbol {
	if len(values) == 0 {
		return nil
	}
	var resolved analysis.Symbol
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		identity := value.ID
		if identity == "" {
			identity = string(value.URI) + "\x00" + value.FQN + "\x00" + value.Signature
		}
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if resolved.ID != "" || resolved.FQN != "" {
			return nil
		}
		resolved = value
	}
	if resolved.ID == "" && resolved.FQN == "" {
		return nil
	}
	return []analysis.Symbol{resolved}
}

func nearestLexicalTypesLocked(values []analysis.Symbol, owner analysis.Symbol, symbols map[string]*analysis.Symbol) []analysis.Symbol {
	distance := make(map[string]int)
	for current, depth := owner, 0; current.ID != ""; depth++ {
		distance[current.ID] = depth
		if current.ContainerID == "" {
			break
		}
		parent := symbols[current.ContainerID]
		if parent == nil {
			break
		}
		current = *parent
	}
	best := int(^uint(0) >> 1)
	var nearest []analysis.Symbol
	for _, value := range values {
		depth, nested := distance[value.ContainerID]
		if value.ContainerID == "" {
			depth, nested = len(distance)+1, true
		}
		if !nested || depth > best {
			continue
		}
		if depth < best {
			best, nearest = depth, nearest[:0]
		}
		nearest = append(nearest, value)
	}
	return nearest
}

func splitInstantiatedType(value string) (string, []string) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
	if len(value) > 1<<20 {
		return "", nil
	}
	open := strings.IndexByte(value, '<')
	if open < 0 {
		return value, nil
	}
	close := matchingTypeArgumentEnd(value, open)
	if close < 0 {
		return strings.TrimSpace(value[:open]), nil
	}
	return strings.TrimSpace(value[:open]), splitTopLevelTypeArguments(value[open+1 : close])
}

func matchingTypeArgumentEnd(value string, open int) int {
	return lexical.MatchingDelimiter(value, open, "<", ">", true)
}

func splitTopLevelTypeArguments(value string) []string {
	return lexical.SplitTopLevelTypes(value, ",", true)
}

func substituteTypeParameters(value string, parameters, arguments []string) string {
	if value == "" || len(parameters) == 0 || len(arguments) == 0 {
		return value
	}
	replacements := make(map[string]string, len(parameters))
	for index, parameter := range parameters {
		if index < len(arguments) {
			replacements[parameter] = arguments[index]
		}
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if !isIdentRune(r) {
			if result.Len()+size > 1<<20 {
				return ""
			}
			result.WriteString(value[index : index+size])
			index += size
			continue
		}
		end := index + size
		for end < len(value) {
			r, size = utf8.DecodeRuneInString(value[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := value[index:end]
		if replacement := replacements[word]; replacement != "" {
			if result.Len()+len(replacement) > 1<<20 {
				return ""
			}
			result.WriteString(replacement)
		} else {
			if result.Len()+len(word) > 1<<20 {
				return ""
			}
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) directSupertypeMatchesLocked(candidate analysis.Symbol, targetID string) bool {
	file := i.files[candidate.URI]
	if file == nil {
		return false
	}
	for _, declared := range candidate.Supertypes {
		for _, resolved := range i.resolveTypeSymbolsForOwnerLocked(file, declared, candidate) {
			if resolved.ID == targetID {
				return true
			}
		}
	}
	return false
}

func (i *Index) contextualLambdaParameterTypeLocked(file *analysis.ParsedFile, parameter analysis.Symbol) string {
	if file.Language != analysis.LanguageKotlin || parameter.ScopeEndByte <= parameter.ScopeStartByte {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return ""
	}
	parameterIndex := 0
	if parameter.Name != "it" {
		peers := make([]analysis.Symbol, 0, 2)
		for _, symbol := range file.Symbols {
			if (symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindVariable) && symbol.ScopeStartByte == parameter.ScopeStartByte && symbol.ScopeEndByte == parameter.ScopeEndByte {
				peers = append(peers, symbol)
			}
		}
		sort.Slice(peers, func(left, right int) bool { return peers[left].NameStartByte < peers[right].NameStartByte })
		for index, peer := range peers {
			if peer.ID == parameter.ID {
				parameterIndex = index
				break
			}
		}
	}
	for _, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start > parameter.StartByte || parameter.EndByte > end {
				continue
			}
			for _, callable := range i.resolveLocked(file, call) {
				if len(callable.Parameters) == 0 {
					continue
				}
				callableParameter := argumentIndex
				if callableParameter >= len(callable.Parameters) {
					callableParameter = len(callable.Parameters) - 1
				}
				parameterType := i.contextualCallableParameterTypeLocked(file, call, callable, callableParameter, document)
				types := kotlinFunctionParameterTypes(parameterType)
				if parameterIndex < len(types) {
					return types[parameterIndex]
				}
			}
		}
	}
	return ""
}

func (i *Index) contextualLambdaReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	if file.Language != analysis.LanguageKotlin {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return ""
	}
	best, bestSpan := "", int(^uint(0)>>1)
	for _, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if at < start || end < at || end-start >= bestSpan {
				continue
			}
			for _, callable := range i.resolveLocked(file, call) {
				if len(callable.Parameters) == 0 {
					continue
				}
				callableParameter := argumentIndex
				if callableParameter >= len(callable.Parameters) {
					callableParameter = len(callable.Parameters) - 1
				}
				parameterType := i.contextualCallableParameterTypeLocked(file, call, callable, callableParameter, document)
				if receiver := kotlinFunctionReceiverType(parameterType); receiver != "" {
					best, bestSpan = receiver, end-start
					break
				}
			}
		}
	}
	return best
}

func (i *Index) enclosingExtensionReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	bestStart, bestEnd, receiver := -1, len(i.documentTextLocked(file.URI))+1, ""
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.ReceiverType == "" || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if symbol.StartByte > bestStart || symbol.StartByte == bestStart && symbol.EndByte < bestEnd {
			bestStart, bestEnd, receiver = symbol.StartByte, symbol.EndByte, symbol.ReceiverType
		}
	}
	return receiver
}

func (i *Index) enclosingContextReceiverTypesLocked(file *analysis.ParsedFile, at int) []string {
	if file.Language != analysis.LanguageKotlin {
		return nil
	}
	text := i.documentTextLocked(file.URI)
	if text == "" {
		return nil
	}
	var callable analysis.Symbol
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if callable.ID == "" || symbol.StartByte >= callable.StartByte && symbol.EndByte <= callable.EndByte {
			callable = symbol
		}
	}
	if callable.ID == "" || callable.StartByte <= 0 || callable.StartByte > len(text) {
		return nil
	}
	end := callable.StartByte
	for end > 0 && unicode.IsSpace(rune(text[end-1])) {
		end--
	}
	if end == 0 || text[end-1] != ')' {
		return nil
	}
	closeAt := end - 1
	depth, openAt := 0, -1
	for index := closeAt; index >= 0; index-- {
		switch text[index] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				openAt = index
				index = -1
			}
		}
	}
	if openAt < 0 {
		return nil
	}
	wordEnd := openAt
	for wordEnd > 0 && unicode.IsSpace(rune(text[wordEnd-1])) {
		wordEnd--
	}
	wordStart := wordEnd
	for wordStart > 0 && isIdentRune(rune(text[wordStart-1])) {
		wordStart--
	}
	if text[wordStart:wordEnd] != "context" {
		return nil
	}
	items := splitTopLevelCallArguments(text[openAt+1 : closeAt])
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if colon := strings.IndexByte(item, ':'); colon >= 0 {
			item = strings.TrimSpace(item[colon+1:])
		}
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (i *Index) contextualCallableParameterTypeLocked(file *analysis.ParsedFile, call analysis.Reference, callable analysis.Symbol, parameterIndex int, document *textdoc.Document) string {
	if parameterIndex < 0 || parameterIndex >= len(callable.Parameters) {
		return ""
	}
	parameterType := callable.Parameters[parameterIndex].Type
	if len(callable.TypeParameters) == 0 || len(call.Arguments) == 0 {
		return parameterType
	}
	inferred := make(map[string]string, len(callable.TypeParameters))
	for argumentIndex, argumentRange := range call.Arguments {
		callableIndex := argumentIndex
		if callableIndex >= len(callable.Parameters) {
			callableIndex = len(callable.Parameters) - 1
		}
		if callableIndex < 0 || callableIndex == parameterIndex {
			continue
		}
		start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
		if start < 0 || end < start || end > len(document.Text) {
			continue
		}
		expression := strings.TrimSpace(document.Text[start:end])
		if equals := topLevelNamedArgumentEquals(expression); equals >= 0 {
			expression = strings.TrimSpace(expression[equals+1:])
		}
		actual := i.inferExpressionTypeLocked(file, expression, call.StartByte)
		if actual != "" {
			i.inferTypeParameterBindingsLocked(file, callable.Parameters[callableIndex].Type, actual, callable.TypeParameters, inferred)
		}
	}
	arguments := make([]string, len(callable.TypeParameters))
	for index, parameter := range callable.TypeParameters {
		arguments[index] = inferred[parameter]
	}
	return substituteTypeParameters(parameterType, callable.TypeParameters, arguments)
}

func topLevelNamedArgumentEquals(expression string) int {
	if index := lexical.TopLevelTokenIndex(expression, "=", true); index >= 0 {
		return index
	}
	angles, parens, brackets, braces := 0, 0, 0, 0
	for index, r := range expression {
		switch r {
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
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
		case '=':
			if angles == 0 && parens == 0 && brackets == 0 && braces == 0 {
				return index
			}
		}
	}
	return -1
}

func kotlinFunctionParameterTypes(functionType string) []string {
	functionType = strings.TrimSpace(strings.TrimSuffix(functionType, "?"))
	arrow := strings.LastIndex(functionType, "->")
	if arrow < 0 {
		return nil
	}
	parameters := strings.TrimSpace(functionType[:arrow])
	if dot := strings.LastIndex(parameters, ".("); dot >= 0 {
		parameters = parameters[dot+1:]
	}
	if len(parameters) < 2 || parameters[0] != '(' || parameters[len(parameters)-1] != ')' {
		return nil
	}
	parameters = strings.TrimSpace(parameters[1 : len(parameters)-1])
	if parameters == "" {
		return nil
	}
	return splitTopLevelCallArguments(parameters)
}

func kotlinFunctionReceiverType(functionType string) string {
	functionType = strings.TrimSpace(strings.TrimSuffix(functionType, "?"))
	arrow := strings.LastIndex(functionType, "->")
	if arrow < 0 {
		return ""
	}
	parameters := strings.TrimSpace(functionType[:arrow])
	dot := strings.LastIndex(parameters, ".(")
	if dot <= 0 {
		return ""
	}
	receiver := strings.TrimSpace(parameters[:dot])
	receiver = strings.TrimSpace(strings.TrimPrefix(receiver, "suspend "))
	return receiver
}

type typeInferenceConstraint struct {
	parameter  string
	lowerBound string
}

type typeInferenceConstraints struct {
	values      []typeInferenceConstraint
	unsupported bool
}

// inferTypeParameterBindingsLocked is the measured fast constraint solver.
// It records lower-bound constraints explicitly, merges repeated constraints
// through the structured type graph's LUB, and reports false for projections,
// captures, intersections, or incompatible shapes. Callers must treat false as
// unknown rather than selecting an overload from a fabricated binding.
func (i *Index) inferTypeParameterBindingsLocked(file *analysis.ParsedFile, pattern, actual string, parameters []string, inferred map[string]string) bool {
	if pattern == "" || actual == "" {
		return false
	}
	constraints := typeInferenceConstraints{}
	matched := collectTypeParameterConstraints(pattern, actual, parameters, &constraints, 0)
	if constraints.unsupported {
		return false
	}
	// A declared parameter such as Iterable<T> also constrains T when the
	// actual argument is List<String>. Walk the instantiated supertype graph and
	// bind against the first matching generic owner instead of requiring equal
	// raw spellings at the call site.
	if !matched {
		patternBase, _ := splitInstantiatedType(pattern)
		for _, owner := range i.instantiatedTypeHierarchyLocked(file, actual) {
			if !sameJvmType(owner.symbol.Name, patternBase) && !sameJvmType(owner.symbol.FQN, patternBase) {
				continue
			}
			instantiated := instantiatedTypeName(owner.symbol.FQN, owner.arguments)
			matched = collectTypeParameterConstraints(pattern, instantiated, parameters, &constraints, 0)
			break
		}
	}
	if !matched || constraints.unsupported || len(constraints.values) == 0 {
		return false
	}
	solved := make(map[string]string, len(inferred)+len(constraints.values))
	for parameter, value := range inferred {
		solved[parameter] = value
	}
	for _, constraint := range constraints.values {
		previous := solved[constraint.parameter]
		if previous == "" {
			solved[constraint.parameter] = constraint.lowerBound
			continue
		}
		merged := i.commonExpressionTypeLocked(file, previous, constraint.lowerBound)
		if merged == "" {
			return false
		}
		solved[constraint.parameter] = merged
	}
	for parameter, value := range solved {
		inferred[parameter] = value
	}
	return true
}

func collectTypeParameterConstraints(pattern, actual string, parameters []string, constraints *typeInferenceConstraints, depth int) bool {
	pattern, actual = strings.TrimSpace(pattern), strings.TrimSpace(actual)
	if depth > 256 {
		constraints.unsupported = true
		return false
	}
	if strings.ContainsAny(pattern, "*&") || strings.ContainsAny(actual, "*&") || strings.Contains(pattern, "? extends ") || strings.Contains(pattern, "? super ") || strings.Contains(actual, "? extends ") || strings.Contains(actual, "? super ") || strings.Contains(pattern, "->") || strings.Contains(actual, "->") {
		constraints.unsupported = true
		return false
	}
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	for _, parameter := range parameters {
		base := strings.TrimSpace(patternBase)
		if strings.HasPrefix(base, "out ") || strings.HasPrefix(base, "in ") {
			constraints.unsupported = true
			return false
		}
		if simpleType(base) == parameter && actual != "" {
			constraints.values = append(constraints.values, typeInferenceConstraint{parameter: parameter, lowerBound: actual})
			return true
		}
	}
	if !sameJvmType(patternBase, actualBase) || len(patternArguments) != len(actualArguments) {
		return false
	}
	matched := true
	for index := range patternArguments {
		if !collectTypeParameterConstraints(patternArguments[index], actualArguments[index], parameters, constraints, depth+1) {
			matched = false
		}
	}
	return matched
}

func matchTypePattern(pattern, actual string, parameters map[string]bool, inferred map[string]string) bool {
	return matchTypePatternDepth(pattern, actual, parameters, inferred, 0)
}

func matchTypePatternDepth(pattern, actual string, parameters map[string]bool, inferred map[string]string, depth int) bool {
	if depth > 256 {
		return false
	}
	pattern = strings.TrimSpace(pattern)
	actual = strings.TrimSpace(actual)
	if strings.HasSuffix(actual, "?") && !strings.HasSuffix(pattern, "?") {
		return false
	}
	pattern = strings.TrimSuffix(pattern, "?")
	actual = strings.TrimSuffix(actual, "?")
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	patternSimple := simpleType(strings.TrimPrefix(strings.TrimPrefix(patternBase, "out "), "in "))
	if parameters[patternSimple] {
		if previous := inferred[patternSimple]; previous != "" {
			return sameJvmType(previous, actual)
		}
		inferred[patternSimple] = actual
		return true
	}
	if simpleType(patternBase) != simpleType(actualBase) || len(patternArguments) != len(actualArguments) {
		return false
	}
	for index := range patternArguments {
		if !matchTypePatternDepth(patternArguments[index], actualArguments[index], parameters, inferred, depth+1) {
			return false
		}
	}
	return true
}

func instantiatedTypeName(name string, arguments []string) string {
	if len(arguments) == 0 {
		return name
	}
	total := len(name) + 2
	for _, argument := range arguments {
		total += len(argument) + 2
		if total > 1<<20 {
			return ""
		}
	}
	return name + "<" + strings.Join(arguments, ", ") + ">"
}

func substituteTypeBindings(value string, bindings map[string]string) string {
	if value == "" || len(bindings) == 0 {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if !isIdentRune(r) {
			if result.Len()+size > 1<<20 {
				return ""
			}
			result.WriteString(value[index : index+size])
			index += size
			continue
		}
		end := index + size
		for end < len(value) {
			r, size = utf8.DecodeRuneInString(value[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := value[index:end]
		if replacement := bindings[word]; replacement != "" {
			if result.Len()+len(replacement) > 1<<20 {
				return ""
			}
			result.WriteString(replacement)
		} else {
			if result.Len()+len(word) > 1<<20 {
				return ""
			}
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) extensionReceiverBindingsLocked(file *analysis.ParsedFile, extension analysis.Symbol, actualType string) (map[string]string, bool) {
	if extension.ReceiverType == "" || actualType == "" {
		return nil, false
	}
	parameters := make(map[string]bool, len(extension.TypeParameters))
	for _, parameter := range extension.TypeParameters {
		parameters[parameter] = true
	}
	actualTypes := []string{actualType}
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, actualType) {
		actualTypes = append(actualTypes, instantiatedTypeName(instantiated.symbol.Name, instantiated.arguments))
		if instantiated.symbol.FQN != "" && instantiated.symbol.FQN != instantiated.symbol.Name {
			actualTypes = append(actualTypes, instantiatedTypeName(instantiated.symbol.FQN, instantiated.arguments))
		}
	}
	for _, actual := range actualTypes {
		bindings := make(map[string]string, len(parameters))
		if !matchTypePattern(extension.ReceiverType, actual, parameters, bindings) {
			continue
		}
		valid := true
		for parameter, actualType := range bindings {
			if !i.typeArgumentSatisfiesBoundsLocked(file, actualType, extension.TypeParameterBounds[parameter]) {
				valid = false
				break
			}
		}
		if valid {
			return bindings, true
		}
	}
	return nil, false
}

// spellingReceiverOwners names the extension buckets a receiver type can reach
// when it resolves to no indexed declaration (kotlin.String without a stdlib
// index, an unresolved library type). Extension buckets are keyed by the
// receiver's simple spelling, so the spelling is the only owner identity such
// a receiver has. Callers still prove applicability against each extension's
// receiver pattern; this is candidate discovery, never a resolution answer.
func spellingReceiverOwners(typeName string) []analysis.Symbol {
	var owners []analysis.Symbol
	for _, root := range splitIntersectionTypes(strings.TrimSpace(typeName)) {
		base, _ := splitInstantiatedType(strings.TrimSuffix(strings.TrimSpace(root), "?"))
		if name := simpleType(strings.TrimSpace(base)); name != "" {
			owners = append(owners, analysis.Symbol{Name: name, Kind: analysis.KindClass})
		}
	}
	return owners
}

func (i *Index) extensionReceiverApplicableLocked(file *analysis.ParsedFile, extension analysis.Symbol, actualType string) bool {
	_, applicable := i.extensionReceiverBindingsLocked(file, extension, actualType)
	return applicable
}

type instantiatedTypeOwner struct {
	symbol    analysis.Symbol
	arguments []string
	distance  int
}

func (i *Index) instantiatedTypeHierarchyLocked(file *analysis.ParsedFile, typeName string) []instantiatedTypeOwner {
	result, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(context.Background(), file, typeName, 4096, newAccessibilityMemoLocked(i, file))
	if !complete {
		return nil
	}
	return result
}

func (i *Index) instantiatedTypeHierarchyBoundedLocked(ctx context.Context, file *analysis.ParsedFile, typeName string, limit int) ([]instantiatedTypeOwner, bool) {
	return i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, typeName, limit, newAccessibilityMemoLocked(i, file))
}

func (i *Index) instantiatedTypeHierarchyBoundedWithMemoLocked(ctx context.Context, file *analysis.ParsedFile, typeName string, limit int, access *accessibilityMemo) ([]instantiatedTypeOwner, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit < 1 || limit > 4096 {
		return nil, false
	}
	type pendingOwner struct {
		name           string
		distance       int
		resolutionFile *analysis.ParsedFile
		lexicalOwner   analysis.Symbol
	}
	current := make([]pendingOwner, 0)
	for _, root := range splitIntersectionTypes(typeName) {
		current = append(current, pendingOwner{name: root, resolutionFile: file})
	}
	seen := make(map[string]bool)
	result := make([]instantiatedTypeOwner, 0, 4)
	for len(current) > 0 {
		next := make([]pendingOwner, 0)
		for cursor := 0; cursor < len(current); cursor++ {
			if ctx.Err() != nil {
				return nil, false
			}
			if len(seen) >= limit || len(current)+len(next) > limit*4 {
				return nil, false
			}
			pending := current[cursor]
			instantiated := pending.name
			base, arguments := splitInstantiatedType(instantiated)
			resolutionFile := pending.resolutionFile
			if resolutionFile == nil {
				resolutionFile = file
			}
			// A source declaration may spell its supertype through an import which
			// does not exist at the eventual call site. Resolve every hierarchy edge
			// in the declaring file's lexical/import context. Keep one shared work
			// allowance by transferring the remaining budget into and out of the
			// edge-local memo.
			resolutionAccess := access
			if resolutionFile.URI != file.URI || pending.lexicalOwner.ID != "" {
				edgeAccess := *access
				edgeAccess.importsReady = false
				edgeAccess.importsComplete = false
				edgeAccess.importsByLocal = nil
				edgeAccess.wildcardImports = nil
				resolutionAccess = &edgeAccess
			}
			resolvedTypes := i.resolveTypeSymbolsForOwnerMemoLocked(resolutionFile, base, pending.lexicalOwner, resolutionAccess)
			if resolutionAccess != access {
				access.remainingWork = resolutionAccess.remainingWork
				access.workExhausted = access.workExhausted || resolutionAccess.workExhausted
			}
			if access.workExhausted {
				return nil, false
			}
			for _, symbol := range resolvedTypes {
				key := symbol.ID + "\x00" + strings.Join(arguments, "\x00")
				if seen[key] {
					continue
				}
				if len(result) >= limit {
					return nil, false
				}
				seen[key] = true
				result = append(result, instantiatedTypeOwner{symbol: symbol, arguments: arguments, distance: pending.distance})
				declarationFile := i.files[symbol.URI]
				if declarationFile == nil {
					declarationFile = resolutionFile
				}
				if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
					// Typealiases are zero-cost edges. Append them to the active
					// level so every zero-cost closure is exhausted before any
					// superclass edge at distance+1 is observed.
					current = append(current, pendingOwner{name: substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments), distance: pending.distance, resolutionFile: declarationFile, lexicalOwner: symbol})
				}
				for _, supertype := range symbol.Supertypes {
					next = append(next, pendingOwner{name: substituteTypeParameters(supertype, symbol.TypeParameters, arguments), distance: pending.distance + 1, resolutionFile: declarationFile, lexicalOwner: symbol})
				}
			}
		}
		current = next
	}
	return result, true
}

func (i *Index) enclosingTypeLocked(file *analysis.ParsedFile, at int) analysis.Symbol {
	var found analysis.Symbol
	for _, symbol := range file.Symbols {
		if analysis.IsTypeKind(symbol.Kind) && symbol.StartByte <= at && at <= symbol.EndByte && (found.ID == "" || symbol.StartByte >= found.StartByte && symbol.EndByte <= found.EndByte) {
			found = symbol
		}
	}
	return found
}

func (i *Index) symbolWithinCallableScopeLocked(file *analysis.ParsedFile, symbol analysis.Symbol, at int) bool {
	container, ok := i.symbols[symbol.ContainerID]
	return ok && analysis.IsCallableKind(container.Kind) && container.URI == file.URI && container.StartByte <= at && at <= container.EndByte
}

func (i *Index) typeAndSupertypesLocked(file *analysis.ParsedFile, typeName string) []string {
	queue := splitIntersectionTypes(typeName)
	seenTypes := map[string]bool{}
	seenSymbols := map[string]bool{}
	var out []string
	for len(queue) > 0 {
		if len(seenTypes) >= 4096 || len(queue) > 8192 || len(out) > 8192 {
			return nil
		}
		instantiated := queue[0]
		queue = queue[1:]
		if instantiated == "" || seenTypes[instantiated] {
			continue
		}
		seenTypes[instantiated] = true
		base, arguments := splitInstantiatedType(instantiated)
		symbols := i.resolveTypeSymbolsLocked(file, base)
		if len(symbols) == 0 {
			out = append(out, simpleType(base))
			continue
		}
		for _, symbol := range symbols {
			if seenSymbols[symbol.ID] {
				continue
			}
			seenSymbols[symbol.ID] = true
			out = append(out, symbol.Name)
			if symbol.FQN != "" && symbol.FQN != symbol.Name {
				out = append(out, symbol.FQN)
			}
			if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
				queue = append(queue, substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments))
			}
			for _, supertype := range symbol.Supertypes {
				queue = append(queue, substituteTypeParameters(supertype, symbol.TypeParameters, arguments))
			}
		}
	}
	return out
}

func splitIntersectionTypes(typeName string) []string {
	if len(typeName) > 1<<20 {
		return nil
	}
	angles, start := 0, 0
	var result []string
	for index := 0; index <= len(typeName); index++ {
		if index == len(typeName) || typeName[index] == '&' && angles == 0 {
			if value := strings.TrimSpace(typeName[start:index]); value != "" {
				if len(result) >= 256 {
					return nil
				}
				result = append(result, value)
			}
			start = index + 1
			continue
		}
		if typeName[index] == '<' {
			angles++
		} else if typeName[index] == '>' && angles > 0 {
			angles--
		}
	}
	if len(result) == 0 {
		return []string{typeName}
	}
	return result
}

func (i *Index) accessibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	return i.accessibleWithMemoLocked(file, symbol, newAccessibilityMemoLocked(i, file), positions...)
}

type accessibilityMemo struct {
	fromModule        *ModuleInfo
	fromSourceSet     string
	ownershipComplete bool
	targetModules     map[protocol.URI]*ModuleInfo
	targetSourceSets  map[protocol.URI]string
	targetComplete    map[protocol.URI]bool
	moduleAccess      map[string]bool
	moduleComplete    bool
	moduleReady       bool
	javaAccess        map[string]bool
	libraryJava       map[string]bool
	javaReadable      map[string]bool
	javaReadComplete  bool
	javaReadReady     bool
	sourceSetDistance map[string]int
	remainingWork     int
	workExhausted     bool
	importsReady      bool
	importsComplete   bool
	importsByLocal    map[string][]analysis.Import
	wildcardImports   []analysis.Import
}

// A non-module key keeps a newly indexed archive inaccessible until the build
// model which introduced it commits. Real access identities always begin with
// an absolute module directory and therefore cannot collide with this marker.
const pendingLibraryAccessKey = "\x00pending-build-refresh"

func (memo *accessibilityMemo) consumeWork(count int) bool {
	if memo == nil || memo.workExhausted || count < 0 || count > memo.remainingWork {
		if memo != nil {
			memo.workExhausted = true
		}
		return false
	}
	memo.remainingWork -= count
	return true
}

func (i *Index) prepareResolutionImportsLocked(file *analysis.ParsedFile, memo *accessibilityMemo) bool {
	if memo.importsReady {
		return memo.importsComplete
	}
	memo.importsReady = true
	if !memo.consumeWork(len(file.Imports)) {
		return false
	}
	memo.importsByLocal = make(map[string][]analysis.Import)
	for _, imported := range file.Imports {
		if imported.Wildcard {
			memo.wildcardImports = append(memo.wildcardImports, imported)
			continue
		}
		name := imported.LocalName()
		memo.importsByLocal[name] = append(memo.importsByLocal[name], imported)
	}
	memo.importsComplete = true
	return true
}

func (i *Index) javaReadableWithMemoLocked(memo *accessibilityMemo, moduleName string) bool {
	if memo.fromModule == nil || memo.fromModule.JavaModuleName == "" || moduleName == "" || memo.fromModule.JavaModuleName == moduleName {
		return true
	}
	if !memo.javaReadReady {
		memo.javaReadable, memo.javaReadComplete = i.javaReadableSetLocked(memo.fromModule)
		memo.javaReadReady = true
	}
	return memo.javaReadComplete && memo.javaReadable[moduleName]
}

func newAccessibilityMemoLocked(i *Index, file *analysis.ParsedFile) *accessibilityMemo {
	from, complete := moduleForURIInModules(file.URI, i.modules)
	fromSourceSet := ""
	if complete {
		fromSourceSet, complete = sourceSetForURIInModule(file.URI, from)
	}
	if i.generation.Load() == 0 {
		complete = true
	}
	if _, library := i.librarySources[file.URI]; library {
		// Library files (jar:/jrt:) belong to no workspace module; their
		// ownership is fully known, and their supertypes and members must be
		// resolvable from the library's own context.
		from, fromSourceSet, complete = nil, "", true
	}
	return &accessibilityMemo{
		fromModule:        from,
		fromSourceSet:     fromSourceSet,
		ownershipComplete: complete,
		targetModules:     make(map[protocol.URI]*ModuleInfo),
		targetSourceSets:  make(map[protocol.URI]string),
		targetComplete:    make(map[protocol.URI]bool),
		javaAccess:        make(map[string]bool),
		libraryJava:       make(map[string]bool),
		sourceSetDistance: make(map[string]int),
		remainingWork:     maxResolutionCandidates,
	}
}

func (i *Index) sourceSetDistanceWithMemoLocked(memo *accessibilityMemo, target *ModuleInfo, targetSet string) int {
	if memo.fromModule == nil || target == nil || memo.fromModule.Name != target.Name || memo.fromModule.Dir != target.Dir {
		return -1
	}
	key := targetSet
	if distance, known := memo.sourceSetDistance[key]; known {
		return distance
	}
	distance := sourceSetAccessDistance(memo.fromModule, memo.fromSourceSet, targetSet)
	memo.sourceSetDistance[key] = distance
	return distance
}

func (i *Index) accessibilityTargetLocked(memo *accessibilityMemo, uri protocol.URI) (*ModuleInfo, string, bool) {
	target, known := memo.targetModules[uri]
	if !known {
		var complete bool
		target, complete = moduleForURIInModules(uri, i.modules)
		memo.targetModules[uri] = target
		if complete {
			memo.targetSourceSets[uri], complete = sourceSetForURIInModule(uri, target)
		}
		if i.generation.Load() == 0 {
			complete = true
		}
		memo.targetComplete[uri] = complete
	}
	return target, memo.targetSourceSets[uri], memo.targetComplete[uri]
}

func (i *Index) moduleCanAccessWithMemoLocked(memo *accessibilityMemo, target *ModuleInfo, targetSourceSet string) bool {
	if !memo.ownershipComplete {
		return false
	}
	from := memo.fromModule
	if from == nil || target == nil {
		return true
	}
	if from.Name == target.Name && from.Dir == target.Dir {
		return sourceSetCanAccess(from, memo.fromSourceSet, targetSourceSet)
	}
	if targetSourceSet != "main" && targetSourceSet != "commonMain" {
		return false
	}
	if !memo.moduleReady {
		byName := make(map[string][]*ModuleInfo, len(i.modules))
		for index := range i.modules {
			module := &i.modules[index]
			key := module.Root + "\x00" + module.Name
			byName[key] = append(byName[key], module)
		}
		memo.moduleAccess, memo.moduleComplete = moduleAccessSet(from, memo.fromSourceSet, byName)
		memo.moduleReady = true
	}
	return memo.moduleComplete && memo.moduleAccess[moduleAccessIdentity(target)]
}

func (i *Index) accessibleWithMemoLocked(file *analysis.ParsedFile, symbol analysis.Symbol, memo *accessibilityMemo, positions ...int) bool {
	if symbol.InteropLanguage != analysis.LanguageUnknown && symbol.InteropLanguage != file.Language {
		return false
	}
	if file.Language == analysis.LanguageJava && containsString(symbol.Modifiers, "JvmSynthetic") {
		return false
	}
	if file.Language == analysis.LanguageJava && symbol.Language == analysis.LanguageKotlin && !symbol.Synthetic {
		if symbol.JVMName != "" || symbol.ContainerID == "" && (analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty) {
			return false
		}
	}
	fromModule := memo.fromModule
	fromSourceSet := memo.fromSourceSet
	targetModule, targetSourceSet, targetComplete := i.accessibilityTargetLocked(memo, symbol.URI)
	if !memo.ownershipComplete && symbol.URI != file.URI || !symbol.Library && !targetComplete && symbol.URI != file.URI {
		return false
	}
	if symbol.Library && fromModule != nil {
		if source, exists := i.librarySources[symbol.URI]; exists {
			if access := i.libraryAccess[filepath.Clean(source.Archive)]; len(access) > 0 && !access[fromModule.Dir] && !access[libraryAccessKey(fromModule.Dir, fromSourceSet)] {
				return false
			}
			if file.Language == analysis.LanguageJava {
				archive := filepath.Clean(source.Archive)
				if module, modular := i.libraryModules[archive]; modular {
					key := archive + "\x00" + symbol.Package
					allowed, known := memo.libraryJava[key]
					if !known {
						allowed = i.javaReadableWithMemoLocked(memo, module.Name)
						if allowed && !module.Automatic && fromModule != nil && fromModule.JavaModuleName != "" && fromModule.JavaModuleName != module.Name {
							targets, exported := module.Exports[symbol.Package]
							allowed = exported && (containsString(targets, "*") || containsString(targets, fromModule.JavaModuleName))
						}
						memo.libraryJava[key] = allowed
					}
					if !allowed {
						return false
					}
				}
			}
		}
	}
	if targetModule != nil && !i.moduleCanAccessWithMemoLocked(memo, targetModule, targetSourceSet) {
		return false
	}
	if file.Language == analysis.LanguageJava && symbol.Language == analysis.LanguageJava {
		key := moduleAccessIdentity(targetModule) + "\x00" + symbol.Package
		allowed, known := memo.javaAccess[key]
		if !known {
			allowed = targetModule == nil || i.javaReadableWithMemoLocked(memo, targetModule.JavaModuleName)
			if allowed && fromModule != nil && targetModule != nil && fromModule.JavaModuleName != "" && targetModule.JavaModuleName != "" && fromModule.JavaModuleName != targetModule.JavaModuleName {
				targets, exported := targetModule.JavaExports[symbol.Package]
				allowed = exported && (containsString(targets, "*") || containsString(targets, fromModule.JavaModuleName))
			}
			memo.javaAccess[key] = allowed
		}
		if !allowed {
			return false
		}
	}
	visibility := ""
	for _, modifier := range symbol.Modifiers {
		if modifier == "private" || modifier == "protected" || modifier == "public" || modifier == "internal" {
			visibility = modifier
		}
	}
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok {
			if IsLocalDeclarationOwner(*owner) {
				if owner.URI != file.URI || len(positions) == 0 || symbol.ScopeStartByte > 0 && positions[0] < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && positions[0] > symbol.ScopeEndByte {
					return false
				}
			}
			if analysis.IsTypeKind(owner.Kind) && !i.accessibleWithMemoLocked(file, *owner, memo, positions...) {
				return false
			}
		}
	}
	if visibility == "protected" && symbol.Language == analysis.LanguageKotlin {
		if symbol.ContainerID == "" || len(positions) == 0 {
			return false
		}
		owner := i.symbols[symbol.ContainerID]
		for owner != nil && !analysis.IsTypeKind(owner.Kind) && owner.ContainerID != "" {
			owner = i.symbols[owner.ContainerID]
		}
		current := i.enclosingTypeLocked(file, positions[0])
		if owner == nil || current.ID == "" || current.ID != owner.ID && !i.containerInheritsLocked(current.ID, owner.ID) {
			return false
		}
	}
	if symbol.URI == file.URI {
		if visibility != "private" || symbol.ContainerID == "" {
			return true
		}
		if len(positions) == 0 {
			return false
		}
		owner, ok := i.symbols[symbol.ContainerID]
		if !ok {
			return false
		}
		if symbol.Language == analysis.LanguageJava {
			for owner.ContainerID != "" {
				parent, exists := i.symbols[owner.ContainerID]
				if !exists || !analysis.IsTypeKind(parent.Kind) {
					break
				}
				owner = parent
			}
		}
		return owner.StartByte <= positions[0] && positions[0] <= owner.EndByte
	}
	if visibility == "private" {
		return false
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && (owner.Kind == analysis.KindInterface || owner.Kind == analysis.KindAnnotation) {
			visibility = "public"
		}
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.Package != file.Package {
		return false // Java package-private declaration.
	}
	if visibility == "protected" && symbol.Package != file.Package {
		if symbol.ContainerID == "" {
			return false
		}
		for _, candidate := range file.Symbols {
			if analysis.IsTypeKind(candidate.Kind) && i.containerInheritsLocked(candidate.ID, symbol.ContainerID) {
				return true
			}
		}
		return false
	}
	if visibility == "internal" && file.Language == analysis.LanguageKotlin && fromModule != nil && targetModule != nil && (fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir) {
		return false
	}
	return true
}

func IsLocalDeclarationOwner(symbol analysis.Symbol) bool {
	return analysis.IsCallableKind(symbol.Kind)
}

func (i *Index) kotlinObjectInstanceMemberLocked(symbol analysis.Symbol) bool {
	if symbol.Language != analysis.LanguageKotlin || symbol.Synthetic || symbol.ContainerID == "" {
		return false
	}
	owner, ok := i.symbols[symbol.ContainerID]
	return ok && owner.Kind == analysis.KindObject
}

func (i *Index) typeQualifierActsAsValueLocked(file *analysis.ParsedFile, types []analysis.Symbol) bool {
	if file.Language != analysis.LanguageKotlin {
		return false
	}
	for _, symbol := range types {
		if symbol.Kind == analysis.KindObject {
			return true
		}
	}
	return false
}

func (i *Index) memberAvailableThroughTypeQualifierLocked(file *analysis.ParsedFile, symbol analysis.Symbol, types []analysis.Symbol) bool {
	if i.staticOrNestedMemberLocked(symbol) {
		return true
	}
	if file.Language == analysis.LanguageKotlin && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && owner.Kind == analysis.KindObject && containsString(owner.Modifiers, "companion") {
			return true
		}
	}
	return i.typeQualifierActsAsValueLocked(file, types) && !symbol.Synthetic
}

func (i *Index) staticOrNestedMemberLocked(symbol analysis.Symbol) bool {
	return analysis.IsTypeKind(symbol.Kind) || containsString(symbol.Modifiers, "static") || symbol.Kind == analysis.KindEnumMember
}

func (i *Index) staticLikeContextLocked(file *analysis.ParsedFile, at int) bool {
	for _, symbol := range file.Symbols {
		if symbol.StartByte <= at && at <= symbol.EndByte {
			if symbol.Language == analysis.LanguageJava && !analysis.IsTypeKind(symbol.Kind) && containsString(symbol.Modifiers, "static") {
				return true
			}
		}
	}
	return false
}

func nestedTypeCapturesOuter(nested, outer analysis.Symbol) bool {
	if nested.Language == analysis.LanguageKotlin {
		return containsString(nested.Modifiers, "inner")
	}
	if nested.Language == analysis.LanguageJava {
		return nested.Kind == analysis.KindClass && outer.Kind != analysis.KindInterface && outer.Kind != analysis.KindAnnotation && !containsString(nested.Modifiers, "static")
	}
	return false
}

func (i *Index) extensionVisibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && analysis.IsCallableKind(owner.Kind) {
			if symbol.URI != file.URI || len(positions) == 0 || symbol.ScopeStartByte > 0 && positions[0] < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && positions[0] > symbol.ScopeEndByte {
				return false
			}
		}
	}
	if symbol.ReceiverType == "" || symbol.URI == file.URI || symbol.Package == file.Package {
		return true
	}
	// Top-level extensions obey exactly the same package/import rules as other
	// top-level declarations. In particular, Kotlin's default imports include
	// the generic extensions in package kotlin (apply, let, run, also, takeIf,
	// and friends). Requiring a textual import here made those declarations
	// discoverable in the index but permanently invisible to resolution.
	if symbol.ContainerID == "" {
		return i.topLevelVisibleLocked(file, symbol)
	}
	for _, imp := range file.Imports {
		if imp.Path == symbol.FQN || imp.Wildcard && imp.Path == symbol.Package {
			return true
		}
	}
	return false
}

func (i *Index) containerInheritsLocked(containerID, targetContainerID string) bool {
	target, ok := i.symbols[targetContainerID]
	if !ok {
		return false
	}
	queue := []string{containerID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		container, exists := i.symbols[id]
		if !exists {
			continue
		}
		file := i.files[container.URI]
		if file == nil {
			continue
		}
		for _, supertype := range container.Supertypes {
			for _, parent := range i.resolveTypeSymbolsForOwnerLocked(file, supertype, *container) {
				if parent.ID == target.ID {
					return true
				}
				queue = append(queue, parent.ID)
			}
		}
	}
	return false
}

func (i *Index) symbolsForIDsLocked(ids []string, accept func(analysis.Symbol) bool) []analysis.Symbol {
	seen := map[string]bool{}
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		s, ok := i.symbols[id]
		if ok && (accept == nil || accept(*s)) {
			seen[id] = true
			out = append(out, *s)
		}
	}
	return out
}
