package index

import (
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/analysis"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func (i *Index) resolveTypeSymbolsLocked(file *analysis.ParsedFile, typeName string) []analysis.Symbol {
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
	filter := func(ids []string) []analysis.Symbol {
		return i.symbolsForIDsLocked(ids, func(symbol analysis.Symbol) bool {
			return analysis.IsTypeKind(symbol.Kind) && i.accessibleLocked(file, symbol)
		})
	}
	if strings.Contains(base, ".") {
		return filter(i.byFQN[base])
	}
	// Lexically declared type parameters and nested/local types have priority.
	var local []string
	for _, id := range i.byName[base] {
		symbol := i.symbols[id]
		if symbol.URI == file.URI && analysis.IsTypeKind(symbol.Kind) {
			local = append(local, id)
		}
	}
	if values := filter(local); len(values) > 0 {
		return values[:1]
	}
	for _, imported := range file.Imports {
		if !imported.Wildcard && imported.LocalName() == base {
			if values := filter(i.byFQN[imported.Path]); len(values) > 0 {
				return values
			}
		}
	}
	if file.Package != "" {
		if values := filter(i.byFQN[file.Package+"."+base]); len(values) > 0 {
			return values
		}
	} else if values := filter(i.byFQN[base]); len(values) > 0 {
		// A file with no package declaration sits in the root package, where a
		// top-level declaration's qualified name is its simple name. Skipping
		// this left such files resolving nothing by scope at all.
		return values
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
		defaults = append(defaults, "java.lang."+base)
	}
	for _, fqn := range defaults {
		if values := filter(i.byFQN[fqn]); len(values) > 0 {
			return values
		}
	}
	for _, imported := range file.Imports {
		if imported.Wildcard {
			if values := filter(i.byFQN[imported.Path+"."+base]); len(values) > 0 {
				return values
			}
		}
	}
	// No global by-name fallback. A simple name that is not declared here, not
	// imported, not in this package and not default-imported is not in scope,
	// and Kotlin will not compile it. Resolving it anyway made navigation jump
	// to a type the file cannot actually name.
	return nil
}

func splitInstantiatedType(value string) (string, []string) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
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
	depth := 0
	for index := open; index < len(value); index++ {
		switch value[index] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func splitTopLevelTypeArguments(value string) []string {
	depth, start := 0, 0
	var result []string
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' && depth == 0 {
			if argument := strings.TrimSpace(value[start:index]); argument != "" {
				result = append(result, argument)
			}
			start = index + 1
			continue
		}
		if value[index] == '<' {
			depth++
		} else if value[index] == '>' {
			depth--
		}
	}
	return result
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
		if !isIdentRune(rune(value[index])) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		word := value[index:end]
		if replacement := replacements[word]; replacement != "" {
			result.WriteString(replacement)
		} else {
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
		for _, resolved := range i.resolveTypeSymbolsLocked(file, declared) {
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
			inferTypeParameterBindings(callable.Parameters[callableIndex].Type, actual, callable.TypeParameters, inferred)
		}
	}
	arguments := make([]string, len(callable.TypeParameters))
	for index, parameter := range callable.TypeParameters {
		arguments[index] = inferred[parameter]
	}
	return substituteTypeParameters(parameterType, callable.TypeParameters, arguments)
}

func topLevelNamedArgumentEquals(expression string) int {
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

func inferTypeParameterBindings(pattern, actual string, parameters []string, inferred map[string]string) {
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	for _, parameter := range parameters {
		if simpleType(patternBase) == parameter && actual != "" {
			inferred[parameter] = actual
			return
		}
	}
	if simpleType(patternBase) != simpleType(actualBase) || len(patternArguments) != len(actualArguments) {
		return
	}
	for index := range patternArguments {
		inferTypeParameterBindings(patternArguments[index], actualArguments[index], parameters, inferred)
	}
}

func matchTypePattern(pattern, actual string, parameters map[string]bool, inferred map[string]string) bool {
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
		if !matchTypePattern(patternArguments[index], actualArguments[index], parameters, inferred) {
			return false
		}
	}
	return true
}

func instantiatedTypeName(name string, arguments []string) string {
	if len(arguments) == 0 {
		return name
	}
	return name + "<" + strings.Join(arguments, ", ") + ">"
}

func substituteTypeBindings(value string, bindings map[string]string) string {
	if value == "" || len(bindings) == 0 {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		word := value[index:end]
		if replacement := bindings[word]; replacement != "" {
			result.WriteString(replacement)
		} else {
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

func (i *Index) extensionReceiverApplicableLocked(file *analysis.ParsedFile, extension analysis.Symbol, actualType string) bool {
	_, applicable := i.extensionReceiverBindingsLocked(file, extension, actualType)
	return applicable
}

type instantiatedTypeOwner struct {
	symbol    analysis.Symbol
	arguments []string
}

func (i *Index) instantiatedTypeHierarchyLocked(file *analysis.ParsedFile, typeName string) []instantiatedTypeOwner {
	queue := splitIntersectionTypes(typeName)
	seen := make(map[string]bool)
	result := make([]instantiatedTypeOwner, 0, 4)
	for len(queue) > 0 {
		instantiated := queue[0]
		queue = queue[1:]
		base, arguments := splitInstantiatedType(instantiated)
		for _, symbol := range i.resolveTypeSymbolsLocked(file, base) {
			key := symbol.ID + "\x00" + strings.Join(arguments, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, instantiatedTypeOwner{symbol: symbol, arguments: arguments})
			if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
				queue = append(queue, substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments))
			}
			for _, supertype := range symbol.Supertypes {
				queue = append(queue, substituteTypeParameters(supertype, symbol.TypeParameters, arguments))
			}
		}
	}
	return result
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
	angles, start := 0, 0
	var result []string
	for index := 0; index <= len(typeName); index++ {
		if index == len(typeName) || typeName[index] == '&' && angles == 0 {
			if value := strings.TrimSpace(typeName[start:index]); value != "" {
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
	fromModule, targetModule := i.moduleForURILocked(file.URI), i.moduleForURILocked(symbol.URI)
	fromSourceSet := i.sourceSetForURILocked(file.URI, fromModule)
	targetSourceSet := i.sourceSetForURILocked(symbol.URI, targetModule)
	if symbol.Library && fromModule != nil {
		if source, exists := i.librarySources[symbol.URI]; exists {
			if access := i.libraryAccess[filepath.Clean(source.Archive)]; len(access) > 0 && !access[fromModule.Dir] && !access[libraryAccessKey(fromModule.Dir, fromSourceSet)] {
				return false
			}
		}
	}
	if targetModule != nil && !i.moduleCanAccessLocked(fromModule, targetModule, fromSourceSet, targetSourceSet) {
		return false
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
			if analysis.IsTypeKind(owner.Kind) && !i.accessibleLocked(file, *owner, positions...) {
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
			for _, parent := range i.resolveTypeSymbolsLocked(file, supertype) {
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
