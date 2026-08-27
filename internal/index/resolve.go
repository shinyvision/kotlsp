package index

import (
	"math/big"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func (i *Index) resolveLocked(file *analysis.ParsedFile, r analysis.Reference) []analysis.Symbol {
	if r.ResolvedID != "" {
		if symbol, ok := i.symbols[r.ResolvedID]; ok {
			return []analysis.Symbol{*symbol}
		}
	}
	if r.ArgumentLabel {
		if file.Language == analysis.LanguageJava {
			if symbols := i.resolveAnnotationAttributeLabelLocked(file, r); len(symbols) > 0 {
				return symbols
			}
		}
		return i.resolveArgumentLabelLocked(file, r)
	}
	ids := make([]string, 0)
	qualifier := r.Qualifier
	implicitReceiverTypes := make([]string, 0, 4)
	if document := i.docs[file.URI]; document != nil {
		// Tree-sitter's qualifier field commonly contains only the final token
		// (`value` in wrap(x).value.member). Prefer the complete balanced source
		// expression so generic return arguments survive through longer chains.
		if textual := expressionQualifierBefore(document.Text, r.StartByte); textual != "" {
			qualifier = textual
		}
	}
	if qualifier == "" {
		if qualifier == "" && file.Language == analysis.LanguageKotlin {
			implicitReceiverTypes = append(implicitReceiverTypes, i.contextualLambdaReceiverTypeLocked(file, r.StartByte), i.enclosingExtensionReceiverTypeLocked(file, r.StartByte))
			implicitReceiverTypes = append(implicitReceiverTypes, i.enclosingContextReceiverTypesLocked(file, r.StartByte)...)
			if enclosing := i.enclosingTypeLocked(file, r.StartByte); enclosing.ID != "" {
				implicitReceiverTypes = append(implicitReceiverTypes, enclosing.Name)
			}
		} else if file.Language == analysis.LanguageJava {
			implicitReceiverTypes = append(implicitReceiverTypes, i.javaSwitchLabelReceiverTypeLocked(file, r.StartByte))
		}
	}
	typeQualifierSymbols := i.resolveTypeSymbolsLocked(file, qualifier)
	typeQualifier := qualifier != "" && !strings.ContainsAny(qualifier, "()[]{} ") && !strings.Contains(qualifier, "::") && len(typeQualifierSymbols) > 0
	typeQualifierValue := i.typeQualifierActsAsValueLocked(file, typeQualifierSymbols)
	callableReference := callableReferenceOperatorBefore(i.documentTextLocked(file.URI), r.StartByte)
	unboundCallableReference := typeQualifier && callableReference
	if r.Role == analysis.RoleImport && r.Qualifier != "" {
		ids = append(ids, i.byFQN[r.Qualifier+"."+r.Name]...)
	}
	if qualifier != "" {
		ids = append(ids, i.anonymousObjectMemberIDsLocked(file, qualifier, r.Name, r.StartByte)...)
		typ := i.typeOfExpressionLocked(file, qualifier, r.StartByte)
		if explicit := explicitReceiverType(qualifier); explicit != "" {
			typ = explicit
		}
		if typ != "" {
			nullableReceiver := file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(typ), "?")
			memberAccessAllowed := !nullableReceiver || kotlinNullableMemberAccessAllowed(i.documentTextLocked(file.URI), r.StartByte)
			validContainers := i.typeAndSupertypesLocked(file, typ)
			for _, container := range validContainers {
				if memberAccessAllowed {
					for _, id := range i.byContainerMember[memberKey(container, r.Name)] {
						if symbol := i.symbols[id]; i.memberInheritedForReceiverLocked(file, *symbol, typ) && (!typeQualifier || unboundCallableReference || i.memberAvailableThroughTypeQualifierLocked(file, *symbol, typeQualifierSymbols)) && i.accessibleLocked(file, *symbol, r.StartByte) {
							ids = append(ids, id)
						}
					}
				}
				for _, id := range i.byReceiverMember[memberKey(container, r.Name)] {
					if symbol := i.symbols[id]; (!typeQualifier || typeQualifierValue || unboundCallableReference) && i.extensionReceiverApplicableLocked(file, *symbol, typ) && (memberAccessAllowed || strings.HasSuffix(strings.TrimSpace(symbol.ReceiverType), "?")) && i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
						ids = append(ids, id)
					}
				}
				if file.Language == analysis.LanguageKotlin {
					for _, id := range i.companionMemberIDsLocked(file, container, r.Name) {
						if i.accessibleLocked(file, *i.symbols[id], r.StartByte) {
							ids = append(ids, id)
						}
					}
				}
			}
		} else {
			ids = append(ids, i.byFQN[qualifier+"."+r.Name]...)
		}
	}
	for _, implicitReceiverType := range implicitReceiverTypes {
		if implicitReceiverType == "" {
			continue
		}
		for _, container := range i.typeAndSupertypesLocked(file, implicitReceiverType) {
			for _, id := range i.byContainerMember[memberKey(container, r.Name)] {
				if symbol := i.symbols[id]; i.memberInheritedForReceiverLocked(file, *symbol, implicitReceiverType) && i.accessibleLocked(file, *symbol, r.StartByte) {
					ids = append(ids, id)
				}
			}
			for _, id := range i.byReceiverMember[memberKey(container, r.Name)] {
				if symbol := i.symbols[id]; i.extensionReceiverApplicableLocked(file, *symbol, implicitReceiverType) && i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
					ids = append(ids, id)
				}
			}
		}
	}
	for _, imp := range file.Imports {
		if imp.Static && file.Language == analysis.LanguageJava {
			if imp.Wildcard || imp.LocalName() == r.Name {
				ids = append(ids, i.staticImportMemberIDsLocked(file, imp, r.Name, r.StartByte)...)
			}
			continue
		}
		if !imp.Wildcard && imp.LocalName() == r.Name {
			ids = append(ids, i.byFQN[imp.Path]...)
		}
		if imp.Wildcard {
			ids = append(ids, i.byFQN[imp.Path+"."+r.Name]...)
		}
	}
	if file.Package != "" {
		ids = append(ids, i.byFQN[file.Package+"."+r.Name]...)
	}
	if r.ContainerID != "" && qualifier == "" {
		instanceReceiver := !i.staticLikeContextLocked(file, r.StartByte)
		for containerID := r.ContainerID; containerID != ""; {
			c, ok := i.symbols[containerID]
			if !ok {
				break
			}
			for _, id := range i.byContainerMember[memberKey(c.Name, r.Name)] {
				s := i.symbols[id]
				if (s.ContainerID == c.ID || s.ContainerName == c.Name) && (instanceReceiver || i.staticOrNestedMemberLocked(*s)) {
					ids = append(ids, id)
				}
			}
			nextID := c.ContainerID
			if next, exists := i.symbols[nextID]; exists && analysis.IsTypeKind(c.Kind) && analysis.IsTypeKind(next.Kind) && !nestedTypeCapturesOuter(*c, *next) {
				instanceReceiver = false
			}
			containerID = nextID
		}
	}
	if len(ids) == 0 && qualifier == "" {
		for _, id := range i.byName[r.Name] {
			symbol := i.symbols[id]
			if i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) && (analysis.IsTypeKind(symbol.Kind) || symbol.ContainerID == "") && i.simpleNameInScopeLocked(file, *symbol) {
				ids = append(ids, id)
			}
		}
	}
	if r.Role == analysis.RoleCall {
		for _, id := range append([]string(nil), ids...) {
			owner := i.symbols[id]
			if !analysis.IsTypeKind(owner.Kind) {
				continue
			}
			for _, constructorID := range i.byContainerMember[memberKey(owner.Name, owner.Name)] {
				constructor := i.symbols[constructorID]
				if constructor.Kind == analysis.KindConstructor && constructor.ContainerID == owner.ID {
					ids = append(ids, constructorID)
				}
			}
		}
	}
	candidates := i.symbolsForIDsLocked(ids, func(s analysis.Symbol) bool {
		if !i.accessibleLocked(file, s, r.StartByte) || !i.extensionVisibleLocked(file, s, r.StartByte) {
			return false
		}
		if typeQualifier && !unboundCallableReference && !i.memberAvailableThroughTypeQualifierLocked(file, s, typeQualifierSymbols) {
			return false
		}
		if !i.protectedReceiverAccessibleLocked(file, s, r) {
			return false
		}
		if isLexicalSymbol(s) && s.URI == file.URI {
			if s.StartByte > r.StartByte || !symbolInScopeAt(s, r.StartByte) {
				return false
			}
		}
		if r.Role == analysis.RoleCall {
			return (analysis.IsCallableKind(s.Kind) || analysis.IsTypeKind(s.Kind)) && (r.Arity < 0 || matchesArityForLanguage(s, r.Arity, file.Language))
		}
		if r.Role == analysis.RoleType {
			return analysis.IsTypeKind(s.Kind)
		}
		return true
	})
	explicitImports := make(map[string]bool)
	if qualifier == "" {
		for _, imported := range file.Imports {
			if !imported.Wildcard && imported.LocalName() == r.Name {
				explicitImports[imported.Path] = true
			}
		}
	}
	fromModule := i.moduleForURILocked(file.URI)
	fromSourceSet := i.sourceSetForURILocked(file.URI, fromModule)
	sourceSetRank := func(symbol analysis.Symbol) int {
		targetModule := i.moduleForURILocked(symbol.URI)
		if fromModule == nil || targetModule == nil || fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir {
			return 0
		}
		targetSet := i.sourceSetForURILocked(symbol.URI, targetModule)
		if distance := sourceSetAccessDistance(fromModule, fromSourceSet, targetSet); distance >= 0 {
			return 40 - distance
		}
		return 0
	}
	receiverRanks := map[string]int{}
	if r.Qualifier != "" || len(implicitReceiverTypes) > 0 {
		receiverTypes := implicitReceiverTypes
		if r.Qualifier != "" {
			receiverTypes = []string{i.typeOfExpressionLocked(file, r.Qualifier, r.StartByte)}
		}
		for _, receiverType := range receiverTypes {
			if receiverType != "" {
				for rank, container := range i.typeAndSupertypesLocked(file, receiverType) {
					if _, exists := receiverRanks[container]; !exists {
						receiverRanks[container] = 1000 - rank
					}
				}
			}
		}
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		as, bs := sourceSetRank(candidates[a]), sourceSetRank(candidates[b])
		if explicitImports[candidates[a].FQN] {
			as += 30
		}
		if explicitImports[candidates[b].FQN] {
			bs += 30
		}
		as += receiverRanks[candidates[a].ContainerName]
		bs += receiverRanks[candidates[b].ContainerName]
		if owner, ok := i.symbols[candidates[a].ContainerID]; ok {
			as += receiverRanks[owner.FQN]
		}
		if owner, ok := i.symbols[candidates[b].ContainerID]; ok {
			bs += receiverRanks[owner.FQN]
		}
		if candidates[a].ContainerID == r.ContainerID {
			as += 100
		}
		if candidates[b].ContainerID == r.ContainerID {
			bs += 100
		}
		if candidates[a].URI == file.URI && candidates[a].StartByte <= r.StartByte && candidates[a].EndByte >= r.StartByte {
			as += 50
		}
		if candidates[b].URI == file.URI && candidates[b].StartByte <= r.StartByte && candidates[b].EndByte >= r.StartByte {
			bs += 50
		}
		if candidates[a].URI == file.URI {
			as += 20
		}
		if candidates[b].URI == file.URI {
			bs += 20
		}
		if candidates[a].Package == file.Package {
			as += 10
		}
		if candidates[b].Package == file.Package {
			bs += 10
		}
		if candidates[a].StartByte <= r.StartByte {
			as += 2
		}
		if candidates[b].StartByte <= r.StartByte {
			bs += 2
		}
		if as == bs {
			aLexical, bLexical := isLexicalSymbol(candidates[a]), isLexicalSymbol(candidates[b])
			if aLexical && bLexical && candidates[a].URI == file.URI && candidates[b].URI == file.URI {
				if candidates[a].ScopeEndByte != candidates[b].ScopeEndByte {
					// The innermost containing block wins; an inner declaration
					// must stop shadowing as soon as that block ends.
					return candidates[a].ScopeEndByte < candidates[b].ScopeEndByte
				}
				if candidates[a].StartByte != candidates[b].StartByte {
					return candidates[a].StartByte > candidates[b].StartByte
				}
			}
			return candidates[a].FQN < candidates[b].FQN
		}
		return as > bs
	})
	if callableReference && len(candidates) > 1 {
		if expected, ok := i.callableReferenceExpectedParametersLocked(file, r.StartByte); ok {
			filtered := make([]analysis.Symbol, 0, len(candidates))
			for _, candidate := range candidates {
				if !analysis.IsCallableKind(candidate.Kind) || len(candidate.Parameters) != len(expected) {
					continue
				}
				matches := true
				for index, parameter := range candidate.Parameters {
					left, right := simpleType(parameter.Type), simpleType(expected[index])
					if file.Language == analysis.LanguageJava {
						matches = javaInvocationType(left) == javaInvocationType(right)
					} else {
						matches = sameJvmType(left, right)
					}
					if !matches {
						break
					}
				}
				if matches {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
	}
	if r.Role == analysis.RoleCall && len(candidates) > 1 {
		scores := make([]int, len(candidates))
		typedScores := make([]bool, len(candidates))
		for n, candidate := range candidates {
			score, typed := i.callCompatibilityLocked(file, r, candidate)
			scores[n] = score
			typedScores[n] = typed
		}
		if file.Language == analysis.LanguageKotlin && (qualifier != "" || len(implicitReceiverTypes) > 0) {
			memberApplicable := false
			for n, candidate := range candidates {
				if candidate.ReceiverType == "" && (!typedScores[n] || scores[n] > -1<<19) {
					memberApplicable = true
					break
				}
			}
			if memberApplicable {
				memberCandidates := make([]analysis.Symbol, 0, len(candidates))
				memberScores := make([]int, 0, len(candidates))
				memberTyped := make([]bool, 0, len(candidates))
				for n, candidate := range candidates {
					if candidate.ReceiverType == "" {
						memberCandidates = append(memberCandidates, candidate)
						memberScores = append(memberScores, scores[n])
						memberTyped = append(memberTyped, typedScores[n])
					}
				}
				candidates, scores, typedScores = memberCandidates, memberScores, memberTyped
			}
		}
		bestScore, anyTyped := -1<<30, false
		for n, score := range scores {
			if typedScores[n] {
				anyTyped = true
				if score > bestScore {
					bestScore = score
				}
			}
		}
		if anyTyped {
			filtered := candidates[:0]
			for n, candidate := range candidates {
				if scores[n] == bestScore {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
	}
	if len(candidates) > 1 {
		if r.Role != analysis.RoleCall || candidates[0].FQN != candidates[1].FQN || candidates[0].URI == candidates[1].URI && !analysis.IsCallableKind(candidates[0].Kind) {
			return candidates[:1]
		}
	}
	return candidates
}

func (i *Index) callableReferenceExpectedParametersLocked(file *analysis.ParsedFile, at int) ([]string, bool) {
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	equals := strings.LastIndexByte(source[:at], '=')
	if equals < 0 {
		return nil, false
	}
	start := strings.LastIndexAny(source[:equals], "\n;{}") + 1
	left := strings.TrimSpace(source[start:equals])
	if file.Language == analysis.LanguageKotlin {
		colon := strings.LastIndexByte(left, ':')
		if colon < 0 {
			return nil, false
		}
		target := strings.TrimSpace(left[colon+1:])
		arrow := strings.Index(target, "->")
		if arrow < 0 {
			return nil, false
		}
		parameters := strings.TrimSpace(target[:arrow])
		parameters = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(parameters, "("), ")"))
		if parameters == "" {
			return []string{}, true
		}
		return splitTopLevelTypeArguments(parameters), true
	}
	fields := strings.Fields(left)
	if len(fields) < 2 {
		return nil, false
	}
	target := strings.Join(fields[:len(fields)-1], " ")
	for _, modifier := range []string{"public ", "protected ", "private ", "static ", "final ", "volatile ", "transient "} {
		target = strings.TrimSpace(strings.ReplaceAll(" "+target+" ", " "+modifier, " "))
	}
	base, arguments := splitInstantiatedType(target)
	switch simpleType(base) {
	case "Consumer", "Predicate", "Function", "UnaryOperator":
		if len(arguments) >= 1 {
			return arguments[:1], true
		}
	case "BiConsumer", "BiPredicate", "BiFunction", "BinaryOperator":
		if len(arguments) >= 2 {
			return arguments[:2], true
		}
	case "Supplier", "Runnable":
		return []string{}, true
	}
	for _, owner := range i.resolveTypeSymbolsLocked(file, base) {
		for _, id := range i.byContainerName[owner.Name] {
			method := i.symbols[id]
			if method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
				continue
			}
			parameters := make([]string, len(method.Parameters))
			for index, parameter := range method.Parameters {
				parameters[index] = substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments)
			}
			return parameters, true
		}
	}
	return nil, false
}

func (i *Index) anonymousObjectMemberIDsLocked(file *analysis.ParsedFile, qualifier, name string, at int) []string {
	qualifier = strings.TrimSpace(qualifier)
	if strings.ContainsAny(qualifier, ".()[]{} 	\r\n") {
		return nil
	}
	var owner analysis.Symbol
	candidates := i.fileAnonymousByName[file.URI][qualifier]
	before := sort.Search(len(candidates), func(index int) bool { return candidates[index].StartByte > at })
	for index := before - 1; index >= 0; index-- {
		symbol := candidates[index]
		if symbol.ScopeEndByte > 0 && at > symbol.ScopeEndByte {
			continue
		}
		owner = *symbol
		break
	}
	if owner.ID == "" {
		return nil
	}
	var ids []string
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.StartByte <= owner.NameEndByte || symbol.EndByte > owner.EndByte || name != "" && symbol.Name != name {
			continue
		}
		if analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || analysis.IsTypeKind(symbol.Kind) {
			ids = append(ids, symbol.ID)
		}
	}
	return ids
}

func (i *Index) resolveAnnotationAttributeLabelLocked(file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	ownerName := AnnotationAttributeOwner(i.documentTextLocked(file.URI), label.StartByte)
	if ownerName == "" {
		return nil
	}
	var ids []string
	for _, owner := range i.resolveTypeSymbolsLocked(file, ownerName) {
		if owner.Kind != analysis.KindAnnotation {
			continue
		}
		for _, id := range i.byContainerMember[memberKey(owner.Name, label.Name)] {
			if symbol := i.symbols[id]; symbol.ContainerID == owner.ID && i.accessibleLocked(file, *symbol, label.StartByte) {
				ids = append(ids, id)
			}
		}
	}
	return i.symbolsForIDsLocked(ids, nil)
}

func (i *Index) memberInheritedForReceiverLocked(file *analysis.ParsedFile, symbol analysis.Symbol, receiverType string) bool {
	if file.Language != analysis.LanguageJava || !containsString(symbol.Modifiers, "static") || symbol.ContainerID == "" {
		return true
	}
	owner, ok := i.symbols[symbol.ContainerID]
	if !ok || owner.Kind != analysis.KindInterface && owner.Kind != analysis.KindAnnotation {
		return true
	}
	for _, receiver := range i.resolveTypeSymbolsLocked(file, receiverType) {
		if receiver.ID == owner.ID {
			return true
		}
	}
	return false
}

func (i *Index) staticImportMemberIDsLocked(file *analysis.ParsedFile, imported analysis.Import, name string, at int) []string {
	ownerName := imported.Path
	if !imported.Wildcard {
		if dot := strings.LastIndexByte(ownerName, '.'); dot >= 0 {
			ownerName = ownerName[:dot]
		}
	}
	var ids []string
	for _, owner := range i.resolveTypeSymbolsLocked(file, ownerName) {
		for _, container := range i.typeAndSupertypesLocked(file, owner.FQN) {
			for _, id := range i.byContainerName[container] {
				symbol := i.symbols[id]
				if symbol.Name == name && i.staticOrNestedMemberLocked(*symbol) && i.memberInheritedForReceiverLocked(file, *symbol, owner.FQN) && i.accessibleLocked(file, *symbol, at) {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func (i *Index) javaSwitchLabelReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	if file.Language != analysis.LanguageJava {
		return ""
	}
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	caseAt := strings.LastIndex(source[:at], "case")
	if caseAt < 0 || caseAt > 0 && isIdentRune(rune(source[caseAt-1])) || caseAt+4 < len(source) && isIdentRune(rune(source[caseAt+4])) {
		return ""
	}
	labelPrefix := source[caseAt+4 : at]
	if strings.Contains(labelPrefix, "->") || strings.Contains(labelPrefix, ":") {
		return ""
	}
	switchAt := strings.LastIndex(source[:caseAt], "switch")
	if switchAt < 0 {
		return ""
	}
	openRelative := strings.IndexByte(source[switchAt:caseAt], '(')
	if openRelative < 0 {
		return ""
	}
	open := switchAt + openRelative
	close := matchingDelimiter(source, open, '(', ')')
	if close < 0 || close >= caseAt {
		return ""
	}
	return i.typeOfExpressionLocked(file, strings.TrimSpace(source[open+1:close]), at)
}

func matchingDelimiter(source string, open int, opening, closing byte) int {
	depth := 0
	for index := open; index < len(source); index++ {
		switch source[index] {
		case opening:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func callableReferenceOperatorBefore(source string, start int) bool {
	if start > len(source) {
		start = len(source)
	}
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(source[:start])
		if !unicode.IsSpace(r) {
			break
		}
		start -= size
	}
	return start >= 2 && source[start-2:start] == "::"
}

func (i *Index) resolveArgumentLabelLocked(file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		document = i.libraryDocs[file.URI]
	}
	if document == nil {
		return nil
	}
	var call *analysis.Reference
	bestSpan := int(^uint(0) >> 1)
	for index := range file.References {
		candidate := &file.References[index]
		if candidate.Role != analysis.RoleCall || candidate.ArgumentLabel || candidate.StartByte >= label.StartByte {
			continue
		}
		for _, argumentRange := range candidate.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start <= label.StartByte && label.EndByte <= end && end-start < bestSpan {
				call, bestSpan = candidate, end-start
			}
		}
	}
	if call == nil {
		// An annotation argument has no enclosing call reference: the
		// annotation name is recorded as a type, not a call. Its attributes
		// still resolve, against the annotation's own members.
		return i.resolveAnnotationAttributeLocked(file, document, label)
	}
	var out []analysis.Symbol
	for _, callable := range i.resolveLocked(file, *call) {
		if !analysis.IsCallableKind(callable.Kind) {
			continue
		}
		before := len(out)
		if declaration := i.files[callable.URI]; declaration != nil {
			for _, symbol := range declaration.Symbols {
				if symbol.Kind == analysis.KindParameter && symbol.ContainerID == callable.ID && symbol.Name == label.Name {
					out = append(out, symbol)
				}
			}
		}
		if len(out) > before {
			continue
		}
		for _, parameter := range callable.Parameters {
			if parameter.Name == label.Name {
				out = append(out, analysis.Symbol{
					ID: callable.ID + "#parameter:" + label.Name, Name: label.Name, FQN: callable.FQN + "." + label.Name,
					Kind: analysis.KindParameter, Language: callable.Language, URI: callable.URI,
					Range: parameter.Range, SelectionRange: parameter.Range, ContainerID: callable.ID,
					ContainerName: callable.Name, Package: callable.Package, Type: parameter.Type,
					Signature: label.Name + ": " + parameter.Type, Library: callable.Library,
				})
			}
		}
	}
	return uniqueSymbols(out)
}

// resolveAnnotationAttributeLocked resolves `name` in `@Ann(name = value)` to
// the attribute declared by the annotation type. Java annotations declare them
// as methods and Kotlin ones as constructor parameters, so both member shapes
// are accepted.
func (i *Index) resolveAnnotationAttributeLocked(file *analysis.ParsedFile, document *textdoc.Document, label analysis.Reference) []analysis.Symbol {
	owner := AnnotationAttributeOwner(document.Text, label.StartByte)
	if owner == "" {
		return nil
	}
	var out []analysis.Symbol
	for _, annotation := range i.resolveTypeSymbolsLocked(file, owner) {
		if !analysis.IsTypeKind(annotation.Kind) {
			continue
		}
		for _, memberID := range i.byContainerName[annotation.Name] {
			member := i.symbols[memberID]
			if member == nil || member.ContainerID != annotation.ID || member.Name != label.Name {
				continue
			}
			if analysis.IsCallableKind(member.Kind) || member.Kind == analysis.KindParameter || member.Kind == analysis.KindProperty || member.Kind == analysis.KindField {
				out = append(out, *member)
			}
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) companionMembersLocked(file *analysis.ParsedFile, container string) []analysis.Symbol {
	seen := make(map[string]bool)
	var members []analysis.Symbol
	for _, owner := range i.resolveTypeSymbolsLocked(file, container) {
		for _, companionID := range i.byContainerName[owner.Name] {
			companion, ok := i.symbols[companionID]
			if !ok || companion.ContainerID != owner.ID || companion.Kind != analysis.KindObject || !containsString(companion.Modifiers, "companion") {
				continue
			}
			for _, memberID := range i.byContainerName[companion.Name] {
				member, exists := i.symbols[memberID]
				if !exists || member.ContainerID != companion.ID || seen[member.ID] {
					continue
				}
				seen[member.ID] = true
				members = append(members, *member)
			}
		}
	}
	return members
}

func (i *Index) companionMemberIDsLocked(file *analysis.ParsedFile, container, name string) []string {
	members := i.companionMembersLocked(file, container)
	ids := make([]string, 0, len(members))
	for _, member := range members {
		if member.Name == name {
			ids = append(ids, member.ID)
		}
	}
	return ids
}

func sameCallableShape(left, right analysis.Symbol) bool {
	if left.Name != right.Name || len(left.Parameters) != len(right.Parameters) {
		return false
	}
	for index := range left.Parameters {
		if simpleType(left.Parameters[index].Type) != simpleType(right.Parameters[index].Type) {
			return false
		}
	}
	return true
}

func (i *Index) protectedReceiverAccessibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, reference analysis.Reference) bool {
	if symbol.Language != analysis.LanguageJava || symbol.Package == file.Package || !containsString(symbol.Modifiers, "protected") {
		return true
	}
	if symbol.ContainerID == "" {
		return false
	}
	current := i.enclosingTypeLocked(file, reference.StartByte)
	if current.ID == "" || !i.containerInheritsLocked(current.ID, symbol.ContainerID) {
		return false
	}
	qualifier := strings.TrimSpace(reference.Qualifier)
	if qualifier == "" || qualifier == "this" || qualifier == "super" {
		return true
	}
	receiverType := i.typeOfExpressionLocked(file, qualifier, reference.StartByte)
	for _, receiver := range i.resolveTypeSymbolsLocked(file, receiverType) {
		if receiver.ID == current.ID || i.containerInheritsLocked(receiver.ID, current.ID) {
			return true
		}
	}
	return false
}

func lexicalBinding(file *analysis.ParsedFile, reference analysis.Reference, candidates []analysis.Symbol) string {
	if reference.Qualifier != "" || reference.Role == analysis.RoleImport {
		return ""
	}
	bestID := ""
	bestContainer, bestScope, bestStart := -1, int(^uint(0)>>1), -1
	for _, symbol := range candidates {
		if symbol.URI != file.URI || symbol.Name != reference.Name || !isLexicalSymbol(symbol) || !lexicalCandidateMatches(reference, symbol) {
			continue
		}
		containerScore := 0
		if symbol.ContainerID != "" && symbol.ContainerID == reference.ContainerID {
			containerScore = 1
		}
		scopeSize := symbol.ScopeEndByte - symbol.ScopeStartByte
		if scopeSize <= 0 {
			scopeSize = int(^uint(0) >> 1)
		}
		if containerScore > bestContainer || containerScore == bestContainer && (scopeSize < bestScope || scopeSize == bestScope && symbol.StartByte > bestStart) {
			bestID, bestContainer, bestScope, bestStart = symbol.ID, containerScore, scopeSize, symbol.StartByte
		}
	}
	return bestID
}

func lexicalCandidateMatches(reference analysis.Reference, symbol analysis.Symbol) bool {
	if symbol.NameEndByte > reference.StartByte {
		return false
	}
	if reference.Role == analysis.RoleType && symbol.Kind != analysis.KindTypeParameter || reference.Role != analysis.RoleType && symbol.Kind == analysis.KindTypeParameter {
		return false
	}
	if reference.Role == analysis.RoleLabel && symbol.Kind != analysis.KindLabel || reference.Role != analysis.RoleLabel && symbol.Kind == analysis.KindLabel {
		return false
	}
	return symbolInScopeAt(symbol, reference.StartByte)
}

func symbolInScopeAt(symbol analysis.Symbol, at int) bool {
	if !(symbol.ScopeStartByte > 0 && at < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && at > symbol.ScopeEndByte) {
		return true
	}
	for _, scope := range symbol.AdditionalScopes {
		if scope.StartByte <= at && at <= scope.EndByte {
			return true
		}
	}
	return false
}

func expressionQualifierBefore(source string, start int) string {
	if start <= 0 || start > len(source) || source[start-1] != '.' {
		return ""
	}
	if explicit := explicitReceiverSourceBefore(source, start); explicit != "" {
		return explicit
	}
	end, index := start-1, start-2
	parenDepth, bracketDepth, braceDepth, angleDepth := 0, 0, 0, 0
	allowLambdaGap := false
	for index >= 0 {
		value := source[index]
		switch value {
		case ')':
			parenDepth++
		case '(':
			if parenDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			parenDepth--
		case ']':
			bracketDepth++
		case '[':
			if bracketDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			bracketDepth--
		case '}':
			braceDepth++
		case '{':
			if braceDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			braceDepth--
			if braceDepth == 0 {
				allowLambdaGap = true
			}
		case '>':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				angleDepth++
			}
		case '<':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth > 0 {
				angleDepth--
			}
		default:
			lambdaGap := allowLambdaGap && braceDepth == 0 && (value == ' ' || value == '\t' || value == '\r' || value == '\n')
			if !lambdaGap {
				allowLambdaGap = false
			}
			if !lambdaGap && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 && !(isIdentRune(rune(value)) || value == '.' || value == ':' || value == '?' || value == '!' || value == '`') {
				return strings.Trim(strings.TrimSpace(source[index+1:end]), ".?!")
			}
		}
		index--
	}
	return strings.Trim(strings.TrimSpace(source[:end]), ".?!")
}

func explicitReceiverSourceBefore(source string, start int) string {
	end := start - 1
	for end > 0 && unicode.IsSpace(rune(source[end-1])) {
		end--
	}
	prefix := source[:end]
	for _, marker := range []string{"super<", "this@"} {
		if at := strings.LastIndex(prefix, marker); at >= 0 {
			candidate := strings.TrimSpace(prefix[at:])
			if marker == "super<" && strings.HasSuffix(candidate, ">") || marker == "this@" && len(candidate) > len(marker) && !strings.ContainsAny(candidate[len(marker):], " \t\r\n.(){}[]") {
				return candidate
			}
		}
	}
	return ""
}

func explicitReceiverType(qualifier string) string {
	qualifier = strings.TrimSpace(qualifier)
	if strings.HasPrefix(qualifier, "super<") && strings.HasSuffix(qualifier, ">") {
		return strings.TrimSpace(qualifier[len("super<") : len(qualifier)-1])
	}
	if strings.HasPrefix(qualifier, "this@") {
		return strings.TrimSpace(strings.TrimPrefix(qualifier, "this@"))
	}
	if strings.HasSuffix(qualifier, ".super") {
		return strings.TrimSuffix(qualifier, ".super")
	}
	if strings.HasSuffix(qualifier, ".this") {
		return strings.TrimSuffix(qualifier, ".this")
	}
	return ""
}

func isLexicalSymbol(symbol analysis.Symbol) bool {
	return symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindTypeParameter || symbol.Kind == analysis.KindLabel ||
		symbol.Kind == analysis.KindProperty && symbol.ScopeEndByte > symbol.EndByte
}

func (i *Index) callCompatibilityLocked(file *analysis.ParsedFile, ref analysis.Reference, candidate analysis.Symbol) (int, bool) {
	doc := i.docs[file.URI]
	if doc == nil {
		return 0, false
	}
	if len(candidate.Parameters) == 0 {
		return 16, len(ref.Arguments) == 0
	}
	score, typed := 0, true
	provided := make(map[int]bool, len(ref.Arguments))
	for n, argumentRange := range ref.Arguments {
		parameterIndex := n
		expression := doc.Slice(argumentRange)
		if name, value, named := namedArgument(expression); named {
			parameterIndex = -1
			for index, parameter := range candidate.Parameters {
				if parameter.Name == name {
					parameterIndex = index
					break
				}
			}
			if parameterIndex < 0 {
				// A named argument makes a candidate without that parameter
				// inapplicable even when its positional types happen to match.
				return -1 << 20, true
			}
			expression = value
		}
		if parameterIndex >= len(candidate.Parameters) {
			parameterIndex = len(candidate.Parameters) - 1
		}
		provided[parameterIndex] = true
		expectedType := strings.TrimSpace(candidate.Parameters[parameterIndex].Type)
		if lambdaTypes, explicitLambda := explicitLambdaParameterTypes(expression, file.Language); explicitLambda {
			expectedParameters := kotlinFunctionParameterTypes(expectedType)
			if file.Language == analysis.LanguageJava {
				expectedParameters = i.functionalParameterTypesLocked(file, expectedType)
			}
			if len(expectedParameters) != len(lambdaTypes) {
				return -1 << 20, true
			}
			for index := range lambdaTypes {
				matches := sameJvmType(lambdaTypes[index], expectedParameters[index])
				if file.Language == analysis.LanguageJava {
					matches = javaInvocationType(simpleType(lambdaTypes[index])) == javaInvocationType(simpleType(expectedParameters[index]))
				}
				if !matches {
					return -1 << 20, true
				}
			}
			score += 48
			continue
		}
		if file.Language == analysis.LanguageKotlin && strings.TrimSpace(expression) == "null" {
			if strings.HasSuffix(expectedType, "?") {
				score += 40
				continue
			}
			return -1 << 20, true
		}
		actualType := strings.TrimSpace(i.inferExpressionTypeLocked(file, expression, ref.StartByte))
		if file.Language == analysis.LanguageKotlin && strings.HasSuffix(actualType, "?") && !strings.HasSuffix(expectedType, "?") {
			return -1 << 20, true
		}
		actual := simpleType(actualType)
		expected := simpleType(expectedType)
		if actual == "" || expected == "" {
			typed = false
			continue
		}
		genericParameter := ""
		for _, parameter := range candidate.TypeParameters {
			if expected == parameter {
				genericParameter = parameter
				break
			}
		}
		if genericParameter != "" {
			if !i.typeArgumentSatisfiesBoundsLocked(file, actualType, candidate.TypeParameterBounds[genericParameter]) {
				return -1 << 20, true
			}
			// A type variable captures the argument precisely, but a concrete
			// identity overload remains more specific when both are applicable.
			score += 30
			continue
		}
		identity := sameJvmType(actual, expected)
		if file.Language == analysis.LanguageJava {
			identity = javaInvocationType(actual) == javaInvocationType(expected)
		}
		if identity {
			score += 32
		} else if file.Language == analysis.LanguageKotlin {
			if conversion, ok := kotlinIntegerLiteralConversionScore(expression, expected); ok {
				score += conversion
			} else if i.isSubtypeLocked(file, actual, expected) {
				score += 24
			} else {
				return -1 << 20, true
			}
		} else if i.isSubtypeLocked(file, actual, expected) {
			score += 24
		} else if file.Language == analysis.LanguageJava {
			if conversion, ok := javaInvocationConversionScore(actual, expected); ok {
				score += conversion
			} else {
				return -1 << 20, true
			}
		}
	}
	defaultsUsed, variadic := 0, false
	for index, parameter := range candidate.Parameters {
		if !provided[index] && parameter.Default != "" {
			defaultsUsed++
		}
		variadic = variadic || parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
	}
	if len(ref.Arguments) == len(candidate.Parameters) {
		score += 16
	}
	score -= defaultsUsed * 4
	if variadic {
		score -= 2
	}
	// Arity/default ranking is semantic evidence even when an incomplete
	// argument expression has no inferable type yet.
	typed = true
	return score, typed
}

func explicitLambdaParameterTypes(expression string, language analysis.Language) ([]string, bool) {
	expression = strings.TrimSpace(expression)
	arrow := strings.Index(expression, "->")
	if arrow < 0 {
		return nil, false
	}
	prefix := strings.TrimSpace(expression[:arrow])
	prefix = strings.TrimSpace(strings.TrimPrefix(prefix, "{"))
	if strings.HasPrefix(prefix, "(") && strings.HasSuffix(prefix, ")") {
		prefix = strings.TrimSpace(prefix[1 : len(prefix)-1])
	}
	if prefix == "" {
		return []string{}, true
	}
	parameters := splitTopLevelCallArguments(prefix)
	types := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		parameter = strings.TrimSpace(parameter)
		if language == analysis.LanguageKotlin {
			colon := topLevelExpressionOperator(parameter, ":")
			if colon < 0 {
				return nil, false
			}
			typ := strings.TrimSpace(parameter[colon+1:])
			if typ == "" {
				return nil, false
			}
			types = append(types, typ)
			continue
		}
		fields := strings.Fields(parameter)
		filtered := fields[:0]
		for _, field := range fields {
			if field != "final" && !strings.HasPrefix(field, "@") {
				filtered = append(filtered, field)
			}
		}
		if len(filtered) < 2 {
			return nil, false
		}
		types = append(types, strings.Join(filtered[:len(filtered)-1], " "))
	}
	return types, true
}

func (i *Index) typeArgumentSatisfiesBoundsLocked(file *analysis.ParsedFile, actual string, bounds []string) bool {
	for _, bound := range bounds {
		if !sameJvmType(actual, bound) && !i.isSubtypeLocked(file, actual, bound) {
			return false
		}
	}
	return true
}

func kotlinIntegerLiteralConversionScore(expression, expected string) (int, bool) {
	expression = strings.ReplaceAll(strings.TrimSpace(expression), "_", "")
	if expression == "" || strings.ContainsAny(expression, ".eEfF") {
		return 0, false
	}
	lower := strings.ToLower(expression)
	if strings.HasSuffix(lower, "l") || strings.HasSuffix(lower, "u") || strings.HasSuffix(lower, "ul") || strings.HasSuffix(lower, "lu") {
		return 0, false
	}
	value, ok := new(big.Int).SetString(expression, 0)
	if !ok {
		return 0, false
	}
	bits, signed := 0, true
	switch simpleType(expected) {
	case "Byte":
		bits = 8
	case "Short":
		bits = 16
	case "Int":
		bits = 32
	case "Long":
		bits = 64
	case "UByte":
		bits, signed = 8, false
	case "UShort":
		bits, signed = 16, false
	case "UInt":
		bits, signed = 32, false
	case "ULong":
		bits, signed = 64, false
	default:
		return 0, false
	}
	if !signed {
		return 28, value.Sign() >= 0 && value.BitLen() <= bits
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	minimum := new(big.Int).Neg(new(big.Int).Set(limit))
	maximum := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
	return 28, value.Cmp(minimum) >= 0 && value.Cmp(maximum) <= 0
}

func namedArgument(expression string) (name, value string, ok bool) {
	expression = strings.TrimSpace(expression)
	for index := 0; index < len(expression); index++ {
		if expression[index] != '=' || index+1 < len(expression) && expression[index+1] == '=' || index > 0 && strings.ContainsRune("=!<>", rune(expression[index-1])) {
			continue
		}
		candidate := strings.TrimSpace(expression[:index])
		if candidate == "" {
			return "", "", false
		}
		for offset, char := range candidate {
			if !(char == '_' || char == '`' || unicode.IsLetter(char) || offset > 0 && unicode.IsDigit(char)) {
				return "", "", false
			}
		}
		return strings.Trim(candidate, "`"), strings.TrimSpace(expression[index+1:]), true
	}
	return "", "", false
}

func sameJvmType(a, b string) bool {
	return canonicalJvmType(a) == canonicalJvmType(b)
}

func canonicalJvmType(value string) string {
	switch strings.ToLower(simpleType(value)) {
	case "byte", "java.lang.byte":
		return "byte"
	case "short", "java.lang.short":
		return "short"
	case "int", "integer", "java.lang.integer":
		return "int"
	case "long", "java.lang.long":
		return "long"
	case "float", "java.lang.float":
		return "float"
	case "double", "java.lang.double":
		return "double"
	case "char", "character", "java.lang.character":
		return "char"
	case "boolean", "java.lang.boolean":
		return "boolean"
	case "string", "java.lang.string":
		return "string"
	default:
		return strings.ToLower(simpleType(value))
	}
}

func javaInvocationConversionScore(actual, expected string) (int, bool) {
	actual, expected = javaInvocationType(actual), javaInvocationType(expected)
	primitiveWidening := map[string][]string{
		"byte":  {"short", "int", "long", "float", "double"},
		"short": {"int", "long", "float", "double"},
		"char":  {"int", "long", "float", "double"},
		"int":   {"long", "float", "double"},
		"long":  {"float", "double"},
		"float": {"double"},
	}
	for distance, candidate := range primitiveWidening[actual] {
		if candidate == expected {
			return 20 - distance, true
		}
	}
	boxed := map[string]string{
		"byte": "java.lang.byte", "short": "java.lang.short", "int": "java.lang.integer", "long": "java.lang.long",
		"float": "java.lang.float", "double": "java.lang.double", "char": "java.lang.character", "boolean": "java.lang.boolean",
	}
	if wrapper := boxed[actual]; wrapper != "" {
		if expected == wrapper {
			return 12, true
		}
		if expected == "java.lang.object" || expected == "java.lang.number" && actual != "char" && actual != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			return 8, true
		}
	}
	unboxed := map[string]string{}
	for primitive, wrapper := range boxed {
		unboxed[wrapper] = primitive
	}
	if primitive := unboxed[actual]; primitive != "" {
		if expected == "java.lang.object" || expected == "java.lang.number" && primitive != "char" && primitive != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			// Widening reference conversion is a strict-invocation candidate and
			// therefore wins before loose unboxing/widening is considered.
			return 24, true
		}
		if primitive == expected {
			return 12, true
		}
		for distance, candidate := range primitiveWidening[primitive] {
			if candidate == expected {
				return 10 - distance, true
			}
		}
	}
	if actual == "java.lang.string" && (expected == "java.lang.object" || expected == "java.lang.charsequence" || expected == "java.io.serializable" || expected == "java.lang.comparable") {
		return 16, true
	}
	return 0, false
}

func javaInvocationType(value string) string {
	value = simpleType(value)
	switch value {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return value
	case "Byte", "Short", "Integer", "Long", "Float", "Double", "Character", "Boolean":
		return "java.lang." + strings.ToLower(value)
	case "integer":
		return "java.lang.integer"
	case "character":
		return "java.lang.character"
	case "String", "string":
		return "java.lang.string"
	case "Object", "Number", "Comparable", "CharSequence":
		return "java.lang." + strings.ToLower(value)
	case "Serializable":
		return "java.io.serializable"
	default:
		return strings.ToLower(value)
	}
}

func (i *Index) isSubtypeLocked(file *analysis.ParsedFile, actual, expected string) bool {
	if file.Language == analysis.LanguageKotlin && simpleType(expected) == "Any" && actual != "" {
		return true
	}
	for _, candidate := range i.typeAndSupertypesLocked(file, actual) {
		if sameJvmType(candidate, expected) {
			return true
		}
	}
	return false
}

func memberKey(container, name string) string { return container + "\x00" + name }

func matchesArity(symbol analysis.Symbol, count int) bool {
	return matchesArityForLanguage(symbol, count, analysis.LanguageKotlin)
}

func matchesArityForLanguage(symbol analysis.Symbol, count int, language analysis.Language) bool {
	if len(symbol.Parameters) == count {
		return true
	}
	if !analysis.IsCallableKind(symbol.Kind) {
		return count == 0
	}
	required := 0
	variadic := false
	for _, parameter := range symbol.Parameters {
		if parameter.Default == "" || language == analysis.LanguageJava {
			required++
		}
		if parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg") {
			variadic = true
		}
	}
	return count >= required && (variadic || count <= len(symbol.Parameters))
}

// simpleNameInScopeLocked reports whether a declaration can be named by its
// simple name from this file. A name is in scope when it is declared here, sits
// in the same package, is imported, or comes from a package the language
// imports by default. Anything else needs an import first, and resolving it
// regardless made go-to-definition jump to a declaration the file cannot name
// and the compiler will not accept.
func (i *Index) simpleNameInScopeLocked(file *analysis.ParsedFile, symbol analysis.Symbol) bool {
	if symbol.URI == file.URI {
		return true
	}
	if symbol.Package == file.Package {
		return true
	}
	for _, imported := range file.Imports {
		if imported.Wildcard {
			if imported.Path == symbol.Package {
				return true
			}
			continue
		}
		if imported.Path == symbol.FQN || imported.LocalName() == symbol.Name && strings.HasSuffix(imported.Path, "."+symbol.Name) {
			return true
		}
		// A member imported by name brings only that member into scope, but its
		// owner is named by the import path itself.
		if strings.HasPrefix(imported.Path, symbol.Package+".") {
			if remainder := imported.Path[len(symbol.Package)+1:]; remainder == symbol.Name || strings.HasPrefix(remainder, symbol.Name+".") {
				return true
			}
		}
	}
	if symbol.Package == "java.lang" {
		return true
	}
	if file.Language == analysis.LanguageKotlin {
		switch symbol.Package {
		case "kotlin", "kotlin.annotation", "kotlin.collections", "kotlin.comparisons", "kotlin.io", "kotlin.ranges", "kotlin.sequences", "kotlin.text", "kotlin.jvm":
			return true
		}
	}
	// A declaration the index recorded without a package cannot be placed, so
	// it is accepted rather than hidden.
	return symbol.Package == ""
}
