package index

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

func (i *Index) Completion(uri protocol.URI, pos protocol.Position, limit int) []analysis.Symbol {
	limited := limit > 0
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	offset := doc.Offset(pos)
	// Nothing the index knows applies inside a string body or comment prose,
	// and a doc comment completes declarations only in its reference
	// positions. A tag name is the server's to offer: no symbol names it.
	kotlin := strings.EqualFold(doc.LanguageID, "kotlin")
	position := CompletionPositionAt(doc.Text, offset, kotlin)
	if position.Scope == CompletionNone || position.Scope == CompletionDocTag {
		return nil
	}
	prefix, qualifier := completionContext(doc.Text, offset)
	// A Kotlin identifier never contains '$'; the one before a template's
	// name introduces it and is not part of the name being typed.
	if kotlin {
		prefix = strings.TrimLeft(prefix, "$")
	}
	if position.Scope != CompletionCode {
		prefix, qualifier = docReferenceContext(doc.Text, offset)
	}
	annotationOwner := AnnotationAttributeOwner(doc.Text, offset)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	if position.Scope == CompletionDocParameter {
		return i.documentedParametersLocked(file, position.DocEnd, prefix)
	}
	// `Owner#member` and `[Owner.member]` reference a member the way code
	// cannot: a doc reference names instance members through the type itself,
	// where an expression would need a receiver.
	if position.Scope == CompletionDocReference && qualifier != "" {
		if members := i.docQualifiedMembersLocked(file, qualifier, prefix, offset); len(members) > 0 {
			return members
		}
	}
	initialCapacity := 256
	if limited {
		initialCapacity = limit * 4
	}
	ids := make([]string, 0, initialCapacity)
	synthetic := make([]analysis.Symbol, 0, 8)
	if annotationOwner != "" {
		usedAttributes := AnnotationAttributeNames(doc.Text, offset)
		for _, owner := range i.resolveTypeSymbolsLocked(file, annotationOwner) {
			if owner.Kind != analysis.KindAnnotation {
				continue
			}
			for _, candidateID := range i.byContainerName[owner.Name] {
				symbol := i.symbols[candidateID]
				if symbol.ContainerID == owner.ID && !usedAttributes[symbol.Name] && analysis.IsCallableKind(symbol.Kind) && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
					ids = append(ids, candidateID)
				}
			}
		}
	} else if qualifier != "" {
		typeQualifierSymbols := i.resolveTypeSymbolsLocked(file, qualifier)
		typeQualifier := len(typeQualifierSymbols) > 0
		typeQualifierValue := i.typeQualifierActsAsValueLocked(file, typeQualifierSymbols)
		ids = append(ids, i.anonymousObjectMemberIDsLocked(file, qualifier, "", offset)...)
		typ := i.typeOfExpressionLocked(file, qualifier, offset)
		if explicit := explicitReceiverType(qualifier); explicit != "" {
			typ = explicit
		}
		if typ != "" {
			containers := i.typeAndSupertypesLocked(file, typ)
			for _, container := range containers {
				for _, candidateID := range i.byContainerName[container] {
					s := i.symbols[candidateID]
					if !i.memberInheritedForReceiverLocked(file, *s, typ) {
						continue
					}
					if typeQualifier && !i.memberAvailableThroughTypeQualifierLocked(file, *s, typeQualifierSymbols) {
						continue
					}
					if i.accessibleLocked(file, *s, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
						ids = append(ids, candidateID)
						if limited && len(ids) >= limit*4 {
							break
						}
					}
				}
				for _, candidateID := range i.byReceiver[container] {
					s := i.symbols[candidateID]
					if (!typeQualifier || typeQualifierValue) && i.extensionReceiverApplicableLocked(file, *s, typ) && i.accessibleLocked(file, *s, offset) && i.extensionVisibleLocked(file, *s, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
						ids = append(ids, candidateID)
					}
				}
				if file.Language == analysis.LanguageKotlin && typeQualifier {
					for _, companion := range i.companionMembersLocked(file, container) {
						if i.accessibleLocked(file, companion, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(companion.Name), strings.ToLower(prefix))) {
							ids = append(ids, companion.ID)
						}
					}
				}
			}
		} else {
			for _, child := range i.packageChildren[qualifier] {
				if prefix == "" || strings.HasPrefix(strings.ToLower(child), strings.ToLower(prefix)) {
					fqn := child
					if qualifier != "" {
						fqn = qualifier + "." + child
					}
					id := "package:" + fqn
					synthetic = append(synthetic, analysis.Symbol{ID: id, Name: child, FQN: fqn, Kind: analysis.KindPackage})
				}
			}
			for _, candidateID := range i.byPackage[qualifier] {
				symbol := i.symbols[candidateID]
				if symbol.ContainerID == "" && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
					ids = append(ids, candidateID)
				}
			}
		}
	} else {
		for _, child := range i.packageChildren[""] {
			if prefix == "" || strings.HasPrefix(strings.ToLower(child), strings.ToLower(prefix)) {
				synthetic = append(synthetic, analysis.Symbol{ID: "package:" + child, Name: child, FQN: child, Kind: analysis.KindPackage})
			}
		}
		currentType := i.enclosingTypeLocked(file, offset)
		if enumType := i.javaSwitchLabelReceiverTypeLocked(file, offset); enumType != "" {
			for _, container := range i.typeAndSupertypesLocked(file, enumType) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if symbol.Kind == analysis.KindEnumMember && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		for _, symbol := range file.Symbols {
			if symbol.StartByte <= offset && (symbol.ContainerID == "" || symbol.ContainerID == currentType.ID || symbol.ContainerID != "" && i.symbolWithinCallableScopeLocked(file, symbol, offset)) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
				ids = append(ids, symbol.ID)
			}
		}
		if currentType.ID != "" {
			for _, container := range i.typeAndSupertypesLocked(file, currentType.Name) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		implicitReceiverTypes := []string{i.contextualLambdaReceiverTypeLocked(file, offset), i.enclosingExtensionReceiverTypeLocked(file, offset)}
		implicitReceiverTypes = append(implicitReceiverTypes, i.enclosingContextReceiverTypesLocked(file, offset)...)
		if enclosing := i.enclosingTypeLocked(file, offset); enclosing.ID != "" {
			implicitReceiverTypes = append(implicitReceiverTypes, enclosing.Name)
		}
		for _, receiverType := range implicitReceiverTypes {
			if receiverType == "" {
				continue
			}
			for _, container := range i.typeAndSupertypesLocked(file, receiverType) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
				for _, id := range i.byReceiver[container] {
					symbol := i.symbols[id]
					if i.extensionReceiverApplicableLocked(file, *symbol, receiverType) && i.accessibleLocked(file, *symbol, offset) && i.extensionVisibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		names := i.completionIndex.allNames()
		if len(prefix) > 0 {
			lower := strings.ToLower(prefix)
			if key, ok := asciiPrefix(lower, 3); ok {
				names = i.completionIndex.prefixBucket(key)
			} else if lower[0] < 128 {
				names = i.completionIndex.initialBucket(lower[0])
			}
		}
		for _, name := range names {
			values := i.completionIndex.get(name)
			if prefix == "" || strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				for _, id := range values {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && i.extensionVisibleLocked(file, *symbol, offset) {
						ids = append(ids, id)
					}
				}
				if limited && len(ids) >= limit*4 {
					break
				}
			}
		}
	}
	seen := map[string]bool{}
	outCapacity := len(ids) + len(synthetic)
	if limited && outCapacity > limit {
		outCapacity = limit
	}
	out := make([]analysis.Symbol, 0, outCapacity)
	for _, symbol := range synthetic {
		key := symbol.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, symbol)
		if limited && len(out) >= limit {
			return out
		}
	}
	// A library type is commonly indexed twice, once from the dependency's own
	// jar and once from its sources jar. Both carry the same qualified name, so
	// offering both puts two identical-looking entries in the list with no way
	// to choose between them. A type's qualified name identifies it uniquely;
	// callables sharing one are overloads and must all be offered.
	seenType := make(map[string]bool)
	// Members of one receiver are offered once each. The same member reaches
	// this list several times over: a multiplatform declaration from both its
	// common and its platform source set, a member and the supertype member it
	// overrides, and the Kotlin and Java views of the same JVM method. A
	// receiver's member is identified by its name and parameter types, so
	// overloads stay distinct while copies collapse -- `address.length` was
	// offered six times before this.
	seenMember := make(map[string]int)
	for _, id := range ids {
		s := i.symbols[id]
		key := s.ID
		if seen[key] || (!strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
			continue
		}
		if analysis.IsTypeKind(s.Kind) && s.FQN != "" {
			if seenType[s.FQN] {
				continue
			}
			seenType[s.FQN] = true
		}
		if qualifier != "" && !analysis.IsTypeKind(s.Kind) {
			member := memberSignatureKey(*s)
			if at, exists := seenMember[member]; exists {
				// Keep the view spelled in this file's language: a Kotlin file
				// names `length` as a property, a Java one as `length()`.
				if s.Language == file.Language && out[at].Language != file.Language {
					out[at] = *s
				}
				continue
			}
			seenMember[member] = len(out)
		}
		// `@throws` and `@exception` take a type and nothing else.
		if position.Scope == CompletionDocType && !analysis.IsTypeKind(s.Kind) {
			continue
		}
		seen[key] = true
		out = append(out, *s)
		if limited && len(out) >= limit {
			break
		}
	}
	return out
}

// memberSignatureKey identifies a receiver's member by what distinguishes one
// member from another: its name and the types it takes.
func memberSignatureKey(symbol analysis.Symbol) string {
	var key strings.Builder
	key.WriteString(symbol.Name)
	key.WriteByte('(')
	for _, parameter := range symbol.Parameters {
		key.WriteString(simpleType(parameter.Type))
		key.WriteByte(';')
	}
	key.WriteByte(')')
	return key.String()
}

// documentedParametersLocked lists the parameters of the declaration a doc
// comment documents, which is the one beginning after it.
func (i *Index) documentedParametersLocked(file *analysis.ParsedFile, docEnd int, prefix string) []analysis.Symbol {
	var documented *analysis.Symbol
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || symbol.StartByte < docEnd {
			continue
		}
		if documented == nil || symbol.StartByte < documented.StartByte {
			documented = symbol
		}
	}
	if documented == nil {
		return nil
	}
	out := make([]analysis.Symbol, 0, len(documented.Parameters))
	add := func(name, typ string, kind analysis.SymbolKind) {
		if name == "" || prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			return
		}
		for _, existing := range out {
			if existing.Name == name {
				return
			}
		}
		out = append(out, analysis.Symbol{ID: "docparam:" + documented.ID + ":" + name, Name: name, Kind: kind, Type: typ, Language: file.Language})
	}
	for _, parameter := range documented.Parameters {
		add(parameter.Name, parameter.Type, analysis.KindParameter)
	}
	// A class documents its constructor's parameters, and KDoc's `@property`
	// names the properties they declare.
	for index := range file.Symbols {
		member := &file.Symbols[index]
		if member.Synthetic || member.ContainerID != documented.ID {
			continue
		}
		if member.Kind == analysis.KindConstructor {
			for _, parameter := range member.Parameters {
				add(parameter.Name, parameter.Type, analysis.KindParameter)
			}
		}
		if member.Kind == analysis.KindProperty || member.Kind == analysis.KindField {
			add(member.Name, member.Type, member.Kind)
		}
	}
	// Type parameters are documented with `@param <T>` in Java and `@param T`
	// in Kotlin.
	for _, name := range documented.TypeParameters {
		add(name, "", analysis.KindTypeParameter)
	}
	return out
}

// docQualifiedMembersLocked lists the members a doc reference may name through
// an owning type, instance and static alike.
func (i *Index) docQualifiedMembersLocked(file *analysis.ParsedFile, qualifier, prefix string, offset int) []analysis.Symbol {
	owners := i.resolveTypeSymbolsLocked(file, qualifier)
	if len(owners) == 0 {
		return nil
	}
	out := make([]analysis.Symbol, 0, 16)
	seen := make(map[string]bool)
	for _, owner := range owners {
		for _, container := range i.typeAndSupertypesLocked(file, owner.Name) {
			for _, id := range i.byContainerName[container] {
				symbol := i.symbols[id]
				if symbol == nil || seen[symbol.ID] || symbol.Synthetic {
					continue
				}
				if prefix != "" && !strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix)) {
					continue
				}
				if !i.accessibleLocked(file, *symbol, offset) {
					continue
				}
				seen[symbol.ID] = true
				out = append(out, *symbol)
			}
		}
	}
	return out
}

// docReferenceContext reads the prefix and qualifier of a doc-comment
// reference. Javadoc separates a member from its owner with '#'; everything
// else spells references the way code does.
func docReferenceContext(text string, offset int) (string, string) {
	prefix, qualifier := completionContext(text, offset)
	if qualifier != "" {
		return prefix, qualifier
	}
	start := offset - len(prefix)
	if start > 0 && text[start-1] == '#' {
		owner := completionIdentifierBefore(text, start-1)
		return prefix, owner
	}
	return prefix, ""
}

// completionIdentifierBefore returns the dotted identifier ending at the
// offset, as `java.util.List` or `List`.
func completionIdentifierBefore(text string, offset int) string {
	start := offset
	for start > 0 {
		value := text[start-1]
		if value != '.' && !isIdentifierByteFast(value) {
			break
		}
		start--
	}
	return text[start:offset]
}

func AnnotationAttributeOwner(source string, offset int) string {
	if offset < 0 || offset > len(source) {
		return ""
	}
	start := strings.LastIndexByte(source[:offset], '@')
	if start < 0 {
		return ""
	}
	openRelative := strings.IndexByte(source[start:offset], '(')
	if openRelative < 0 {
		return ""
	}
	open := start + openRelative
	depth := 0
	for index := open; index < offset; index++ {
		switch source[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				// The annotation's own argument list closed before this
				// position. Anything further belongs to whatever the annotation
				// is attached to -- a class's parameter list keeps the running
				// depth positive and made every position inside the declaration
				// look like an annotation argument.
				return ""
			}
		}
	}
	if depth <= 0 {
		return ""
	}
	owner := strings.TrimSpace(source[start+1 : open])
	// A use-site target names where the annotation is applied, not what it is:
	// `@field:Column(...)` is a Column.
	if colon := strings.IndexByte(owner, ':'); colon >= 0 {
		owner = strings.TrimSpace(owner[colon+1:])
	}
	for _, value := range owner {
		if value != '.' && value != '$' && value != '_' && !unicode.IsLetter(value) && !unicode.IsDigit(value) {
			return ""
		}
	}
	return owner
}

func AnnotationAttributeNames(source string, offset int) map[string]bool {
	used := make(map[string]bool)
	if offset < 0 || offset > len(source) {
		return used
	}
	start := strings.LastIndexByte(source[:offset], '@')
	if start < 0 {
		return used
	}
	openRelative := strings.IndexByte(source[start:offset], '(')
	if openRelative < 0 {
		return used
	}
	value := source[start+openRelative+1 : offset]
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		after := end
		for after < len(value) && unicode.IsSpace(rune(value[after])) {
			after++
		}
		if after < len(value) && value[after] == '=' {
			used[value[index:end]] = true
		}
		index = end
	}
	return used
}

func completionContext(s string, at int) (string, string) {
	if at > len(s) {
		at = len(s)
	}
	start := at
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:start])
		if r == utf8.RuneError && size == 1 || !isIdentRune(r) {
			break
		}
		start -= size
	}
	prefix := s[start:at]
	if start > 0 && s[start-1] == '.' {
		return prefix, expressionQualifierBefore(s, start)
	}
	return prefix, ""
}

func isUnqualifiedCompletionSymbol(symbol analysis.Symbol) bool {
	return symbol.ContainerID == "" && isWorkspaceSymbol(symbol)
}

func asciiPrefix(value string, maximum int) (string, bool) {
	if value == "" {
		return "", false
	}
	length := len(value)
	if length > maximum {
		length = maximum
	}
	for n := 0; n < length; n++ {
		if value[n] >= 128 {
			return "", false
		}
	}
	return value[:length], true
}
