package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) SymbolAt(uri protocol.URI, pos protocol.Position) (analysis.Symbol, *analysis.Reference, bool) {
	doc, ok := i.Document(uri)
	if !ok {
		return analysis.Symbol{}, nil, false
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return analysis.Symbol{}, nil, false
	}
	for _, s := range file.Symbols {
		if offset >= s.NameStartByte && offset < s.NameEndByte {
			return s, nil, true
		}
	}
	for n := range file.References {
		r := &file.References[n]
		if offset >= r.StartByte && offset < r.EndByte {
			resolved := i.resolveLocked(file, *r)
			if len(resolved) > 0 {
				return resolved[0], r, true
			}
		}
	}
	// Editors commonly place the cursor immediately after an identifier. Keep
	// that convenience only as a fallback, after testing the end-exclusive LSP
	// ranges so adjacent punctuation conventions such as box[0] win.
	for _, s := range file.Symbols {
		if offset == s.NameEndByte && offset >= s.NameStartByte {
			return s, nil, true
		}
	}
	for n := range file.References {
		r := &file.References[n]
		if offset == r.EndByte && offset >= r.StartByte {
			resolved := i.resolveLocked(file, *r)
			if len(resolved) > 0 {
				return resolved[0], r, true
			}
		}
	}
	return analysis.Symbol{}, nil, false
}

func (i *Index) Definitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	if resolved, handled := i.springDataDefinitionLocked(file, offset); handled {
		return resolved
	}
	for _, s := range file.Symbols {
		if offset >= s.NameStartByte && offset < s.NameEndByte {
			return []analysis.Symbol{s}
		}
	}
	for _, r := range file.References {
		if offset >= r.StartByte && offset < r.EndByte {
			if resolved := i.resolveLocked(file, r); len(resolved) > 0 {
				return resolved
			}
		}
	}
	for _, s := range file.Symbols {
		if offset == s.NameEndByte && offset >= s.NameStartByte {
			return []analysis.Symbol{s}
		}
	}
	for _, r := range file.References {
		if offset == r.EndByte && offset >= r.StartByte {
			if resolved := i.resolveLocked(file, r); len(resolved) > 0 {
				return resolved
			}
		}
	}
	return nil
}

// CallSignatures returns the complete overload family and the best active
// signature at a call site. Constructor navigation intentionally targets the
// class, while signature help exposes all constructors and selects one.
func (i *Index) CallSignatures(uri protocol.URI, pos protocol.Position) ([]analysis.Symbol, int) {
	doc, ok := i.Document(uri)
	if !ok {
		return nil, 0
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil, 0
	}
	var reference *analysis.Reference
	for index := range file.References {
		candidate := &file.References[index]
		if candidate.Role == analysis.RoleCall && (candidate.StartByte <= offset && offset <= candidate.EndByte) {
			reference = candidate
			break
		}
	}
	if reference == nil {
		return nil, 0
	}
	resolved := i.resolveLocked(file, *reference)
	candidates := make([]analysis.Symbol, 0, len(resolved)+2)
	seen := make(map[string]bool)
	appendCandidate := func(symbol *analysis.Symbol) {
		if symbol != nil && analysis.IsCallableKind(symbol.Kind) && i.accessibleLocked(file, *symbol, reference.StartByte) && !seen[symbol.ID] {
			seen[symbol.ID] = true
			candidates = append(candidates, *symbol)
		}
	}
	for _, symbol := range resolved {
		if analysis.IsTypeKind(symbol.Kind) {
			for _, id := range i.byContainerMember[memberKey(symbol.Name, symbol.Name)] {
				constructor := i.symbols[id]
				if constructor != nil && constructor.Kind == analysis.KindConstructor && constructor.ContainerID == symbol.ID {
					appendCandidate(constructor)
				}
			}
			continue
		}
		if !analysis.IsCallableKind(symbol.Kind) {
			continue
		}
		if symbol.ContainerID != "" {
			for _, id := range i.byContainerMember[memberKey(symbol.ContainerName, symbol.Name)] {
				candidate := i.symbols[id]
				if candidate != nil && candidate.ContainerID == symbol.ContainerID && candidate.Kind == symbol.Kind {
					appendCandidate(candidate)
				}
			}
		} else if symbol.FQN != "" {
			for _, id := range i.byFQN[symbol.FQN] {
				appendCandidate(i.symbols[id])
			}
		} else {
			appendCandidate(i.symbols[symbol.ID])
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}
	sortSymbols(candidates)
	active := 0
	if len(candidates) == 1 {
		return candidates, active
	}
	scores := make([]int, len(candidates))
	best, typed := -1<<30, false
	for index, candidate := range candidates {
		score, hasTypes := i.callCompatibilityLocked(file, *reference, candidate)
		scores[index] = score
		if hasTypes {
			if !typed || score > best {
				typed = true
				best = score
				active = index
			}
		}
	}
	if !typed {
		best = scores[0]
		for index := 1; index < len(scores); index++ {
			if scores[index] > best {
				best, active = scores[index], index
			}
		}
	}
	return candidates, active
}

// PackageDefinitions mirrors IntelliJ's Java/Kotlin package providers: a
// package reference navigates to each workspace directory containing files in
// that exact package. Library packages are deliberately excluded.
func (i *Index) PackageDefinitions(uri protocol.URI, pos protocol.Position) []protocol.Location {
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	offset := doc.Offset(pos)
	start := strings.LastIndexByte(doc.Text[:offset], '\n') + 1
	end := len(doc.Text)
	if newline := strings.IndexByte(doc.Text[offset:], '\n'); newline >= 0 {
		end = offset + newline
	}
	line := doc.Text[start:end]
	trimmed := strings.TrimLeft(line, " \t")
	indent := len(line) - len(trimmed)
	keyword := ""
	switch {
	case strings.HasPrefix(trimmed, "package "):
		keyword = "package"
	case strings.HasPrefix(trimmed, "import "):
		keyword = "import"
	default:
		return nil
	}
	qualifiedStart := indent + len(keyword)
	for qualifiedStart < len(line) && (line[qualifiedStart] == ' ' || line[qualifiedStart] == '\t') {
		qualifiedStart++
	}
	if keyword == "import" && strings.HasPrefix(line[qualifiedStart:], "static ") {
		qualifiedStart += len("static ")
	}
	relative := offset - start
	if relative < qualifiedStart || relative > len(line) {
		return nil
	}
	if relative == len(line) || relative > qualifiedStart && !isIdentRune(rune(line[relative])) {
		relative--
	}
	if relative < qualifiedStart || !isIdentRune(rune(line[relative])) {
		return nil
	}
	tokenEnd := relative + 1
	for tokenEnd < len(line) && isIdentRune(rune(line[tokenEnd])) {
		tokenEnd++
	}
	qualified := strings.ReplaceAll(strings.Trim(line[qualifiedStart:tokenEnd], "."), "`", "")
	i.mu.RLock()
	directories := append([]protocol.URI(nil), i.packages[qualified]...)
	i.mu.RUnlock()
	locations := make([]protocol.Location, 0, len(directories))
	for _, directory := range directories {
		locations = append(locations, protocol.Location{URI: directory, Range: protocol.Range{}})
	}
	return locations
}

func (i *Index) TypeDefinitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	s, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	if analysis.IsTypeKind(s.Kind) {
		return []analysis.Symbol{s}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[s.URI]
	if file == nil {
		return nil
	}
	typ := s.Type
	if typ == "" || typ == "var" || typ == "val" {
		typ = i.inferExpressionTypeLocked(file, s.Initializer, s.StartByte)
	}
	if typ == "" {
		return nil
	}
	return i.resolveTypeSymbolsLocked(file, typ)
}

func (i *Index) Implementations(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []analysis.Symbol
	if containsString(target.Modifiers, "expect") || i.containerHasKotlinModifierLocked(target, "expect") {
		for _, counterpart := range i.expectActualFamilyLocked(target) {
			if counterpart.ID != target.ID && (containsString(counterpart.Modifiers, "actual") || i.containerHasKotlinModifierLocked(counterpart, "actual")) {
				out = append(out, counterpart)
			}
		}
	}
	if analysis.IsTypeKind(target.Kind) {
		queue := []analysis.Symbol{target}
		seen := map[string]bool{}
		for len(queue) > 0 {
			parent := queue[0]
			queue = queue[1:]
			ids := append([]string(nil), i.bySuper[parent.Name]...)
			ids = append(ids, i.bySuper[parent.FQN]...)
			for _, id := range ids {
				if seen[id] {
					continue
				}
				if candidate, ok := i.symbols[id]; ok {
					if !i.directSupertypeMatchesLocked(*candidate, parent.ID) {
						continue
					}
					seen[id] = true
					out = append(out, *candidate)
					queue = append(queue, *candidate)
				}
			}
		}
	}
	if analysis.IsCallableKind(target.Kind) {
		for _, id := range i.byName[target.Name] {
			candidate, ok := i.symbols[id]
			if ok && analysis.IsCallableKind(candidate.Kind) && sameCallableShape(*candidate, target) && candidate.ContainerID != target.ContainerID && i.containerInheritsLocked(candidate.ContainerID, target.ContainerID) {
				out = append(out, *candidate)
			}
		}
	}
	sortSymbols(out)
	return out
}

func (i *Index) References(uri protocol.URI, pos protocol.Position, includeDeclaration bool) []protocol.Location {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	family := i.referenceFamilyLocked(target)
	out := make([]protocol.Location, 0)
	if includeDeclaration {
		for _, member := range family {
			out = append(out, member.Location())
		}
	}
	for _, member := range family {
		for _, r := range i.refsByName[member.Name] {
			if r.ResolvedID != "" {
				if r.ResolvedID == member.ID {
					out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
				}
				continue
			}
			file := i.files[r.URI]
			if file == nil {
				continue
			}
			resolved := i.resolveLocked(file, r)
			for _, s := range resolved {
				if s.ID == member.ID {
					out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
					break
				}
			}
		}
	}
	return uniqueLocations(out)
}

func (i *Index) referenceFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	origin := target
	if target.OriginID != "" {
		if value, ok := i.symbols[target.OriginID]; ok {
			origin = *value
		}
	}
	family := []analysis.Symbol{origin}
	for _, id := range i.byOrigin[origin.ID] {
		if symbol, ok := i.symbols[id]; ok {
			family = append(family, *symbol)
		}
	}
	for _, counterpart := range i.expectActualFamilyLocked(origin) {
		if counterpart.ID != origin.ID {
			family = append(family, counterpart)
			for _, id := range i.byOrigin[counterpart.ID] {
				if symbol, ok := i.symbols[id]; ok {
					family = append(family, *symbol)
				}
			}
		}
	}
	if analysis.IsCallableKind(origin.Kind) && origin.ContainerID != "" {
		for _, id := range i.byName[origin.Name] {
			candidate, ok := i.symbols[id]
			if !ok || candidate.ID == origin.ID || candidate.ContainerID == "" || !analysis.IsCallableKind(candidate.Kind) || !sameCallableShape(*candidate, origin) {
				continue
			}
			if i.containerInheritsLocked(candidate.ContainerID, origin.ContainerID) || i.containerInheritsLocked(origin.ContainerID, candidate.ContainerID) {
				family = append(family, *candidate)
			}
		}
	}
	property, bean := beanPropertyName(origin.Name)
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		property, bean = origin.Name, true
	}
	if bean && origin.ContainerID != "" {
		stem := property
		if stem != "" && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		for _, name := range []string{property, "get" + stem, "is" + stem, "set" + stem} {
			for _, id := range i.byContainerMember[memberKey(origin.ContainerName, name)] {
				candidate := i.symbols[id]
				if candidate.ContainerID == origin.ContainerID {
					family = append(family, *candidate)
				}
			}
		}
	}
	return uniqueSymbols(family)
}

func (i *Index) expectActualFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	if target.Language != analysis.LanguageKotlin || target.FQN == "" {
		return nil
	}
	targetMarked := containsString(target.Modifiers, "expect") || containsString(target.Modifiers, "actual")
	if !targetMarked && target.ContainerID != "" {
		targetMarked = i.containerHasKotlinModifierLocked(target, "expect") || i.containerHasKotlinModifierLocked(target, "actual")
	}
	if !targetMarked {
		return nil
	}
	targetModule := i.moduleForURILocked(target.URI)
	result := []analysis.Symbol{target}
	for _, id := range i.byFQN[target.FQN] {
		candidate, ok := i.symbols[id]
		if !ok || candidate.ID == target.ID || candidate.Language != analysis.LanguageKotlin || candidate.Kind != target.Kind {
			continue
		}
		if analysis.IsCallableKind(target.Kind) && !sameCallableShape(*candidate, target) {
			continue
		}
		candidateMarked := containsString(candidate.Modifiers, "expect") || containsString(candidate.Modifiers, "actual") || i.containerHasKotlinModifierLocked(*candidate, "expect") || i.containerHasKotlinModifierLocked(*candidate, "actual")
		if !candidateMarked {
			continue
		}
		candidateModule := i.moduleForURILocked(candidate.URI)
		if targetModule != nil && candidateModule != nil && (targetModule.Name != candidateModule.Name || targetModule.Dir != candidateModule.Dir) {
			continue
		}
		result = append(result, *candidate)
	}
	return uniqueSymbols(result)
}

func (i *Index) containerHasKotlinModifierLocked(symbol analysis.Symbol, modifier string) bool {
	for containerID := symbol.ContainerID; containerID != ""; {
		container, ok := i.symbols[containerID]
		if !ok {
			return false
		}
		if containsString(container.Modifiers, modifier) {
			return true
		}
		containerID = container.ContainerID
	}
	return false
}

func (i *Index) SymbolsInFile(uri protocol.URI) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	f := i.files[uri]
	if f == nil {
		return nil
	}
	out := make([]analysis.Symbol, 0, len(f.Symbols))
	for _, symbol := range f.Symbols {
		if !symbol.Synthetic {
			out = append(out, symbol)
		}
	}
	return out
}

// InferredType resolves a declaration initializer using the same constructor,
// factory, literal, and collection inference used by member completion.
func (i *Index) InferredType(uri protocol.URI, symbolID string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	symbol, ok := i.symbols[symbolID]
	if file == nil || !ok || symbol.URI != uri {
		return ""
	}
	if symbol.Type != "" && symbol.Type != "var" {
		return simpleType(symbol.Type)
	}
	return simpleType(i.inferExpressionTypeLocked(file, symbol.Initializer, symbol.StartByte))
}

func (i *Index) FunctionalParameterTypes(uri protocol.URI, typeName string) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	return i.functionalParameterTypesLocked(file, typeName)
}

func (i *Index) functionalParameterTypesLocked(file *analysis.ParsedFile, typeName string) []string {
	base, arguments := splitInstantiatedType(typeName)
	var methods []analysis.Symbol
	for _, owner := range i.resolveTypeSymbolsLocked(file, base) {
		if owner.Kind != analysis.KindInterface {
			continue
		}
		for _, id := range i.byContainerName[owner.Name] {
			method := i.symbols[id]
			if method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
				continue
			}
			methods = append(methods, *method)
		}
		if len(methods) == 1 {
			out := make([]string, len(methods[0].Parameters))
			for index, parameter := range methods[0].Parameters {
				out[index] = substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments)
			}
			return out
		}
	}
	return nil
}

func (i *Index) Supertypes(item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []analysis.Symbol
	for _, name := range item.Supertypes {
		out = append(out, i.symbolsForIDsLocked(i.byName[simpleType(name)], func(s analysis.Symbol) bool { return analysis.IsTypeKind(s.Kind) })...)
	}
	return uniqueSymbols(out)
}

func (i *Index) Subtypes(item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	ids := append([]string(nil), i.bySuper[item.Name]...)
	ids = append(ids, i.bySuper[item.FQN]...)
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if symbol, ok := i.symbols[id]; ok {
			out = append(out, *symbol)
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) CallsFrom(item analysis.Symbol) map[string][]analysis.Reference {
	if document, ok := i.Document(item.URI); ok {
		i.ensureLibraryReferences(item.URI, document)
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := map[string][]analysis.Reference{}
	f := i.files[item.URI]
	if f == nil {
		return out
	}
	for _, r := range f.References {
		if r.ContainerID != item.ID || r.Role != analysis.RoleCall {
			continue
		}
		for _, s := range i.resolveLocked(f, r) {
			out[s.ID] = append(out[s.ID], r)
		}
	}
	return out
}

func (i *Index) CallsTo(item analysis.Symbol) map[string][]analysis.Reference {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := map[string][]analysis.Reference{}
	for _, r := range i.refsByName[item.Name] {
		f := i.files[r.URI]
		if f == nil || r.Role != analysis.RoleCall {
			continue
		}
		for _, s := range i.resolveLocked(f, r) {
			if s.ID == item.ID {
				out[r.ContainerID] = append(out[r.ContainerID], r)
			}
		}
	}
	return out
}

func (i *Index) Rename(uri protocol.URI, pos protocol.Position, newName string) protocol.WorkspaceEdit {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{}}
	}
	changes := make(map[protocol.URI][]protocol.TextEdit)
	i.mu.RLock()
	origin := target
	if target.OriginID != "" {
		if value, exists := i.symbols[target.OriginID]; exists {
			origin = *value
		}
	}
	propertyName, interopFamily := interopRenamePropertyName(target, origin, newName)
	family := i.referenceFamilyLocked(origin)
	seen := make(map[string]bool)
	add := func(location protocol.Location, replacement string) {
		key := string(location.URI) + "|" + itoa(location.Range.Start.Line) + ":" + itoa(location.Range.Start.Character) + "-" + itoa(location.Range.End.Line) + ":" + itoa(location.Range.End.Character)
		if !seen[key] {
			seen[key] = true
			changes[location.URI] = append(changes[location.URI], protocol.TextEdit{Range: location.Range, NewText: replacement})
		}
	}
	for _, member := range family {
		replacement := newName
		if interopFamily {
			replacement = interopRenameMemberName(member, propertyName)
		}
		add(member.Location(), replacement)
		for _, reference := range i.refsByName[member.Name] {
			file := i.files[reference.URI]
			if file == nil {
				continue
			}
			for _, resolved := range i.resolveLocked(file, reference) {
				if resolved.ID == member.ID {
					text := i.documentTextLocked(reference.URI)
					if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != member.Name {
						// Kotlin operator/convention references are structural
						// syntax, not identifier tokens. IntelliJ leaves them
						// untouched and removes `operator` when necessary.
						break
					}
					add(protocol.Location{URI: reference.URI, Range: reference.Range}, replacement)
					break
				}
			}
		}
	}
	i.mu.RUnlock()
	return protocol.WorkspaceEdit{Changes: changes}
}

// Renameable reports whether every resolved use can be changed by replacing
// an identifier token. Kotlin convention calls such as `left + right`,
// destructuring, indexing, and delegation are semantic references whose
// source range is punctuation or another structural form. Replacing those
// ranges with the requested identifier would produce invalid source, while
// omitting them would silently break the program, so the LSP rejects that
// rename until it has a full structural refactoring for the convention.
func (i *Index) Renameable(uri protocol.URI, pos protocol.Position) bool {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok || target.Library {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	origin := target
	if target.OriginID != "" {
		if value, exists := i.symbols[target.OriginID]; exists {
			origin = *value
		}
	}
	for _, member := range i.referenceFamilyLocked(origin) {
		for _, reference := range i.refsByName[member.Name] {
			file := i.files[reference.URI]
			if file == nil {
				continue
			}
			resolvedToMember := false
			for _, resolved := range i.resolveLocked(file, reference) {
				if resolved.ID == member.ID {
					resolvedToMember = true
					break
				}
			}
			if !resolvedToMember {
				continue
			}
			text := i.documentTextLocked(reference.URI)
			if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != member.Name {
				return false
			}
		}
	}
	return true
}

func interopRenamePropertyName(target, origin analysis.Symbol, requested string) (string, bool) {
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		if target.Synthetic && target.InteropLanguage == analysis.LanguageJava {
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
		return strings.Trim(requested, "`"), true
	}
	if origin.Language == analysis.LanguageJava {
		if _, bean := beanPropertyName(origin.Name); bean {
			if target.Synthetic && target.InteropLanguage == analysis.LanguageKotlin {
				return strings.Trim(requested, "`"), true
			}
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
	}
	return "", false
}

func interopRenameMemberName(member analysis.Symbol, propertyName string) string {
	if member.InteropLanguage == analysis.LanguageKotlin || member.Language == analysis.LanguageKotlin && member.Kind == analysis.KindProperty && !member.Synthetic {
		return propertyName
	}
	if _, ok := beanPropertyName(member.Name); ok {
		stem := propertyName
		if len(stem) > 0 && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		switch {
		case strings.HasPrefix(member.Name, "set"):
			return "set" + stem
		case strings.HasPrefix(member.Name, "is"):
			return "is" + stem
		default:
			return "get" + stem
		}
	}
	return propertyName
}

func beanPropertyName(accessor string) (string, bool) {
	for _, prefix := range []string{"get", "set", "is"} {
		if strings.HasPrefix(accessor, prefix) {
			return decapitalizeBean(accessor[len(prefix):])
		}
	}
	return "", false
}

// SemanticTokens returns lexical/declaration tokens plus references classified
// from the symbol each reference actually resolves to. The parser's role-based
// token remains as a fallback for temporarily unresolved code.
func (i *Index) SemanticTokens(uri protocol.URI) ([]analysis.Token, uint64, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil, 0, false
	}
	tokens := append([]analysis.Token(nil), file.Tokens...)
	type semanticClassification struct {
		typ       uint32
		modifiers uint32
	}
	classifications := make(map[[2]int]semanticClassification, len(file.Symbols)+len(file.References))
	declarationSpans := make(map[[2]int]bool, len(file.Symbols))
	declarationSymbols := make(map[[2]int]analysis.Symbol, len(file.Symbols))
	for _, symbol := range file.Symbols {
		key := [2]int{symbol.NameStartByte, symbol.NameEndByte}
		declarationSpans[key] = true
		if previous, exists := declarationSymbols[key]; !exists || previous.Synthetic && !symbol.Synthetic {
			declarationSymbols[key] = symbol
		}
	}
	for key, symbol := range declarationSymbols {
		classifications[key] = semanticClassification{
			typ: symbol.Kind.SemanticToken(), modifiers: semanticModifiersForSymbol(symbol, true, analysis.RoleRead),
		}
	}
	for _, reference := range file.References {
		key := [2]int{reference.StartByte, reference.EndByte}
		if declarationSpans[key] {
			continue
		}
		resolved := i.resolveLocked(file, reference)
		if len(resolved) > 0 {
			classifications[key] = semanticClassification{
				typ: resolved[0].Kind.SemanticToken(), modifiers: semanticModifiersForSymbol(resolved[0], false, reference.Role),
			}
		}
	}
	for n := range tokens {
		if classification, ok := classifications[[2]int{tokens[n].StartByte, tokens[n].EndByte}]; ok {
			tokens[n].Type = classification.typ
			tokens[n].Modifiers = classification.modifiers
		}
	}
	return tokens, file.TextHash, true
}

func semanticModifiersForSymbol(symbol analysis.Symbol, declaration bool, role analysis.ReferenceRole) uint32 {
	var modifiers uint32
	if declaration {
		modifiers |= analysis.SemanticModifierDeclaration
	}
	if containsString(symbol.Modifiers, "final") || containsString(symbol.Modifiers, "const") || containsString(symbol.Modifiers, "val") {
		modifiers |= analysis.SemanticModifierReadonly
	}
	static := containsString(symbol.Modifiers, "static") || containsString(symbol.Modifiers, "JvmStatic") || containsString(symbol.Modifiers, "companion")
	if symbol.Language == analysis.LanguageKotlin && symbol.ContainerID == "" && (symbol.Kind == analysis.KindProperty || analysis.IsCallableKind(symbol.Kind)) {
		static = true
	}
	if static {
		modifiers |= analysis.SemanticModifierStatic
	}
	if symbol.Deprecated || containsString(symbol.Modifiers, "deprecated") || containsString(symbol.Modifiers, "Deprecated") {
		modifiers |= analysis.SemanticModifierDeprecated
	}
	if containsString(symbol.Modifiers, "abstract") {
		modifiers |= analysis.SemanticModifierAbstract
	}
	if containsString(symbol.Modifiers, "suspend") {
		modifiers |= analysis.SemanticModifierAsync
	}
	variable := symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || symbol.Kind == analysis.KindVariable
	readonly := modifiers&analysis.SemanticModifierReadonly != 0
	if variable && !readonly || !declaration && role == analysis.RoleWrite {
		modifiers |= analysis.SemanticModifierModification
	}
	if symbol.Library && (symbol.Package == "kotlin" || strings.HasPrefix(symbol.Package, "kotlin.")) {
		modifiers |= analysis.SemanticModifierDefaultLibrary
	}
	return modifiers
}

// FilesImportingPrefix returns only workspace files whose import path is equal
// to prefix or starts with prefix plus a dot. Import prefixes are maintained as
// files enter the index, avoiding a whole-workspace scan on package moves.
func (i *Index) FilesImportingPrefix(prefix string) []*analysis.ParsedFile {
	i.mu.RLock()
	defer i.mu.RUnlock()
	seen := make(map[protocol.URI]bool)
	out := make([]*analysis.ParsedFile, 0, len(i.importersByPrefix[prefix]))
	for _, uri := range i.importersByPrefix[prefix] {
		if seen[uri] {
			continue
		}
		file := i.files[uri]
		if file == nil {
			continue
		}
		if _, ok := uriutil.Path(uri); !ok {
			continue
		}
		seen[uri] = true
		out = append(out, file)
	}
	return out
}

// UsedImports reports imports that contribute an unqualified semantic
// reference. Comments, strings, and fully-qualified expressions never enter
// the parser's reference stream and therefore cannot keep an import alive.
func (i *Index) UsedImports(uri protocol.URI) map[string]bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	used := make(map[string]bool)
	if file == nil {
		return used
	}
	for _, imported := range file.Imports {
		for _, reference := range file.References {
			if reference.Role == analysis.RoleImport || reference.Qualifier != "" {
				continue
			}
			if !imported.Wildcard && reference.Name == imported.LocalName() {
				used[imported.Path] = true
				break
			}
			if imported.Wildcard {
				for _, symbol := range i.resolveLocked(file, reference) {
					if symbol.Package == imported.Path || strings.HasPrefix(symbol.FQN, imported.Path+".") {
						used[imported.Path] = true
						break
					}
				}
			}
			if used[imported.Path] {
				break
			}
		}
	}
	return used
}

func importPrefixes(path string) []string {
	parts := strings.Split(strings.TrimSpace(path), ".")
	out := make([]string, 0, len(parts))
	for n, part := range parts {
		if part == "" {
			break
		}
		out = append(out, strings.Join(parts[:n+1], "."))
	}
	return out
}
