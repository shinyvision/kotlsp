package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// The scope engine decides whether a simple name is provably unresolved at a
// position. "Provably" is the whole difficulty: the index knowing of no binding
// is not evidence, because the index does not perform inference. The engine
// therefore argues the other way round. It takes every declaration of the name
// that exists anywhere in the index -- workspace, libraries, JDK -- and shows
// that none of them can be visible here. A declaration is visible through a
// small number of routes, all of which are enumerable:
//
//   - it is lexical in this file (a local, parameter, lambda parameter);
//   - it is top-level and reachable by package, import, or default import;
//   - it is a member of a type whose members are in scope: an enclosing
//     class and its whole hierarchy, a companion, an extension or context
//     receiver, an anonymous object's supertypes, or the receiver of an
//     enclosing lambda;
//   - it is imported by name, or its owner is imported with a star.
//
// Whenever any of those routes cannot be fully enumerated -- a supertype that
// does not resolve, a lambda whose callee is unknown, an anonymous function
// with a receiver -- the scope is incomplete and the engine says nothing.
type scopeSet struct {
	complete bool
	// types holds the IDs of every type whose declared members are visible.
	types map[string]bool
	// javaObject records that members of java.lang.Object are in scope, which
	// Kotlin does not always model under the same names.
	javaObject bool
	reason     string
}

func (s *scopeSet) incomplete(reason string) {
	if s.complete {
		s.reason = reason
	}
	s.complete = false
}

type span struct{ start, end int }

type anonymousSpan struct {
	span
	supertypes []string
}

type lambdaSpan struct {
	span
	receivers  []string
	known      bool
	classified bool
	reason     string
}

// unresolvedNameContext memoises the per-file structure the engine needs, so
// a file with hundreds of references pays for the text scans once.
type unresolvedNameContext struct {
	file          *analysis.ParsedFile
	text          string
	mask          []bool
	prepared      bool
	scopes        map[string]*scopeSet
	hierarchies   map[string]hierarchyResult
	lambdas       []lambdaSpan
	anonymous     []anonymousSpan
	anonymousFuns []span
	accounted     map[string]bool
	whenPresent   bool
	segments      map[string]bool
	nameStarts    map[int]bool
}

var declarationKeywords = map[string]bool{
	"object": true, "class": true, "interface": true, "fun": true, "val": true, "var": true,
	"typealias": true, "enum": true, "package": true, "import": true, "constructor": true, "record": true,
}

func (c *unresolvedNameContext) isDeclarationName(at int) bool {
	if c.nameStarts == nil {
		c.nameStarts = make(map[int]bool, len(c.file.Symbols))
		for _, symbol := range c.file.Symbols {
			if !symbol.Synthetic {
				c.nameStarts[symbol.NameStartByte] = true
			}
		}
	}
	if c.nameStarts[at] {
		return true
	}
	// A name introduced by a declaration keyword is declared, whatever the
	// parser recorded it as: `companion object A` is filed as 'Companion'.
	if c.text == "" {
		return false
	}
	end := skipBackCode(c.text, c.mask, at-1)
	if end < 0 || !isIdentifierByteFast(c.text[end]) {
		return false
	}
	start := end
	for start > 0 && isIdentifierByteFast(c.text[start-1]) {
		start--
	}
	return declarationKeywords[c.text[start:end+1]]
}

// isPackageSegment reports whether a name is a segment of any indexed package,
// which makes a bare occurrence of it a possible package reference.
func (c *unresolvedNameContext) isPackageSegment(i *Index, name string) bool {
	if c.segments == nil {
		c.segments = make(map[string]bool)
		for pkg := range i.byPackage {
			for _, segment := range strings.Split(pkg, ".") {
				c.segments[segment] = true
			}
		}
		for pkg := range i.packages {
			for _, segment := range strings.Split(pkg, ".") {
				c.segments[segment] = true
			}
		}
	}
	return c.segments[name]
}

type hierarchyResult struct {
	types    []analysis.Symbol
	complete bool
	reason   string
}

// resolveOneTypeLocked resolves a type name to one declaration. A library
// indexed from both its sources and its binary yields two symbols with one
// FQN; those are the same type and both are returned. Different FQNs are an
// ambiguity and fail.
func (i *Index) resolveOneTypeLocked(file *analysis.ParsedFile, typeName string) ([]analysis.Symbol, bool) {
	base, _ := splitInstantiatedType(typeName)
	if paren := strings.IndexByte(base, '('); paren >= 0 {
		base = base[:paren]
	}
	base = strings.TrimSpace(strings.TrimSuffix(base, "?"))
	if base == "" {
		return nil, false
	}
	resolved := i.resolveTypeSymbolsLocked(file, base)
	if len(resolved) == 0 {
		return nil, false
	}
	fqn := ""
	for _, symbol := range resolved {
		if symbol.Synthetic || symbol.Kind == analysis.KindTypeParameter || symbol.Kind == analysis.KindTypeAlias || symbol.FQN == "" {
			return nil, false
		}
		if fqn == "" {
			fqn = symbol.FQN
		} else if fqn != symbol.FQN {
			return nil, false
		}
	}
	return resolved, true
}

func newUnresolvedNameContext(file *analysis.ParsedFile) *unresolvedNameContext {
	return &unresolvedNameContext{file: file, scopes: map[string]*scopeSet{}, hierarchies: map[string]hierarchyResult{}, accounted: map[string]bool{}}
}

func (c *unresolvedNameContext) prepare(i *Index) {
	if c.prepared {
		return
	}
	c.prepared = true
	c.text = i.documentTextLocked(c.file.URI)
	c.mask = codeMask(c.text, c.file.Language == analysis.LanguageKotlin)
	c.whenPresent = strings.Contains(c.text, "when") || strings.Contains(c.text, "switch") || strings.Contains(c.text, "case")
	if c.file.Language == analysis.LanguageKotlin {
		c.lambdas = i.lambdaSpansLocked(c)
		c.anonymous = kotlinAnonymousObjects(c.text, c.mask)
		c.anonymousFuns = kotlinAnonymousReceiverFunctions(c.text, c.mask)
	} else {
		c.anonymous = javaAnonymousClasses(c.text, c.mask)
	}
}

// Names the compiler binds without any declaration the index could hold.
var scopeEngineSkips = map[string]bool{
	"it": true, "this": true, "super": true, "field": true, "Companion": true,
	"copy": true, "equals": true, "hashCode": true, "toString": true, "invoke": true,
	"values": true, "valueOf": true, "entries": true, "name": true, "ordinal": true,
	"getClass": true, "wait": true, "notify": true, "notifyAll": true, "clone": true, "finalize": true,
	"length": true, "class": true, "javaClass": true,
}

// nameProvablyUnresolvedLocked is the entry point for an unqualified read,
// write, or call whose name the resolver could not bind.
func (i *Index) nameProvablyUnresolvedLocked(c *unresolvedNameContext, ref analysis.Reference) bool {
	unresolved, _ := i.unresolvedVerdictLocked(c, ref)
	return unresolved
}

// unresolvedVerdictLocked is the engine proper. The reason is for tests and
// for explaining an abstention on a real project; it costs nothing.
func (i *Index) unresolvedVerdictLocked(c *unresolvedNameContext, ref analysis.Reference) (bool, string) {
	name := ref.Name
	if name == "" || scopeEngineSkips[name] || implicitNames[name] || strings.HasPrefix(name, "component") {
		return false, "name is bound by the language"
	}
	file := c.file
	for _, imported := range file.Imports {
		if imported.LocalName() == name || imported.Alias == name {
			return false, "an import declares the name"
		}
	}
	c.prepare(i)
	if c.text == "" {
		return false, "no text"
	}
	// The parser reports a member access continued on the next line
	// (`\n    .member(...)`) with an empty qualifier. What precedes the name
	// in the text is authoritative: a dot means this is not a bare name.
	if before := skipBackCode(c.text, c.mask, ref.StartByte-1); before >= 0 && (c.text[before] == '.' || c.text[before] == ':' || c.text[before] == '?') {
		return false, "qualified access"
	}
	if c.isPackageSegment(i, name) {
		return false, "the name is a package segment"
	}
	// The parser emits a reference for some declared names it records under
	// another name (a companion object's own name, say). A reference sitting
	// exactly on a declaration's name is that declaration, not a use.
	if c.isDeclarationName(ref.StartByte) {
		return false, "the reference is a declaration's own name"
	}
	if !c.occurrencesAccounted(name) {
		return false, "an occurrence of the name is not modelled by the parser"
	}
	scope := i.scopeAtLocked(c, ref)
	if scope == nil || !scope.complete {
		reason := "scope incomplete"
		if scope != nil && scope.reason != "" {
			reason += ": " + scope.reason
		}
		return false, reason
	}
	candidates := append([]string(nil), i.byName[name]...)
	if file.Language == analysis.LanguageKotlin {
		// A Java getter is visible to Kotlin under the property's name.
		title := strings.ToUpper(name[:1]) + name[1:]
		candidates = append(candidates, i.byName["get"+title]...)
		candidates = append(candidates, i.byName["is"+title]...)
		if ref.Role == analysis.RoleWrite {
			candidates = append(candidates, i.byName["set"+title]...)
		}
	}
	for _, id := range candidates {
		candidate := i.symbols[id]
		if candidate == nil {
			return false, "dangling symbol"
		}
		if i.candidatePossiblyVisibleLocked(c, scope, *candidate, ref) {
			return false, "possibly visible: " + candidate.FQN + " (" + string(candidate.URI) + ")"
		}
	}
	return true, ""
}

// candidatePossiblyVisibleLocked is deliberately generous: any route by which
// the declaration might be in scope keeps it.
func (i *Index) candidatePossiblyVisibleLocked(c *unresolvedNameContext, scope *scopeSet, candidate analysis.Symbol, ref analysis.Reference) bool {
	file := c.file
	if candidate.Synthetic && candidate.InteropLanguage != analysis.LanguageUnknown && candidate.InteropLanguage != file.Language {
		return false
	}
	// A local of this file may be in scope wherever it sits; the parser's
	// scopes are not trusted to decide that. A local of another file never is.
	if isLexicalSymbol(candidate) {
		return candidate.URI == file.URI
	}
	// Enum entries and sealed subclasses may be named bare in a `when` or
	// `switch` over their type; K2 also has context-sensitive resolution
	// behind a flag. Neither is modelled.
	if c.whenPresent && (candidate.Kind == analysis.KindEnumMember || analysis.IsTypeKind(candidate.Kind)) {
		return true
	}
	if candidate.Kind == analysis.KindPackage {
		return true
	}
	if candidate.ContainerID == "" {
		return i.topLevelVisibleLocked(file, candidate)
	}
	container := i.symbols[candidate.ContainerID]
	if container == nil {
		return true
	}
	if analysis.IsCallableKind(container.Kind) {
		// A declaration local to a function: a local class, a local function,
		// or a member of an anonymous object, which the parser files under the
		// enclosing callable. Visible somewhere in its own file, never elsewhere.
		return candidate.URI == file.URI
	}
	if !analysis.IsTypeKind(container.Kind) {
		return true
	}
	if scope.types[container.ID] {
		return true
	}
	if scope.javaObject && container.FQN == "java.lang.Object" {
		return true
	}
	for _, imported := range file.Imports {
		if imported.Wildcard {
			if imported.Path == container.FQN {
				return true
			}
			continue
		}
		if imported.Path == candidate.FQN || candidate.FQN != "" && imported.Path == container.FQN+"."+candidate.Name {
			return true
		}
	}
	// A nested type of an enclosing scope is named bare; a nested type of a
	// type in the same package or an imported type still needs qualification.
	if analysis.IsTypeKind(candidate.Kind) {
		return len(i.resolveTypeSymbolsLocked(file, candidate.Name)) > 0
	}
	return false
}

// topLevelVisibleLocked mirrors the language's rules for a declaration with
// no container: same package, explicit import, star import, default import.
func (i *Index) topLevelVisibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol) bool {
	if symbol.Package == "" && symbol.FQN == "" {
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
		if imported.Path == symbol.FQN {
			return true
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
	return false
}

// occurrencesAccounted checks that every appearance of the identifier in the
// file's code is either a reference the parser produced or a declared name.
// An appearance the parser did not model -- a binding form it does not know,
// a construct it mis-parsed -- could be a declaration, so it counts as one.
func (c *unresolvedNameContext) occurrencesAccounted(name string) bool {
	if accounted, seen := c.accounted[name]; seen {
		return accounted
	}
	positions := make(map[int]bool)
	for _, reference := range c.file.References {
		if reference.Name == name {
			positions[reference.StartByte] = true
		}
	}
	for _, symbol := range c.file.Symbols {
		if symbol.Name == name {
			positions[symbol.NameStartByte] = true
		}
	}
	accounted := true
	text := c.text
	for at := 0; at < len(text); {
		found := strings.Index(text[at:], name)
		if found < 0 {
			break
		}
		start := at + found
		end := start + len(name)
		at = end
		if start > 0 && isIdentifierByteFast(text[start-1]) || end < len(text) && isIdentifierByteFast(text[end]) {
			continue
		}
		if !c.mask[start] || positions[start] || inImportOrPackageLine(text, start) {
			continue
		}
		accounted = false
		break
	}
	c.accounted[name] = accounted
	return accounted
}

func inImportOrPackageLine(text string, at int) bool {
	lineStart := strings.LastIndexByte(text[:at], '\n') + 1
	line := strings.TrimSpace(text[lineStart:at])
	return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "package ")
}

// scopeAtLocked computes the set of types whose members are visible at the
// reference, or an incomplete scope when any part of it cannot be enumerated.
func (i *Index) scopeAtLocked(c *unresolvedNameContext, ref analysis.Reference) *scopeSet {
	at := ref.StartByte
	var keyParts []string
	keyParts = append(keyParts, ref.ContainerID)
	for _, lambda := range c.lambdas {
		if lambda.start < at && at < lambda.end {
			keyParts = append(keyParts, "l"+itoa(lambda.start))
		}
	}
	for _, anonymous := range c.anonymous {
		if anonymous.start < at && at < anonymous.end {
			keyParts = append(keyParts, "o"+itoa(anonymous.start))
		}
	}
	key := strings.Join(keyParts, "|")
	if scope, ok := c.scopes[key]; ok {
		return scope
	}
	scope := &scopeSet{complete: true, types: map[string]bool{}}
	c.scopes[key] = scope
	file := c.file
	add := func(symbol analysis.Symbol) {
		hierarchy := i.completeHierarchyLocked(c, symbol)
		if !hierarchy.complete {
			scope.incomplete("hierarchy of " + symbol.Name + ": " + hierarchy.reason)
			return
		}
		for _, member := range hierarchy.types {
			scope.types[member.ID] = true
			if member.Language == analysis.LanguageJava {
				scope.javaObject = true
			}
			// Companion members are visible bare inside the class and its
			// subclasses.
			for _, id := range i.byContainerName[member.Name] {
				nested := i.symbols[id]
				if nested == nil || nested.ContainerID != member.ID || nested.Kind != analysis.KindObject {
					continue
				}
				companion := i.completeHierarchyLocked(c, *nested)
				if !companion.complete {
					scope.incomplete("companion of " + member.Name + ": " + companion.reason)
					return
				}
				for _, owner := range companion.types {
					scope.types[owner.ID] = true
				}
			}
		}
	}
	addTypeName := func(typeName string) {
		typeName = strings.TrimSpace(typeName)
		if typeName == "" {
			scope.incomplete("empty receiver type")
			return
		}
		resolved, ok := i.resolveOneTypeLocked(file, typeName)
		if !ok {
			scope.incomplete("receiver type " + typeName + " does not resolve to one type")
			return
		}
		for _, symbol := range resolved {
			add(symbol)
		}
	}
	for containerID := ref.ContainerID; containerID != ""; {
		container, ok := i.symbols[containerID]
		if !ok {
			scope.incomplete("container missing")
			break
		}
		if analysis.IsTypeKind(container.Kind) {
			add(*container)
		} else if analysis.IsCallableKind(container.Kind) || container.Kind == analysis.KindProperty {
			if container.ReceiverType != "" {
				addTypeName(container.ReceiverType)
			}
		}
		containerID = container.ContainerID
	}
	if file.Language == analysis.LanguageKotlin {
		for _, contextType := range i.enclosingContextReceiverTypesLocked(file, at) {
			addTypeName(contextType)
		}
		if strings.Contains(c.text, "context(") {
			// Context parameters and receivers are modelled loosely; the
			// receiver types above may not be the whole story.
			scope.incomplete("file uses context receivers")
		}
		for _, function := range c.anonymousFuns {
			if function.start <= at && at <= function.end {
				scope.incomplete("inside an anonymous function with a receiver")
			}
		}
		for index := range c.lambdas {
			lambda := &c.lambdas[index]
			if lambda.start < at && at < lambda.end {
				if !lambda.classified {
					lambda.classified = true
					lambda.receivers, lambda.known, lambda.reason = i.lambdaReceiversLocked(c, lambda.start, scope)
				}
				if !lambda.known {
					scope.incomplete("lambda at " + itoa(lambda.start) + ": " + lambda.reason)
					continue
				}
				for _, receiver := range lambda.receivers {
					addTypeName(receiver)
				}
			}
		}
	}
	for _, anonymous := range c.anonymous {
		if anonymous.start < at && at < anonymous.end {
			if len(anonymous.supertypes) == 0 {
				continue
			}
			for _, supertype := range anonymous.supertypes {
				addTypeName(supertype)
			}
		}
	}
	return scope
}

func (i *Index) enclosingCallableLocked(file *analysis.ParsedFile, at int) *analysis.Symbol {
	var found *analysis.Symbol
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || !analysis.IsCallableKind(symbol.Kind) || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if found == nil || symbol.StartByte >= found.StartByte && symbol.EndByte <= found.EndByte {
			found = symbol
		}
	}
	return found
}

// completeHierarchyLocked returns a type with all of its supertypes, or an
// incomplete result when any supertype fails to resolve to exactly one type
// whose declaration the index has parsed. Library and Java types are allowed:
// their members are indexed from sources or from rendered class files.
func (i *Index) completeHierarchyLocked(c *unresolvedNameContext, owner analysis.Symbol) hierarchyResult {
	if cached, ok := c.hierarchies[owner.ID]; ok {
		return cached
	}
	// Guard against cycles while computing.
	c.hierarchies[owner.ID] = hierarchyResult{}
	result := hierarchyResult{complete: true}
	seen := map[string]bool{owner.ID: true}
	queue := []analysis.Symbol{owner}
	result.types = append(result.types, owner)
	implicit := func(symbol analysis.Symbol) []string {
		var out []string
		if symbol.Language == analysis.LanguageKotlin {
			out = append(out, "kotlin.Any")
			if symbol.Kind == analysis.KindEnum {
				out = append(out, "kotlin.Enum")
			}
		} else if symbol.Language == analysis.LanguageJava {
			out = append(out, "java.lang.Object")
			if symbol.Kind == analysis.KindEnum {
				out = append(out, "java.lang.Enum")
			}
			if symbol.Kind == analysis.KindRecord {
				out = append(out, "java.lang.Record")
			}
		}
		return out
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.Kind == analysis.KindTypeParameter || current.Kind == analysis.KindTypeAlias {
			result.complete, result.reason = false, current.Name+" is a type parameter or alias"
			break
		}
		file := i.files[current.URI]
		if file == nil {
			result.complete, result.reason = false, "no parsed file for "+current.FQN
			break
		}
		names := append([]string(nil), current.Supertypes...)
		names = append(names, implicit(current)...)
		for _, supertype := range names {
			// Implicit supertypes are always qualified; if even they do not
			// resolve, the standard library is not indexed.
			resolved, ok := i.resolveOneTypeLocked(file, supertype)
			if !ok {
				result.complete, result.reason = false, "supertype "+supertype+" of "+current.Name+" does not resolve to one type"
				break
			}
			for _, symbol := range resolved {
				if !seen[symbol.ID] {
					seen[symbol.ID] = true
					result.types = append(result.types, symbol)
					queue = append(queue, symbol)
				}
			}
		}
		if !result.complete {
			break
		}
	}
	c.hierarchies[owner.ID] = result
	return result
}

// lambdaSpansLocked finds every lambda literal in the file from the parameter
// symbols the parser gives each one, and classifies its receiver.
func (i *Index) lambdaSpansLocked(c *unresolvedNameContext) []lambdaSpan {
	text, mask := c.text, c.mask
	seen := map[int]bool{}
	var out []lambdaSpan
	for _, symbol := range c.file.Symbols {
		if symbol.Kind != analysis.KindParameter && symbol.Kind != analysis.KindVariable {
			continue
		}
		open := -1
		if symbol.Name == "it" && symbol.StartByte < len(text) && text[symbol.StartByte] == '{' {
			open = symbol.StartByte
		} else {
			at := symbol.StartByte - 1
			for at >= 0 && (text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r' || text[at] == '(') {
				at--
			}
			if at >= 0 && text[at] == '{' {
				open = at
			}
		}
		if open < 0 || seen[open] {
			continue
		}
		seen[open] = true
		end := matchingBrace(text, mask, open)
		if end < 0 {
			continue
		}
		out = append(out, lambdaSpan{span: span{open, end}})
	}
	return out
}

// lambdaReceiversLocked works out what a lambda's implicit receiver could be
// from the call it is passed to. It returns known=false for any shape it does
// not understand, which makes every name inside the lambda unreportable.
func (i *Index) lambdaReceiversLocked(c *unresolvedNameContext, open int, scope *scopeSet) ([]string, bool, string) {
	text, mask := c.text, c.mask
	at := skipBackCode(text, mask, open-1)
	if at < 0 {
		return nil, false, "nothing precedes the lambda"
	}
	var arguments []string
	var argumentOffsets []int
	argumentsKnown := true
	if text[at] == ')' {
		parenOpen := matchingParenBackward(text, mask, at)
		if parenOpen < 0 {
			return nil, false, "unbalanced arguments"
		}
		offset := parenOpen + 1
		for _, argument := range splitTopLevel(text[parenOpen+1:at], ',') {
			leading := len(argument) - len(strings.TrimLeft(argument, " \t\r\n"))
			arguments = append(arguments, strings.TrimSpace(argument))
			argumentOffsets = append(argumentOffsets, offset+leading)
			offset += len(argument) + 1
		}
		at = skipBackCode(text, mask, parenOpen-1)
		if at < 0 {
			return nil, false, "nothing precedes the arguments"
		}
	} else {
		argumentsKnown = false
	}
	if !isIdentifierByteFast(text[at]) {
		return nil, false, "not a call with a trailing lambda"
	}
	nameEnd := at + 1
	nameStart := at
	for nameStart > 0 && isIdentifierByteFast(text[nameStart-1]) {
		nameStart--
	}
	callee := text[nameStart:nameEnd]
	if callee == "" || callee[0] >= '0' && callee[0] <= '9' {
		return nil, false, "no callee"
	}
	if isKeyword(callee) {
		return nil, false, "the block follows the keyword " + callee
	}
	receiverExpression := ""
	receiverOffset := 0
	hasReceiver := false
	before := skipBackCode(text, mask, nameStart-1)
	if before >= 0 && text[before] == '.' {
		hasReceiver = true
		exprEnd := before
		if before > 0 && text[before-1] == '?' {
			exprEnd = before - 1
		}
		exprStart := expressionStartBackward(text, mask, exprEnd)
		if exprStart < 0 {
			return nil, false, "receiver expression of " + callee + " not understood"
		}
		receiverExpression = strings.TrimSpace(text[exprStart:exprEnd])
		receiverOffset = exprStart
	}
	// A local or parameter of this name is a value, and a value with a
	// trailing lambda is an invoke-operator call whose receiver is unknown.
	for _, symbol := range i.fileSymbolsByName[c.file.URI][callee] {
		if isLexicalSymbol(*symbol) {
			return nil, false, "a local value named " + callee + " may be invoked through an invoke operator"
		}
	}
	candidates := i.byName[callee]
	if len(candidates) == 0 {
		return nil, false, "callee " + callee + " is unknown"
	}
	var receivers []string
	for _, id := range candidates {
		candidate := i.symbols[id]
		if candidate == nil {
			return nil, false, "dangling symbol"
		}
		if !analysis.IsCallableKind(candidate.Kind) && !analysis.IsTypeKind(candidate.Kind) {
			// A value invoked with a trailing lambda goes through an `invoke`
			// operator -- a member, or an imported extension such as Spring
			// Security's `HttpSecurity.invoke(HttpSecurityDsl.() -> Unit)` --
			// and the lambda's receiver is whatever that operator declares.
			if isLexicalSymbol(*candidate) && candidate.URI == c.file.URI || !isLexicalSymbol(*candidate) && i.callablePossiblyVisibleLocked(c, scope, *candidate) {
				return nil, false, "a value named " + callee + " may be invoked through an invoke operator"
			}
			continue
		}
		if !i.callablePossiblyVisibleLocked(c, scope, *candidate) {
			continue
		}
		parameters := candidate.Parameters
		if analysis.IsTypeKind(candidate.Kind) && len(parameters) == 0 {
			continue
		}
		for _, parameter := range parameters {
			receiver, ok := i.functionTypeReceiverLocked(candidate, parameter.Type)
			if !ok {
				return nil, false, "parameter " + parameter.Name + " of " + callee + " has type " + parameter.Type + ", which may be a function type with a receiver"
			}
			if receiver == "" {
				continue
			}
			if containsString(candidate.TypeParameters, receiver) {
				bound := ""
				if hasReceiver {
					typ, ok := i.simpleExpressionTypeLocked(c, receiverExpression, receiverOffset, scope)
					if !ok {
						return nil, false, "receiver expression " + receiverExpression + " has no evident type"
					}
					bound = typ
				}
				for index, other := range parameters {
					if strings.TrimSpace(other.Type) != receiver {
						continue
					}
					if !argumentsKnown || index >= len(arguments) || strings.Contains(arguments[index], "=") {
						return nil, false, "argument binding " + receiver + " of " + callee + " is not evident"
					}
					typ, ok := i.simpleExpressionTypeLocked(c, arguments[index], argumentOffsets[index], scope)
					if !ok {
						return nil, false, "argument " + arguments[index] + " has no evident type"
					}
					bound = typ
				}
				if bound != "" {
					receivers = append(receivers, bound)
				}
				continue
			}
			receivers = append(receivers, receiver)
		}
	}
	return receivers, true, ""
}

// callablePossiblyVisibleLocked asks whether a callable could be the one a
// call binds to here: a member of a type in scope, or a visible top-level.
func (i *Index) callablePossiblyVisibleLocked(c *unresolvedNameContext, scope *scopeSet, candidate analysis.Symbol) bool {
	if candidate.Synthetic && candidate.InteropLanguage != analysis.LanguageUnknown && candidate.InteropLanguage != c.file.Language {
		return false
	}
	if candidate.ContainerID == "" {
		return i.topLevelVisibleLocked(c.file, candidate)
	}
	container := i.symbols[candidate.ContainerID]
	if container == nil {
		return true
	}
	if analysis.IsCallableKind(container.Kind) {
		return candidate.URI == c.file.URI
	}
	if scope.types[container.ID] || scope.types[candidate.ID] || scope.javaObject && container.FQN == "java.lang.Object" {
		return true
	}
	// A constructor is reached through its class's name; a nested class or
	// object through the scope of its owner.
	if candidate.Kind == analysis.KindConstructor || analysis.IsTypeKind(candidate.Kind) {
		return len(i.resolveTypeSymbolsLocked(c.file, candidate.Name)) > 0 || scope.types[container.ID]
	}
	for _, imported := range c.file.Imports {
		if imported.Wildcard && imported.Path == container.FQN || !imported.Wildcard && imported.Path == container.FQN+"."+candidate.Name {
			return true
		}
	}
	return false
}

// functionTypeReceiverLocked returns the receiver of a parameter's type when
// it is a function type, "" when the parameter can take a lambda without a
// receiver, and ok=false when it cannot tell.
func (i *Index) functionTypeReceiverLocked(callable *analysis.Symbol, parameterType string) (string, bool) {
	parameterType = strings.TrimSpace(parameterType)
	if parameterType == "" {
		return "", false
	}
	if strings.Contains(parameterType, "->") {
		receiver := kotlinFunctionReceiverType(parameterType)
		if receiver == "" && strings.Contains(parameterType, ".(") {
			return "", false
		}
		base, _ := splitInstantiatedType(receiver)
		return strings.TrimSpace(base), true
	}
	base, _ := splitInstantiatedType(parameterType)
	base = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(base, "vararg "), "?"))
	if containsString(callable.TypeParameters, base) {
		return "", true
	}
	// A type parameter of the owning class (`Function<T, R>.apply(T)`) binds
	// through the receiver's type arguments; the caller checks those for a
	// function type before trusting this.
	if owner := i.symbols[callable.ContainerID]; owner != nil && containsString(owner.TypeParameters, base) {
		return "", true
	}
	file := i.files[callable.URI]
	if file == nil {
		return "", false
	}
	resolved := i.resolveTypeSymbolsLocked(file, base)
	if len(resolved) == 0 {
		return "", false
	}
	for _, symbol := range resolved {
		if symbol.Kind == analysis.KindTypeAlias || symbol.Kind == analysis.KindTypeParameter {
			return "", false
		}
	}
	return "", true
}

// simpleExpressionTypeLocked types the few expression shapes that need no
// inference: a constructor call of a resolvable class, a literal, or a name
// bound to a declaration with an explicit type.
func (i *Index) simpleExpressionTypeLocked(c *unresolvedNameContext, expression string, at int, scope *scopeSet) (string, bool) {
	expression = strings.TrimSpace(expression)
	if expression == "" || expression == "this" {
		return "", false
	}
	if kind := literalKind(expression); kind != "" {
		return kind, true
	}
	if paren := strings.IndexByte(expression, '('); paren > 0 && expression[len(expression)-1] == ')' {
		name := expression[:paren]
		if !isSimpleIdentifier(name) {
			return "", false
		}
		// A function of the same name that is callable here would win over
		// the constructor, and its return type is not evident.
		for _, id := range i.byName[name] {
			symbol := i.symbols[id]
			if symbol == nil || analysis.IsTypeKind(symbol.Kind) || symbol.Kind == analysis.KindConstructor {
				continue
			}
			if i.callablePossiblyVisibleLocked(c, scope, *symbol) {
				return "", false
			}
		}
		resolved, ok := i.resolveOneTypeLocked(c.file, name)
		if !ok || !isKotlinClassLike(resolved[0].Kind) && resolved[0].Kind != analysis.KindRecord {
			return "", false
		}
		return name, true
	}
	if !isSimpleIdentifier(expression) {
		return "", false
	}
	// The innermost local or parameter of that name in scope here, else the
	// resolver's answer for a property.
	var local *analysis.Symbol
	for _, symbol := range i.fileSymbolsByName[c.file.URI][expression] {
		if !isLexicalSymbol(*symbol) || symbol.StartByte > at || !symbolInScopeAt(*symbol, at) {
			continue
		}
		if local == nil || symbol.StartByte > local.StartByte {
			local = symbol
		}
	}
	var resolved []analysis.Symbol
	if local != nil {
		resolved = []analysis.Symbol{*local}
	} else {
		resolved = i.resolveLocked(c.file, analysis.Reference{Name: expression, URI: c.file.URI, StartByte: at, EndByte: at + len(expression), ContainerID: i.containerIDAtLocked(c.file, at), Role: analysis.RoleRead, Arity: -1})
	}
	if len(resolved) != 1 {
		return "", false
	}
	typ := strings.TrimSpace(resolved[0].Type)
	if typ == "" || strings.Contains(typ, "->") || strings.HasSuffix(typ, "?") || typ == "var" {
		return "", false
	}
	return typ, true
}

func (i *Index) containerIDAtLocked(file *analysis.ParsedFile, at int) string {
	var found *analysis.Symbol
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || !isContainerKind(symbol.Kind) || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if found == nil || symbol.StartByte >= found.StartByte && symbol.EndByte <= found.EndByte {
			found = symbol
		}
	}
	if found == nil {
		return ""
	}
	return found.ID
}

func isContainerKind(kind analysis.SymbolKind) bool {
	return analysis.IsTypeKind(kind) || analysis.IsCallableKind(kind) || kind == analysis.KindProperty
}

func isSimpleIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isIdentifierByteFast(value[index]) {
			return false
		}
	}
	return !(value[0] >= '0' && value[0] <= '9')
}

var kotlinKeywords = map[string]bool{
	"if": true, "else": true, "when": true, "for": true, "while": true, "do": true, "try": true, "catch": true, "finally": true,
	"return": true, "throw": true, "fun": true, "val": true, "var": true, "class": true, "object": true, "interface": true,
	"in": true, "is": true, "as": true, "null": true, "true": true, "false": true, "this": true, "super": true, "typealias": true,
	"package": true, "import": true, "break": true, "continue": true, "init": true, "constructor": true, "by": true, "get": true, "set": true,
	"where": true, "new": true, "switch": true, "case": true, "default": true, "synchronized": true, "static": true, "public": true, "private": true,
}

func isKeyword(value string) bool { return kotlinKeywords[value] }

// kotlinAnonymousObjects finds `object : A, B { ... }` expressions and their
// supertypes. A bare `object { }` has no supertypes and adds nothing.
func kotlinAnonymousObjects(text string, mask []bool) []anonymousSpan {
	var out []anonymousSpan
	for _, at := range keywordPositions(text, mask, "object") {
		next := skipForwardCode(text, mask, at+len("object"))
		if next < 0 {
			continue
		}
		var supertypes []string
		open := -1
		if text[next] == '{' {
			open = next
		} else if text[next] == ':' {
			brace := indexTopLevel(text, mask, next+1, '{')
			if brace < 0 {
				continue
			}
			supertypes = supertypeNames(text[next+1 : brace])
			open = brace
		} else {
			continue
		}
		end := matchingBrace(text, mask, open)
		if end < 0 {
			continue
		}
		out = append(out, anonymousSpan{span: span{open, end}, supertypes: supertypes})
	}
	return out
}

// javaAnonymousClasses finds `new T(...) { ... }` bodies.
func javaAnonymousClasses(text string, mask []bool) []anonymousSpan {
	var out []anonymousSpan
	for _, at := range keywordPositions(text, mask, "new") {
		next := skipForwardCode(text, mask, at+len("new"))
		if next < 0 {
			continue
		}
		paren := indexTopLevel(text, mask, next, '(')
		if paren < 0 {
			continue
		}
		typeName := strings.TrimSpace(text[next:paren])
		if typeName == "" || strings.ContainsAny(typeName, "[]{};=") {
			continue
		}
		closing := matchingParen(text, paren)
		if closing < 0 {
			continue
		}
		open := skipForwardCode(text, mask, closing+1)
		if open < 0 || text[open] != '{' {
			continue
		}
		end := matchingBrace(text, mask, open)
		if end < 0 {
			continue
		}
		out = append(out, anonymousSpan{span: span{open, end}, supertypes: []string{typeName}})
	}
	return out
}

// kotlinAnonymousReceiverFunctions finds `fun T.(...) { }` expressions, whose
// bodies see T's members through a receiver the parser does not record.
func kotlinAnonymousReceiverFunctions(text string, mask []bool) []span {
	var out []span
	for _, at := range keywordPositions(text, mask, "fun") {
		next := skipForwardCode(text, mask, at+len("fun"))
		if next < 0 || text[next] == '(' {
			continue
		}
		paren := indexTopLevel(text, mask, next, '(')
		if paren < 0 {
			continue
		}
		head := strings.TrimSpace(text[next:paren])
		if !strings.HasSuffix(head, ".") {
			continue
		}
		closing := matchingParen(text, paren)
		if closing < 0 {
			continue
		}
		open := indexTopLevel(text, mask, closing+1, '{')
		end := len(text)
		if open >= 0 {
			if body := matchingBrace(text, mask, open); body >= 0 {
				end = body
			}
		}
		out = append(out, span{at, end})
	}
	return out
}

func supertypeNames(list string) []string {
	var out []string
	for _, part := range splitTopLevel(list, ',') {
		base, _ := splitInstantiatedType(strings.TrimSpace(part))
		if paren := strings.IndexByte(base, '('); paren >= 0 {
			base = base[:paren]
		}
		base = strings.TrimSpace(base)
		if by := strings.Index(base, " by "); by >= 0 {
			base = strings.TrimSpace(base[:by])
		}
		if base != "" {
			out = append(out, base)
		}
	}
	return out
}

// keywordPositions returns every position where the keyword appears as a whole
// word in code.
func keywordPositions(text string, mask []bool, keyword string) []int {
	var out []int
	for at := 0; at < len(text); {
		found := strings.Index(text[at:], keyword)
		if found < 0 {
			break
		}
		start := at + found
		end := start + len(keyword)
		at = end
		if start > 0 && isIdentifierByteFast(text[start-1]) || end < len(text) && isIdentifierByteFast(text[end]) || !mask[start] {
			continue
		}
		out = append(out, start)
	}
	return out
}

// skipForwardCode returns the first code byte at or after at that is not
// whitespace, or -1.
func skipForwardCode(text string, mask []bool, at int) int {
	for at < len(text) {
		if !mask[at] || text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r' {
			at++
			continue
		}
		return at
	}
	return -1
}

// skipBackCode returns the last code byte at or before at that is not
// whitespace, or -1.
func skipBackCode(text string, mask []bool, at int) int {
	for at >= 0 {
		if at >= len(text) || !mask[at] || text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r' {
			at--
			continue
		}
		return at
	}
	return -1
}

// indexTopLevel finds the next occurrence of want at nesting depth zero.
func indexTopLevel(text string, mask []bool, from int, want byte) int {
	depth := 0
	for at := from; at < len(text); at++ {
		if !mask[at] {
			continue
		}
		value := text[at]
		if value == want && depth == 0 {
			return at
		}
		switch value {
		case '(', '[', '<':
			depth++
		case ')', ']', '>':
			if depth > 0 {
				depth--
			}
		case '{', '}', ';':
			if value != want {
				return -1
			}
		}
	}
	return -1
}

func matchingBrace(text string, mask []bool, open int) int {
	depth := 0
	for at := open; at < len(text); at++ {
		if !mask[at] {
			continue
		}
		switch text[at] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return at
			}
		}
	}
	return -1
}

func matchingParenBackward(text string, mask []bool, closing int) int {
	depth := 0
	for at := closing; at >= 0; at-- {
		if !mask[at] {
			continue
		}
		switch text[at] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return at
			}
		}
	}
	return -1
}

// expressionStartBackward finds where the balanced expression ending just
// before end begins: identifiers, dots, and bracketed groups.
func expressionStartBackward(text string, mask []bool, end int) int {
	at := end - 1
	for at >= 0 {
		if !mask[at] {
			return -1
		}
		value := text[at]
		switch {
		case isIdentifierByteFast(value):
			at--
		case value == ')' || value == ']':
			open := -1
			if value == ')' {
				open = matchingParenBackward(text, mask, at)
			} else {
				open = matchingBracketBackward(text, mask, at)
			}
			if open < 0 {
				return -1
			}
			at = open - 1
		case value == '.':
			at--
		case value == '?' && at+1 < len(text) && text[at+1] == '.':
			at--
		case value == '"':
			open := stringStartBackward(text, at)
			if open < 0 {
				return -1
			}
			at = open - 1
		default:
			return at + 1
		}
	}
	return 0
}

func matchingBracketBackward(text string, mask []bool, closing int) int {
	depth := 0
	for at := closing; at >= 0; at-- {
		if !mask[at] {
			continue
		}
		switch text[at] {
		case ']':
			depth++
		case '[':
			depth--
			if depth == 0 {
				return at
			}
		}
	}
	return -1
}

func stringStartBackward(text string, closing int) int {
	for at := closing - 1; at >= 0; at-- {
		if text[at] == '"' && (at == 0 || text[at-1] != '\\') {
			return at
		}
		if text[at] == '\n' {
			return -1
		}
	}
	return -1
}

// splitTopLevel splits on a separator outside brackets, braces, and strings.
func splitTopLevel(list string, separator byte) []string {
	var out []string
	depth, start := 0, 0
	inString := false
	for at := 0; at < len(list); at++ {
		value := list[at]
		if inString {
			if value == '\\' {
				at++
			} else if value == '"' {
				inString = false
			}
			continue
		}
		switch value {
		case '"':
			inString = true
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		default:
			if value == separator && depth == 0 {
				out = append(out, list[start:at])
				start = at + 1
			}
		}
	}
	if strings.TrimSpace(list[start:]) != "" || len(out) > 0 {
		out = append(out, list[start:])
	}
	return out
}

// codeMask marks every byte that is code: outside comments and outside string
// and character literals. Inside a Kotlin string, a template expression is
// code again, and a `$name` template names an identifier that is code too.
func codeMask(text string, kotlin bool) []bool {
	mask := make([]bool, len(text))
	type frame struct {
		kind  byte // '"' for a string, 't' for a triple-quoted string, '{' for a template block
		depth int
	}
	var stack []frame
	for at := 0; at < len(text); at++ {
		value := text[at]
		if len(stack) > 0 && stack[len(stack)-1].kind != '{' {
			top := &stack[len(stack)-1]
			if value == '\\' && top.kind == '"' {
				at++
				continue
			}
			if top.kind == '"' && (value == '"' || value == '\n') {
				stack = stack[:len(stack)-1]
				continue
			}
			if top.kind == 't' && value == '"' && at+2 < len(text) && text[at+1] == '"' && text[at+2] == '"' {
				stack = stack[:len(stack)-1]
				at += 2
				continue
			}
			if kotlin && value == '$' && at+1 < len(text) {
				if text[at+1] == '{' {
					stack = append(stack, frame{kind: '{'})
					at++
					mask[at] = true
					continue
				}
				if isIdentifierByteFast(text[at+1]) && !(text[at+1] >= '0' && text[at+1] <= '9') {
					end := at + 1
					for end < len(text) && isIdentifierByteFast(text[end]) {
						mask[end] = true
						end++
					}
					at = end - 1
				}
			}
			continue
		}
		// Code, possibly inside a template block.
		if value == '/' && at+1 < len(text) && text[at+1] == '/' {
			for at < len(text) && text[at] != '\n' {
				at++
			}
			continue
		}
		if value == '/' && at+1 < len(text) && text[at+1] == '*' {
			depth := 1
			at += 2
			for at < len(text) && depth > 0 {
				if kotlin && text[at] == '/' && at+1 < len(text) && text[at+1] == '*' {
					depth++
					at += 2
					continue
				}
				if text[at] == '*' && at+1 < len(text) && text[at+1] == '/' {
					depth--
					at += 2
					continue
				}
				at++
			}
			at--
			continue
		}
		if value == '"' {
			if at+2 < len(text) && text[at+1] == '"' && text[at+2] == '"' {
				stack = append(stack, frame{kind: 't'})
				at += 2
			} else {
				stack = append(stack, frame{kind: '"'})
			}
			continue
		}
		if value == '\'' {
			end := at + 1
			for end < len(text) && text[end] != '\'' && text[end] != '\n' {
				if text[end] == '\\' {
					end++
				}
				end++
			}
			at = end
			continue
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if value == '{' {
				top.depth++
			} else if value == '}' {
				if top.depth == 0 {
					mask[at] = true
					stack = stack[:len(stack)-1]
					continue
				}
				top.depth--
			}
		}
		mask[at] = true
	}
	return mask
}
