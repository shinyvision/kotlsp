package index

import (
	"regexp"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// The predictive rules share one idea: a literal has a type the compiler will
// name in exactly one way, and a declared type that is one of the language's
// own builtins is compared against it. Everything here stays within what can be
// read off the text with certainty; anything needing inference is not attempted.

var (
	intLiteral     = regexp.MustCompile(`^[0-9]+$`)
	hexLiteral     = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)
	binaryLiteral  = regexp.MustCompile(`^0[bB][01]+$`)
	decimalLiteral = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

// literalKind names the type Kotlin gives a literal, in the compiler's own
// rendering, or "" when the text is not a plain literal. Unsigned literals are
// deliberately unnamed: their types are not in the comparison set.
func literalKind(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	switch text[0] {
	case '"':
		if len(text) >= 2 && text[len(text)-1] == '"' {
			return "String"
		}
		return ""
	case '\'':
		if len(text) >= 3 && text[len(text)-1] == '\'' {
			return "Char"
		}
		return ""
	}
	if text == "true" || text == "false" {
		return "Boolean"
	}
	number := strings.ReplaceAll(strings.TrimPrefix(text, "-"), "_", "")
	if number == "" {
		return ""
	}
	lower := strings.ToLower(number)
	if strings.HasSuffix(lower, "u") || strings.HasSuffix(lower, "ul") {
		return ""
	}
	if strings.HasSuffix(number, "L") {
		body := number[:len(number)-1]
		if intLiteral.MatchString(body) || hexLiteral.MatchString(body) || binaryLiteral.MatchString(body) {
			return "Long"
		}
		return ""
	}
	if hexLiteral.MatchString(number) || binaryLiteral.MatchString(number) {
		return "Int"
	}
	if strings.HasSuffix(lower, "f") {
		if decimalLiteral.MatchString(number[:len(number)-1]) {
			return "Float"
		}
		return ""
	}
	if intLiteral.MatchString(number) {
		return "Int"
	}
	if decimalLiteral.MatchString(number) {
		return "Double"
	}
	return ""
}

// literalAcceptedBy reports whether a literal of one kind may initialise a
// declaration of the given builtin type. The only conversion Kotlin performs is
// an integer literal widening to Long.
func literalAcceptedBy(expected, actual string) bool {
	if actual == "" || expected == actual {
		return true
	}
	return expected == "Long" && actual == "Int"
}

var comparableBuiltins = map[string]bool{
	"String": true, "Int": true, "Long": true, "Double": true, "Float": true, "Char": true, "Boolean": true,
}

// builtinExpectedTypeLocked returns the builtin a declared type denotes, in the
// compiler's rendering, or "" when the declaration is anything else: nullable,
// generic, qualified beyond kotlin., a user type of the same simple name, or a
// name the index cannot place because the standard library is not indexed.
func (i *Index) builtinExpectedTypeLocked(file *analysis.ParsedFile, declared string) string {
	name := strings.TrimSpace(declared)
	if name == "" || strings.HasSuffix(name, "?") || strings.ContainsAny(name, "<>[]()") {
		return ""
	}
	name = strings.TrimPrefix(name, "kotlin.")
	if strings.Contains(name, ".") || !comparableBuiltins[name] {
		return ""
	}
	resolved := i.resolveTypeSymbolsLocked(file, name)
	if len(resolved) == 0 {
		return ""
	}
	for _, symbol := range resolved {
		if symbol.FQN != "kotlin."+name {
			return ""
		}
	}
	return name
}

func (i *Index) documentLocked(uri protocol.URI) *textdoc.Document {
	if document := i.docs[uri]; document != nil {
		return document
	}
	if document := i.indexedDocs[uri]; document != nil {
		return document
	}
	return i.libraryDocs[uri]
}

func declarationText(text string, symbol *analysis.Symbol) string {
	if symbol.StartByte < 0 || symbol.EndByte > len(text) || symbol.StartByte >= symbol.EndByte {
		return ""
	}
	return text[symbol.StartByte:symbol.EndByte]
}

// initializerSpan locates the expression after the '=' of a declaration.
func initializerSpan(text string, symbol *analysis.Symbol) (int, int, bool) {
	from, limit := symbol.NameEndByte, symbol.EndByte
	if from < 0 || limit > len(text) || from >= limit {
		return 0, 0, false
	}
	eq := strings.IndexByte(text[from:limit], '=')
	if eq < 0 {
		return 0, 0, false
	}
	start := from + eq + 1
	for start < limit && (text[start] == ' ' || text[start] == '\t' || text[start] == '\n' || text[start] == '\r') {
		start++
	}
	end := limit
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\n' || text[end-1] == '\r' || text[end-1] == ';') {
		end--
	}
	if start >= end {
		return 0, 0, false
	}
	return start, end, true
}

// matchingParen returns the index of the ')' closing the '(' at open.
func matchingParen(text string, open int) int {
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

// functionBodyText returns what follows a function's parameter list: its
// return type, then either an expression body after '=' or a block. The bool
// reports whether the declaration has a body at all.
func functionTail(text string, symbol *analysis.Symbol) (string, bool) {
	declaration := declarationText(text, symbol)
	if declaration == "" {
		return "", false
	}
	nameOffset := symbol.NameEndByte - symbol.StartByte
	if nameOffset < 0 || nameOffset > len(declaration) {
		return "", false
	}
	open := strings.IndexByte(declaration[nameOffset:], '(')
	if open < 0 {
		return "", false
	}
	closing := matchingParen(declaration, nameOffset+open)
	if closing < 0 {
		return "", false
	}
	tail := declaration[closing+1:]
	return tail, strings.ContainsAny(tail, "{=")
}

// propertyHasBodyOrAccessor reports whether a property declaration carries an
// initialiser, a delegate, or an accessor -- anything that supplies its value.
func propertyHasBodyOrAccessor(declaration string) bool {
	if strings.Contains(declaration, "=") {
		return true
	}
	for _, marker := range []string{" by ", "\tby ", "get(", "get ", "set(", "set "} {
		if strings.Contains(declaration, marker) {
			return true
		}
	}
	return strings.Contains(declaration, "\nget") || strings.Contains(declaration, "\nset")
}

func isKotlinClassLike(kind analysis.SymbolKind) bool {
	return kind == analysis.KindClass || kind == analysis.KindInterface || kind == analysis.KindObject || kind == analysis.KindEnum || kind == analysis.KindAnnotation
}

// typeMembersLocked lists the declared members of one type.
func (i *Index) typeMembersLocked(owner analysis.Symbol) []*analysis.Symbol {
	out := make([]*analysis.Symbol, 0, 8)
	for _, id := range i.byContainerName[owner.ID] {
		member := i.symbols[id]
		if member == nil || member.ContainerID != owner.ID || member.Synthetic {
			continue
		}
		switch member.Kind {
		case analysis.KindFunction, analysis.KindMethod, analysis.KindProperty, analysis.KindField:
			out = append(out, member)
		}
	}
	return out
}

// resolvedHierarchyLocked returns every supertype of a type, transitively. It
// fails when any supertype cannot be resolved to exactly one Kotlin workspace
// declaration: a library or Java supertype may carry members the index does
// not model in the same terms, and nothing sound can be said about names then.
func (i *Index) resolvedHierarchyLocked(owner analysis.Symbol) ([]analysis.Symbol, bool) {
	seen := map[string]bool{owner.ID: true}
	queue := []analysis.Symbol{owner}
	var out []analysis.Symbol
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		file := i.files[current.URI]
		if file == nil {
			return nil, false
		}
		for _, supertype := range current.Supertypes {
			base, _ := splitInstantiatedType(supertype)
			if paren := strings.IndexByte(base, '('); paren >= 0 {
				base = base[:paren]
			}
			base = strings.TrimSpace(base)
			if base == "" {
				return nil, false
			}
			resolved := i.resolveTypeSymbolsLocked(file, base)
			if len(resolved) != 1 {
				return nil, false
			}
			symbol := resolved[0]
			if symbol.Language != analysis.LanguageKotlin || symbol.Library || symbol.Synthetic || !isKotlinClassLike(symbol.Kind) {
				return nil, false
			}
			if !seen[symbol.ID] {
				seen[symbol.ID] = true
				out = append(out, symbol)
				queue = append(queue, symbol)
			}
		}
	}
	return out, true
}

// memberIsAbstractLocked decides abstractness the way the language does: an
// explicit modifier, or an interface member with nothing supplying a body.
func (i *Index) memberIsAbstractLocked(owner analysis.Symbol, member *analysis.Symbol) bool {
	if containsString(member.Modifiers, "abstract") {
		return true
	}
	if owner.Kind != analysis.KindInterface {
		return false
	}
	text := i.documentTextLocked(member.URI)
	if text == "" {
		return false
	}
	switch member.Kind {
	case analysis.KindFunction, analysis.KindMethod:
		_, hasBody := functionTail(text, member)
		return !hasBody
	case analysis.KindProperty, analysis.KindField:
		return !propertyHasBodyOrAccessor(declarationText(text, member))
	}
	return false
}
