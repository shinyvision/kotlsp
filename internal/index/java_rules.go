package index

import (
	"path"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// javac reports every error under one code, so a Java prediction is identified
// by its message. Each message here is javac's own first line, captured from a
// hosted run; the prefixes are what the soundness gate checks fired.
const (
	javaPublicClassFile     = "class %s is public, should be declared in a file named %s.java"
	javaNotAbstract         = " is not abstract and does not override abstract method "
	javaFinalAssign         = "cannot assign a value to final variable "
	javaFinalParameter      = "final parameter "
	javaMissingReturnValue  = "incompatible types: missing return value"
	javaUnexpectedReturn    = "incompatible types: unexpected return value"
	javaOverridesNothing    = "method does not override or implement a method from a supertype"
	javaNonStaticVariable   = "non-static variable "
	javaNonStaticMethod     = "non-static method "
	javaStaticContextSuffix = " cannot be referenced from a static context"
	javaIncompatible        = "incompatible types: "
	javaAbstractNew         = " is abstract; cannot be instantiated"
	javaMissingReturn       = "missing return statement"
	javaUnreachable         = "unreachable statement"
	javaUnreported          = "unreported exception "
	javaDereferenced        = " cannot be dereferenced"
	javaAlreadyDefined      = " is already defined in "
	javaDuplicateClass      = "duplicate class: "
	javaCannotFindSymbol    = "cannot find symbol"
)

func init() {
	registerFastRule(fastRule{
		codes:     []string{"compiler"},
		languages: []analysis.Language{analysis.LanguageJava},
		javaMessages: []string{
			"class ", javaNotAbstract, javaFinalAssign, javaFinalParameter, javaMissingReturnValue, javaUnexpectedReturn,
			javaOverridesNothing, javaNonStaticVariable, javaNonStaticMethod, javaIncompatible,
			javaAbstractNew, javaMissingReturn, javaUnreachable, javaUnreported, javaDereferenced,
			javaAlreadyDefined, javaDuplicateClass, javaCannotFindSymbol,
		},
		usesWorkspaceIndex: true,
		apply:              javaShapes,
	})
}

func javaDiagnostic(r protocol.Range, message string) protocol.Diagnostic {
	return protocol.Diagnostic{Range: r, Severity: 1, Source: "kotlsp", Code: "compiler", Message: message}
}

func javaShapes(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.documentLocked(file.URI)
	if document == nil || document.Text == "" {
		return nil
	}
	c := newUnresolvedNameContext(file)
	c.prepare(i)
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || symbol.URI != file.URI {
			continue
		}
		switch symbol.Kind {
		case analysis.KindClass, analysis.KindInterface, analysis.KindEnum, analysis.KindRecord, analysis.KindAnnotation:
			out = append(out, publicClassFilename(c, symbol)...)
			out = append(out, i.javaAbstractNotImplemented(c, document, symbol)...)
		case analysis.KindMethod, analysis.KindConstructor:
			out = append(out, i.javaReturnShapes(c, document, symbol)...)
			out = append(out, i.javaOverridesNothing(c, document, symbol)...)
			out = append(out, i.javaMissingReturn(c, document, symbol)...)
			out = append(out, i.javaUnreportedExceptions(c, document, symbol)...)
		case analysis.KindField, analysis.KindVariable:
			out = append(out, i.javaLiteralInitializers(c, document, symbol)...)
		}
	}
	out = append(out, i.javaFinalAssignments(c, document)...)
	out = append(out, i.javaStaticContext(c, document)...)
	out = append(out, i.javaAbstractInstantiations(c, document)...)
	out = append(out, javaUnreachableStatements(c, document)...)
	out = append(out, i.javaPrimitiveDereferences(c, document)...)
	return out
}

func publicClassFilename(c *unresolvedNameContext, symbol *analysis.Symbol) []protocol.Diagnostic {
	if symbol.ContainerID != "" || !containsString(symbol.Modifiers, "public") {
		return nil
	}
	base := strings.TrimSuffix(path.Base(string(symbol.URI)), ".java")
	if base == symbol.Name {
		return nil
	}
	return []protocol.Diagnostic{javaDiagnostic(symbol.SelectionRange, "class "+symbol.Name+" is public, should be declared in a file named "+symbol.Name+".java")}
}

// javaSignature renders a method's parameters the way javac does in messages:
// declared simple types, no spaces, varargs as '...'. It fails on anything
// javac would render differently from the source: qualified names and type
// parameters, which javac substitutes.
func javaSignature(owner *analysis.Symbol, method *analysis.Symbol) (string, bool) {
	var parts []string
	for _, parameter := range method.Parameters {
		typ := strings.ReplaceAll(parameter.Type, " ", "")
		base, _ := splitInstantiatedType(typ)
		base = strings.TrimSuffix(base, "[]")
		if typ == "" || strings.Contains(typ, ".") || containsString(method.TypeParameters, base) || owner != nil && containsString(owner.TypeParameters, base) {
			return "", false
		}
		if parameter.Variadic {
			typ += "..."
		}
		parts = append(parts, typ)
	}
	return method.Name + "(" + strings.Join(parts, ",") + ")", true
}

// javaHierarchyLocked returns a Java type's complete hierarchy when every type
// in it is Java: a Kotlin supertype presents its properties to Java under
// accessor names the index does not model here.
func (i *Index) javaHierarchyLocked(c *unresolvedNameContext, owner analysis.Symbol) ([]analysis.Symbol, bool) {
	hierarchy := i.completeHierarchyLocked(c, owner)
	if !hierarchy.complete {
		return nil, false
	}
	for _, symbol := range hierarchy.types {
		if symbol.Language != analysis.LanguageJava {
			return nil, false
		}
	}
	return hierarchy.types, true
}

func javaMethodIsAbstract(i *Index, owner analysis.Symbol, method *analysis.Symbol) bool {
	if containsString(method.Modifiers, "abstract") {
		return true
	}
	if owner.Kind != analysis.KindInterface || hasAnyModifier(method, "default", "static", "private") {
		return false
	}
	_, hasBody := functionTail(i.documentTextLocked(method.URI), method)
	return !hasBody
}

func (i *Index) javaAbstractNotImplemented(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, owner *analysis.Symbol) []protocol.Diagnostic {
	if owner.Kind != analysis.KindClass || containsString(owner.Modifiers, "abstract") {
		return nil
	}
	if strings.Contains(c.text[owner.StartByte:owner.NameStartByte], "\n") {
		// javac anchors the message to the declaration; with annotations on
		// earlier lines the line is not evident.
		return nil
	}
	hierarchy, ok := i.javaHierarchyLocked(c, *owner)
	if !ok {
		return nil
	}
	type abstractMethod struct {
		owner  analysis.Symbol
		method *analysis.Symbol
	}
	concrete := make(map[string]bool)
	abstracts := make(map[string]abstractMethod)
	var order []string
	for _, typ := range hierarchy {
		for _, member := range i.typeMembersLocked(typ) {
			if member.Kind != analysis.KindMethod {
				continue
			}
			key := member.Name + "/" + strconv.Itoa(len(member.Parameters))
			if typ.ID != owner.ID && javaMethodIsAbstract(i, typ, member) {
				if _, seen := abstracts[key]; !seen {
					abstracts[key] = abstractMethod{owner: typ, method: member}
					order = append(order, key)
				}
			} else {
				concrete[key] = true
			}
		}
	}
	var missing []abstractMethod
	for _, key := range order {
		if !concrete[key] && !overridesAnyMember(*abstracts[key].method) {
			missing = append(missing, abstracts[key])
		}
	}
	if len(missing) != 1 {
		return nil
	}
	signature, ok := javaSignature(&missing[0].owner, missing[0].method)
	if !ok {
		return nil
	}
	return []protocol.Diagnostic{javaDiagnostic(owner.SelectionRange, owner.Name+javaNotAbstract+signature+" in "+missing[0].owner.Name)}
}

// javaBodyIsPlain reports whether a body contains none of the constructs that
// introduce a nested scope with its own return and exception rules.
func javaBodyIsPlain(c *unresolvedNameContext, start, end int) bool {
	if strings.Contains(c.text[start:end], "->") {
		return false
	}
	for _, keyword := range []string{"class", "interface", "enum", "record"} {
		if countWord(c, start, end, keyword) > 0 {
			return false
		}
	}
	for _, anonymous := range c.anonymous {
		if anonymous.start >= start && anonymous.end <= end {
			return false
		}
	}
	return true
}

func (i *Index) javaReturnShapes(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, method *analysis.Symbol) []protocol.Diagnostic {
	if method.Kind != analysis.KindMethod {
		return nil
	}
	start, end, ok := blockBody(c, method)
	if !ok || !javaBodyIsPlain(c, start, end) {
		return nil
	}
	void := strings.TrimSpace(method.Type) == "void"
	var out []protocol.Diagnostic
	for _, at := range keywordPositions(c.text[start:end], c.mask[start:end], "return") {
		at += start
		next := skipForwardCode(c.text, c.mask, at+len("return"))
		if next < 0 {
			continue
		}
		bare := c.text[next] == ';'
		if void && !bare {
			out = append(out, javaDiagnostic(document.Range(at, at+len("return")), javaUnexpectedReturn))
		} else if !void && bare && strings.TrimSpace(method.Type) != "" {
			out = append(out, javaDiagnostic(document.Range(at, at+len("return")), javaMissingReturnValue))
		}
	}
	return out
}

func (i *Index) javaOverridesNothing(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, method *analysis.Symbol) []protocol.Diagnostic {
	if method.Kind != analysis.KindMethod || !containsString(method.Modifiers, "Override") {
		return nil
	}
	owner := i.symbols[method.ContainerID]
	if owner == nil || !analysis.IsTypeKind(owner.Kind) || owner.Kind == analysis.KindRecord || owner.Kind == analysis.KindEnum {
		return nil
	}
	hierarchy, ok := i.javaHierarchyLocked(c, *owner)
	if !ok {
		return nil
	}
	for _, typ := range hierarchy {
		if typ.ID == owner.ID {
			continue
		}
		for _, member := range i.typeMembersLocked(typ) {
			if member.Kind == analysis.KindMethod && member.Name == method.Name && len(member.Parameters) == len(method.Parameters) {
				return nil
			}
		}
	}
	annotation := strings.Index(c.text[method.StartByte:method.NameStartByte], "@Override")
	if annotation < 0 {
		return nil
	}
	at := method.StartByte + annotation
	return []protocol.Diagnostic{javaDiagnostic(document.Range(at, at+len("@Override")), javaOverridesNothing)}
}

func (i *Index) javaMissingReturn(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, method *analysis.Symbol) []protocol.Diagnostic {
	if method.Kind != analysis.KindMethod || hasAnyModifier(method, "abstract", "native") {
		return nil
	}
	declared := strings.TrimSpace(method.Type)
	if declared == "" || declared == "void" {
		return nil
	}
	start, end, ok := blockBody(c, method)
	if !ok {
		return nil
	}
	for _, keyword := range []string{"return", "throw", "while", "do", "for"} {
		if countWord(c, start, end, keyword) > 0 {
			return nil
		}
	}
	return []protocol.Diagnostic{javaDiagnostic(document.Range(end, end+1), javaMissingReturn)}
}

func (i *Index) javaUnreportedExceptions(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, method *analysis.Symbol) []protocol.Diagnostic {
	start, end, ok := blockBody(c, method)
	if !ok || !javaBodyIsPlain(c, start, end) || countWord(c, start, end, "try") > 0 {
		return nil
	}
	header := c.text[method.NameEndByte:start]
	if strings.Contains(header, "throws") {
		return nil
	}
	var out []protocol.Diagnostic
	for _, at := range keywordPositions(c.text[start:end], c.mask[start:end], "throw") {
		at += start
		next := skipForwardCode(c.text, c.mask, at+len("throw"))
		if next < 0 || !strings.HasPrefix(c.text[next:], "new") || next+3 >= len(c.text) || isIdentifierByteFast(c.text[next+3]) {
			continue
		}
		nameStart := skipForwardCode(c.text, c.mask, next+3)
		if nameStart < 0 {
			continue
		}
		nameEnd := nameStart
		for nameEnd < len(c.text) && isIdentifierByteFast(c.text[nameEnd]) {
			nameEnd++
		}
		name := c.text[nameStart:nameEnd]
		open := skipForwardCode(c.text, c.mask, nameEnd)
		if name == "" || open < 0 || c.text[open] != '(' || strings.Contains(c.text[at:nameEnd], "\n") {
			continue
		}
		resolved, ok := i.resolveOneTypeLocked(c.file, name)
		if !ok {
			continue
		}
		hierarchy := i.completeHierarchyLocked(c, resolved[0])
		if !hierarchy.complete {
			continue
		}
		checked, unchecked := false, false
		for _, typ := range hierarchy.types {
			switch typ.FQN {
			case "java.lang.Exception":
				checked = true
			case "java.lang.RuntimeException", "java.lang.Error":
				unchecked = true
			}
		}
		if !checked || unchecked {
			continue
		}
		out = append(out, javaDiagnostic(document.Range(at, at+len("throw")), javaUnreported+name+"; must be caught or declared to be thrown"))
	}
	return out
}

var javaPrimitives = map[string]bool{"byte": true, "short": true, "char": true, "int": true, "long": true, "float": true, "double": true, "boolean": true}

// javaLiteralKind names a literal's type as javac renders it.
func javaLiteralKind(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if text == "null" {
		return "<null>"
	}
	if text == "true" || text == "false" {
		return "boolean"
	}
	switch text[0] {
	case '"':
		if len(text) >= 2 && text[len(text)-1] == '"' && !strings.Contains(text[1:len(text)-1], "\"") {
			return "String"
		}
		return ""
	case '\'':
		if len(text) >= 3 && text[len(text)-1] == '\'' {
			return "char"
		}
		return ""
	}
	number := strings.ReplaceAll(strings.TrimPrefix(text, "-"), "_", "")
	lower := strings.ToLower(number)
	switch {
	case strings.HasSuffix(lower, "l"):
		if intLiteral.MatchString(number[:len(number)-1]) || hexLiteral.MatchString(number[:len(number)-1]) {
			return "long"
		}
	case strings.HasSuffix(lower, "f"):
		if decimalLiteral.MatchString(number[:len(number)-1]) {
			return "float"
		}
	case strings.HasSuffix(lower, "d"):
		if decimalLiteral.MatchString(number[:len(number)-1]) {
			return "double"
		}
	case intLiteral.MatchString(number) || hexLiteral.MatchString(number) || binaryLiteral.MatchString(number):
		return "int"
	case decimalLiteral.MatchString(number):
		return "double"
	}
	return ""
}

func javaIntLiteralValue(text string) (int64, bool) {
	number := strings.ReplaceAll(strings.TrimSpace(text), "_", "")
	negative := strings.HasPrefix(number, "-")
	number = strings.TrimPrefix(number, "-")
	base := 10
	switch {
	case strings.HasPrefix(strings.ToLower(number), "0x"):
		base, number = 16, number[2:]
	case strings.HasPrefix(strings.ToLower(number), "0b"):
		base, number = 2, number[2:]
	case len(number) > 1 && number[0] == '0':
		base, number = 8, number[1:]
	}
	value, err := strconv.ParseInt(number, base, 64)
	if err != nil {
		return 0, false
	}
	if negative {
		value = -value
	}
	return value, true
}

// javaLiteralMessage is javac's verdict on assigning a literal to a declared
// type, or "" when it compiles or cannot be decided from the text.
func javaLiteralMessage(expected, literal string) string {
	kind := javaLiteralKind(literal)
	if kind == "" {
		return ""
	}
	lossy := func(from string) string {
		return javaIncompatible + "possible lossy conversion from " + from + " to " + expected
	}
	convert := func(from string) string {
		return javaIncompatible + from + " cannot be converted to " + expected
	}
	switch expected {
	case "String":
		if kind == "String" || kind == "<null>" {
			return ""
		}
		return convert(kind)
	case "boolean":
		if kind == "boolean" {
			return ""
		}
		return convert(kind)
	case "byte", "short", "char", "int", "long", "float", "double":
	default:
		return ""
	}
	rank := map[string]int{"byte": 1, "short": 2, "char": 2, "int": 3, "long": 4, "float": 5, "double": 6}
	switch kind {
	case "boolean", "String", "<null>":
		return convert(kind)
	case "char":
		return ""
	case "int":
		if rank[expected] >= rank["int"] {
			return ""
		}
		value, ok := javaIntLiteralValue(literal)
		if !ok {
			return ""
		}
		var low, high int64
		switch expected {
		case "byte":
			low, high = -128, 127
		case "short":
			low, high = -32768, 32767
		case "char":
			low, high = 0, 65535
		}
		if value < low || value > high {
			return lossy("int")
		}
		return ""
	case "long", "float", "double":
		if rank[expected] >= rank[kind] {
			return ""
		}
		return lossy(kind)
	}
	return ""
}

// javaExpectedTypeLocked names a declared type javac will render verbatim: a
// primitive, or String when it is java.lang.String.
func (i *Index) javaExpectedTypeLocked(file *analysis.ParsedFile, declared string) string {
	name := strings.TrimSpace(declared)
	if javaPrimitives[name] {
		return name
	}
	if name != "String" {
		return ""
	}
	resolved, ok := i.resolveOneTypeLocked(file, name)
	if !ok || resolved[0].FQN != "java.lang.String" {
		return ""
	}
	return name
}

func (i *Index) javaLiteralInitializers(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, symbol *analysis.Symbol) []protocol.Diagnostic {
	expected := i.javaExpectedTypeLocked(c.file, symbol.Type)
	if expected == "" || symbol.Initializer == "" {
		return nil
	}
	start, end, ok := initializerSpan(c.text, symbol)
	if !ok {
		return nil
	}
	message := javaLiteralMessage(expected, c.text[start:end])
	if message == "" {
		return nil
	}
	return []protocol.Diagnostic{javaDiagnostic(document.Range(start, end), message)}
}

// javaFinalAssignments covers a plain write to a final that already has its
// value: a final field or local with an initialiser, or a final parameter.
func (i *Index) javaFinalAssignments(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, ref := range c.file.References {
		if ref.Qualifier != "" && ref.Qualifier != "this" || ref.ArgumentLabel || ref.Role == analysis.RoleType || ref.Role == analysis.RoleImport {
			continue
		}
		// The Java parser does not mark writes; the text after the name does.
		if !javaWriteFollows(c, ref.EndByte) {
			continue
		}
		resolved := i.resolveLocked(c.file, ref)
		if len(resolved) != 1 || resolved[0].URI != c.file.URI {
			continue
		}
		target := resolved[0]
		declaration := declarationText(c.text, &target)
		final := false
		switch target.Kind {
		case analysis.KindField:
			final = containsString(target.Modifiers, "final") && strings.Contains(declaration, "=")
		case analysis.KindParameter:
			final = strings.HasPrefix(strings.TrimSpace(declaration), "final ") || strings.Contains(declaration, " final ")
		case analysis.KindVariable:
			lineStart := strings.LastIndexAny(c.text[:target.StartByte], ";{}\n") + 1
			prefix := c.text[lineStart:target.StartByte]
			final = strings.Contains(declaration, "=") && len(keywordPositions(prefix, c.mask[lineStart:target.StartByte], "final")) > 0
		}
		if !final {
			continue
		}
		if target.Kind == analysis.KindParameter {
			out = append(out, javaDiagnostic(ref.Range, javaFinalParameter+target.Name+" may not be assigned"))
			continue
		}
		out = append(out, javaDiagnostic(ref.Range, javaFinalAssign+target.Name))
	}
	return out
}

func (i *Index) javaStaticContext(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	inAnonymous := func(at int) bool {
		for _, anonymous := range c.anonymous {
			if anonymous.start < at && at < anonymous.end {
				return true
			}
		}
		return false
	}
	for _, ref := range c.file.References {
		if ref.Qualifier != "" || ref.ArgumentLabel || ref.Role == analysis.RoleType || ref.Role == analysis.RoleImport || ref.Role == analysis.RoleLabel {
			continue
		}
		if !i.staticLikeContextLocked(c.file, ref.StartByte) || inAnonymous(ref.StartByte) {
			continue
		}
		if len(i.resolveLocked(c.file, ref)) > 0 {
			continue
		}
		before := skipBackCode(c.text, c.mask, ref.StartByte-1)
		if before >= 0 && c.text[before] == '.' {
			continue
		}
		enclosing := i.enclosingTypeLocked(c.file, ref.StartByte)
		if enclosing.ID == "" {
			continue
		}
		hierarchy, ok := i.javaHierarchyLocked(c, enclosing)
		if !ok {
			continue
		}
		var fields, methods []*analysis.Symbol
		conflict := false
		for _, typ := range hierarchy {
			for _, member := range i.typeMembersLocked(typ) {
				if member.Name != ref.Name {
					continue
				}
				if containsString(member.Modifiers, "static") {
					conflict = true
				}
				switch member.Kind {
				case analysis.KindField:
					fields = append(fields, member)
				case analysis.KindMethod:
					methods = append(methods, member)
				}
			}
		}
		if conflict {
			continue
		}
		call := ref.Role == analysis.RoleCall
		switch {
		case !call && len(fields) == 1 && len(methods) == 0:
			out = append(out, javaDiagnostic(ref.Range, javaNonStaticVariable+ref.Name+javaStaticContextSuffix))
		case call && len(methods) == 1 && len(fields) == 0:
			owner := i.symbols[methods[0].ContainerID]
			signature, ok := javaSignature(owner, methods[0])
			if !ok {
				continue
			}
			out = append(out, javaDiagnostic(ref.Range, javaNonStaticMethod+signature+javaStaticContextSuffix))
		}
	}
	for _, at := range keywordPositions(c.text, c.mask, "this") {
		if !i.staticLikeContextLocked(c.file, at) || inAnonymous(at) {
			continue
		}
		before := skipBackCode(c.text, c.mask, at-1)
		if before >= 0 && c.text[before] == '.' {
			continue
		}
		out = append(out, javaDiagnostic(document.Range(at, at+len("this")), javaNonStaticVariable+"this"+javaStaticContextSuffix))
	}
	return out
}

func (i *Index) javaAbstractInstantiations(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, ref := range c.file.References {
		if ref.Role != analysis.RoleCall || ref.Qualifier != "" || ref.ArgumentLabel {
			continue
		}
		before := skipBackCode(c.text, c.mask, ref.StartByte-1)
		if before < 2 || c.text[before-2:before+1] != "new" || before >= 3 && isIdentifierByteFast(c.text[before-3]) {
			continue
		}
		if strings.Contains(c.text[before:ref.StartByte], "\n") {
			continue
		}
		open := skipForwardCode(c.text, c.mask, ref.EndByte)
		if open < 0 || c.text[open] != '(' {
			continue
		}
		closing := matchingParen(c.text, open)
		if closing < 0 {
			continue
		}
		if after := skipForwardCode(c.text, c.mask, closing+1); after >= 0 && c.text[after] == '{' {
			continue
		}
		resolved, ok := i.resolveOneTypeLocked(c.file, ref.Name)
		if !ok {
			continue
		}
		target := resolved[0]
		if target.Kind != analysis.KindInterface && !(target.Kind == analysis.KindClass && containsString(target.Modifiers, "abstract")) {
			continue
		}
		out = append(out, javaDiagnostic(ref.Range, ref.Name+javaAbstractNew))
	}
	return out
}

// javaUnreachableStatements reports the statement after an unconditional
// jump in the same block.
func javaUnreachableStatements(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, keyword := range []string{"return", "throw", "break", "continue"} {
		for _, at := range keywordPositions(c.text, c.mask, keyword) {
			before := skipBackCode(c.text, c.mask, at-1)
			if before < 0 {
				continue
			}
			switch c.text[before] {
			case ')', '>':
				continue
			}
			if before >= 3 && c.text[before-3:before+1] == "else" || before >= 1 && c.text[before-1:before+1] == "do" {
				continue
			}
			end := at + len(keyword)
			depth := 0
			for ; end < len(c.text); end++ {
				if !c.mask[end] {
					continue
				}
				switch c.text[end] {
				case '(', '{', '[':
					depth++
				case ')', '}', ']':
					depth--
				}
				if depth < 0 {
					end = -1
					break
				}
				if c.text[end] == ';' && depth == 0 {
					break
				}
			}
			if end < 0 || end >= len(c.text) {
				continue
			}
			next := skipForwardCode(c.text, c.mask, end+1)
			if next < 0 || c.text[next] == '}' {
				continue
			}
			if strings.HasPrefix(c.text[next:], "case") || strings.HasPrefix(c.text[next:], "default") {
				continue
			}
			lineEnd := strings.IndexByte(c.text[next:], '\n')
			if lineEnd < 0 {
				lineEnd = len(c.text) - next
			}
			out = append(out, javaDiagnostic(document.Range(next, next+lineEnd), javaUnreachable))
		}
	}
	return out
}

func (i *Index) javaPrimitiveDereferences(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for _, ref := range c.file.References {
		if ref.Qualifier == "" || !isSimpleIdentifier(ref.Qualifier) || ref.ArgumentLabel {
			continue
		}
		dot := ref.StartByte - 1
		if dot < 1 || c.text[dot] != '.' {
			continue
		}
		qualifierStart := dot - len(ref.Qualifier)
		if qualifierStart < 0 || c.text[qualifierStart:dot] != ref.Qualifier || qualifierStart > 0 && isIdentifierByteFast(c.text[qualifierStart-1]) {
			continue
		}
		var binding *analysis.Symbol
		for _, symbol := range i.fileSymbolsByName[c.file.URI][ref.Qualifier] {
			if symbol.Kind != analysis.KindParameter && symbol.Kind != analysis.KindVariable || symbol.StartByte > ref.StartByte || !symbolInScopeAt(*symbol, ref.StartByte) {
				continue
			}
			if binding == nil || symbol.StartByte > binding.StartByte {
				binding = symbol
			}
		}
		if binding == nil || !javaPrimitives[strings.TrimSpace(binding.Type)] {
			continue
		}
		out = append(out, javaDiagnostic(ref.Range, strings.TrimSpace(binding.Type)+javaDereferenced))
	}
	return out
}

// javaWriteFollows reports whether the name ending at end is assigned:
// followed by '=', a compound assignment, or '++'/'--'.
func javaWriteFollows(c *unresolvedNameContext, end int) bool {
	at := skipForwardCode(c.text, c.mask, end)
	if at < 0 {
		return false
	}
	rest := c.text[at:]
	if strings.HasPrefix(rest, "==") {
		return false
	}
	if strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "++") || strings.HasPrefix(rest, "--") {
		return true
	}
	for _, operator := range []string{"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="} {
		if strings.HasPrefix(rest, operator) {
			return true
		}
	}
	return false
}
