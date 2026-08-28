package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/jsonrpc"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (s *Server) formatting(ctx context.Context, raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
		Options      protocol.FormattingOptions      `json:"options"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	doc, ok := s.index.DocumentContext(ctx, p.TextDocument.URI)
	if !ok {
		return []protocol.TextEdit{}, nil
	}
	formatted, completed := formatSourceContext(ctx, doc.Text, p.Options, strings.HasSuffix(strings.ToLower(string(p.TextDocument.URI)), ".kt") || strings.HasSuffix(strings.ToLower(string(p.TextDocument.URI)), ".kts"))
	if !completed {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "request cancelled"}
	}
	if formatted == doc.Text {
		return []protocol.TextEdit{}, nil
	}
	return []protocol.TextEdit{{Range: doc.Range(0, len(doc.Text)), NewText: formatted}}, nil
}

func (s *Server) rangeFormatting(ctx context.Context, raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
		Range        protocol.Range                  `json:"range"`
		Options      protocol.FormattingOptions      `json:"options"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	doc, ok := s.index.DocumentContext(ctx, p.TextDocument.URI)
	if !ok {
		return []protocol.TextEdit{}, nil
	}
	originalStarts := sourceLineStarts(doc.Text)
	startLine := p.Range.Start.Line
	if startLine < 0 {
		startLine = 0
	}
	if startLine >= len(originalStarts) {
		return []protocol.TextEdit{}, nil
	}
	endLine := p.Range.End.Line
	if endLine < startLine {
		endLine = startLine
	}
	endExclusive := endLine + 1
	if p.Range.End.Character == 0 && endLine > startLine {
		endExclusive = endLine
	}
	if endExclusive > len(originalStarts) {
		endExclusive = len(originalStarts)
	}
	originalStart := originalStarts[startLine]
	originalEnd := len(doc.Text)
	if endExclusive < len(originalStarts) {
		originalEnd = originalStarts[endExclusive]
	}
	kotlin := strings.HasSuffix(strings.ToLower(string(p.TextDocument.URI)), ".kt") || strings.HasSuffix(strings.ToLower(string(p.TextDocument.URI)), ".kts")
	if rangeTouchesProtectedLexicalRegion(doc.Text, originalStart, originalEnd, kotlin) {
		return []protocol.TextEdit{}, nil
	}
	depth, lexicalState, completed := formatterContextBeforeContext(ctx, doc.Text[:originalStart], kotlin)
	if !completed {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "request cancelled"}
	}
	// A line range beginning inside literal/comment content cannot be formatted
	// independently. Returning no edit is safer than treating that content as
	// code; a later AST formatter can expand to the enclosing construct.
	if lexicalState.Triple || lexicalState.BlockCommentDepth > 0 {
		return []protocol.TextEdit{}, nil
	}
	segment := doc.Text[originalStart:originalEnd]
	newText, completed := formatSourceContext(ctx, segment, p.Options, kotlin)
	if !completed {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "request cancelled"}
	}
	newText = indentFormattedRange(newText, depth, p.Options)
	if segment == newText {
		return []protocol.TextEdit{}, nil
	}
	language := analysis.LanguageJava
	if kotlin {
		language = analysis.LanguageKotlin
	}
	before, beforeOK := analysis.SyntaxFingerprint(ctx, doc.Text, language)
	updated := doc.Text[:originalStart] + newText + doc.Text[originalEnd:]
	after, afterOK := analysis.SyntaxFingerprint(ctx, updated, language)
	if !beforeOK || !afterOK || before != after {
		return []protocol.TextEdit{}, nil
	}
	return []protocol.TextEdit{{Range: doc.Range(originalStart, originalEnd), NewText: newText}}, nil
}

func rangeTouchesProtectedLexicalRegion(source string, start, end int, kotlin bool) bool {
	touches := false
	complete := lexical.ScanRegionsBounded(source, kotlin, 100_000, func(region lexical.Region) {
		if touches || region.Kind == lexical.Code {
			return
		}
		if region.OuterStart < end && start < region.OuterEnd {
			touches = true
		}
	})
	// An incomplete lexical model cannot prove that the selection is code.
	return !complete || touches
}

func formatterDepthBefore(source string) int {
	depth, _ := formatterDepthBeforeContext(context.Background(), source)
	return depth
}

func formatterDepthBeforeContext(ctx context.Context, source string) (int, bool) {
	depth, _, completed := formatterContextBeforeContext(ctx, source, true)
	return depth, completed
}

func formatterContextBeforeContext(ctx context.Context, source string, kotlin bool) (int, formatLexState, bool) {
	depth := 0
	state := formatLexState{}
	for index, line := range strings.Split(source, "\n") {
		if index&127 == 0 && ctx.Err() != nil {
			return 0, formatLexState{}, false
		}
		opens, closes, _ := scanStructureLanguage(line, &state, kotlin)
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
	}
	return depth, state, ctx.Err() == nil
}

func indentFormattedRange(formatted string, depth int, opts protocol.FormattingOptions) string {
	if depth <= 0 || formatted == "" {
		return formatted
	}
	if opts.TabSize <= 0 {
		opts.TabSize = 4
	}
	unit := "\t"
	if opts.InsertSpaces {
		unit = strings.Repeat(" ", opts.TabSize)
	}
	indent := strings.Repeat(unit, depth)
	lines := strings.Split(formatted, "\n")
	for index := range lines {
		if strings.TrimSpace(lines[index]) != "" {
			lines[index] = indent + lines[index]
		}
	}
	return strings.Join(lines, "\n")
}

func sourceLineStarts(source string) []int {
	starts := []int{0}
	for offset := 0; offset < len(source); offset++ {
		if source[offset] == '\n' {
			starts = append(starts, offset+1)
		}
	}
	return starts
}

func (s *Server) codeActions(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	ctx := operationContext(contexts)
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
		Range        protocol.Range                  `json:"range"`
		Context      struct {
			Diagnostics []protocol.Diagnostic `json:"diagnostics"`
			Only        []string              `json:"only"`
		} `json:"context"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	doc, ok := s.index.DocumentContext(ctx, p.TextDocument.URI)
	if !ok {
		return []protocol.CodeAction{}, nil
	}
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	actions := make([]protocol.CodeAction, 0, 8)
	if edit, ok := organizeImports(doc.Text, doc.Range(0, len(doc.Text)), p.TextDocument.URI, s.index.UsedImports(p.TextDocument.URI)); ok {
		actions = append(actions, protocol.CodeAction{Title: "Organize imports", Kind: "source.organizeImports", Edit: &protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{p.TextDocument.URI: {edit}}}})
	}
	selected := doc.Slice(p.Range)
	if strings.TrimSpace(selected) != "" {
		for _, action := range s.extractActions(p.TextDocument.URI, p.Range, doc, selected, ctx) {
			// OpenKotlin's extract providers deliberately use commands rather than
			// embedding edits.  The second argument is its sealed Payload.Data
			// DTO; keeping that wire shape matters to clients which persist or
			// replay code actions.
			action.Command = &protocol.Command{
				Title: action.Title, Command: action.Kind,
				Arguments: []any{p.TextDocument.URI, map[string]any{
					"type":      "com.jetbrains.ls.api.features.impl.common.extract.LSExtractMemberProviderBase.Payload.Data",
					"selection": p.Range, "choice": action.Title,
				}},
			}
			action.Edit = nil
			actions = append(actions, action)
		}
	}
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	if action, ok := s.inlineVariableAction(p.TextDocument.URI, p.Range, doc, ctx); ok {
		actions = append(actions, action)
	}
	for _, diagnostic := range p.Context.Diagnostics {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		if action, ok := diagnosticQuickFix(p.TextDocument.URI, doc.Text, diagnostic); ok {
			actions = append(actions, action)
		}
		if action, ok := s.createJavaMethodQuickFixContext(ctx, p.TextDocument.URI, doc, diagnostic); ok {
			actions = append(actions, action)
		}
		candidates := diagnosticCandidates(diagnostic)
		if len(candidates) > 1 {
			entries := make([]any, 0, len(candidates))
			commands := make([]map[string]any, 0, len(candidates))
			for _, fqn := range candidates {
				if edit, available := addImportEdit(doc.Text, p.TextDocument.URI, fqn); available {
					start, end := doc.Offset(edit.Range.Start), doc.Offset(edit.Range.End)
					updated := doc.Text[:start] + edit.NewText + doc.Text[end:]
					entries = append(entries, map[string]any{"index": len(commands), "name": "Import " + fqn})
					commands = append(commands, map[string]any{"type": "UpdateFileText", "fileUrl": p.TextDocument.URI, "oldText": doc.Text, "newText": updated})
				}
			}
			if len(commands) > 1 {
				sessionID := s.modSequence.Add(1)
				s.modMu.Lock()
				s.pruneModSessionsLocked(time.Now())
				s.modSessions[sessionID] = commands
				s.modSessionCreated[sessionID] = time.Now()
				s.modMu.Unlock()
				payload := map[string]any{"type": "ChooseAction", "sessionId": sessionID, "title": "Choose import", "entries": entries}
				actions = append(actions, protocol.CodeAction{Title: "Choose import", Kind: "quickfix", Diagnostics: []protocol.Diagnostic{diagnostic}, Command: &protocol.Command{Title: "Choose import", Command: "applyModCommand", Arguments: []any{payload}}})
			}
		}
		for _, fqn := range candidates {
			if edit, ok := addImportEdit(doc.Text, p.TextDocument.URI, fqn); ok {
				actions = append(actions, protocol.CodeAction{Title: "Import " + fqn, Kind: "quickfix", Diagnostics: []protocol.Diagnostic{diagnostic}, IsPreferred: len(candidates) == 1, Edit: &protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{p.TextDocument.URI: {edit}}}})
			}
		}
	}
	if len(p.Context.Only) > 0 {
		filtered := actions[:0]
		for _, a := range actions {
			for _, only := range p.Context.Only {
				if a.Kind == only || strings.HasPrefix(a.Kind, only+".") {
					filtered = append(filtered, a)
					break
				}
			}
		}
		actions = filtered
	}
	return actions, nil
}

func (s *Server) createJavaMethodQuickFix(uri protocol.URI, doc *textdoc.Document, diagnostic protocol.Diagnostic) (protocol.CodeAction, bool) {
	return s.createJavaMethodQuickFixContext(context.Background(), uri, doc, diagnostic)
}

func (s *Server) createJavaMethodQuickFixContext(ctx context.Context, uri protocol.URI, doc *textdoc.Document, diagnostic protocol.Diagnostic) (protocol.CodeAction, bool) {
	if !strings.HasSuffix(strings.ToLower(string(uri)), ".java") {
		return protocol.CodeAction{}, false
	}
	code := fmt.Sprint(diagnostic.Code)
	if code != "CALL_UNRESOLVED_NAME" && code != "cannot-find-symbol" && code != "compiler.err.cant.resolve.location.args" {
		return protocol.CodeAction{}, false
	}
	source := doc.Text
	start := doc.Offset(diagnostic.Range.Start)
	if start < 0 || start >= len(source) {
		return protocol.CodeAction{}, false
	}
	nameStart, nameEnd := javaIdentifierAt(source, start)
	if nameStart < 0 {
		return protocol.CodeAction{}, false
	}
	name := source[nameStart:nameEnd]
	if javaKeyword(name) {
		return protocol.CodeAction{}, false
	}
	open := skipJavaSpaceAndComments(source, nameEnd)
	if open >= len(source) || source[open] != '(' {
		return protocol.CodeAction{}, false
	}
	close := matchingJavaDelimiter(source, open, '(', ')')
	if close < 0 {
		return protocol.CodeAction{}, false
	}
	// Code-action diagnostics can be stale (and compiler diagnostics may not
	// be mirrored in the index yet). The current parse is the authority:
	// require exactly one unqualified call reference at the diagnostic's name
	// that still resolves to nothing before an edit is fabricated.
	file, parsed := s.index.Parsed(uri)
	if !parsed {
		return protocol.CodeAction{}, false
	}
	matchingReferences := 0
	for _, reference := range file.References {
		if reference.Role == analysis.RoleCall && reference.Name == name && reference.StartByte == nameStart && reference.EndByte == nameEnd && (reference.Qualifier == "" || reference.Qualifier == "this") {
			matchingReferences++
		}
	}
	if matchingReferences != 1 || len(s.index.DefinitionsContext(ctx, uri, doc.Position(nameStart))) != 0 || ctx.Err() != nil {
		return protocol.CodeAction{}, false
	}

	symbols := s.index.SymbolsInFile(uri)
	owner, ok := innermostJavaType(symbols, nameStart)
	if !ok || owner.Kind == analysis.KindInterface || owner.Kind == analysis.KindAnnotation {
		return protocol.CodeAction{}, false
	}
	// Creating a member on a textually guessed receiver can put it in the
	// wrong class. This implementation is intentionally limited to an
	// unqualified invocation (or explicit this) in the enclosing type.
	if receiver := javaCallReceiver(source, nameStart); receiver != "" && receiver != "this" {
		return protocol.CodeAction{}, false
	}
	insert := owner.EndByte
	if insert > len(source) {
		insert = len(source)
	}
	if relative := strings.LastIndex(source[owner.StartByte:insert], "}"); relative >= 0 {
		insert = owner.StartByte + relative
	} else {
		return protocol.CodeAction{}, false
	}
	callable, inCallable := innermostJavaCallable(symbols, nameStart)
	static := inCallable && hasModifier(callable, "static")
	returnType, returnKnown := inferredJavaCreatedReturnType(source, nameStart, close, callable, inCallable, symbols, s.index, uri)
	if !returnKnown {
		return protocol.CodeAction{}, false
	}
	arguments := splitJavaCallArguments(source[open+1 : close])
	parameters := make([]string, 0, len(arguments))
	usedNames := make(map[string]bool, len(arguments))
	for argumentIndex, argument := range arguments {
		typ, parameterName, known := inferredJavaCreatedParameter(argument, nameStart, symbols, s.index, uri)
		if !known {
			return protocol.CodeAction{}, false
		}
		if parameterName == "" || javaKeyword(parameterName) {
			parameterName = "value"
		}
		baseName := parameterName
		for suffix := 2; usedNames[parameterName]; suffix++ {
			parameterName = fmt.Sprintf("%s%d", baseName, suffix)
			if baseName == "value" {
				parameterName = fmt.Sprintf("arg%d", argumentIndex+1)
			}
		}
		usedNames[parameterName] = true
		parameters = append(parameters, typ+" "+parameterName)
	}

	closingIndent := javaLineIndent(source, insert)
	methodIndent := closingIndent + "    "
	visibility := "private "
	body := " {\n" + methodIndent + "    throw new UnsupportedOperationException(\"TODO\");\n" + methodIndent + "}"
	staticText := ""
	if static {
		staticText = "static "
	}
	method := "\n" + methodIndent + visibility + staticText + returnType + " " + name + "(" + strings.Join(parameters, ", ") + ")" + body + "\n" + closingIndent
	edit := protocol.TextEdit{Range: doc.Range(insert, insert), NewText: method}
	return protocol.CodeAction{
		Title:       "Create method '" + name + "'",
		Kind:        "quickfix",
		Diagnostics: []protocol.Diagnostic{diagnostic},
		IsPreferred: true,
		Edit:        &protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: {edit}}},
	}, true
}

func javaCallReceiver(source string, nameStart int) string {
	at := nameStart - 1
	for at >= 0 && unicode.IsSpace(rune(source[at])) {
		at--
	}
	if at < 0 || source[at] != '.' {
		return ""
	}
	end := at
	at--
	for at >= 0 && (source[at] == '_' || source[at] == '$' || source[at] >= 'a' && source[at] <= 'z' || source[at] >= 'A' && source[at] <= 'Z' || source[at] >= '0' && source[at] <= '9') {
		at--
	}
	return source[at+1 : end]
}

func javaIdentifierAt(source string, offset int) (int, int) {
	if offset == len(source) && offset > 0 {
		_, width := utf8.DecodeLastRuneInString(source[:offset])
		offset -= width
	}
	if offset < 0 || offset >= len(source) {
		return -1, -1
	}
	r, _ := utf8.DecodeRuneInString(source[offset:])
	if !isJavaIdentifierRune(r, false) && offset > 0 {
		previous, width := utf8.DecodeLastRuneInString(source[:offset])
		if isJavaIdentifierRune(previous, false) {
			offset -= width
		}
	}
	start := offset
	for start > 0 {
		previous, width := utf8.DecodeLastRuneInString(source[:start])
		if !isJavaIdentifierRune(previous, false) {
			break
		}
		start -= width
	}
	end := offset
	for end < len(source) {
		current, width := utf8.DecodeRuneInString(source[end:])
		if !isJavaIdentifierRune(current, end == start) {
			break
		}
		end += width
	}
	first, _ := utf8.DecodeRuneInString(source[start:end])
	if start == end || !isJavaIdentifierRune(first, true) {
		return -1, -1
	}
	return start, end
}

func isJavaIdentifierRune(value rune, first bool) bool {
	if value == '_' || value == '$' || unicode.IsLetter(value) || unicode.Is(unicode.Sc, value) || unicode.Is(unicode.Pc, value) {
		return true
	}
	return !first && (unicode.IsDigit(value) || unicode.Is(unicode.Mn, value) || unicode.Is(unicode.Mc, value) || unicode.Is(unicode.Cf, value))
}

func javaKeyword(value string) bool {
	switch value {
	case "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while", "record", "sealed", "permits", "non-sealed", "var", "yield":
		return true
	default:
		return false
	}
}

func skipJavaSpaceAndComments(source string, offset int) int {
	for offset < len(source) {
		if unicode.IsSpace(rune(source[offset])) {
			offset++
			continue
		}
		if strings.HasPrefix(source[offset:], "//") {
			if newline := strings.IndexByte(source[offset+2:], '\n'); newline >= 0 {
				offset += newline + 3
				continue
			}
			return len(source)
		}
		if strings.HasPrefix(source[offset:], "/*") {
			if end := strings.Index(source[offset+2:], "*/"); end >= 0 {
				offset += end + 4
				continue
			}
			return len(source)
		}
		break
	}
	return offset
}

func matchingJavaDelimiter(source string, open int, opening, closing byte) int {
	return lexical.MatchingDelimiter(source, open, string(opening), string(closing), false)
}

func splitJavaCallArguments(value string) []string {
	return lexical.SplitTopLevel(value, ",", false)
}

func innermostJavaType(symbols []analysis.Symbol, at int) (analysis.Symbol, bool) {
	var best analysis.Symbol
	found := false
	for _, symbol := range symbols {
		if !analysis.IsTypeKind(symbol.Kind) || symbol.StartByte > at || symbol.EndByte < at {
			continue
		}
		if !found || symbol.StartByte >= best.StartByte && symbol.EndByte <= best.EndByte {
			best, found = symbol, true
		}
	}
	return best, found
}

func innermostJavaCallable(symbols []analysis.Symbol, at int) (analysis.Symbol, bool) {
	var best analysis.Symbol
	found := false
	for _, symbol := range symbols {
		if symbol.Kind != analysis.KindMethod && symbol.Kind != analysis.KindConstructor && symbol.Kind != analysis.KindFunction || symbol.StartByte > at || symbol.EndByte < at {
			continue
		}
		if !found || symbol.StartByte >= best.StartByte && symbol.EndByte <= best.EndByte {
			best, found = symbol, true
		}
	}
	return best, found
}

func inferredJavaCreatedReturnType(source string, callStart, callEnd int, callable analysis.Symbol, inCallable bool, symbols []analysis.Symbol, idx *index.Index, uri protocol.URI) (string, bool) {
	statementStart := strings.LastIndexAny(source[:callStart], ";{}") + 1
	prefix := strings.TrimSpace(source[statementStart:callStart])
	after := skipJavaSpaceAndComments(source, callEnd+1)
	if prefix == "" && after < len(source) && source[after] == ';' {
		return "void", true
	}
	if strings.HasSuffix(prefix, "return") && inCallable && callable.Type != "" {
		return callable.Type, true
	}
	declaration := regexp.MustCompile(`(?s)([A-Za-z_$][A-Za-z0-9_$.<>?\[\], ]*)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*$`)
	if match := declaration.FindStringSubmatch(prefix); len(match) == 2 {
		typ := strings.TrimSpace(match[1])
		if typ != "var" {
			return typ, true
		}
	}
	if equals := strings.LastIndex(prefix, "="); equals >= 0 {
		name := strings.TrimSpace(prefix[:equals])
		if at := strings.LastIndexAny(name, " \t\n"); at >= 0 {
			name = name[at+1:]
		}
		if typ := javaSymbolType(name, callStart, symbols, idx, uri); typ != "" {
			return typ, true
		}
	}
	return "", false
}

func inferredJavaCreatedParameter(argument string, at int, symbols []analysis.Symbol, idx *index.Index, uri protocol.URI) (string, string, bool) {
	argument = strings.TrimSpace(argument)
	if argument == "true" || argument == "false" {
		return "boolean", "value", true
	}
	if argument == "null" {
		return "", "", false
	}
	if strings.HasPrefix(argument, "\"") {
		return "String", "value", true
	}
	if strings.HasPrefix(argument, "'") {
		return "char", "value", true
	}
	if regexp.MustCompile(`^[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)[lL]$`).MatchString(argument) {
		return "long", "value", true
	}
	if regexp.MustCompile(`^[+-]?(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*|[0-9][0-9_]*[eE][+-]?[0-9_]+)[fF]$`).MatchString(argument) {
		return "float", "value", true
	}
	if regexp.MustCompile(`^[+-]?(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*|[0-9][0-9_]*[eE][+-]?[0-9_]+)[dD]?$`).MatchString(argument) {
		return "double", "value", true
	}
	if regexp.MustCompile(`^[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)$`).MatchString(argument) {
		return "int", "value", true
	}
	if match := regexp.MustCompile(`^new\s+([A-Za-z_$][A-Za-z0-9_$.<>?\[\]]*)`).FindStringSubmatch(argument); len(match) == 2 {
		return match[1], "value", true
	}
	if match := regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]*)$`).FindStringSubmatch(argument); len(match) == 2 {
		if typ := javaSymbolType(match[1], at, symbols, idx, uri); typ != "" {
			return typ, match[1], true
		}
		return "", match[1], false
	}
	return "", "value", false
}

func javaSymbolType(name string, at int, symbols []analysis.Symbol, idx *index.Index, uri protocol.URI) string {
	var best analysis.Symbol
	found := false
	for _, symbol := range symbols {
		if symbol.Name != name || symbol.NameStartByte >= at || symbol.ScopeStartByte > at || symbol.ScopeEndByte < at {
			continue
		}
		if !found || symbol.NameStartByte > best.NameStartByte {
			best, found = symbol, true
		}
	}
	if !found {
		return ""
	}
	if best.Type != "" && best.Type != "var" {
		return best.Type
	}
	return idx.InferredType(uri, best.ID)
}

func javaLineIndent(source string, offset int) string {
	lineStart := strings.LastIndexByte(source[:offset], '\n') + 1
	end := lineStart
	for end < offset && (source[end] == ' ' || source[end] == '\t') {
		end++
	}
	return source[lineStart:end]
}

func diagnosticQuickFix(uri protocol.URI, source string, diagnostic protocol.Diagnostic) (protocol.CodeAction, bool) {
	code := fmt.Sprint(diagnostic.Code)
	if code != "unused-import" && code != "duplicate-import" && code != "unresolved-import" {
		return protocol.CodeAction{}, false
	}
	r := diagnostic.Range
	lines := strings.Split(source, "\n")
	if r.Start.Line < 0 || r.Start.Line >= len(lines) {
		return protocol.CodeAction{}, false
	}
	r.Start.Character = 0
	r.End.Line = r.Start.Line + 1
	r.End.Character = 0
	if r.End.Line >= len(lines) {
		r.End.Line = r.Start.Line
		r.End.Character = utf16Len(lines[r.Start.Line])
	}
	return protocol.CodeAction{Title: "Remove import", Kind: "quickfix", Diagnostics: []protocol.Diagnostic{diagnostic}, IsPreferred: true, Edit: &protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: {{Range: r, NewText: ""}}}}}, true
}

func diagnosticCandidates(diagnostic protocol.Diagnostic) []string {
	data, ok := diagnostic.Data.(map[string]any)
	if !ok {
		return nil
	}
	if values, ok := data["candidates"].([]string); ok {
		return values
	}
	values, ok := data["candidates"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func addImportEdit(source string, uri protocol.URI, fqn string) (protocol.TextEdit, bool) {
	java := strings.HasSuffix(strings.ToLower(string(uri)), ".java")
	line := "import " + fqn
	if java {
		line += ";"
	}
	line += "\n"
	lines := strings.Split(source, "\n")
	insertLine := 0
	for n, existing := range lines {
		trim := strings.TrimSpace(existing)
		if strings.HasPrefix(trim, "package ") || strings.HasPrefix(trim, "import ") {
			insertLine = n + 1
		}
		if trim == strings.TrimSpace(line) {
			return protocol.TextEdit{}, false
		}
	}
	if insertLine > 0 && insertLine <= len(lines) && strings.HasPrefix(strings.TrimSpace(lines[insertLine-1]), "package ") {
		line = "\n" + line
	}
	position := protocol.Position{Line: insertLine}
	return protocol.TextEdit{Range: protocol.Range{Start: position, End: position}, NewText: line}, true
}

func utf16Len(text string) int {
	n := 0
	for _, r := range text {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func (s *Server) codeLens(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	if !s.runMainCodeLens.Load() {
		return []protocol.CodeLens{}, nil
	}
	ctx := operationContext(contexts)
	symbols := s.index.SymbolsInFile(p.TextDocument.URI)
	out := make([]protocol.CodeLens, 0)
	for index, sym := range symbols {
		if index&255 == 0 {
			if responseErr := canceledResponse(ctx); responseErr != nil {
				return nil, responseErr
			}
		}
		if !s.isRunnableMain(sym) {
			continue
		}
		mainClass := s.mainClass(sym)
		if mainClass == "" {
			continue
		}
		for _, lens := range []struct {
			title   string
			noDebug bool
		}{{"Run", true}, {"Debug", false}} {
			arguments := map[string]any{"mainClass": mainClass, "uri": sym.URI, "noDebug": lens.noDebug}
			out = append(out, protocol.CodeLens{Range: sym.SelectionRange, Command: &protocol.Command{Title: lens.title, Command: "intellij_debugger.runMain", Arguments: []any{arguments}}})
		}
	}
	return out, nil
}

func (s *Server) isRunnableMain(sym analysis.Symbol) bool {
	if sym.Name != "main" || sym.Kind != analysis.KindFunction && sym.Kind != analysis.KindMethod {
		return false
	}
	if sym.Type != "" && sym.Type != "void" && sym.Type != "Unit" {
		return false
	}
	validParameters := len(sym.Parameters) == 0
	if len(sym.Parameters) == 1 {
		typeName := strings.ReplaceAll(sym.Parameters[0].Type, " ", "")
		if sym.Language == analysis.LanguageJava {
			validParameters = typeName == "String[]" || typeName == "java.lang.String[]" || typeName == "String..."
		} else {
			validParameters = typeName == "Array<String>" || typeName == "Array<outString>" || typeName == "kotlin.Array<String>"
		}
	}
	if !validParameters {
		return false
	}
	if sym.Language == analysis.LanguageJava {
		return sym.Kind == analysis.KindMethod && sym.ContainerID != "" && hasModifier(sym, "public") && hasModifier(sym, "static") && len(sym.Parameters) == 1
	}
	if sym.ContainerID == "" {
		return true
	}
	owner, ok := s.index.Symbol(sym.ContainerID)
	if !ok || owner.Kind != analysis.KindObject {
		return false
	}
	if hasModifier(owner, "companion") {
		return hasModifier(sym, "JvmStatic")
	}
	return true
}

func hasModifier(symbol analysis.Symbol, modifier string) bool {
	for _, candidate := range symbol.Modifiers {
		if candidate == modifier {
			return true
		}
	}
	return false
}

func (s *Server) mainClass(sym analysis.Symbol) string {
	if sym.Language == analysis.LanguageJava {
		if sym.ContainerID == "" {
			return ""
		}
		owner, ok := s.index.Symbol(sym.ContainerID)
		if !ok || !analysis.IsTypeKind(owner.Kind) {
			return ""
		}
		return s.binaryTypeName(owner)
	}
	if sym.ContainerID != "" {
		owner, ok := s.index.Symbol(sym.ContainerID)
		if ok && analysis.IsTypeKind(owner.Kind) {
			if hasModifier(owner, "companion") && owner.ContainerID != "" {
				if outer, outerOK := s.index.Symbol(owner.ContainerID); outerOK && analysis.IsTypeKind(outer.Kind) {
					return s.binaryTypeName(outer)
				}
			}
			return s.binaryTypeName(owner)
		}
	}
	base := kotlinFileFacadeName(s.index, sym.URI)
	if sym.Package != "" {
		return sym.Package + "." + base
	}
	return base
}

func (s *Server) binaryTypeName(symbol analysis.Symbol) string {
	names := []string{symbol.Name}
	current := symbol
	for current.ContainerID != "" {
		parent, ok := s.index.Symbol(current.ContainerID)
		if !ok || !analysis.IsTypeKind(parent.Kind) {
			break
		}
		names = append(names, parent.Name)
		current = parent
	}
	for left, right := 0, len(names)-1; left < right; left, right = left+1, right-1 {
		names[left], names[right] = names[right], names[left]
	}
	result := strings.Join(names, "$")
	if current.Package != "" {
		result = current.Package + "." + result
	}
	return result
}

var kotlinJVMNamePattern = regexp.MustCompile(`(?m)@file:(?:kotlin\.jvm\.)?JvmName\s*\(\s*"([^"]+)"\s*\)`)

func kotlinFileFacadeName(idx *index.Index, uri protocol.URI) string {
	if doc, ok := idx.Document(uri); ok {
		if match := kotlinJVMNamePattern.FindStringSubmatch(doc.Text); len(match) == 2 {
			return sanitizeJVMIdentifier(match[1])
		}
	}
	base := strings.TrimSuffix(uriutil.Base(uri), filepath.Ext(uriutil.Base(uri)))
	base = sanitizeJVMIdentifier(base)
	if base == "" {
		base = "_"
	}
	runes := []rune(base)
	if runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] -= 'a' - 'A'
	}
	return string(runes) + "Kt"
}

func sanitizeJVMIdentifier(value string) string {
	var out strings.Builder
	for index, r := range value {
		valid := r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || index > 0 && r >= '0' && r <= '9'
		if valid {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

func (s *Server) inlayHints(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	ctx := operationContext(contexts)
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
		Range        protocol.Range                  `json:"range"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	_, ok := s.index.DocumentContext(ctx, p.TextDocument.URI)
	if !ok {
		return []protocol.InlayHint{}, nil
	}
	file, ok := s.index.Parsed(p.TextDocument.URI)
	if !ok {
		return []protocol.InlayHint{}, nil
	}
	out := make([]protocol.InlayHint, 0)
	for _, sym := range file.Symbols {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		if sym.Type != "" && sym.Type != "var" || sym.Kind != analysis.KindVariable && sym.Kind != analysis.KindProperty {
			continue
		}
		if before(sym.SelectionRange.End, p.Range.Start) || before(p.Range.End, sym.SelectionRange.Start) {
			continue
		}
		value := s.index.InferredType(p.TextDocument.URI, sym.ID)
		if value != "" {
			out = append(out, protocol.InlayHint{Position: sym.SelectionRange.End, Label: ": " + value, Kind: 1, PaddingLeft: false, PaddingRight: true, Data: map[string]string{"symbolId": sym.ID}})
		}
	}
	for _, parameter := range s.index.ParameterHintsContext(ctx, p.TextDocument.URI, p.Range) {
		out = append(out, protocol.InlayHint{
			Position: parameter.Position, Label: parameter.Label, Kind: 2, PaddingRight: true,
			Data: map[string]any{"symbolId": parameter.Callable.ID, "parameter": parameter.ParameterIndex},
		})
	}
	if file.Language == analysis.LanguageJava {
		for _, parameter := range s.index.JavaLambdaParameterHintsContext(ctx, p.TextDocument.URI, p.Range) {
			out = append(out, protocol.InlayHint{Position: parameter.Position, Label: parameter.Label, Kind: 1, PaddingRight: true,
				Data: map[string]any{"symbolId": parameter.Callable.ID, "javaLambdaParameter": parameter.ParameterIndex}})
		}
		for _, reference := range file.References {
			if responseErr := canceledResponse(ctx); responseErr != nil {
				return nil, responseErr
			}
			if reference.Role != analysis.RoleCall || reference.Qualifier == "" || !strings.Contains(reference.Qualifier, "\n") || before(reference.Range.End, p.Range.Start) || before(p.Range.End, reference.Range.Start) {
				continue
			}
			definitions := s.index.DefinitionsContext(ctx, p.TextDocument.URI, reference.Range.Start)
			if len(definitions) == 1 && definitions[0].Type != "" && definitions[0].Type != "void" {
				out = append(out, protocol.InlayHint{Position: reference.Range.End, Label: ": " + definitions[0].Type, Kind: 1, PaddingLeft: true, Data: map[string]any{"symbolId": definitions[0].ID, "methodChain": true}})
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return before(out[a].Position, out[b].Position) })
	return out, nil
}

func splitCommaTypes(value string) []string {
	return lexical.SplitTopLevelTypes(value, ",", true)
}

func (s *Server) resolveInlayHint(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var hint protocol.InlayHint
	if err := decode(raw, &hint); err != nil {
		return nil, invalidParams(err)
	}
	if hint.Tooltip == nil {
		if data, ok := hint.Data.(map[string]any); ok {
			if id, ok := data["symbolId"].(string); ok {
				if symbol, ok := s.index.Symbol(id); ok {
					hint.Tooltip = protocol.MarkupContent{Kind: "markdown", Value: "Parameter of `" + symbol.DisplaySignature() + "`"}
				}
			}
		}
		if hint.Tooltip == nil {
			hint.Tooltip = protocol.MarkupContent{Kind: "markdown", Value: "Inferred type"}
		}
	}
	return hint, nil
}

func (s *Server) signatureHelp(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	ctx := operationContext(contexts)
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	doc, ok := s.index.DocumentContext(ctx, p.TextDocument.URI)
	if !ok {
		return nil, nil
	}
	offset := doc.Offset(p.Position)
	name, namePos, active := callAt(doc.Text, offset)
	if name == "" {
		return nil, nil
	}
	symbols, activeSignature := s.index.CallSignaturesContext(ctx, p.TextDocument.URI, doc.Position(namePos))
	if len(symbols) == 0 {
		symbols = s.index.DefinitionsContext(ctx, p.TextDocument.URI, doc.Position(namePos))
	}
	if len(symbols) == 0 {
		symbols = s.index.CallablesNamedContext(ctx, p.TextDocument.URI, doc.Position(namePos), name, 64)
	}
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	sigs := make([]protocol.SignatureInformation, 0)
	activeName := namedArgumentNameAt(doc.Text, namePos+len(name), offset)
	mappedActive := false
	for _, sym := range symbols {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		if sym.Name != name || !analysis.IsCallableKind(sym.Kind) {
			continue
		}
		parameterLabels := make([]string, 0, len(sym.Parameters))
		for _, parameter := range sym.Parameters {
			label := parameter.Name
			if parameter.Type != "" {
				typ := parameter.Type
				if doc.LanguageID == "kotlin" && sym.Language == analysis.LanguageJava {
					typ = index.KotlinDisplayType(typ)
				}
				if doc.LanguageID == "java" && sym.Language == analysis.LanguageJava {
					label = typ + " " + parameter.Name
				} else {
					label += ": " + typ
				}
			}
			if parameter.Default != "" {
				label += " = " + parameter.Default
			}
			parameterLabels = append(parameterLabels, label)
		}
		if activeName != "" && !mappedActive {
			for index, parameter := range sym.Parameters {
				if parameter.Name == activeName {
					active, mappedActive = index, true
					break
				}
			}
		}
		label := sym.DisplaySignature()
		if doc.LanguageID == "kotlin" && sym.Language == analysis.LanguageJava && !strings.HasPrefix(label, "fun ") {
			label = kotlinJavaSignatureLabel(sym)
		}
		params := make([]protocol.ParameterInformation, 0, len(parameterLabels))
		search := 0
		for _, parameterLabel := range parameterLabels {
			if relative := strings.Index(label[search:], parameterLabel); relative >= 0 {
				start := search + relative
				params = append(params, protocol.ParameterInformation{Label: []int{start, start + len(parameterLabel)}})
				search = start + len(parameterLabel)
			} else {
				params = append(params, protocol.ParameterInformation{Label: parameterLabel})
			}
		}
		signatureActive := active
		if signatureActive >= len(params) && len(params) > 0 {
			signatureActive = len(params) - 1
		}
		sigs = append(sigs, protocol.SignatureInformation{Label: label, Documentation: documentation(sym), Parameters: params, ActiveParam: &signatureActive})
	}
	if len(sigs) == 0 {
		return nil, nil
	}
	if active >= len(sigs[0].Parameters) && len(sigs[0].Parameters) > 0 {
		active = len(sigs[0].Parameters) - 1
	}
	var rootActive any
	if active > 0 || doc.LanguageID == "java" {
		rootActive = active
	}
	return protocol.SignatureHelp{Signatures: sigs, ActiveSignature: activeSignature, ActiveParameter: rootActive}, nil
}

func kotlinJavaSignatureLabel(symbol analysis.Symbol) string {
	var label strings.Builder
	if symbol.Kind == analysis.KindConstructor {
		label.WriteString(symbol.Name)
	} else {
		label.WriteString("fun ")
		label.WriteString(symbol.Name)
	}
	label.WriteByte('(')
	for parameterIndex, parameter := range symbol.Parameters {
		if parameterIndex > 0 {
			label.WriteString(", ")
		}
		label.WriteString(parameter.Name)
		if parameter.Type != "" {
			label.WriteString(": ")
			label.WriteString(index.KotlinDisplayType(parameter.Type))
		}
	}
	label.WriteByte(')')
	if resultType := index.KotlinDisplayType(symbol.Type); symbol.Kind != analysis.KindConstructor && resultType != "" && resultType != "Unit" {
		label.WriteString(": ")
		label.WriteString(resultType)
	}
	return label.String()
}

func (s *Server) prepareHierarchy(raw json.RawMessage, typeHierarchy bool, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	ctx := operationContext(contexts)
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	sym, _, ok := s.index.SymbolAtContext(ctx, p.TextDocument.URI, p.Position)
	if !ok {
		return nil, nil
	}
	if typeHierarchy && !analysis.IsTypeKind(sym.Kind) {
		defs := s.index.TypeDefinitionsContext(ctx, p.TextDocument.URI, p.Position)
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		if len(defs) == 0 {
			return nil, nil
		}
		items := make([]protocol.CallHierarchyItem, 0, len(defs))
		seen := make(map[string]bool, len(defs))
		for _, definition := range defs {
			if analysis.IsTypeKind(definition.Kind) && !seen[definition.ID] {
				seen[definition.ID] = true
				items = append(items, s.hierarchyItemContext(ctx, definition))
			}
		}
		if len(items) == 0 {
			return nil, nil
		}
		return items, nil
	}
	if !typeHierarchy && !analysis.IsCallableKind(sym.Kind) && !analysis.IsTypeKind(sym.Kind) {
		return nil, nil
	}
	return []protocol.CallHierarchyItem{s.hierarchyItemContext(ctx, sym)}, nil
}

func (s *Server) incomingCalls(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p struct {
		Item protocol.CallHierarchyItem `json:"item"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	target, ok := s.symbolFromHierarchy(p.Item)
	if !ok {
		return []protocol.CallHierarchyIncomingCall{}, nil
	}
	ctx := operationContext(contexts)
	calls := s.index.CallsToContext(ctx, target)
	out := make([]protocol.CallHierarchyIncomingCall, 0, len(calls))
	for id, refs := range calls {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		caller, ok := s.index.Symbol(id)
		if !ok {
			continue
		}
		ranges := make([]protocol.Range, len(refs))
		for n := range refs {
			ranges[n] = refs[n].Range
		}
		out = append(out, protocol.CallHierarchyIncomingCall{From: s.hierarchyItemContext(ctx, caller), FromRanges: ranges})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].From.Name < out[b].From.Name })
	return out, nil
}

func (s *Server) outgoingCalls(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p struct {
		Item protocol.CallHierarchyItem `json:"item"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	caller, ok := s.symbolFromHierarchy(p.Item)
	if !ok {
		return []protocol.CallHierarchyOutgoingCall{}, nil
	}
	ctx := operationContext(contexts)
	calls := s.index.CallsFromContext(ctx, caller)
	out := make([]protocol.CallHierarchyOutgoingCall, 0, len(calls))
	for id, refs := range calls {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		target, ok := s.index.Symbol(id)
		if !ok {
			continue
		}
		ranges := make([]protocol.Range, len(refs))
		for n := range refs {
			ranges[n] = refs[n].Range
		}
		out = append(out, protocol.CallHierarchyOutgoingCall{To: s.hierarchyItemContext(ctx, target), FromRanges: ranges})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].To.Name < out[b].To.Name })
	return out, nil
}

func (s *Server) typeHierarchy(raw json.RawMessage, supertypes bool, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p struct {
		Item protocol.TypeHierarchyItem `json:"item"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	sym, ok := s.symbolFromHierarchy(p.Item)
	if !ok {
		return []protocol.TypeHierarchyItem{}, nil
	}
	var symbols []analysis.Symbol
	ctx := operationContext(contexts)
	if supertypes {
		symbols = s.index.SupertypesContext(ctx, sym)
	} else {
		symbols = s.index.SubtypesContext(ctx, sym)
	}
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	out := make([]protocol.TypeHierarchyItem, 0, len(symbols))
	for _, x := range symbols {
		out = append(out, s.hierarchyItemContext(ctx, x))
	}
	return out, nil
}

func (s *Server) willRenameFiles(raw json.RawMessage, contexts ...context.Context) (any, *jsonrpc.ResponseError) {
	var p struct {
		Files []protocol.FileRename `json:"files"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	ctx := operationContext(contexts)
	combined := protocol.WorkspaceEdit{Changes: make(map[protocol.URI][]protocol.TextEdit)}
	type packageMove struct{ oldPackage, newPackage string }
	packageMoves := make([]packageMove, 0)
	packageMoveSeen := make(map[packageMove]bool)
	var workspaceFiles []*analysis.ParsedFile
	loadWorkspaceFiles := func() *jsonrpc.ResponseError {
		if workspaceFiles != nil {
			return nil
		}
		var truncated bool
		workspaceFiles, truncated = s.index.WorkspaceFilesContext(ctx, 10_000)
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return responseErr
		}
		if truncated {
			return &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "file-rename analysis exceeds its 10000-file safety limit"}
		}
		return nil
	}
	addPackageEdit := func(file *analysis.ParsedFile, relocatedPath string) {
		newPackage := relocatedPackage(mustFilePath(file.URI), relocatedPath, file.Package)
		if newPackage == file.Package {
			return
		}
		move := packageMove{file.Package, newPackage}
		if !packageMoveSeen[move] {
			packageMoveSeen[move] = true
			packageMoves = append(packageMoves, move)
		}
		if file.Package != "" && file.PackageRange.Start != file.PackageRange.End {
			text := "package " + newPackage
			if file.Language == analysis.LanguageJava {
				text += ";"
			}
			combined.Changes[file.URI] = append(combined.Changes[file.URI], protocol.TextEdit{Range: file.PackageRange, NewText: text})
		}
	}
	for _, f := range p.Files {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		oldPath, oldOK := uriutil.Path(f.OldURI)
		newPath, newOK := uriutil.Path(f.NewURI)
		if oldOK && newOK {
			if file, exists := s.index.Parsed(f.OldURI); exists {
				addPackageEdit(file, newPath)
			} else {
				if responseErr := loadWorkspaceFiles(); responseErr != nil {
					return nil, responseErr
				}
				for _, file := range workspaceFiles {
					filePath, ok := uriutil.Path(file.URI)
					if !ok || filePath != oldPath && !strings.HasPrefix(filePath, oldPath+string(filepath.Separator)) {
						continue
					}
					addPackageEdit(file, newPath+strings.TrimPrefix(filePath, oldPath))
				}
			}
		}
		oldBase := strings.TrimSuffix(uriutil.Base(f.OldURI), filepath.Ext(uriutil.Base(f.OldURI)))
		newBase := strings.TrimSuffix(uriutil.Base(f.NewURI), filepath.Ext(uriutil.Base(f.NewURI)))
		if oldBase == newBase {
			continue
		}
		symbols := s.index.SymbolsInFile(f.OldURI)
		for _, sym := range symbols {
			if sym.Name == oldBase && analysis.IsTypeKind(sym.Kind) {
				edit := s.index.RenameContext(ctx, f.OldURI, sym.SelectionRange.Start, newBase)
				for u, edits := range edit.Changes {
					combined.Changes[u] = append(combined.Changes[u], edits...)
				}
			}
		}
	}
	for _, moved := range packageMoves {
		if responseErr := canceledResponse(ctx); responseErr != nil {
			return nil, responseErr
		}
		if moved.oldPackage == "" {
			continue
		}
		importing, truncated := s.index.FilesImportingPrefixContext(ctx, moved.oldPackage, 10_000)
		if truncated {
			return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "file-rename importer analysis exceeds its 10000-file safety limit"}
		}
		for _, file := range importing {
			for _, imported := range file.Imports {
				if moved.oldPackage == "" || imported.Path != moved.oldPackage && !strings.HasPrefix(imported.Path, moved.oldPackage+".") {
					continue
				}
				path := moved.newPackage + strings.TrimPrefix(imported.Path, moved.oldPackage)
				combined.Changes[file.URI] = append(combined.Changes[file.URI], protocol.TextEdit{Range: imported.Range, NewText: renderImport(path, imported, file.Language)})
			}
		}
		if responseErr := loadWorkspaceFiles(); responseErr != nil {
			return nil, responseErr
		}
		for _, file := range workspaceFiles {
			if responseErr := canceledResponse(ctx); responseErr != nil {
				return nil, responseErr
			}
			doc, ok := s.index.DocumentContext(ctx, file.URI)
			if !ok {
				continue
			}
			if len(file.References) > 500_000 {
				return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "file-rename reference analysis exceeds its per-file safety limit"}
			}
			for referenceIndex, reference := range file.References {
				if referenceIndex&255 == 0 {
					if responseErr := canceledResponse(ctx); responseErr != nil {
						return nil, responseErr
					}
				}
				if reference.Role == analysis.RoleImport {
					continue
				}
				target, _, resolved := s.index.SymbolAtContext(ctx, file.URI, reference.Range.Start)
				if !resolved || target.Package != moved.oldPackage && !strings.HasPrefix(target.Package, moved.oldPackage+".") {
					continue
				}
				start, found := qualifiedPackagePrefix(doc.Text, reference.StartByte, moved.oldPackage)
				if !found {
					continue
				}
				edit := protocol.TextEdit{Range: doc.Range(start, start+len(moved.oldPackage)), NewText: moved.newPackage}
				combined.Changes[file.URI] = appendUniqueEdit(combined.Changes[file.URI], edit)
			}
		}
	}
	return combined, nil
}

func qualifiedPackagePrefix(source string, referenceStart int, packageName string) (int, bool) {
	if referenceStart <= 0 || referenceStart > len(source) || packageName == "" {
		return 0, false
	}
	index := referenceStart - 1
	for index >= 0 && (source[index] == ' ' || source[index] == '\t' || source[index] == '\r' || source[index] == '\n') {
		index--
	}
	if index < 0 || source[index] != '.' {
		return 0, false
	}
	index--
	end := index + 1
	for index >= 0 {
		value := source[index]
		if value == '_' || value == '$' || value == '.' || value == '`' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
			index--
			continue
		}
		break
	}
	start := index + 1
	qualifier := strings.Trim(source[start:end], ".`")
	if qualifier != packageName && !strings.HasPrefix(qualifier, packageName+".") {
		return 0, false
	}
	return start, true
}

func appendUniqueEdit(edits []protocol.TextEdit, edit protocol.TextEdit) []protocol.TextEdit {
	for _, existing := range edits {
		if existing.Range == edit.Range && existing.NewText == edit.NewText {
			return edits
		}
	}
	return append(edits, edit)
}

func mustFilePath(uri protocol.URI) string {
	path, _ := uriutil.Path(uri)
	return path
}

func relocatedPackage(oldFile, newFile, oldPackage string) string {
	if oldPackage == "" {
		return oldPackage
	}
	if filepath.Clean(filepath.Dir(oldFile)) == filepath.Clean(filepath.Dir(newFile)) {
		return oldPackage
	}
	sourceRoot := filepath.Dir(oldFile)
	for range strings.Split(oldPackage, ".") {
		sourceRoot = filepath.Dir(sourceRoot)
	}
	relative, err := filepath.Rel(sourceRoot, filepath.Dir(newFile))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return oldPackage
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return oldPackage
		}
	}
	return strings.Join(parts, ".")
}

func renderImport(path string, imported analysis.Import, language analysis.Language) string {
	var text strings.Builder
	text.WriteString("import ")
	if imported.Static && language == analysis.LanguageJava {
		text.WriteString("static ")
	}
	text.WriteString(path)
	if imported.Wildcard {
		text.WriteString(".*")
	}
	if imported.Alias != "" {
		text.WriteString(" as ")
		text.WriteString(imported.Alias)
	}
	if language == analysis.LanguageJava {
		text.WriteByte(';')
	}
	return text.String()
}

func (s *Server) executeCommand(ctx context.Context, raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.ExecuteCommandParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	switch p.Command {
	case "decompile":
		return s.decompileCommand(ctx, p.Arguments)
	case "intellij.java.resolveClassDocument":
		return s.resolveClassDocumentCommand(p.Arguments)
	case "java.organize.imports", "kotlin.organize.imports":
		return s.organizeImportsCommand(ctx, p.Arguments)
	case "intellij.java.resolveJavaExecutable":
		javaExec := ""
		if len(p.Arguments) > 0 {
			var argument struct {
				URI protocol.URI `json:"uri"`
			}
			if json.Unmarshal(p.Arguments[0], &argument) == nil && argument.URI != "" {
				if module, found := s.index.ModuleFor(argument.URI); found && module.JavaHome != "" {
					javaExec = javaExecutableInHome(module.JavaHome)
				}
			}
		}
		if javaExec == "" {
			javaExec = s.configuredJavaExecutable()
		}
		if javaExec == "" {
			javaExec = javaExecutable()
		}
		if javaExec == "" {
			return nil, &jsonrpc.ResponseError{Code: -32803, Message: "No JDK configured for the project"}
		}
		return map[string]any{"javaExec": javaExec}, nil
	case "intellij.java.resolveWorkingDirectory":
		return s.resolveWorkingDirectoryCommand(p.Arguments)
	case "intellij.java.resolveClasspath":
		// Launch/debug clients build their classpath from this command. During
		// the initial workspace scan the module classpaths are still empty, so
		// answering immediately would hand the debuggee a classpath of just its
		// own output directories and it would die on the first missing class.
		// Block until the scan lands instead; bounded by the request context.
		s.index.WaitForLibraries(ctx)
		uri, responseErr := s.commandDocumentURI(p.Arguments)
		if responseErr != nil {
			return nil, responseErr
		}
		classpath, modulePath, moduleName := s.index.ClasspathFor(uri)
		// Launch/debug clients need the runtime classpath: runtimeOnly
		// dependencies (JDBC drivers, devtools) are absent from the compile
		// classpath that ClasspathFor reports.
		if runtime := s.index.RuntimeClasspathFor(uri); len(runtime) > 0 {
			seen := make(map[string]bool, len(classpath))
			for _, entry := range classpath {
				seen[entry] = true
			}
			for _, entry := range runtime {
				if !seen[entry] {
					classpath = append(classpath, entry)
				}
			}
			sort.Strings(classpath)
		}
		return map[string]any{"classpath": classpath, "modulePath": modulePath, "moduleName": moduleName}, nil
	case "set-highwatermark-file":
		if len(p.Arguments) != 1 {
			return nil, invalidParams(fmt.Errorf("expected exactly one file path"))
		}
		var path string
		if err := json.Unmarshal(p.Arguments[0], &path); err != nil || path == "" {
			return nil, invalidParams(fmt.Errorf("expected a file path"))
		}
		s.rootMu.Lock()
		s.watermarkPath = filepath.Clean(path)
		s.rootMu.Unlock()
		s.watermark.Store(0)
		s.refreshWatermarkFile()
		return nil, nil
	case "wait-for-highwatermark":
		if len(p.Arguments) != 1 {
			return nil, invalidParams(fmt.Errorf("expected exactly one timestamp"))
		}
		var timestamp int64
		if err := json.Unmarshal(p.Arguments[0], &timestamp); err != nil {
			return nil, invalidParams(fmt.Errorf("expected a timestamp number"))
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for s.watermark.Load() < timestamp {
			s.refreshWatermarkFile()
			select {
			case <-ctx.Done():
				return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "request cancelled"}
			case <-ticker.C:
			}
		}
		return nil, nil
	case "exportWorkspace":
		return s.exportWorkspace(ctx, p.Arguments)
	case "applyModCommand":
		return s.applyModCommand(ctx, p.Arguments)
	case "chooseModCommandAction":
		return s.chooseModCommandAction(ctx, p.Arguments)
	case "interpolateFileTemplate":
		return s.interpolateFileTemplate(p.Arguments)
	case "jetbrains.java.completion.apply", "jetbrains.kotlin.completion.apply":
		return s.applyCompletionCommand(ctx, p.Command, p.Arguments)
	case "start_debug_server":
		port, err := s.startDAP()
		if err != nil {
			return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: "start debug server: " + err.Error()}
		}
		return port, nil
	case "refactor.extract.variable", "refactor.extract.function", "refactor.extract.field", "refactor.extract.constant":
		return s.extractRefactorCommand(ctx, p.Command, p.Arguments)
	default:
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.MethodNotFound, Message: "unsupported command: " + p.Command}
	}
}

func (s *Server) commandDocumentURI(args []json.RawMessage) (protocol.URI, *jsonrpc.ResponseError) {
	if len(args) == 0 {
		return "", invalidParams(fmt.Errorf("missing required argument: uri"))
	}
	var payload struct {
		URI protocol.URI `json:"uri"`
	}
	if json.Unmarshal(args[0], &payload) != nil || payload.URI == "" {
		return "", invalidParams(fmt.Errorf("missing required argument: uri"))
	}
	if _, ok := s.index.Parsed(payload.URI); !ok {
		return "", &jsonrpc.ResponseError{Code: -32803, Message: "No file found for uri: '" + string(payload.URI) + "'"}
	}
	return payload.URI, nil
}

func (s *Server) extractRefactorCommand(ctx context.Context, command string, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	var payload struct {
		URI          protocol.URI   `json:"uri"`
		Range        protocol.Range `json:"range"`
		TextDocument struct {
			URI protocol.URI `json:"uri"`
		} `json:"textDocument"`
	}
	choice := ""
	switch len(args) {
	case 2:
		// Exact OpenKotlin wire format: [DocumentUri, Payload.Data].
		if err := json.Unmarshal(args[0], &payload.URI); err != nil || payload.URI == "" {
			return nil, invalidParams(fmt.Errorf("invalid refactoring document URI"))
		}
		var data struct {
			Type      string         `json:"type"`
			Selection protocol.Range `json:"selection"`
			Choice    string         `json:"choice"`
			Message   string         `json:"message"`
		}
		if err := json.Unmarshal(args[1], &data); err != nil {
			return nil, invalidParams(fmt.Errorf("invalid refactoring payload: %w", err))
		}
		if strings.HasSuffix(data.Type, "Payload.Error") || strings.EqualFold(data.Type, "Error") {
			if s.conn != nil {
				_ = s.conn.Notify("window/showMessage", map[string]any{"type": 1, "message": data.Message})
			}
			return true, nil
		}
		payload.Range, choice = data.Selection, data.Choice
	case 1:
		// Backward compatibility with early kotlsp actions.
		if err := json.Unmarshal(args[0], &payload); err != nil {
			return nil, invalidParams(fmt.Errorf("invalid refactoring payload: %w", err))
		}
		if payload.URI == "" {
			payload.URI = payload.TextDocument.URI
		}
	default:
		return nil, invalidParams(fmt.Errorf("expected document URI and refactoring payload"))
	}
	doc, ok := s.index.DocumentContext(ctx, payload.URI)
	if !ok || payload.Range.Start == payload.Range.End {
		return nil, invalidParams(fmt.Errorf("refactoring requires a document URI and non-empty range"))
	}
	start, end := doc.Offset(payload.Range.Start), doc.Offset(payload.Range.End)
	if start < 0 || end <= start || end > len(doc.Text) {
		return nil, invalidParams(fmt.Errorf("refactoring range is outside the document"))
	}
	for _, action := range s.extractActions(payload.URI, payload.Range, doc, doc.Text[start:end], ctx) {
		if action.Kind == command && action.Edit != nil && (choice == "" || choice == action.Title) {
			if err := s.applyWorkspaceEdit(ctx, action.Title, *action.Edit); err != nil {
				return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
			}
			return true, nil
		}
	}
	return nil, &jsonrpc.ResponseError{Code: -32803, Message: "refactoring is not available for the selected code"}
}

func (s *Server) resolveWorkingDirectoryCommand(args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) == 0 {
		return nil, invalidParams(fmt.Errorf("missing required argument: uri"))
	}
	var p struct {
		URI protocol.URI `json:"uri"`
	}
	if json.Unmarshal(args[0], &p) != nil || p.URI == "" {
		return nil, invalidParams(fmt.Errorf("missing required argument: uri"))
	}
	path, ok := uriutil.Path(p.URI)
	if !ok {
		return map[string]any{"workingDirectory": nil}, nil
	}
	if module, found := s.index.ModuleFor(p.URI); found {
		return map[string]any{"workingDirectory": module.Dir}, nil
	}
	s.rootMu.RLock()
	defer s.rootMu.RUnlock()
	best := ""
	for _, rootURI := range s.roots {
		root, rootOK := uriutil.Path(rootURI)
		if rootOK && (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) && len(root) > len(best) {
			best = root
		}
	}
	if best == "" {
		return map[string]any{"workingDirectory": nil}, nil
	}
	return map[string]any{"workingDirectory": best}, nil
}

func (s *Server) resolveClassDocumentCommand(args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) == 0 {
		return nil, invalidParams(fmt.Errorf("missing required argument: fqn"))
	}
	var p struct {
		FQN string `json:"fqn"`
	}
	if err := json.Unmarshal(args[0], &p); err != nil || strings.TrimSpace(p.FQN) == "" {
		return nil, invalidParams(fmt.Errorf("invalid or missing required argument: fqn"))
	}
	symbols := s.index.SymbolsByFQN(p.FQN)
	seen := make(map[protocol.URI]bool, len(symbols))
	var uris []protocol.URI
	for _, symbol := range symbols {
		if symbol.Library || !analysis.IsTypeKind(symbol.Kind) || seen[symbol.URI] {
			continue
		}
		seen[symbol.URI] = true
		uris = append(uris, symbol.URI)
	}
	if len(uris) == 0 {
		return nil, &jsonrpc.ResponseError{Code: -32803, Message: "No file found for class: " + p.FQN}
	}
	if len(uris) > 1 {
		values := make([]string, len(uris))
		for n := range uris {
			values[n] = string(uris[n])
		}
		sort.Strings(values)
		return nil, &jsonrpc.ResponseError{Code: -32803, Message: fmt.Sprintf("Class %q is ambiguous; it is declared in %s", p.FQN, strings.Join(values, ", "))}
	}
	return map[string]any{"uri": uris[0]}, nil
}

func (s *Server) organizeImportsCommand(ctx context.Context, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) == 0 {
		return nil, invalidParams(fmt.Errorf("missing document URI"))
	}
	var uri protocol.URI
	if json.Unmarshal(args[0], &uri) != nil {
		var obj struct {
			URI protocol.URI `json:"uri"`
		}
		if json.Unmarshal(args[0], &obj) != nil {
			return nil, invalidParams(fmt.Errorf("invalid document URI"))
		}
		uri = obj.URI
	}
	doc, ok := s.index.DocumentContext(ctx, uri)
	if !ok {
		return nil, nil
	}
	edit, ok := organizeImports(doc.Text, doc.Range(0, len(doc.Text)), uri, s.index.UsedImports(uri))
	if !ok {
		return protocol.WorkspaceEdit{}, nil
	}
	return protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: {edit}}}, nil
}

func (s *Server) decompileCommand(ctx context.Context, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) == 0 {
		return nil, invalidParams(fmt.Errorf("missing URI"))
	}
	var uri string
	if json.Unmarshal(args[0], &uri) != nil {
		return nil, invalidParams(fmt.Errorf("invalid URI"))
	}
	if !strings.HasPrefix(uri, "jar:") && !strings.HasPrefix(uri, "jrt:") {
		return nil, invalidParams(fmt.Errorf("unsupported URI scheme; expected jar or jrt"))
	}
	if doc, ok := s.index.DocumentContext(ctx, protocol.URI(uri)); ok {
		return map[string]any{"code": doc.Text, "language": doc.LanguageID}, nil
	}
	return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidParams, Message: "library URI is not indexed: " + uri}
}

func (s *Server) symbolFromHierarchy(item protocol.CallHierarchyItem) (analysis.Symbol, bool) {
	if data, ok := item.Data.(map[string]any); ok {
		if id, ok := data["symbolId"].(string); ok {
			return s.index.Symbol(id)
		}
	}
	symbols := s.index.SymbolsInFile(item.URI)
	for _, sym := range symbols {
		if sym.Name == item.Name && sym.SelectionRange == item.SelectionRange {
			return sym, true
		}
	}
	return analysis.Symbol{}, false
}
func (s *Server) hierarchyItem(sym analysis.Symbol) protocol.CallHierarchyItem {
	return s.hierarchyItemContext(context.Background(), sym)
}

func (s *Server) hierarchyItemContext(ctx context.Context, sym analysis.Symbol) protocol.CallHierarchyItem {
	return protocol.CallHierarchyItem{Name: sym.Name, Kind: sym.Kind.LSP(), Tags: deprecatedTags(sym), Detail: sym.DisplaySignature(), URI: s.externalURIContext(ctx, sym.Location().URI), Range: sym.Range, SelectionRange: sym.Location().Range, Data: map[string]string{"symbolId": sym.ID}}
}

func organizeImports(text string, full protocol.Range, uri protocol.URI, semanticUsage ...map[string]bool) (protocol.TextEdit, bool) {
	lines := strings.Split(text, "\n")
	first, last := -1, -1
	type importLine struct {
		text, local string
		path        string
		wildcard    bool
		static      bool
	}
	for n, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "import ") {
			if first < 0 {
				first = n
			}
			last = n
		}
	}
	if first < 0 {
		return protocol.TextEdit{}, false
	}
	body := ""
	if last+1 < len(lines) {
		body = strings.Join(lines[last+1:], "\n")
	}
	used := codeIdentifierSet(body)
	var usedPaths map[string]bool
	if len(semanticUsage) > 0 {
		usedPaths = semanticUsage[0]
	}
	java := strings.HasSuffix(strings.ToLower(string(uri)), ".java")
	parseImport := func(line string) importLine {
		trim := strings.TrimSpace(line)
		path := strings.TrimSpace(strings.TrimPrefix(trim, "import "))
		// Exclude trailing comments from the name used for liveness checks while
		// retaining the source line byte-for-byte in the resulting import block.
		if java {
			if semi := strings.IndexByte(path, ';'); semi >= 0 {
				path = path[:semi]
			}
		} else if comment := strings.Index(path, "//"); comment >= 0 {
			path = strings.TrimSpace(path[:comment])
		}
		path = strings.TrimSuffix(strings.TrimSpace(path), ";")
		static := false
		if strings.HasPrefix(path, "static ") {
			static = true
			path = strings.TrimSpace(strings.TrimPrefix(path, "static "))
		}
		local := path
		if before, alias, ok := strings.Cut(path, " as "); ok {
			path, local = strings.TrimSpace(before), strings.TrimSpace(alias)
		} else if dot := strings.LastIndexByte(path, '.'); dot >= 0 {
			local = path[dot+1:]
		}
		wildcard := strings.HasSuffix(path, ".*")
		return importLine{text: trim, local: local, path: strings.TrimSuffix(path, ".*"), wildcard: wildcard, static: static}
	}

	// Comments and blank lines split independently sortable import groups. This
	// preserves their exact text and relative position instead of swallowing or
	// detaching them when imports on either side are reordered.
	var organized []string
	seen := make(map[string]bool)
	chunk := make([]importLine, 0)
	flush := func() {
		filtered := chunk[:0]
		for _, entry := range chunk {
			live := used[entry.local]
			if usedPaths != nil {
				// Semantic evidence can add liveness but may not subtract lexical
				// evidence while the fast resolver is intentionally incomplete.
				live = live || usedPaths[entry.path]
			}
			if live && !seen[entry.text] {
				seen[entry.text] = true
				filtered = append(filtered, entry)
			}
		}
		sort.SliceStable(filtered, func(a, b int) bool {
			if filtered[a].static != filtered[b].static {
				return !filtered[a].static
			}
			return filtered[a].text < filtered[b].text
		})
		for n, entry := range filtered {
			if n > 0 && entry.static != filtered[n-1].static && java {
				organized = append(organized, "")
			}
			organized = append(organized, entry.text)
		}
		chunk = chunk[:0]
	}
	for _, line := range lines[first : last+1] {
		if strings.HasPrefix(strings.TrimSpace(line), "import ") {
			chunk = append(chunk, parseImport(line))
			continue
		}
		flush()
		organized = append(organized, line)
	}
	flush()
	newText := strings.Join(organized, "\n")
	if newText != "" {
		newText += "\n"
	}
	start := protocol.Position{Line: first, Character: 0}
	end := protocol.Position{Line: last + 1, Character: 0}
	if last+1 >= len(lines) {
		end = full.End
		newText = strings.TrimSuffix(newText, "\n")
	}
	old := strings.Join(lines[first:last+1], "\n")
	if strings.TrimSuffix(newText, "\n") == old {
		return protocol.TextEdit{}, false
	}
	return protocol.TextEdit{Range: protocol.Range{Start: start, End: end}, NewText: newText}, true
}

func codeIdentifierSet(text string) map[string]bool {
	used := make(map[string]bool)
	for index := 0; index < len(text); {
		if index+1 < len(text) && text[index] == '/' && text[index+1] == '/' {
			if newline := strings.IndexByte(text[index+2:], '\n'); newline >= 0 {
				index += newline + 2
				continue
			}
			break
		}
		if index+1 < len(text) && text[index] == '/' && text[index+1] == '*' {
			if end := strings.Index(text[index+2:], "*/"); end >= 0 {
				index += end + 4
				continue
			}
			break
		}
		if text[index] == '"' || text[index] == '\'' {
			quote := text[index]
			index++
			for index < len(text) {
				if text[index] == '\\' {
					index += 2
					continue
				}
				value := text[index]
				index++
				if value == quote {
					break
				}
			}
			continue
		}
		if isCodeIdentifierByte(text[index], false) {
			start := index
			for index < len(text) && isCodeIdentifierByte(text[index], index > start) {
				index++
			}
			before := start - 1
			for before >= 0 && (text[before] == ' ' || text[before] == '\t') {
				before--
			}
			if before < 0 || text[before] != '.' {
				used[text[start:index]] = true
			}
			continue
		}
		index++
	}
	return used
}

func isCodeIdentifierByte(value byte, continuation bool) bool {
	return value == '_' || value == '$' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || continuation && value >= '0' && value <= '9'
}

func formatSource(source string, opts protocol.FormattingOptions, kotlin bool) string {
	formatted, _ := formatSourceContext(context.Background(), source, opts, kotlin)
	return formatted
}

func formatSourceContext(ctx context.Context, source string, opts protocol.FormattingOptions, kotlin bool) (string, bool) {
	// This is deliberately a minimal whitespace formatter, not a style engine.
	// Its hard contract is conservative: preserve lexical content, prove the
	// concrete syntax fingerprint unchanged, and abstain if either parse cannot
	// establish that proof.
	original := source
	if ctx.Err() != nil {
		return "", false
	}
	if opts.TabSize <= 0 {
		opts.TabSize = 4
	}
	unit := "\t"
	if opts.InsertSpaces {
		unit = strings.Repeat(" ", opts.TabSize)
	}
	lineSeparator := "\n"
	if strings.Contains(source, "\r\n") {
		lineSeparator = "\r\n"
	}
	var completed bool
	source, completed = expandFormatterBlocksContext(ctx, strings.ReplaceAll(source, "\r\n", "\n"), kotlin)
	if !completed {
		return "", false
	}
	lines := strings.Split(source, "\n")
	depth := 0
	continuation := 0
	state := formatLexState{}
	for n, line := range lines {
		if n&127 == 0 && ctx.Err() != nil {
			return "", false
		}
		stateAtStart := state
		opens, closes, parenDelta := scanStructureLanguage(line, &state, kotlin)
		// Raw strings and the body of block comments are content, not layout.
		// Preserve their leading whitespace byte-for-byte.
		if stateAtStart.Triple || stateAtStart.BlockCommentDepth > 0 {
			if opts.TrimTrailingWhitespace && !stateAtStart.Triple {
				lines[n] = strings.TrimRightFunc(line, unicode.IsSpace)
			}
			continuation += parenDelta
			if continuation < 0 {
				continuation = 0
			}
			depth += opens - closes
			if depth < 0 {
				depth = 0
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			lines[n] = ""
			continue
		}
		trim, completed = normalizeLineSpacingContext(ctx, trim, kotlin)
		if !completed {
			return "", false
		}
		leadingClose := leadingCloseCount(trim)
		lineDepth := depth - leadingClose
		if lineDepth < 0 {
			lineDepth = 0
		}
		continuationIndent := 0
		if continuation > 0 && leadingClose == 0 && !startsContinuationCloser(trim) {
			continuationIndent = 1
		}
		lines[n] = strings.Repeat(unit, lineDepth+continuationIndent) + trim
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
		continuation += parenDelta
		if continuation < 0 {
			continuation = 0
		}
		if opts.TrimTrailingWhitespace {
			lines[n] = strings.TrimRightFunc(lines[n], unicode.IsSpace)
		}
	}
	result := strings.Join(lines, lineSeparator)
	if opts.TrimFinalNewlines {
		result = strings.TrimRight(result, "\r\n")
	}
	if opts.InsertFinalNewline && !strings.HasSuffix(result, lineSeparator) {
		result += lineSeparator
	}
	language := analysis.LanguageJava
	if kotlin {
		language = analysis.LanguageKotlin
	}
	before, beforeOK := analysis.SyntaxFingerprint(ctx, original, language)
	after, afterOK := analysis.SyntaxFingerprint(ctx, result, language)
	if !beforeOK || !afterOK || before != after {
		return original, ctx.Err() == nil
	}
	return result, ctx.Err() == nil
}

func normalizeLineSpacing(line string, kotlin bool) string {
	formatted, _ := normalizeLineSpacingContext(context.Background(), line, kotlin)
	return formatted
}

func normalizeLineSpacingContext(ctx context.Context, line string, kotlin bool) (string, bool) {
	var out strings.Builder
	spacePending := false
	compactBraces := 0
	writePending := func(next byte) {
		if !spacePending || out.Len() == 0 {
			spacePending = false
			return
		}
		previous := lastByte(out.String())
		if previous != ' ' && previous != '\t' && next != ',' && next != ';' && next != ')' && next != ']' && next != '}' {
			out.WriteByte(' ')
		}
		spacePending = false
	}
	trimOutputSpace := func() {
		value := out.String()
		for len(value) > 0 && (value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
			value = value[:len(value)-1]
		}
		if len(value) != out.Len() {
			out.Reset()
			out.WriteString(value)
		}
	}
	for at := 0; at < len(line); {
		if at&1023 == 0 && ctx.Err() != nil {
			return "", false
		}
		if line[at] == ' ' || line[at] == '\t' {
			spacePending = true
			at++
			continue
		}
		if at+1 < len(line) && (line[at:at+2] == "//" || line[at:at+2] == "/*") {
			writePending('/')
			out.WriteString(line[at:])
			break
		}
		if at+2 < len(line) && line[at:at+3] == `"""` {
			writePending('"')
			out.WriteString(line[at:])
			break
		}
		if line[at] == '"' || line[at] == '\'' {
			writePending(line[at])
			quote := line[at]
			end, escaped := at+1, false
			for end < len(line) {
				if escaped {
					escaped = false
				} else if line[end] == '\\' {
					escaped = true
				} else if line[end] == quote {
					end++
					break
				}
				end++
			}
			out.WriteString(line[at:end])
			at = end
			continue
		}
		if line[at] == ',' {
			trimOutputSpace()
			out.WriteByte(',')
			spacePending = at+1 < len(line)
			at++
			continue
		}
		if line[at] == ';' {
			trimOutputSpace()
			out.WriteByte(';')
			spacePending = false
			at++
			continue
		}
		if line[at] == '(' && controlKeywordBefore(line, at) {
			trimOutputSpace()
			if out.Len() > 0 && lastByte(out.String()) != ' ' {
				out.WriteByte(' ')
			}
			out.WriteByte('(')
			spacePending = false
			at++
			continue
		}
		if line[at] == '{' {
			trimOutputSpace()
			previous := lastByte(out.String())
			compact := !kotlin && (compactBraces > 0 || previous == ']' || previous == '=' || previous == '(' || previous == '[')
			if compact {
				if previous == '=' {
					out.WriteByte(' ')
				}
				out.WriteByte('{')
				compactBraces++
				spacePending = false
				at++
				continue
			}
			if out.Len() > 0 {
				previous = lastByte(out.String())
				if previous != ' ' && previous != '\t' && previous != '{' && previous != '[' && previous != '(' && previous != '$' {
					out.WriteByte(' ')
				}
			}
			out.WriteByte('{')
			spacePending = at+1 < len(line) && line[at+1] != '}'
			at++
			continue
		}
		if line[at] == '}' {
			trimOutputSpace()
			if !kotlin && compactBraces > 0 {
				out.WriteByte('}')
				compactBraces--
				spacePending = false
				at++
				continue
			}
			if out.Len() > 0 {
				previous := lastByte(out.String())
				if previous != '{' && previous != ' ' && previous != '\t' {
					out.WriteByte(' ')
				}
			}
			out.WriteByte('}')
			spacePending = at+1 < len(line) && line[at+1] != ')' && line[at+1] != ';' && line[at+1] != ',' && line[at+1] != '}'
			at++
			continue
		}
		if kotlin && line[at] == ':' && (at == 0 || line[at-1] != ':' && line[at-1] != '?') && (at+1 >= len(line) || line[at+1] != ':' && line[at+1] != '=') {
			trimOutputSpace()
			out.WriteByte(':')
			spacePending = at+1 < len(line)
			at++
			continue
		}
		if !kotlin && line[at] == ':' && javaEnhancedForColon(line, at) {
			trimOutputSpace()
			if out.Len() > 0 && lastByte(out.String()) != ' ' {
				out.WriteByte(' ')
			}
			out.WriteByte(':')
			spacePending = true
			at++
			continue
		}
		if operator, width := spacingOperator(line, at); width > 0 {
			trimOutputSpace()
			if out.Len() > 0 && lastByte(out.String()) != ' ' {
				out.WriteByte(' ')
			}
			out.WriteString(operator)
			spacePending = at+width < len(line)
			at += width
			continue
		}
		writePending(line[at])
		out.WriteByte(line[at])
		at++
	}
	return strings.TrimSpace(out.String()), ctx.Err() == nil
}

func javaEnhancedForColon(line string, at int) bool {
	open := strings.LastIndexByte(line[:at], '(')
	if open < 0 || strings.TrimSpace(line[open+1:at]) == "" || strings.Contains(line[open+1:at], "?") {
		return false
	}
	before := strings.TrimSpace(line[:open])
	return strings.HasSuffix(before, "for")
}

func expandFormatterBlocks(source string, kotlin bool) string {
	formatted, _ := expandFormatterBlocksContext(context.Background(), source, kotlin)
	return formatted
}

func expandFormatterBlocksContext(ctx context.Context, source string, kotlin bool) (string, bool) {
	var out strings.Builder
	out.Grow(len(source) + len(source)/16)
	state := formatLexState{}
	blockKinds := make([]bool, 0, 16)
	parenDepth := 0
	lineStart := 0
	for index := 0; index < len(source); index++ {
		if index&1023 == 0 && ctx.Err() != nil {
			return "", false
		}
		value := source[index]
		if state.BlockCommentDepth > 0 {
			out.WriteByte(value)
			if kotlin && value == '/' && index+1 < len(source) && source[index+1] == '*' {
				index++
				out.WriteByte('*')
				state.BlockCommentDepth++
			} else if value == '*' && index+1 < len(source) && source[index+1] == '/' {
				index++
				out.WriteByte('/')
				state.BlockCommentDepth--
			}
			if value == '\n' {
				lineStart = index + 1
			}
			continue
		}
		if state.Triple {
			if index+2 < len(source) && source[index:index+3] == `"""` {
				out.WriteString(`"""`)
				index += 2
				state.Triple = false
			} else {
				out.WriteByte(value)
				if value == '\n' {
					lineStart = index + 1
				}
			}
			continue
		}
		if state.Quote != 0 {
			out.WriteByte(value)
			if state.Escaped {
				state.Escaped = false
			} else if value == '\\' {
				state.Escaped = true
			} else if value == state.Quote {
				state.Quote = 0
			}
			continue
		}
		if kotlin && index+2 < len(source) && source[index:index+3] == `"""` {
			out.WriteString(`"""`)
			index += 2
			state.Triple = true
			continue
		}
		if index+1 < len(source) && source[index:index+2] == "//" {
			end := strings.IndexByte(source[index:], '\n')
			if end < 0 {
				out.WriteString(source[index:])
				break
			}
			out.WriteString(source[index : index+end+1])
			index += end
			lineStart = index + 1
			continue
		}
		if index+1 < len(source) && source[index:index+2] == "/*" {
			out.WriteString("/*")
			index++
			state.BlockCommentDepth = 1
			continue
		}
		if value == '\'' || value == '"' {
			state.Quote = value
			out.WriteByte(value)
			continue
		}
		if value == '\n' {
			out.WriteByte(value)
			lineStart = index + 1
			continue
		}
		if value == '(' {
			parenDepth++
		}
		if value == ')' {
			if parenDepth > 0 {
				parenDepth--
			}
		}
		if value == ')' && !kotlin && javaDeclarationAnnotationContinues(source[lineStart:index+1], source[index+1:]) {
			out.WriteString(")\n")
			lineStart = index + 1
			continue
		}
		if value == '{' {
			block := formatterBlockOpening(source[lineStart:index], kotlin, blockKinds)
			blockKinds = append(blockKinds, block)
			out.WriteByte(value)
			next := nextFormatterByte(source, index+1)
			if block && next != '}' && next != '\n' && lastByte(out.String()) != '\n' {
				out.WriteByte('\n')
				lineStart = index + 1
			}
			continue
		}
		if value == '}' {
			block := true
			if len(blockKinds) > 0 {
				block = blockKinds[len(blockKinds)-1]
				blockKinds = blockKinds[:len(blockKinds)-1]
			}
			if block {
				trimFormatterOutputSpace(&out)
				if out.Len() > 0 && lastByte(out.String()) != '\n' {
					out.WriteByte('\n')
				}
			}
			out.WriteByte(value)
			if block && !formatterCloseContinues(source, index+1) {
				next := nextFormatterByte(source, index+1)
				if next != 0 && next != ';' && next != ',' && next != ')' && next != '\n' {
					out.WriteByte('\n')
					lineStart = index + 1
				}
			}
			continue
		}
		if value == ';' && parenDepth == 0 {
			out.WriteByte(value)
			next := nextFormatterByte(source, index+1)
			if next != 0 && next != '\n' && next != '}' {
				out.WriteByte('\n')
				lineStart = index + 1
			}
			continue
		}
		out.WriteByte(value)
	}
	return out.String(), ctx.Err() == nil
}

func javaDeclarationAnnotationContinues(prefix, suffix string) bool {
	trimmed := strings.TrimSpace(prefix)
	if !strings.HasPrefix(trimmed, "@") {
		return false
	}
	at := 0
	for at < len(suffix) && (suffix[at] == ' ' || suffix[at] == '\t' || suffix[at] == '\r') {
		at++
	}
	if at >= len(suffix) || suffix[at] == '\n' {
		return false
	}
	next := suffix[at]
	return next == '@' || next == '_' || next == '$' || next >= 'A' && next <= 'Z' || next >= 'a' && next <= 'z'
}

func formatterBlockOpening(prefix string, kotlin bool, stack []bool) bool {
	trimmed := strings.TrimSpace(prefix)
	if !kotlin {
		previous := byte(0)
		if trimmed != "" {
			previous = trimmed[len(trimmed)-1]
		}
		if previous == ']' || previous == '=' || previous == '(' || previous == '[' || len(stack) > 0 && !stack[len(stack)-1] && (previous == ',' || previous == '{') {
			return false
		}
		return true
	}
	lower := " " + strings.ToLower(trimmed) + " "
	for _, keyword := range []string{" class ", " interface ", " object ", " fun ", " when", " if", " for", " while", " try", " catch", " finally", " else", " do ", " init", " constructor", " get", " set"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return strings.HasSuffix(trimmed, "->")
}

func formatterCloseContinues(source string, after int) bool {
	for after < len(source) && (source[after] == ' ' || source[after] == '\t') {
		after++
	}
	for _, word := range []string{"else", "catch", "finally"} {
		if strings.HasPrefix(source[after:], word) {
			return true
		}
	}
	return false
}

func nextFormatterByte(source string, after int) byte {
	for after < len(source) && (source[after] == ' ' || source[after] == '\t' || source[after] == '\r') {
		after++
	}
	if after >= len(source) {
		return 0
	}
	return source[after]
}

func trimFormatterOutputSpace(out *strings.Builder) {
	value := out.String()
	trimmed := strings.TrimRight(value, " \t")
	if len(trimmed) != len(value) {
		out.Reset()
		out.WriteString(trimmed)
	}
}

func spacingOperator(line string, at int) (string, int) {
	for _, operator := range []string{"===", "!==", ">>>=", "<<=", ">>=", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "->", "?:"} {
		if strings.HasPrefix(line[at:], operator) {
			return operator, len(operator)
		}
	}
	if line[at] == '=' {
		return "=", 1
	}
	if line[at] == '<' || line[at] == '>' {
		previous, next := previousNonSpace(line, at), nextNonSpace(line, at+1)
		if isSpacingOperand(previous) && isSpacingOperand(next) && !genericAngleAt(line, at) {
			return line[at : at+1], 1
		}
		return "", 0
	}
	if !strings.ContainsRune("+-*/%", rune(line[at])) {
		return "", 0
	}
	previous, next := previousNonSpace(line, at), nextNonSpace(line, at+1)
	if isSpacingOperand(previous) && isSpacingOperand(next) {
		return line[at : at+1], 1
	}
	return "", 0
}

func controlKeywordBefore(line string, open int) bool {
	end := open
	for end > 0 && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && (line[start-1] == '_' || line[start-1] >= 'a' && line[start-1] <= 'z' || line[start-1] >= 'A' && line[start-1] <= 'Z') {
		start--
	}
	switch line[start:end] {
	case "if", "for", "while", "when", "catch", "switch", "synchronized", "try":
		return true
	default:
		return false
	}
}

func genericAngleAt(line string, at int) bool {
	if line[at] == '<' {
		start := at
		for start > 0 && (line[start-1] == '_' || line[start-1] == '$' || line[start-1] >= 'a' && line[start-1] <= 'z' || line[start-1] >= 'A' && line[start-1] <= 'Z' || line[start-1] >= '0' && line[start-1] <= '9') {
			start--
		}
		if start < at && line[start] >= 'A' && line[start] <= 'Z' {
			return true
		}
		depth := 0
		for index := at; index < len(line); index++ {
			switch line[index] {
			case '<':
				depth++
			case '>':
				depth--
				if depth == 0 {
					next := nextNonSpace(line, index+1)
					return next == '(' || next == '.' || next == ':'
				}
			}
		}
		return false
	}
	depth := 0
	for index := at; index >= 0; index-- {
		switch line[index] {
		case '>':
			depth++
		case '<':
			depth--
			if depth == 0 {
				return genericAngleAt(line, index)
			}
		}
	}
	return false
}

func previousNonSpace(line string, before int) byte {
	for before > 0 {
		before--
		if line[before] != ' ' && line[before] != '\t' {
			return line[before]
		}
	}
	return 0
}

func nextNonSpace(line string, after int) byte {
	for after < len(line) {
		if line[after] != ' ' && line[after] != '\t' {
			return line[after]
		}
		after++
	}
	return 0
}

func isSpacingOperand(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '$' || value == '`' || value == ')' || value == ']' || value == '}' || value == '"' || value == '\''
}

func lastByte(value string) byte {
	if value == "" {
		return 0
	}
	return value[len(value)-1]
}

type formatLexState = lexical.State

func scanStructure(line string, state *formatLexState) (opens, closes, parenDelta int) {
	return scanStructureLanguage(line, state, true)
}

func scanStructureLanguage(line string, state *formatLexState, kotlin bool) (opens, closes, parenDelta int) {
	return state.ScanStructure(line, kotlin)
}

func leadingCloseCount(line string) int {
	count := 0
	for _, r := range line {
		if unicode.IsSpace(r) {
			continue
		}
		if r == '}' {
			count++
			continue
		}
		break
	}
	return count
}

func startsContinuationCloser(line string) bool {
	return strings.HasPrefix(line, ")") || strings.HasPrefix(line, "]")
}
func indentAt(text string, offset int) string {
	if offset > len(text) {
		offset = len(text)
	}
	start := strings.LastIndexByte(text[:offset], '\n') + 1
	end := start
	for end < len(text) && (text[end] == ' ' || text[end] == '\t') {
		end++
	}
	return text[start:end]
}
func allNumeric(s string) bool {
	s = strings.TrimSpace(strings.TrimSuffix(s, "L"))
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}
func callAt(text string, offset int) (string, int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(text) {
		offset = len(text)
	}
	type delimiter struct {
		kind   byte
		at     int
		active int
	}
	stack := make([]delimiter, 0, 8)
	var quote byte
	rawString, escaped, lineComment, blockComment := false, false, false, false
	for n := 0; n < offset; n++ {
		c := text[n]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if c == '*' && n+1 < offset && text[n+1] == '/' {
				blockComment = false
				n++
			}
			continue
		}
		if quote != 0 {
			if rawString {
				if c == '"' && n+2 < offset && text[n+1] == '"' && text[n+2] == '"' {
					quote, rawString = 0, false
					n += 2
				}
				continue
			}
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && n+1 < offset {
			if text[n+1] == '/' {
				lineComment = true
				n++
				continue
			}
			if text[n+1] == '*' {
				blockComment = true
				n++
				continue
			}
		}
		if c == '"' || c == '\'' {
			quote = c
			if c == '"' && n+2 < offset && text[n+1] == '"' && text[n+2] == '"' {
				rawString = true
				n += 2
			}
			continue
		}
		switch c {
		case '(', '[', '{':
			stack = append(stack, delimiter{kind: c, at: n})
		case ')', ']', '}':
			want := byte('(')
			if c == ']' {
				want = '['
			} else if c == '}' {
				want = '{'
			}
			for len(stack) > 0 {
				last := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if last.kind == want {
					break
				}
			}
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].kind == '(' {
				stack[len(stack)-1].active++
			}
		}
	}
	for n := len(stack) - 1; n >= 0; n-- {
		if stack[n].kind != '(' {
			continue
		}
		end := stack[n].at
		start := end
		for start > 0 && (unicode.IsLetter(rune(text[start-1])) || unicode.IsDigit(rune(text[start-1])) || text[start-1] == '_' || text[start-1] == '$' || text[start-1] == '`') {
			start--
		}
		name := strings.Trim(text[start:end], "`")
		if name != "" {
			return name, start, stack[n].active
		}
	}
	return "", 0, 0
}

func namedArgumentNameAt(text string, callNameEnd, offset int) string {
	if callNameEnd < 0 || offset < callNameEnd || offset > len(text) {
		return ""
	}
	open := strings.IndexByte(text[callNameEnd:offset], '(')
	if open < 0 {
		return ""
	}
	start := callNameEnd + open + 1
	depth := 0
	inString, escaped := byte(0), false
	for index := start; index < offset; index++ {
		value := text[index]
		if inString != 0 {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == inString {
				inString = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			inString = value
			continue
		}
		switch value {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				start = index + 1
			}
		}
	}
	argument := strings.TrimSpace(text[start:offset])
	if equals := strings.IndexByte(argument, '='); equals >= 0 {
		name := strings.Trim(strings.TrimSpace(argument[:equals]), "`")
		if name == "" {
			return ""
		}
		for index, value := range name {
			if value != '_' && !unicode.IsLetter(value) && !(index > 0 && unicode.IsDigit(value)) {
				return ""
			}
		}
		return name
	}
	return ""
}
