package lsp

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func (s *Server) extractActions(uri protocol.URI, selectedRange protocol.Range, doc *textdoc.Document, selected string, contexts ...context.Context) []protocol.CodeAction {
	ctx := operationContext(contexts)
	if ctx.Err() != nil {
		return nil
	}
	file, ok := s.index.Parsed(uri)
	if !ok {
		return nil
	}
	kotlin := file.Language == analysis.LanguageKotlin
	startOffset := doc.Offset(selectedRange.Start)
	endOffset := doc.Offset(selectedRange.End)
	if startOffset >= endOffset {
		return nil
	}
	trimmed := strings.TrimSpace(selected)
	parameters := extractionParameters(file.Symbols, startOffset, endOffset, trimmed)
	evidence := s.index.ExpressionEvidence(uri, trimmed, startOffset)
	statementOffset := lineStart(doc.Text, startOffset)
	indent := indentAt(doc.Text, startOffset)
	name := uniqueSymbolName(file.Symbols, "extractedValue")
	variableDeclaration := indent
	if kotlin {
		variableDeclaration += "val " + name + " = " + trimmed + "\n"
	} else {
		variableDeclaration += evidence.Type + " " + name + " = " + strings.TrimSuffix(trimmed, ";") + ";\n"
	}
	variable := refactorAction("Extract variable", "refactor.extract.variable", uri,
		protocol.TextEdit{Range: doc.Range(statementOffset, statementOffset), NewText: variableDeclaration},
		protocol.TextEdit{Range: selectedRange, NewText: name},
	)

	functionName := uniqueSymbolName(file.Symbols, "extractedFunction")
	functionInsert, functionIndent, owner := extractionInsertion(doc, file.Symbols, startOffset)
	returnType := evidence.Type
	expression := isExpressionSelection(trimmed)
	static := owner.ID != "" && containingCallableHasModifier(file.Symbols, startOffset, "static")
	if (returnType == "Any" || returnType == "Object") && len(parameters) > 0 {
		candidate := extractionParameterType(parameters[0], kotlin)
		if candidate != "" {
			sameType := true
			for _, parameter := range parameters[1:] {
				if extractionParameterType(parameter, kotlin) != candidate {
					sameType = false
					break
				}
			}
			if sameType {
				returnType = candidate
			}
		}
	}
	parameterDeclaration, arguments := extractionParameterText(parameters, kotlin)
	var functionText string
	if kotlin {
		if expression {
			functionText = "\n" + functionIndent + "private fun " + functionName + "(" + parameterDeclaration + "): " + returnType + " = " + trimmed + "\n"
		} else {
			body := reindentBlock(trimmed, functionIndent+"    ")
			functionText = "\n" + functionIndent + "private fun " + functionName + "(" + parameterDeclaration + ") {\n" + body + "\n" + functionIndent + "}\n"
		}
	} else {
		modifier := "private "
		if static {
			modifier += "static "
		}
		if expression {
			functionText = "\n" + functionIndent + modifier + returnType + " " + functionName + "(" + parameterDeclaration + ") {\n" + functionIndent + "    return " + strings.TrimSuffix(trimmed, ";") + ";\n" + functionIndent + "}\n"
		} else {
			body := reindentBlock(trimmed, functionIndent+"    ")
			functionText = "\n" + functionIndent + modifier + "void " + functionName + "(" + parameterDeclaration + ") {\n" + body + "\n" + functionIndent + "}\n"
		}
	}
	actions := make([]protocol.CodeAction, 0, 4)
	// Moving a potentially throwing or side-effecting subexpression to the
	// beginning of its line changes short-circuit/evaluation order. The fast
	// extractor therefore offers a variable only for proven constants.
	if evidence.Constant && evidence.Type != "" {
		actions = append(actions, variable)
	}
	// A local or parameter is passed by value. Moving an assignment/inc/dec of
	// that binding into a new function would mutate only the extracted
	// function's copy (and Kotlin postfix expressions can also become invalid).
	// Keep refactoring complete for expressions and referent mutations, but do
	// not advertise or execute a semantics-changing extraction.
	if evidence.RefactoringSafe && extractionFunctionSemanticallySafe(ctx, s, uri, file, doc, startOffset, endOffset, trimmed, parameters, returnType) {
		actions = append(actions, refactorAction("Extract function", "refactor.extract.function", uri,
			protocol.TextEdit{Range: doc.Range(functionInsert, functionInsert), NewText: functionText},
			protocol.TextEdit{Range: selectedRange, NewText: functionName + "(" + arguments + ")" + statementTerminator(trimmed, kotlin)},
		))
	}
	if (owner.ID != "" || kotlin) && len(parameters) == 0 && evidence.Constant && evidence.Type != "" {
		fieldName := uniqueSymbolName(file.Symbols, "extractedField")
		fieldType := evidence.Type
		var fieldText string
		if kotlin {
			fieldText = "\n" + functionIndent + "private val " + fieldName + ": " + fieldType + " = " + trimmed + "\n"
		} else {
			fieldText = "\n" + functionIndent + "private " + fieldType + " " + fieldName + " = " + strings.TrimSuffix(trimmed, ";") + ";\n"
		}
		actions = append(actions, refactorAction("Extract field", "refactor.extract.field", uri,
			protocol.TextEdit{Range: doc.Range(functionInsert, functionInsert), NewText: fieldText},
			protocol.TextEdit{Range: selectedRange, NewText: fieldName},
		))

		if evidence.Constant {
			constantName := uniqueSymbolName(file.Symbols, "EXTRACTED_CONSTANT")
			var constantText string
			if kotlin {
				declaration := "private const val " + constantName + ": " + evidence.Type + " = " + trimmed
				if owner.ID != "" && owner.Kind != analysis.KindObject {
					constantText = "\n" + functionIndent + "companion object {\n" + functionIndent + "    " + declaration + "\n" + functionIndent + "}\n"
				} else {
					constantText = "\n" + functionIndent + declaration + "\n"
				}
			} else {
				constantText = "\n" + functionIndent + "private static final " + evidence.Type + " " + constantName + " = " + strings.TrimSuffix(trimmed, ";") + ";\n"
			}
			actions = append(actions, refactorAction("Extract constant", "refactor.extract.constant", uri,
				protocol.TextEdit{Range: doc.Range(functionInsert, functionInsert), NewText: constantText},
				protocol.TextEdit{Range: selectedRange, NewText: constantName},
			))
		}
	}
	return actions
}

func selectionMutatesExtractionParameter(selected string, parameters []analysis.Symbol) bool {
	for _, parameter := range parameters {
		name := parameter.Name
		for search := 0; search+len(name) <= len(selected); {
			relative := strings.Index(selected[search:], name)
			if relative < 0 {
				break
			}
			start := search + relative
			end := start + len(name)
			search = end
			if start > 0 && isIdentifierByte(selected[start-1]) || end < len(selected) && isIdentifierByte(selected[end]) {
				continue
			}
			before := previousNonSpaceIndex(selected, start)
			after := nextNonSpaceIndex(selected, end)
			if before >= 1 && (selected[before-1:before+1] == "++" || selected[before-1:before+1] == "--") {
				return true
			}
			if after+1 < len(selected) && (selected[after:after+2] == "++" || selected[after:after+2] == "--") {
				return true
			}
			if after < len(selected) && selected[after] == '=' && (after+1 >= len(selected) || selected[after+1] != '=') {
				return true
			}
			if after+1 < len(selected) && selected[after+1] == '=' && strings.ContainsRune("+-*/%&|^", rune(selected[after])) {
				return true
			}
			if after+2 < len(selected) && (selected[after:after+3] == "<<=" || selected[after:after+3] == ">>=") {
				return true
			}
			if after+3 < len(selected) && selected[after:after+4] == ">>>=" {
				return true
			}
		}
	}
	return false
}

// extractionFunctionSemanticallySafe defines the deliberately narrow proof
// boundary for the fast refactoring. A pure expression over uniquely bound
// locals/parameters is safe to move; calls, fields/properties, writes, control
// flow, unknown types, and incomplete bindings are delegated to a future
// compiler-backed refactoring service by withholding the action.
func extractionFunctionSemanticallySafe(ctx context.Context, s *Server, uri protocol.URI, file *analysis.ParsedFile, doc *textdoc.Document, start, end int, selected string, parameters []analysis.Symbol, returnType string) bool {
	if !isExpressionSelection(selected) || returnType == "" || returnType == "Any" || returnType == "Object" || selectionMutatesExtractionParameter(selected, parameters) {
		return false
	}
	for _, token := range []string{"return", "throw", "break", "continue", "this", "super", "new", "++", "--", "=", "::", "->"} {
		if token == "=" {
			if strings.Contains(selected, "=") {
				return false
			}
			continue
		}
		if strings.Contains(selected, token) {
			return false
		}
	}
	unaccounted := codeIdentifierSet(selected)
	for _, keyword := range []string{"true", "false", "null"} {
		delete(unaccounted, keyword)
	}
	resolvedByName := make(map[string]string)
	for _, reference := range file.References {
		if ctx.Err() != nil {
			return false
		}
		if reference.StartByte < start || reference.EndByte > end {
			continue
		}
		if reference.EndByte > len(doc.Text) || !isSimpleIdentifierText(strings.Trim(doc.Text[reference.StartByte:reference.EndByte], "`")) {
			// Kotlin operator conventions (`a + b` referencing `plus`) are not
			// bindings the extracted function must carry: the operand
			// references decide, and the operator keeps resolving against the
			// same operand types inside the new function.
			continue
		}
		definitions := s.index.DefinitionsContext(ctx, uri, reference.Range.Start)
		if len(definitions) != 1 {
			return false
		}
		definition := definitions[0]
		if definition.Kind != analysis.KindParameter && definition.Kind != analysis.KindVariable {
			return false
		}
		if definition.URI != uri || definition.StartByte >= start || definition.ScopeStartByte > start || definition.ScopeEndByte < end {
			return false
		}
		if extractionParameterType(definition, file.Language == analysis.LanguageKotlin) == "" {
			return false
		}
		if previous := resolvedByName[reference.Name]; previous != "" && previous != definition.ID {
			// Two different bindings with the same spelling cannot be represented
			// by one extracted-function parameter without changing semantics.
			return false
		}
		resolvedByName[reference.Name] = definition.ID
		delete(unaccounted, reference.Name)
	}
	parameterByName := make(map[string]string, len(parameters))
	for _, parameter := range parameters {
		if previous := parameterByName[parameter.Name]; previous != "" && previous != parameter.ID {
			return false
		}
		parameterByName[parameter.Name] = parameter.ID
		if resolvedByName[parameter.Name] != parameter.ID {
			return false
		}
	}
	for name, id := range resolvedByName {
		if parameterByName[name] != id {
			return false
		}
	}
	return len(unaccounted) == 0 && doc.Offset(doc.Position(start)) == start
}

func isIdentifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func previousNonSpaceIndex(value string, before int) int {
	for before > 0 {
		before--
		if value[before] != ' ' && value[before] != '\t' && value[before] != '\r' && value[before] != '\n' {
			return before
		}
	}
	return -1
}

func nextNonSpaceIndex(value string, after int) int {
	for after < len(value) && (value[after] == ' ' || value[after] == '\t' || value[after] == '\r' || value[after] == '\n') {
		after++
	}
	return after
}

func extractionParameters(symbols []analysis.Symbol, start, end int, selected string) []analysis.Symbol {
	byName := make(map[string]analysis.Symbol)
	identifiers := codeIdentifierSet(selected)
	for _, symbol := range symbols {
		if symbol.StartByte >= start || symbol.ScopeStartByte > start || symbol.ScopeEndByte < end {
			continue
		}
		if symbol.Kind != analysis.KindParameter && symbol.Kind != analysis.KindVariable {
			continue
		}
		if !identifiers[symbol.Name] {
			continue
		}
		previous, exists := byName[symbol.Name]
		if !exists || symbol.ScopeStartByte > previous.ScopeStartByte || symbol.ScopeStartByte == previous.ScopeStartByte && symbol.StartByte > previous.StartByte {
			byName[symbol.Name] = symbol
		}
	}
	candidates := make([]analysis.Symbol, 0, len(byName))
	for _, symbol := range byName {
		candidates = append(candidates, symbol)
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		return strings.Index(selected, candidates[a].Name) < strings.Index(selected, candidates[b].Name)
	})
	return candidates
}

func extractionParameterText(parameters []analysis.Symbol, kotlin bool) (string, string) {
	declarations := make([]string, 0, len(parameters))
	arguments := make([]string, 0, len(parameters))
	seen := make(map[string]bool)
	for _, parameter := range parameters {
		if seen[parameter.Name] {
			continue
		}
		seen[parameter.Name] = true
		typeName := extractionParameterType(parameter, kotlin)
		if typeName == "" || typeName == "var" {
			if kotlin {
				typeName = "Any"
			} else {
				typeName = "Object"
			}
		}
		if kotlin {
			declarations = append(declarations, parameter.Name+": "+typeName)
		} else {
			declarations = append(declarations, typeName+" "+parameter.Name)
		}
		arguments = append(arguments, parameter.Name)
	}
	return strings.Join(declarations, ", "), strings.Join(arguments, ", ")
}

func extractionParameterType(parameter analysis.Symbol, kotlin bool) string {
	typeName := parameter.Type
	if (typeName == "" || typeName == "var") && parameter.Initializer != "" {
		typeName = expressionType(parameter.Initializer, kotlin)
	}
	return typeName
}

func (s *Server) inlineVariableAction(uri protocol.URI, requested protocol.Range, doc *textdoc.Document, contexts ...context.Context) (protocol.CodeAction, bool) {
	ctx := operationContext(contexts)
	if ctx.Err() != nil {
		return protocol.CodeAction{}, false
	}
	file, ok := s.index.Parsed(uri)
	if !ok {
		return protocol.CodeAction{}, false
	}
	offset := doc.Offset(requested.Start)
	for _, symbol := range file.Symbols {
		if symbol.Kind != analysis.KindVariable {
			continue
		}
		if offset < symbol.NameStartByte || offset > symbol.NameEndByte {
			continue
		}
		declaration := doc.Text[symbol.StartByte:symbol.EndByte]
		equals := strings.IndexByte(declaration, '=')
		if equals < 0 {
			return protocol.CodeAction{}, false
		}
		initializer := strings.TrimSpace(strings.TrimSuffix(declaration[equals+1:], ";"))
		evidence := s.index.ExpressionEvidence(uri, initializer, symbol.StartByte)
		if initializer == "" || strings.Contains(initializer, "\n") || !evidence.Constant || evidence.Type == "" {
			return protocol.CodeAction{}, false
		}
		locations := s.index.ReferencesContext(ctx, uri, symbol.SelectionRange.Start, false)
		if len(locations) == 0 {
			return protocol.CodeAction{}, false
		}
		for _, reference := range file.References {
			if reference.Name == symbol.Name && reference.StartByte > symbol.EndByte && reference.Role == analysis.RoleWrite {
				return protocol.CodeAction{}, false
			}
		}
		edits := make([]protocol.TextEdit, 0, len(locations)+1)
		for _, location := range locations {
			if location.URI != uri {
				return protocol.CodeAction{}, false
			}
			edits = append(edits, protocol.TextEdit{Range: location.Range, NewText: "(" + initializer + ")"})
		}
		start, end := inlineDeclarationRemoval(doc.Text, symbol.StartByte, symbol.EndByte)
		edits = append(edits, protocol.TextEdit{Range: doc.Range(start, end), NewText: ""})
		return refactorAction("Inline variable", "refactor.inline.variable", uri, edits...), true
	}
	return protocol.CodeAction{}, false
}

func inlineDeclarationRemoval(text string, start, end int) (int, int) {
	lineBegin := lineStart(text, start)
	lineEnd := lineEndIncludingNewline(text, end)
	contentEnd := lineEnd
	if contentEnd > lineBegin && text[contentEnd-1] == '\n' {
		contentEnd--
	}
	if strings.TrimSpace(text[lineBegin:start]) == "" && strings.TrimSpace(text[end:contentEnd]) == "" {
		return lineBegin, lineEnd
	}
	for end < len(text) && (text[end] == ' ' || text[end] == '\t') {
		end++
	}
	if end < len(text) && text[end] == ';' {
		end++
		for end < len(text) && (text[end] == ' ' || text[end] == '\t') {
			end++
		}
		return start, end
	}
	for start > lineBegin && (text[start-1] == ' ' || text[start-1] == '\t') {
		start--
	}
	if start > lineBegin && text[start-1] == ';' {
		start--
	}
	return start, end
}

func refactorAction(title, kind string, uri protocol.URI, edits ...protocol.TextEdit) protocol.CodeAction {
	return protocol.CodeAction{Title: title, Kind: kind, Edit: &protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: edits}}}
}

func extractionInsertion(doc *textdoc.Document, symbols []analysis.Symbol, offset int) (int, string, analysis.Symbol) {
	var owner analysis.Symbol
	for _, symbol := range symbols {
		if !analysis.IsTypeKind(symbol.Kind) || symbol.StartByte >= offset || symbol.EndByte < offset {
			continue
		}
		if owner.ID == "" || symbol.StartByte >= owner.StartByte && symbol.EndByte <= owner.EndByte {
			owner = symbol
		}
	}
	if owner.ID != "" {
		brace := strings.IndexByte(doc.Text[owner.StartByte:offset], '{')
		if brace >= 0 {
			insert := owner.StartByte + brace + 1
			if owner.Kind == analysis.KindEnum {
				lastEntryEnd := insert
				for _, symbol := range symbols {
					if symbol.Kind == analysis.KindEnumMember && symbol.ContainerID == owner.ID && symbol.EndByte > lastEntryEnd {
						lastEntryEnd = symbol.EndByte
					}
				}
				if semicolon := strings.IndexByte(doc.Text[lastEntryEnd:offset], ';'); semicolon >= 0 {
					insert = lastEntryEnd + semicolon + 1
				}
			}
			return insert, indentAt(doc.Text, owner.StartByte) + "    ", owner
		}
	}
	insert := 0
	for _, symbol := range symbols {
		if symbol.ContainerID == "" && symbol.StartByte < offset {
			insert = lineStart(doc.Text, symbol.StartByte)
			break
		}
	}
	return insert, "", owner
}

func expressionType(expression string, kotlin bool) string {
	expression = strings.TrimSpace(strings.TrimSuffix(expression, ";"))
	switch {
	case strings.HasPrefix(expression, "\"") || strings.HasPrefix(expression, "\"\"\""):
		return "String"
	case expression == "true" || expression == "false":
		if kotlin {
			return "Boolean"
		}
		return "boolean"
	case strings.HasSuffix(expression, "L") && allNumeric(strings.TrimSuffix(expression, "L")):
		if kotlin {
			return "Long"
		}
		return "long"
	case allNumeric(expression) && strings.Contains(expression, "."):
		if kotlin {
			return "Double"
		}
		return "double"
	case allNumeric(expression):
		if kotlin {
			return "Int"
		}
		return "int"
	default:
		return ""
	}
}

func isExpressionSelection(value string) bool {
	value = strings.TrimSpace(value)
	return !strings.Contains(value, "\n") && !strings.HasSuffix(value, ";") && !strings.HasPrefix(value, "return ") && !strings.HasPrefix(value, "throw ")
}

func statementTerminator(selected string, kotlin bool) string {
	if !kotlin && (strings.HasSuffix(strings.TrimSpace(selected), ";") || strings.Contains(selected, "\n")) {
		return ";"
	}
	return ""
}

func uniqueSymbolName(symbols []analysis.Symbol, base string) string {
	used := make(map[string]bool, len(symbols))
	for _, symbol := range symbols {
		used[symbol.Name] = true
	}
	if !used[base] {
		return base
	}
	for n := 2; ; n++ {
		candidate := base + integerString(n)
		if !used[candidate] {
			return candidate
		}
	}
}

func integerString(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [24]byte
	n := len(digits)
	for value > 0 {
		n--
		digits[n] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[n:])
}

func containingCallableHasModifier(symbols []analysis.Symbol, offset int, modifier string) bool {
	for _, symbol := range symbols {
		if analysis.IsCallableKind(symbol.Kind) && symbol.StartByte <= offset && offset <= symbol.EndByte {
			for _, candidate := range symbol.Modifiers {
				if candidate == modifier {
					return true
				}
			}
		}
	}
	return false
}

func reindentBlock(value, indent string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	minimum := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		count := 0
		for _, r := range line {
			if !unicode.IsSpace(r) {
				break
			}
			count++
		}
		if minimum < 0 || count < minimum {
			minimum = count
		}
	}
	if minimum < 0 {
		minimum = 0
	}
	for n := range lines {
		line := lines[n]
		cut := 0
		for cut < len(line) && cut < minimum && (line[cut] == ' ' || line[cut] == '\t') {
			cut++
		}
		lines[n] = indent + line[cut:]
	}
	return strings.Join(lines, "\n")
}

func lineStart(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	return strings.LastIndexByte(text[:offset], '\n') + 1
}

func lineEndIncludingNewline(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	if end := strings.IndexByte(text[offset:], '\n'); end >= 0 {
		return offset + end + 1
	}
	return len(text)
}

func isSimpleIdentifierText(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if r == '_' || r == '$' || unicode.IsLetter(r) || index > 0 && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
