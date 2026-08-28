package analysis

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

type largeContainer struct {
	symbol int
	depth  int
}

// maxLargeFileOccurrences bounds the declarations and references the large
// fallback publishes. Large mode starts at 8 MiB of source, which at ordinary
// identifier density is on the order of a million occurrences; a cap far
// below that withheld the very call sites the fallback exists to retain.
const maxLargeFileOccurrences = 1 << 20

// largeLexState carries the constructs which can cross a line boundary. The
// large-file parser intentionally recognizes only line-oriented declarations,
// but it must never recognize declaration-shaped prose inside a block comment
// or text/raw string as code.
type largeLexState struct {
	blockDepth int
	triple     bool
}

// parseLargeDeclarations is a bounded-memory, linear fallback for generated
// Kotlin/Java files. It extracts every line-oriented declaration without an
// AST timeout, preserving document symbols and name-based navigation while a
// file is far beyond normal interactive size.
func parseLargeDeclarations(ctx context.Context, doc *textdoc.Document, parsed *ParsedFile) {
	source := doc.Text
	type lexicalResult struct {
		references []Reference
		tokens     []Token
		exhausted  bool
	}
	lexicalDone := make(chan lexicalResult, 1)
	go func() {
		lexical := &ParsedFile{URI: parsed.URI, Language: parsed.Language}
		exhausted := addLargeReferences(ctx, doc, lexical)
		lexicalDone <- lexicalResult{references: lexical.References, tokens: lexical.Tokens, exhausted: exhausted}
	}()
	containers := make([]largeContainer, 0, 8)
	depth, lineNumber := 0, 0
	lexical := largeLexState{}
	for lineStart := 0; lineStart <= len(source); {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		if len(parsed.Symbols) >= maxLargeFileOccurrences {
			parsed.Diagnostics = append(parsed.Diagnostics, protocol.Diagnostic{Severity: 1, Source: "kotlsp", Code: "large-file-occurrence-limit", Message: "large-file declarations exceed the 1048576-symbol publication safety limit; remaining analysis was withheld"})
			break
		}
		lineEnd := strings.IndexByte(source[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(source)
		} else {
			lineEnd += lineStart
		}
		line := source[lineStart:lineEnd]
		codeLine := maskLargeCodeLine(line, parsed.Language, &lexical)
		trimOffset := 0
		for trimOffset < len(codeLine) && (codeLine[trimOffset] == ' ' || codeLine[trimOffset] == '\t' || codeLine[trimOffset] == '\r') {
			trimOffset++
		}
		trimmed := codeLine[trimOffset:]
		if parsed.Package == "" && strings.HasPrefix(trimmed, "package ") {
			value := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "package "), ";"))
			parsed.Package = value
			parsed.PackageRange = protocol.Range{Start: protocol.Position{Line: lineNumber, Character: trimOffset}, End: protocol.Position{Line: lineNumber, Character: len(line)}}
		} else if strings.HasPrefix(trimmed, "import ") {
			if len(parsed.Imports) >= 100_000 {
				parsed.Diagnostics = append(parsed.Diagnostics, protocol.Diagnostic{Severity: 1, Source: "kotlsp", Code: "large-file-import-limit", Message: "large-file imports exceed the 100000-import safety limit; remaining analysis was withheld"})
				break
			}
			value := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "import "), ";"))
			wildcard := strings.HasSuffix(value, ".*")
			value = strings.TrimSuffix(value, ".*")
			parsed.Imports = append(parsed.Imports, Import{Path: value, Wildcard: wildcard, Range: protocol.Range{Start: protocol.Position{Line: lineNumber, Character: trimOffset}, End: protocol.Position{Line: lineNumber, Character: len(line)}}})
		}

		containerID, containerName := "", ""
		if len(containers) > 0 {
			owner := parsed.Symbols[containers[len(containers)-1].symbol]
			containerID, containerName = owner.ID, owner.Name
		}
		if kind, nameStart, nameEnd, ok := largeTypeDeclaration(trimmed, parsed.Language); ok {
			absoluteNameStart := lineStart + trimOffset + nameStart
			absoluteNameEnd := lineStart + trimOffset + nameEnd
			name := source[absoluteNameStart:absoluteNameEnd]
			fqn := name
			if containerID != "" {
				fqn = parsed.Symbols[containers[len(containers)-1].symbol].FQN + "." + name
			} else if parsed.Package != "" {
				fqn = parsed.Package + "." + name
			}
			symbol := Symbol{ID: SymbolID(doc.URI, lineStart+trimOffset, kind, name), Name: name, FQN: fqn, Kind: kind, Language: parsed.Language, URI: doc.URI,
				Range: doc.Range(lineStart+trimOffset, lineEnd), SelectionRange: doc.Range(absoluteNameStart, absoluteNameEnd), StartByte: lineStart + trimOffset, EndByte: lineEnd,
				NameStartByte: absoluteNameStart, NameEndByte: absoluteNameEnd, ScopeStartByte: lineStart + trimOffset, ScopeEndByte: lineEnd,
				ContainerID: containerID, ContainerName: containerName, Package: parsed.Package}
			parsed.Symbols = append(parsed.Symbols, symbol)
			if strings.Contains(trimmed[nameEnd:], "{") {
				containers = append(containers, largeContainer{symbol: len(parsed.Symbols) - 1, depth: depth + 1})
			}
		} else if nameStart, nameEnd, parameters, returnType, ok := largeCallableDeclaration(trimmed, parsed.Language, containerName); ok {
			absoluteNameStart := lineStart + trimOffset + nameStart
			absoluteNameEnd := lineStart + trimOffset + nameEnd
			name := source[absoluteNameStart:absoluteNameEnd]
			kind := KindFunction
			if containerID != "" {
				kind = KindMethod
			}
			fqn := name
			if containerID != "" {
				fqn = parsed.Symbols[containers[len(containers)-1].symbol].FQN + "." + name
			} else if parsed.Package != "" {
				fqn = parsed.Package + "." + name
			}
			parsed.Symbols = append(parsed.Symbols, Symbol{ID: SymbolID(doc.URI, lineStart+trimOffset, kind, name), Name: name, FQN: fqn, Kind: kind, Language: parsed.Language, URI: doc.URI,
				Range: doc.Range(lineStart+trimOffset, lineEnd), SelectionRange: doc.Range(absoluteNameStart, absoluteNameEnd), StartByte: lineStart + trimOffset, EndByte: lineEnd,
				NameStartByte: absoluteNameStart, NameEndByte: absoluteNameEnd, ScopeStartByte: lineStart + trimOffset, ScopeEndByte: lineEnd,
				ContainerID: containerID, ContainerName: containerName, Package: parsed.Package, Type: returnType, Parameters: parameters})
			callableIndex := len(parsed.Symbols) - 1
			if strings.Contains(trimmed[nameEnd:], "{") {
				containers = append(containers, largeContainer{symbol: callableIndex, depth: depth + 1})
			}
			parameterRegionStart := strings.IndexByte(trimmed, '(') + 1
			for _, parameter := range parameters {
				relative := strings.Index(trimmed[parameterRegionStart:], parameter.Name)
				if relative < 0 {
					continue
				}
				relative += parameterRegionStart
				parameterStart := lineStart + trimOffset + relative
				callable := parsed.Symbols[callableIndex]
				parsed.Symbols = append(parsed.Symbols, Symbol{ID: SymbolID(doc.URI, parameterStart, KindParameter, parameter.Name), Name: parameter.Name, FQN: callable.FQN + "." + parameter.Name,
					Kind: KindParameter, Language: parsed.Language, URI: doc.URI, Range: doc.Range(parameterStart, parameterStart+len(parameter.Name)), SelectionRange: doc.Range(parameterStart, parameterStart+len(parameter.Name)),
					StartByte: parameterStart, EndByte: parameterStart + len(parameter.Name), NameStartByte: parameterStart, NameEndByte: parameterStart + len(parameter.Name),
					ScopeStartByte: callable.StartByte, ScopeEndByte: callable.EndByte, ContainerID: callable.ID, ContainerName: callable.Name, Package: parsed.Package, Type: parameter.Type})
				parameterRegionStart = relative + len(parameter.Name)
			}
		} else if nameStart, nameEnd, typ, _, ok := largeVariableDeclaration(trimmed, parsed.Language); ok {
			absoluteNameStart := lineStart + trimOffset + nameStart
			absoluteNameEnd := lineStart + trimOffset + nameEnd
			name := source[absoluteNameStart:absoluteNameEnd]
			kind := KindProperty
			if parsed.Language == LanguageJava {
				kind = KindField
			}
			if len(containers) > 0 && (parsed.Symbols[containers[len(containers)-1].symbol].Kind == KindFunction || parsed.Symbols[containers[len(containers)-1].symbol].Kind == KindMethod || parsed.Symbols[containers[len(containers)-1].symbol].Kind == KindConstructor) {
				kind = KindVariable
			}
			fqn := name
			if containerID != "" {
				fqn = parsed.Symbols[containers[len(containers)-1].symbol].FQN + "." + name
			} else if parsed.Package != "" {
				fqn = parsed.Package + "." + name
			}
			parsed.Symbols = append(parsed.Symbols, Symbol{ID: SymbolID(doc.URI, lineStart+trimOffset, kind, name), Name: name, FQN: fqn, Kind: kind, Language: parsed.Language, URI: doc.URI,
				Range: doc.Range(lineStart+trimOffset, lineEnd), SelectionRange: doc.Range(absoluteNameStart, absoluteNameEnd), StartByte: lineStart + trimOffset, EndByte: lineEnd,
				NameStartByte: absoluteNameStart, NameEndByte: absoluteNameEnd, ScopeStartByte: absoluteNameEnd, ScopeEndByte: lineEnd,
				ContainerID: containerID, ContainerName: containerName, Package: parsed.Package, Type: typ})
		}

		depth += largeBraceDelta(codeLine)
		for len(containers) > 0 && depth < containers[len(containers)-1].depth {
			frame := containers[len(containers)-1]
			containers = containers[:len(containers)-1]
			parsed.Symbols[frame.symbol].EndByte = lineEnd
			parsed.Symbols[frame.symbol].ScopeEndByte = lineEnd
			parsed.Symbols[frame.symbol].Range.End = doc.Position(lineEnd)
		}
		if lineEnd == len(source) {
			break
		}
		lineStart, lineNumber = lineEnd+1, lineNumber+1
	}
	for _, symbol := range parsed.Symbols {
		parsed.Tokens = append(parsed.Tokens, Token{Range: symbol.SelectionRange, StartByte: symbol.NameStartByte, EndByte: symbol.NameEndByte, Type: semanticTypeForKind(symbol.Kind), Modifiers: 1})
	}
	owners := make(map[string]Symbol, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		if isContainerKind(symbol.Kind) {
			owners[symbol.ID] = symbol
		}
	}
	for index := range parsed.Symbols {
		symbol := &parsed.Symbols[index]
		if (symbol.Kind == KindVariable || symbol.Kind == KindParameter) && symbol.ContainerID != "" {
			if owner, ok := owners[symbol.ContainerID]; ok {
				symbol.ScopeEndByte = owner.EndByte
			}
		}
	}
	lexed := <-lexicalDone
	if lexed.exhausted {
		parsed.Diagnostics = append(parsed.Diagnostics, protocol.Diagnostic{Severity: 1, Source: "kotlsp", Code: "large-file-occurrence-limit", Message: "large-file references exceed the 1048576-occurrence publication safety limit; remaining analysis was withheld"})
	}
	declarationCursor := 0
	for index, reference := range lexed.references {
		for declarationCursor < len(parsed.Symbols) && parsed.Symbols[declarationCursor].NameEndByte <= reference.StartByte &&
			!(parsed.Symbols[declarationCursor].NameStartByte == reference.StartByte && parsed.Symbols[declarationCursor].NameEndByte == reference.EndByte) {
			declarationCursor++
		}
		if declarationCursor < len(parsed.Symbols) && parsed.Symbols[declarationCursor].NameStartByte == reference.StartByte && parsed.Symbols[declarationCursor].NameEndByte == reference.EndByte {
			continue
		}
		parsed.References = append(parsed.References, reference)
		// addLargeReferences emits exactly one token with each reference. Pair
		// them by index instead of allocating and probing a second 60k-entry
		// byte-range map on every large-file edit.
		if index < len(lexed.tokens) {
			parsed.Tokens = append(parsed.Tokens, lexed.tokens[index])
		}
	}
	assignLargeReferenceContainers(parsed)
	sort.SliceStable(parsed.Tokens, func(left, right int) bool { return parsed.Tokens[left].StartByte < parsed.Tokens[right].StartByte })
}

func maskLargeCodeLine(line string, language Language, state *largeLexState) string {
	masked := []byte(line)
	blank := func(start, end int) {
		for index := start; index < end; index++ {
			if masked[index] != '\t' && masked[index] != '\r' {
				masked[index] = ' '
			}
		}
	}
	for index := 0; index < len(line); {
		if state.blockDepth > 0 {
			start := index
			for index < len(line) && state.blockDepth > 0 {
				if index+1 < len(line) && line[index] == '/' && line[index+1] == '*' && language == LanguageKotlin {
					state.blockDepth++
					index += 2
					continue
				}
				if index+1 < len(line) && line[index] == '*' && line[index+1] == '/' {
					state.blockDepth--
					index += 2
					continue
				}
				index++
			}
			blank(start, index)
			continue
		}
		if state.triple {
			start := index
			if end := strings.Index(line[index:], "\"\"\""); end >= 0 {
				index += end + 3
				state.triple = false
			} else {
				index = len(line)
			}
			blank(start, index)
			continue
		}
		if index+1 < len(line) && line[index] == '/' && line[index+1] == '/' {
			blank(index, len(line))
			break
		}
		if index+1 < len(line) && line[index] == '/' && line[index+1] == '*' {
			start := index
			state.blockDepth = 1
			index += 2
			blank(start, index)
			continue
		}
		if index+2 < len(line) && line[index:index+3] == "\"\"\"" {
			start := index
			state.triple = true
			index += 3
			blank(start, index)
			continue
		}
		if line[index] == '"' || line[index] == '\'' {
			start, quote := index, line[index]
			index++
			escaped := false
			for index < len(line) {
				value := line[index]
				index++
				if escaped {
					escaped = false
				} else if value == '\\' {
					escaped = true
				} else if value == quote {
					break
				}
			}
			blank(start, index)
			continue
		}
		index++
	}
	return string(masked)
}

func assignLargeReferenceContainers(parsed *ParsedFile) {
	symbolCursor := 0
	active := make([]Symbol, 0, 8)
	for index := range parsed.References {
		start := parsed.References[index].StartByte
		for len(active) > 0 && active[len(active)-1].EndByte < start {
			active = active[:len(active)-1]
		}
		for symbolCursor < len(parsed.Symbols) && parsed.Symbols[symbolCursor].StartByte <= start {
			symbol := parsed.Symbols[symbolCursor]
			symbolCursor++
			if isContainerKind(symbol.Kind) && symbol.EndByte >= start {
				active = append(active, symbol)
			}
		}
		if len(active) > 0 {
			parsed.References[index].ContainerID = active[len(active)-1].ID
		}
	}
}

// addLargeReferences supplies the same name/call navigation substrate as the
// tree parser without constructing a multi-hundred-megabyte syntax tree. It is
// a single lexical pass and ignores comments, strings, package/import lines,
// and declaration name spans.
func addLargeReferences(ctx context.Context, doc *textdoc.Document, parsed *ParsedFile) bool {
	source := doc.Text
	declarations := make(map[[2]int]bool, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		declarations[[2]int{symbol.NameStartByte, symbol.NameEndByte}] = true
	}
	keywords := kotlinKeywords
	if parsed.Language == LanguageJava {
		keywords = javaKeywords
	}
	lineStart := 0
	for index := 0; index < len(source); {
		if index&4095 == 0 && ctx.Err() != nil {
			return false
		}
		if len(parsed.References) >= maxLargeFileOccurrences {
			return true
		}
		if source[index] == '\n' {
			index++
			lineStart = index
			continue
		}
		trimmed := strings.TrimLeft(source[lineStart:index+1], " \t\r")
		if strings.HasPrefix(trimmed, "package ") || strings.HasPrefix(trimmed, "import ") {
			if newline := strings.IndexByte(source[index:], '\n'); newline >= 0 {
				index += newline
				continue
			}
			break
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '/' {
			if newline := strings.IndexByte(source[index+2:], '\n'); newline >= 0 {
				index += newline + 2
				continue
			}
			break
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
			depth := 1
			index += 2
			for index < len(source) && depth > 0 {
				if index&4095 == 0 && ctx.Err() != nil {
					return false
				}
				if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
					depth++
					index += 2
					continue
				}
				if index+1 < len(source) && source[index] == '*' && source[index+1] == '/' {
					depth--
					index += 2
					continue
				}
				index++
			}
			continue
		}
		if source[index] == '"' || source[index] == '\'' {
			quote := source[index]
			triple := quote == '"' && index+2 < len(source) && source[index+1] == '"' && source[index+2] == '"'
			if triple {
				index += 3
				if end := strings.Index(source[index:], "\"\"\""); end >= 0 {
					index += end + 3
					continue
				}
				break
			}
			index++
			for index < len(source) {
				if source[index] == '\\' {
					index += 2
					continue
				}
				value := source[index]
				index++
				if value == quote {
					break
				}
			}
			continue
		}
		if !isLargeIdentifierStart(source[index]) {
			index++
			continue
		}
		start := index
		index++
		for index < len(source) && isLargeIdentifierByte(source[index]) {
			index++
		}
		end := index
		name := source[start:end]
		if declarations[[2]int{start, end}] || keywords[name] {
			continue
		}
		qualifier := ""
		before := start - 1
		for before >= 0 && (source[before] == ' ' || source[before] == '\t') {
			before--
		}
		if before >= 0 && source[before] == '.' {
			qualifierEnd := before
			qualifierStart := qualifierEnd
			for qualifierStart > 0 && isLargeIdentifierByte(source[qualifierStart-1]) {
				qualifierStart--
			}
			qualifier = source[qualifierStart:qualifierEnd]
		}
		after := end
		for after < len(source) && (source[after] == ' ' || source[after] == '\t') {
			after++
		}
		role, arity := RoleRead, -1
		var arguments []protocol.Range
		if after < len(source) && source[after] == '(' {
			role = RoleCall
			var complete bool
			arguments, after, complete = largeCallArguments(ctx, doc, source, after)
			if complete {
				arity = len(arguments)
			} else {
				arguments = nil
			}
		} else if name[0] >= 'A' && name[0] <= 'Z' {
			role = RoleType
		}
		parsed.References = append(parsed.References, Reference{Name: name, Qualifier: qualifier, URI: doc.URI, Range: doc.Range(start, end), StartByte: start, EndByte: end, Role: role, Arity: arity, Arguments: arguments})
		parsed.Tokens = append(parsed.Tokens, Token{Range: doc.Range(start, end), StartByte: start, EndByte: end, Type: func() uint32 {
			if role == RoleType {
				return 1
			}
			if role == RoleCall {
				return 13
			}
			return 8
		}()})
	}
	return false
}

func isLargeIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func largeCallArguments(ctx context.Context, doc *textdoc.Document, source string, open int) ([]protocol.Range, int, bool) {
	parenDepth, bracketDepth, braceDepth, start := 1, 0, 0, open+1
	var arguments []protocol.Range
	for index := open + 1; index < len(source); index++ {
		if index&4095 == 0 && ctx.Err() != nil {
			return nil, open + 1, false
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '/' {
			if newline := strings.IndexByte(source[index+2:], '\n'); newline >= 0 {
				index += newline + 1
				continue
			}
			return arguments, open + 1, false
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
			depth := 1
			index++
			for index++; index < len(source) && depth > 0; index++ {
				if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
					depth++
					index++
				} else if index+1 < len(source) && source[index] == '*' && source[index+1] == '/' {
					depth--
					index++
				}
			}
			if depth > 0 {
				return arguments, open + 1, false
			}
			index--
			continue
		}
		if source[index] == '"' || source[index] == '\'' {
			quote := source[index]
			if quote == '"' && index+2 < len(source) && source[index:index+3] == "\"\"\"" {
				if end := strings.Index(source[index+3:], "\"\"\""); end >= 0 {
					index += end + 5
					continue
				}
				return arguments, open + 1, false
			}
			escaped := false
			for index++; index < len(source); index++ {
				value := source[index]
				if escaped {
					escaped = false
				} else if value == '\\' {
					escaped = true
				} else if value == quote {
					break
				}
			}
			if index >= len(source) {
				return arguments, open + 1, false
			}
			continue
		}
		switch source[index] {
		case '(':
			parenDepth++
		case ')':
			parenDepth--
			if parenDepth == 0 {
				if valueStart, valueEnd := trimByteRange(source, start, index); valueEnd > valueStart {
					arguments = append(arguments, doc.Range(valueStart, valueEnd))
				}
				return arguments, index + 1, true
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ',':
			if parenDepth == 1 && bracketDepth == 0 && braceDepth == 0 {
				if len(arguments) >= 4096 {
					return nil, open + 1, false
				}
				if valueStart, valueEnd := trimByteRange(source, start, index); valueEnd > valueStart {
					arguments = append(arguments, doc.Range(valueStart, valueEnd))
				}
				start = index + 1
			}
		}
	}
	return arguments, open + 1, false
}

func trimByteRange(source string, start, end int) (int, int) {
	for start < end && (source[start] == ' ' || source[start] == '\t' || source[start] == '\r' || source[start] == '\n') {
		start++
	}
	for end > start && (source[end-1] == ' ' || source[end-1] == '\t' || source[end-1] == '\r' || source[end-1] == '\n') {
		end--
	}
	return start, end
}

func largeTypeDeclaration(line string, language Language) (SymbolKind, int, int, bool) {
	candidates := []struct {
		word string
		kind SymbolKind
	}{{"annotation class", KindAnnotation}, {"enum class", KindEnum}, {"interface", KindInterface}, {"class", KindClass}, {"object", KindObject}}
	if language == LanguageJava {
		candidates = []struct {
			word string
			kind SymbolKind
		}{{"@interface", KindAnnotation}, {"interface", KindInterface}, {"enum", KindEnum}, {"record", KindRecord}, {"class", KindClass}}
	}
	for _, candidate := range candidates {
		at := wordIndex(line, candidate.word)
		if at < 0 {
			continue
		}
		start := at + len(candidate.word)
		for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
			start++
		}
		end := identifierEnd(line, start)
		if end > start {
			return candidate.kind, start, end, true
		}
	}
	return KindUnknown, 0, 0, false
}

func largeCallableDeclaration(line string, language Language, container string) (int, int, []Parameter, string, bool) {
	open := strings.IndexByte(line, '(')
	if open < 0 {
		return 0, 0, nil, "", false
	}
	nameEnd := open
	for nameEnd > 0 && (line[nameEnd-1] == ' ' || line[nameEnd-1] == '\t') {
		nameEnd--
	}
	nameStart := nameEnd
	for nameStart > 0 && isLargeIdentifierByte(line[nameStart-1]) {
		nameStart--
	}
	if nameStart == nameEnd {
		return 0, 0, nil, "", false
	}
	name := line[nameStart:nameEnd]
	if language == LanguageKotlin {
		funAt := wordIndex(line[:nameStart], "fun")
		if funAt < 0 {
			return 0, 0, nil, "", false
		}
	} else {
		switch name {
		case "if", "for", "while", "switch", "catch", "return", "new", "throw", "synchronized":
			return 0, 0, nil, "", false
		}
		if nameStart == 0 {
			return 0, 0, nil, "", false
		}
		head := strings.TrimSpace(line[:nameStart])
		// Large mode deliberately prefers a missed complex declaration over an
		// invented one. Calls such as service.run(value), return run(value), and
		// result = run(value) used to look like methods because they contain the
		// same identifier/parenthesis surface. A Java declaration must have a
		// type-or-constructor head, never an expression operator or statement
		// keyword immediately before the candidate name.
		if strings.ContainsAny(head, ".=+*/%!?:|&") {
			return 0, 0, nil, "", false
		}
		headFields := strings.Fields(head)
		if len(headFields) == 0 {
			return 0, 0, nil, "", false
		}
		lastHead := headFields[len(headFields)-1]
		if name != container {
			switch lastHead {
			case "return", "throw", "new", "case", "yield", "assert", "else", "do":
				return 0, 0, nil, "", false
			}
			if !largeJavaTypeHead(lastHead) {
				return 0, 0, nil, "", false
			}
		}
	}
	close := strings.IndexByte(line[open+1:], ')')
	if close < 0 {
		return 0, 0, nil, "", false
	}
	close += open + 1
	parameters, parametersOK := largeParameters(line[open+1:close], language)
	if !parametersOK {
		return 0, 0, nil, "", false
	}
	returnType := ""
	if language == LanguageKotlin {
		tail := strings.TrimSpace(line[close+1:])
		if strings.HasPrefix(tail, ":") {
			tail = strings.TrimSpace(tail[1:])
			end := strings.IndexAny(tail, "={ \t")
			if end < 0 {
				end = len(tail)
			}
			returnType = strings.TrimSpace(tail[:end])
		}
	} else if name != container {
		head := strings.Fields(line[:nameStart])
		if len(head) > 0 {
			returnType = head[len(head)-1]
		}
	}
	return nameStart, nameEnd, parameters, returnType, true
}

func largeJavaTypeHead(value string) bool {
	value = strings.TrimSpace(value)
	for strings.HasSuffix(value, "[]") {
		value = strings.TrimSuffix(value, "[]")
	}
	if value == "" || value == "void" {
		return value == "void"
	}
	for index, r := range value {
		if index == 0 {
			if r != '_' && r != '$' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && r != '$' && r != '.' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func largeVariableDeclaration(line string, language Language) (nameStart, nameEnd int, typ, initializer string, ok bool) {
	if language == LanguageKotlin {
		at, keywordLength := wordIndex(line, "val"), len("val")
		if at < 0 {
			at, keywordLength = wordIndex(line, "var"), len("var")
		}
		if at < 0 {
			return 0, 0, "", "", false
		}
		nameStart = at + keywordLength
		for nameStart < len(line) && (line[nameStart] == ' ' || line[nameStart] == '\t') {
			nameStart++
		}
		nameEnd = identifierEnd(line, nameStart)
		if nameEnd == nameStart {
			return 0, 0, "", "", false
		}
		tail := strings.TrimSpace(line[nameEnd:])
		if strings.HasPrefix(tail, ":") {
			typeText := strings.TrimSpace(tail[1:])
			end := strings.IndexAny(typeText, "=;")
			if end < 0 {
				end = len(typeText)
			}
			typ = strings.TrimSpace(typeText[:end])
		}
		if equal := strings.IndexByte(tail, '='); equal >= 0 {
			initializer = strings.TrimSpace(strings.TrimSuffix(tail[equal+1:], ";"))
		}
		return nameStart, nameEnd, typ, initializer, true
	}
	if !strings.Contains(line, "=") || strings.Contains(line, "(") {
		return 0, 0, "", "", false
	}
	equal := strings.IndexByte(line, '=')
	left := strings.TrimSpace(line[:equal])
	fields := strings.Fields(left)
	if len(fields) < 2 {
		return 0, 0, "", "", false
	}
	name := fields[len(fields)-1]
	nameEnd = strings.LastIndex(line[:equal], name) + len(name)
	nameStart = nameEnd - len(name)
	if identifierEnd(line, nameStart) != nameEnd {
		return 0, 0, "", "", false
	}
	typ = fields[len(fields)-2]
	initializer = strings.TrimSpace(strings.TrimSuffix(line[equal+1:], ";"))
	return nameStart, nameEnd, typ, initializer, true
}

func largeParameters(value string, language Language) ([]Parameter, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return []Parameter{}, true
	}
	parameters := make([]Parameter, 0, 8)
	for start, parts := 0, 0; start <= len(value); parts++ {
		if parts >= 4096 || len(parameters) >= 4096 {
			return nil, false
		}
		end := strings.IndexByte(value[start:], ',')
		if end < 0 {
			end = len(value)
		} else {
			end += start
		}
		part := value[start:end]
		part = strings.TrimSpace(part)
		if language == LanguageKotlin {
			name, typ, ok := strings.Cut(part, ":")
			if ok {
				rawName := strings.TrimSpace(name)
				variadic := strings.HasPrefix(rawName, "vararg ")
				rawName = strings.TrimSpace(strings.TrimPrefix(rawName, "vararg "))
				parameters = append(parameters, Parameter{Name: rawName, Type: strings.TrimSpace(strings.SplitN(typ, "=", 2)[0]), Variadic: variadic})
			}
		} else {
			fields := strings.Fields(part)
			if len(fields) >= 2 {
				typeName := strings.Join(fields[:len(fields)-1], " ")
				variadic := strings.Contains(typeName, "...")
				parameters = append(parameters, Parameter{Name: fields[len(fields)-1], Type: strings.ReplaceAll(typeName, "...", ""), Variadic: variadic})
			}
		}
		if end == len(value) {
			break
		}
		start = end + 1
	}
	return parameters, true
}

func wordIndex(value, word string) int {
	for offset := 0; ; {
		at := strings.Index(value[offset:], word)
		if at < 0 {
			return -1
		}
		at += offset
		beforeOK := at == 0 || !isLargeIdentifierByte(value[at-1])
		after := at + len(word)
		afterOK := after == len(value) || !isLargeIdentifierByte(value[after])
		if beforeOK && afterOK {
			return at
		}
		offset = at + 1
	}
}

func identifierEnd(value string, start int) int {
	end := start
	for end < len(value) && isLargeIdentifierByte(value[end]) {
		end++
	}
	return end
}

func isLargeIdentifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func largeBraceDelta(line string) int {
	delta := 0
	inString, escaped := byte(0), false
	for index := 0; index < len(line); index++ {
		value := line[index]
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
		if value == '/' && index+1 < len(line) && line[index+1] == '/' {
			break
		}
		if value == '\'' || value == '"' {
			inString = value
			continue
		}
		if value == '{' {
			delta++
		} else if value == '}' {
			delta--
		}
	}
	return delta
}
