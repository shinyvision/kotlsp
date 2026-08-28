// Package lexical provides the shared, immutable lexical boundary model used
// by editor features that must operate on incomplete Java/Kotlin source.
package lexical

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type Kind uint8

const (
	Code Kind = iota
	Literal
	LineComment
	BlockComment
	DocComment
)

type Region struct {
	Start, End           int
	OuterStart, OuterEnd int
	Kind                 Kind
	Nested               bool
}

type TokenKind uint8

const (
	Identifier TokenKind = iota
	Number
	String
	Character
	Operator
	Delimiter
)

type Token struct {
	Start int
	End   int
	Kind  TokenKind
	Text  string
}

// Tokenize is the shared lossless token boundary layer for incomplete Java and
// Kotlin snippets. It recognizes Unicode/backtick identifiers, nested Kotlin
// comments, Kotlin raw strings, Java text blocks, escapes, and maximal
// operators while retaining byte offsets into the original source.
func Tokenize(text string, kotlin bool) []Token {
	tokens, complete := TokenizeBounded(text, kotlin, 100_000)
	if !complete {
		return nil
	}
	return tokens
}

// TokenizeBounded is the trust-boundary form of Tokenize. It distinguishes a
// genuinely token-free snippet from one whose token inventory was withheld,
// allowing semantic consumers to abstain instead of reasoning from a prefix.
func TokenizeBounded(text string, kotlin bool, limit int) ([]Token, bool) {
	if limit <= 0 {
		return nil, false
	}
	tokens := make([]Token, 0, min(len(text)/4, limit))
	appendToken := func(token Token) bool {
		if len(tokens) >= limit {
			return false
		}
		tokens = append(tokens, token)
		return true
	}
	for at := 0; at < len(text); {
		if unicode.IsSpace(rune(text[at])) {
			at++
			continue
		}
		if at+1 < len(text) && text[at:at+2] == "//" {
			if end := strings.IndexByte(text[at+2:], '\n'); end >= 0 {
				at += end + 3
			} else {
				break
			}
			continue
		}
		if at+1 < len(text) && text[at:at+2] == "/*" {
			depth, cursor := 1, at+2
			for cursor < len(text) && depth > 0 {
				if kotlin && cursor+1 < len(text) && text[cursor:cursor+2] == "/*" {
					depth++
					cursor += 2
				} else if cursor+1 < len(text) && text[cursor:cursor+2] == "*/" {
					depth--
					cursor += 2
				} else {
					_, size := utf8.DecodeRuneInString(text[cursor:])
					cursor += max(size, 1)
				}
			}
			at = cursor
			continue
		}
		start := at
		if at+2 < len(text) && text[at:at+3] == `"""` {
			at += 3
			if end := strings.Index(text[at:], `"""`); end >= 0 {
				at += end + 3
			} else {
				at = len(text)
			}
			if !appendToken(Token{Start: start, End: at, Kind: String, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		if text[at] == '"' || text[at] == '\'' {
			quote := text[at]
			at++
			for at < len(text) {
				if text[at] == '\\' {
					at += min(2, len(text)-at)
					continue
				}
				value := text[at]
				at++
				if value == quote || value == '\n' {
					break
				}
			}
			kind := String
			if quote == '\'' {
				kind = Character
			}
			if !appendToken(Token{Start: start, End: at, Kind: kind, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		if kotlin && text[at] == '`' {
			at++
			for at < len(text) && text[at] != '`' && text[at] != '\n' {
				_, size := utf8.DecodeRuneInString(text[at:])
				at += max(size, 1)
			}
			if at < len(text) && text[at] == '`' {
				at++
			}
			if !appendToken(Token{Start: start, End: at, Kind: Identifier, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(text[at:])
		if identifierRuneStart(r, kotlin) {
			at += size
			for at < len(text) {
				r, size = utf8.DecodeRuneInString(text[at:])
				if !identifierRunePart(r, kotlin) {
					break
				}
				at += size
			}
			if !appendToken(Token{Start: start, End: at, Kind: Identifier, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		if unicode.IsDigit(r) {
			at += size
			for at < len(text) {
				r, size = utf8.DecodeRuneInString(text[at:])
				if !unicode.IsDigit(r) && !unicode.IsLetter(r) && r != '_' && r != '.' {
					break
				}
				at += size
			}
			if !appendToken(Token{Start: start, End: at, Kind: Number, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		if strings.ContainsRune("()[]{};,", r) {
			at += size
			if !appendToken(Token{Start: start, End: at, Kind: Delimiter, Text: text[start:at]}) {
				return nil, false
			}
			continue
		}
		at += size
		for at < len(text) {
			next, nextSize := utf8.DecodeRuneInString(text[at:])
			if unicode.IsSpace(next) || unicode.IsLetter(next) || unicode.IsDigit(next) || strings.ContainsRune("()[]{};,\"'`", next) {
				break
			}
			at += nextSize
		}
		if !appendToken(Token{Start: start, End: at, Kind: Operator, Text: text[start:at]}) {
			return nil, false
		}
	}
	return tokens, true
}

func identifierRuneStart(value rune, kotlin bool) bool {
	return value == '_' || kotlin && value == '$' || unicode.IsLetter(value)
}

func identifierRunePart(value rune, kotlin bool) bool {
	return identifierRuneStart(value, kotlin) || unicode.IsDigit(value) || unicode.Is(unicode.Mn, value) || unicode.Is(unicode.Mc, value)
}

// SplitTopLevel returns byte-faithful expression segments separated only at
// delimiter depth zero. Literal/comment delimiters are tokens and therefore
// cannot corrupt balancing.
func SplitTopLevel(text string, separator string, kotlin bool) []string {
	return splitTopLevel(text, separator, kotlin, false)
}

// SplitTopLevelTypes is the type-grammar variant of SplitTopLevel. In a type
// list every balanced angle pair is generic syntax; the expression variant
// below requires contextual evidence so comparisons such as a < b, c remain
// two arguments.
func SplitTopLevelTypes(text string, separator string, kotlin bool) []string {
	return splitTopLevel(text, separator, kotlin, true)
}

func splitTopLevel(text string, separator string, kotlin, typeGrammar bool) []string {
	tokens, complete := TokenizeBounded(text, kotlin, 100_000)
	if !complete {
		return nil
	}
	start := 0
	parens, brackets, braces, angles := 0, 0, 0, 0
	var values []string
	for tokenIndex, token := range tokens {
		if parens == 0 && brackets == 0 && braces == 0 && angles == 0 && token.Text == separator {
			if value := strings.TrimSpace(text[start:token.Start]); value != "" {
				values = append(values, value)
			}
			start = token.End
			continue
		}
		switch token.Text {
		case "(":
			parens++
		case ")":
			parens--
		case "[":
			brackets++
		case "]":
			brackets--
		case "{":
			braces++
		case "}":
			braces--
		case "<":
			if angles > 0 || typeGrammar || genericAngleOpens(tokens, tokenIndex) {
				angles++
			}
		case ">":
			if angles > 0 {
				angles--
			}
		default:
			if strings.Trim(token.Text, ">") == "" {
				angles -= min(angles, len(token.Text))
			}
		}
	}
	if value := strings.TrimSpace(text[start:]); value != "" {
		values = append(values, value)
	}
	return values
}

func genericAngleOpens(tokens []Token, opening int) bool {
	if opening <= 0 || opening >= len(tokens) || tokens[opening].Text != "<" {
		return false
	}
	previous := tokens[opening-1]
	if previous.Kind != Identifier && previous.Text != ">" && previous.Text != "]" && previous.Text != ")" {
		return false
	}
	depth := 0
	for index := opening; index < len(tokens); index++ {
		text := tokens[index].Text
		switch text {
		case "<":
			depth++
		case ">":
			depth--
		default:
			if strings.Trim(text, ">") == "" {
				depth -= len(text)
			}
		}
		if depth > 0 {
			continue
		}
		if depth < 0 {
			return false
		}
		if index+1 == len(tokens) {
			return true
		}
		next := tokens[index+1]
		switch next.Text {
		case "(", ")", "[", "]", "{", "}", ".", "?.", "::", ",", ";", "?", "!", ":":
			return true
		}
		// A capitalized owner followed by a name is overwhelmingly a generic
		// type declaration (Map<K,V> values), not a relational expression.
		first, _ := utf8.DecodeRuneInString(strings.Trim(previous.Text, "`"))
		return next.Kind == Identifier && unicode.IsUpper(first)
	}
	return false
}

// GenericAngleOpening exposes the shared comparison-versus-type-argument
// decision to structured expression consumers without making them reimplement
// the token lookahead rules.
func GenericAngleOpening(tokens []Token, opening int) bool {
	return genericAngleOpens(tokens, opening)
}

func TopLevelTokenIndex(text, wanted string, kotlin bool) int {
	tokens, complete := TokenizeBounded(text, kotlin, 100_000)
	if !complete {
		return -1
	}
	parens, brackets, braces, angles := 0, 0, 0, 0
	for tokenIndex, token := range tokens {
		if parens == 0 && brackets == 0 && braces == 0 && angles == 0 && token.Text == wanted {
			return token.Start
		}
		switch token.Text {
		case "(":
			parens++
		case ")":
			parens--
		case "[":
			brackets++
		case "]":
			brackets--
		case "{":
			braces++
		case "}":
			braces--
		case "<":
			if angles > 0 || genericAngleOpens(tokens, tokenIndex) {
				angles++
			}
		case ">":
			if angles > 0 {
				angles--
			}
		default:
			if strings.Trim(token.Text, ">") == "" {
				angles -= min(angles, len(token.Text))
			}
		}
	}
	return -1
}

func MatchingDelimiter(text string, open int, opening, closing string, kotlin bool) int {
	depth := 0
	started := false
	tokens, complete := TokenizeBounded(text, kotlin, 100_000)
	if !complete {
		return -1
	}
	for _, token := range tokens {
		if token.Start < open {
			continue
		}
		if !started {
			if token.Start != open || token.Text != opening {
				return -1
			}
			started = true
		}
		if token.Text == opening {
			depth++
		} else if token.Text == closing {
			depth--
			if depth == 0 {
				return token.Start
			}
		} else if closing == ">" && strings.Trim(token.Text, ">") == "" {
			for offset := range len(token.Text) {
				depth--
				if depth == 0 {
					return token.Start + offset
				}
			}
		}
	}
	return -1
}

func (r Region) Contains(offset int) bool {
	if offset < r.Start {
		return false
	}
	if r.Nested {
		return offset < r.End
	}
	return offset <= r.End
}

func ScanRegions(text string, kotlin bool, visit func(Region)) {
	_ = ScanRegionsBounded(text, kotlin, 100_000, visit)
}

// ScanRegionsBounded returns false instead of emitting a partial region model
// when adversarial nesting or region counts exceed the shared lexical limits.
func ScanRegionsBounded(text string, kotlin bool, maxRegions int, visit func(Region)) bool {
	type frame struct {
		kind       byte
		bodyStart  int
		braceDepth int
	}
	var stack []frame
	regions := 0
	emit := func(region Region) bool {
		if regions >= maxRegions {
			return false
		}
		regions++
		visit(region)
		return true
	}
	for at := 0; at < len(text); at++ {
		value := text[at]
		if len(stack) > 0 && stack[len(stack)-1].kind != '{' {
			top := &stack[len(stack)-1]
			if top.kind == '"' && value == '\\' {
				at++
				continue
			}
			if top.kind == '"' && (value == '"' || value == '\n') {
				if !emit(Region{Start: top.bodyStart, End: at, OuterStart: top.bodyStart - 1, OuterEnd: at + 1, Kind: Literal}) {
					return false
				}
				stack = stack[:len(stack)-1]
				continue
			}
			if top.kind == 't' && value == '"' && at+2 < len(text) && text[at+1] == '"' && text[at+2] == '"' {
				if !emit(Region{Start: top.bodyStart, End: at, OuterStart: top.bodyStart - 3, OuterEnd: at + 3, Kind: Literal}) {
					return false
				}
				stack = stack[:len(stack)-1]
				at += 2
				continue
			}
			if kotlin && value == '$' && at+1 < len(text) {
				if text[at+1] == '{' {
					if len(stack) >= 1024 {
						return false
					}
					stack = append(stack, frame{kind: '{', bodyStart: at + 1})
					at++
					continue
				}
				if start := at + 1; identifierStart(text, start) {
					end := start
					for end < len(text) && identifierByte(text[end]) {
						end++
					}
					if !emit(Region{Start: start, End: end, OuterStart: start, OuterEnd: end, Kind: Code, Nested: true}) {
						return false
					}
					at = end - 1
				}
			}
			continue
		}
		if value == '/' && at+1 < len(text) && text[at+1] == '/' {
			end := at + 2
			for end < len(text) && text[end] != '\n' {
				end++
			}
			if !emit(Region{Start: at + 2, End: end, OuterStart: at, OuterEnd: min(end+1, len(text)), Kind: LineComment}) {
				return false
			}
			at = end
			continue
		}
		if value == '/' && at+1 < len(text) && text[at+1] == '*' {
			kind, bodyStart := BlockComment, at+2
			if at+2 < len(text) && text[at+2] == '*' && !(at+3 < len(text) && text[at+3] == '/') {
				kind, bodyStart = DocComment, at+3
			}
			depth, end := 1, at+2
			for end < len(text) && depth > 0 {
				if kotlin && text[end] == '/' && end+1 < len(text) && text[end+1] == '*' {
					depth++
					end += 2
					continue
				}
				if text[end] == '*' && end+1 < len(text) && text[end+1] == '/' {
					depth--
					if depth == 0 {
						break
					}
					end += 2
					continue
				}
				end++
			}
			if bodyStart > end {
				bodyStart = end
			}
			if !emit(Region{Start: bodyStart, End: end, OuterStart: at, OuterEnd: min(end+2, len(text)), Kind: kind}) {
				return false
			}
			at = end + 1
			continue
		}
		if value == '"' {
			if len(stack) >= 1024 {
				return false
			}
			if at+2 < len(text) && text[at+1] == '"' && text[at+2] == '"' {
				stack = append(stack, frame{kind: 't', bodyStart: at + 3})
				at += 2
			} else {
				stack = append(stack, frame{kind: '"', bodyStart: at + 1})
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
			if !emit(Region{Start: at + 1, End: min(end, len(text)), OuterStart: at, OuterEnd: min(end+1, len(text)), Kind: Literal}) {
				return false
			}
			at = end
			continue
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if value == '{' {
				top.braceDepth++
			} else if value == '}' {
				if top.braceDepth == 0 {
					if !emit(Region{Start: top.bodyStart, End: at + 1, OuterStart: top.bodyStart, OuterEnd: at + 1, Kind: Code, Nested: true}) {
						return false
					}
					stack = stack[:len(stack)-1]
					continue
				}
				top.braceDepth--
			}
		}
	}
	for index := len(stack) - 1; index >= 0; index-- {
		kind, nested := Literal, false
		if stack[index].kind == '{' {
			kind, nested = Code, true
		}
		if !emit(Region{Start: stack[index].bodyStart, End: len(text), OuterStart: stack[index].bodyStart, OuterEnd: len(text), Kind: kind, Nested: nested}) {
			return false
		}
	}
	return true
}

func identifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func identifierStart(text string, at int) bool {
	return at < len(text) && identifierByte(text[at]) && !(text[at] >= '0' && text[at] <= '9')
}

// State carries multiline lexical state between formatter lines.
type State struct {
	BlockCommentDepth int
	Triple            bool
	Quote             byte
	Escaped           bool
}

func (state *State) ScanStructure(line string, kotlin bool) (opens, closes, parenDelta int) {
	for at := 0; at < len(line); at++ {
		if state.BlockCommentDepth > 0 {
			if kotlin && at+1 < len(line) && line[at] == '/' && line[at+1] == '*' {
				state.BlockCommentDepth++
				at++
			} else if at+1 < len(line) && line[at] == '*' && line[at+1] == '/' {
				state.BlockCommentDepth--
				at++
			}
			continue
		}
		if state.Triple {
			if at+2 < len(line) && line[at:at+3] == `"""` {
				state.Triple = false
				at += 2
			}
			continue
		}
		if state.Quote != 0 {
			if state.Escaped {
				state.Escaped = false
				continue
			}
			if line[at] == '\\' {
				state.Escaped = true
			} else if line[at] == state.Quote {
				state.Quote = 0
			}
			continue
		}
		if at+2 < len(line) && line[at:at+3] == `"""` {
			state.Triple = true
			at += 2
			continue
		}
		if at+1 < len(line) && line[at:at+2] == "//" {
			break
		}
		if at+1 < len(line) && line[at:at+2] == "/*" {
			state.BlockCommentDepth = 1
			at++
			continue
		}
		if line[at] == '\'' || line[at] == '"' {
			state.Quote = line[at]
			continue
		}
		switch line[at] {
		case '{':
			opens++
		case '}':
			closes++
		case '(', '[':
			parenDelta++
		case ')', ']':
			parenDelta--
		}
	}
	state.Quote, state.Escaped = 0, false
	return opens, closes, parenDelta
}
