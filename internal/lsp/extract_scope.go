package lsp

import (
	"regexp"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// statementInsertion is where a declaration extracted from offset goes: just
// before the statement that contains it, in the innermost block that does.
type statementInsertion struct {
	offset int
	indent string
	// inline is set when that statement shares its line with the block's
	// opening brace (`map { it.name }`); the declaration then gets lines of
	// its own.
	inline bool
	// replaceFrom, when below offset, is where whitespace the declaration
	// replaces begins.
	replaceFrom int
}

var whenBodyHeader = regexp.MustCompile(`\bwhen\b\s*(\(.*\))?\s*$`)

var lambdaParametersBeforeArrow = regexp.MustCompile(`^[\s\w,():<>?.@*]*->`)

// statementInsertionPoint finds where to declare a value extracted from
// offset. The start of the selection's line is not that place: inside a
// multi-line chain it is the middle of an expression, and after `}.map {` it
// is inside the previous lambda. A class or `when` body is no place for a
// local either: the first is skipped as unsupported, the second is part of
// the statement around it.
func statementInsertionPoint(text string, offset int, symbols []analysis.Symbol) (statementInsertion, bool) {
	if offset <= 0 || offset > len(text) {
		return statementInsertion{}, false
	}
	var blocks []int
	for index := 0; index < offset; index++ {
		switch c := text[index]; c {
		case '"', '\'':
			index = skipLiteral(text, index, offset)
		case '/':
			if index+1 < offset && text[index+1] == '/' {
				if end := strings.IndexByte(text[index:offset], '\n'); end >= 0 {
					index += end
				} else {
					index = offset
				}
			} else if index+1 < offset && text[index+1] == '*' {
				if end := strings.Index(text[index+2:offset], "*/"); end >= 0 {
					index += end + 3
				} else {
					index = offset
				}
			}
		case '{':
			blocks = append(blocks, index)
		case '}':
			if len(blocks) > 0 {
				blocks = blocks[:len(blocks)-1]
			}
		}
	}
	for len(blocks) > 0 {
		open := blocks[len(blocks)-1]
		blocks = blocks[:len(blocks)-1]
		header := strings.TrimSpace(text[lineStart(text, open):open])
		if isTypeBody(open, symbols, text) {
			return statementInsertion{}, false
		}
		if whenBodyHeader.MatchString(header) {
			// A `when` body lists branches, not statements; the local goes
			// before the statement the `when` belongs to.
			continue
		}
		bodyStart := open + 1
		if arrow := lambdaParametersBeforeArrow.FindStringIndex(text[bodyStart:offset]); arrow != nil {
			bodyStart += arrow[1]
		}
		start := statementStartWithin(text, bodyStart, offset)
		for start < offset && (text[start] == ' ' || text[start] == '\t' || text[start] == '\n' || text[start] == '\r') {
			start++
		}
		lineBegin := lineStart(text, start)
		if lineBegin <= open {
			// `{ it * x }`: the spaces after the brace give way to the new line.
			spaces := start
			for spaces > bodyStart && (text[spaces-1] == ' ' || text[spaces-1] == '\t') {
				spaces--
			}
			return statementInsertion{offset: start, replaceFrom: spaces, indent: indentAt(text, open) + "    ", inline: true}, true
		}
		if strings.TrimSpace(text[lineBegin:start]) != "" {
			return statementInsertion{offset: start, indent: indentAt(text, start), inline: true}, true
		}
		return statementInsertion{offset: lineBegin, indent: text[lineBegin:start]}, true
	}
	return statementInsertion{}, false
}

// isTypeBody reports whether the brace at open opens a class, object or
// interface body, where a local declaration cannot go.
func isTypeBody(open int, symbols []analysis.Symbol, text string) bool {
	for _, symbol := range symbols {
		// The file's JVM facade class spans the whole file but has no body.
		if !analysis.IsTypeKind(symbol.Kind) || symbol.Synthetic || symbol.StartByte > open || symbol.EndByte <= open {
			continue
		}
		from := symbol.NameEndByte
		if from <= symbol.StartByte || from > open {
			from = symbol.StartByte
		}
		if brace := typeBodyBrace(text, from, symbol.EndByte); brace == open {
			return true
		}
	}
	header := strings.TrimSpace(text[lineStart(text, open):open])
	return strings.HasPrefix(header, "object") || strings.Contains(header, "= object") || strings.Contains(header, "companion object")
}

// typeBodyBrace finds the brace that opens a type's body, skipping the
// parentheses of its primary constructor and of supertype calls.
func typeBodyBrace(text string, from, end int) int {
	depth := 0
	for index := from; index < end && index < len(text); index++ {
		switch c := text[index]; c {
		case '"', '\'':
			index = skipLiteral(text, index, end)
		case '(', '<', '[':
			depth++
		case ')', '>', ']':
			depth--
		case '{':
			if depth <= 0 {
				return index
			}
		}
	}
	return -1
}

// statementStartWithin returns where the statement containing offset starts,
// scanning the block body from start. Line breaks end statements unless the
// next line continues the expression (`.map { }`) or the line ends in an
// operator.
func statementStartWithin(text string, start, offset int) int {
	statement := start
	depth := 0
	for index := start; index < offset; index++ {
		switch c := text[index]; c {
		case '"', '\'':
			index = skipLiteral(text, index, offset)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ';':
			if depth == 0 {
				statement = index + 1
			}
		case '\n':
			if depth != 0 {
				continue
			}
			previous := strings.TrimSpace(text[lineStart(text, index):index])
			next := strings.TrimSpace(text[index+1 : min(len(text), index+1+strings.IndexByte(text[index+1:]+"\n", '\n'))])
			if previous == "" || !continuesExpression(previous, next) {
				statement = index + 1
			}
		}
	}
	return statement
}

func continuesExpression(previous, next string) bool {
	for _, prefix := range []string{".", "?.", "?:", "&&", "||", "+", "*", "/", "%", "==", "!=", "as ", "as?", "->"} {
		if strings.HasPrefix(next, prefix) {
			return true
		}
	}
	for _, suffix := range []string{"=", "(", ",", ".", "+", "-", "*", "/", "&&", "||", "?:", "->", "?."} {
		if strings.HasSuffix(previous, suffix) {
			return true
		}
	}
	return false
}

func skipLiteral(text string, open, end int) int {
	quote := text[open]
	if quote == '"' && strings.HasPrefix(text[open:], `"""`) {
		if close := strings.Index(text[open+3:end], `"""`); close >= 0 {
			return open + 3 + close + 2
		}
		return end
	}
	for index := open + 1; index < end; index++ {
		switch text[index] {
		case '\\':
			index++
		case quote:
			return index
		case '\n':
			return index
		}
	}
	return end
}

// companionBodyInsertion is where a constant goes in the class's existing
// companion object, or ok=false when it has none (or one without a body).
func companionBodyInsertion(text string, symbols []analysis.Symbol, owner analysis.Symbol) (int, string, bool) {
	for _, symbol := range symbols {
		if symbol.Kind != analysis.KindObject || symbol.ContainerID != owner.ID || !containsModifier(symbol.Modifiers, "companion") {
			continue
		}
		brace := typeBodyBrace(text, symbol.StartByte, symbol.EndByte+1)
		if brace < 0 {
			return 0, "", false
		}
		return brace + 1, indentAt(text, symbol.StartByte) + "    ", true
	}
	return 0, "", false
}
