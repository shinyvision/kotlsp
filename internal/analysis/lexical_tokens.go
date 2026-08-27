package analysis

import (
	"sort"
	"unicode"
	"unicode/utf8"
)

var semanticModifiers = map[string]bool{
	"abstract": true, "actual": true, "const": true, "crossinline": true,
	"data": true, "expect": true, "external": true, "final": true,
	"infix": true, "inline": true, "inner": true, "internal": true,
	"lateinit": true, "native": true, "noinline": true, "open": true,
	"operator": true, "override": true, "private": true, "protected": true,
	"public": true, "reified": true, "sealed": true, "static": true,
	"strictfp": true, "suspend": true, "synchronized": true, "tailrec": true,
	"transient": true, "vararg": true, "volatile": true,
}

func (b *parseBuilder) addLexicalTokens() {
	source := b.source
	for at := 0; at < len(source); {
		if isSpaceByte(source[at]) {
			at++
			continue
		}
		if at+1 < len(source) && source[at] == '/' && source[at+1] == '/' {
			end := at + 2
			for end < len(source) && source[end] != '\n' {
				end++
			}
			b.addLexicalSpan(at, end, 17, 0)
			at = end
			continue
		}
		if at+1 < len(source) && source[at] == '/' && source[at+1] == '*' {
			end, depth := at+2, 1
			for end < len(source) && depth > 0 {
				if end+1 < len(source) && source[end] == '/' && source[end+1] == '*' {
					depth++
					end += 2
				} else if end+1 < len(source) && source[end] == '*' && source[end+1] == '/' {
					depth--
					end += 2
				} else {
					end++
				}
			}
			mods := uint32(0)
			if at+2 < len(source) && source[at+2] == '*' {
				mods = SemanticModifierDocumentation
			}
			b.addLexicalSpan(at, end, 17, mods)
			at = end
			continue
		}
		if at+2 < len(source) && string(source[at:at+3]) == `"""` {
			end := at + 3
			for end+2 < len(source) && string(source[end:end+3]) != `"""` {
				end++
			}
			if end+2 < len(source) {
				end += 3
			}
			b.addLexicalSpan(at, end, 18, 0)
			at = end
			continue
		}
		if source[at] == '"' || source[at] == '\'' {
			quote, end, escaped := source[at], at+1, false
			for end < len(source) {
				if escaped {
					escaped = false
				} else if source[end] == '\\' {
					escaped = true
				} else if source[end] == quote {
					end++
					break
				} else if source[end] == '\n' {
					break
				}
				end++
			}
			b.addLexicalSpan(at, end, 18, 0)
			at = end
			continue
		}
		if source[at] >= '0' && source[at] <= '9' {
			end := at + 1
			for end < len(source) && (isIdentifierByte(source[end]) || source[end] == '.' || source[end] == '_') {
				end++
			}
			b.addLexicalSpan(at, end, 19, 0)
			at = end
			continue
		}
		if source[at] == '@' {
			end := at + 1
			for end < len(source) && isIdentifierByte(source[end]) {
				end++
			}
			if end > at+1 {
				b.addLexicalSpan(at+1, end, 22, 0)
				at = end
				continue
			}
		}
		if isIdentifierStart(source[at:]) {
			end := at
			for end < len(source) {
				r, size := utf8.DecodeRune(source[end:])
				if size == 0 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$') {
					break
				}
				end += size
			}
			word := string(source[at:end])
			if b.keywords[word] {
				typeID := uint32(15)
				if semanticModifiers[word] {
					typeID = 16
				}
				b.addLexicalSpan(at, end, typeID, 0)
			}
			at = end
			continue
		}
		if isOperatorByte(source[at]) {
			end := at + 1
			for end < len(source) && isOperatorByte(source[end]) {
				end++
			}
			b.addLexicalSpan(at, end, 21, 0)
			at = end
			continue
		}
		_, size := utf8.DecodeRune(source[at:])
		if size < 1 {
			size = 1
		}
		at += size
	}
}

func (b *parseBuilder) addLexicalSpan(start, end int, tokenType, modifiers uint32) {
	if start >= end {
		return
	}
	// Semantic tokens were sorted once before lexical scanning. Subtract their
	// occupied intervals with a binary search and forward sweep instead of an
	// O(lexical*semantic) all-pairs comparison.
	occupied := b.lexicalOccupied
	index := sort.Search(len(occupied), func(index int) bool { return occupied[index].EndByte > start })
	cursor := start
	emit := func(spanStart, spanEnd int) {
		lineStart := spanStart
		for lineStart < spanEnd {
			lineEnd := lineStart
			for lineEnd < spanEnd && b.source[lineEnd] != '\n' && b.source[lineEnd] != '\r' {
				lineEnd++
			}
			if lineEnd > lineStart {
				b.parsed.Tokens = append(b.parsed.Tokens, Token{Range: b.doc.Range(lineStart, lineEnd), StartByte: lineStart, EndByte: lineEnd, Type: tokenType, Modifiers: modifiers})
			}
			lineStart = lineEnd + 1
		}
	}
	for index < len(occupied) && occupied[index].StartByte < end {
		existing := occupied[index]
		if existing.StartByte > cursor {
			spanEnd := existing.StartByte
			if spanEnd > end {
				spanEnd = end
			}
			emit(cursor, spanEnd)
		}
		if existing.EndByte > cursor {
			cursor = existing.EndByte
		}
		if cursor >= end {
			return
		}
		index++
	}
	if cursor < end {
		emit(cursor, end)
	}
}

func isIdentifierStart(source []byte) bool {
	if len(source) == 0 {
		return false
	}
	r, _ := utf8.DecodeRune(source)
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

func isIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '$'
}

func isSpaceByte(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func isOperatorByte(value byte) bool {
	return value == '+' || value == '-' || value == '*' || value == '/' || value == '%' || value == '=' || value == '!' || value == '<' || value == '>' || value == '&' || value == '|' || value == '^' || value == '~' || value == '?' || value == ':'
}

func sortTokens(tokens []Token) {
	sort.SliceStable(tokens, func(i, j int) bool {
		if tokens[i].StartByte == tokens[j].StartByte {
			return tokens[i].EndByte < tokens[j].EndByte
		}
		return tokens[i].StartByte < tokens[j].StartByte
	})
}
