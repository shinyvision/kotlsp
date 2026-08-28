package index

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/lexical"
)

// Where a position sits lexically decides what may be completed there. Offering
// members of a value inside a string literal or a sentence of prose is noise:
// the compiler resolves nothing there, so nothing the index knows applies.
//
// Neither literals nor comments are uniform, though, and the exceptions are
// exactly the places completion is most useful:
//
//   - A Kotlin string template is code. In "$user" the identifier after the
//     '$' is an expression; in "${user.email}" the whole braced expression is.
//     Note that "$user.email" is *not* a member access -- Kotlin binds the
//     simple form to the identifier alone and the rest is literal text -- so
//     the two forms are treated differently rather than as "anything after $".
//   - A doc comment carries reference positions: '@param' names, '@throws'
//     types, '@see', '{@link Owner#member}', and KDoc's '[Reference]'. Those
//     name the same declarations code names, and completing them is the point
//     of writing them.
//
// Everything else in a literal or a comment completes nothing.
type regionKind uint8

const (
	regionCode regionKind = iota
	// regionLiteral is the body of a string or character literal.
	regionLiteral
	regionLineComment
	regionBlockComment
	regionDocComment
)

// region is a run of source text of one kind.
//
// It carries two extents because its two consumers need different ones. The
// body is what a cursor can sit in: the bytes between a string's quotes, or
// after a comment's introducer. A delimiter belongs to no body, which is what
// makes a cursor immediately before an opening quote code (`f(|"x")`) while a
// cursor immediately before the closing one is still inside the string
// (`"x|"`). The outer extent includes the delimiters, because a scan looking
// for code must step over the whole construct rather than land on its edge.
type region struct {
	start, end           int
	outerStart, outerEnd int
	kind                 regionKind
	// nested marks a code region carved out of a literal: a Kotlin template.
	nested bool
}

// contains reports whether a cursor at the given offset sits in the region. A
// cursor is a gap between bytes, so a literal or comment body includes its own
// end -- the gap before the closing delimiter is inside the literal -- while a
// template's code ends where its brace does.
func (r region) contains(offset int) bool {
	if offset < r.start {
		return false
	}
	if r.nested {
		return offset < r.end
	}
	return offset <= r.end
}

// lexRegions walks source text and reports every literal and comment body,
// along with the code regions Kotlin templates carve out of a string. Code
// outside any literal or comment is not reported: it is the default.
//
// Regions are emitted in the order their bodies end, so a template's code
// region arrives before the literal containing it.
func lexRegions(text string, kotlin bool, visit func(region)) bool {
	return lexical.ScanRegionsBounded(text, kotlin, 100_000, func(value lexical.Region) {
		visit(region{
			start:      value.Start,
			end:        value.End,
			outerStart: value.OuterStart,
			outerEnd:   value.OuterEnd,
			kind:       regionKind(value.Kind),
			nested:     value.Nested,
		})
	})
}

// codeMask marks every byte of source that is code: outside comments and
// outside string and character literals, but including a Kotlin template's
// expression.
func codeMask(text string, kotlin bool) []bool {
	mask := make([]bool, len(text))
	for index := range mask {
		mask[index] = true
	}
	// Regions arrive innermost first -- a string inside `${...}` closes before
	// the template does -- so the first region to claim a byte wins and the
	// enclosing one cannot mark it back.
	decided := make([]byte, (len(text)+7)/8)
	complete := lexRegions(text, kotlin, func(r region) {
		code := r.kind == regionCode
		for index := max(r.outerStart, 0); index < r.outerEnd && index < len(mask); index++ {
			bit := byte(1 << uint(index&7))
			if decided[index>>3]&bit != 0 {
				continue
			}
			decided[index>>3] |= bit
			mask[index] = code
		}
	})
	if !complete {
		for index := range mask {
			mask[index] = false
		}
	}
	return mask
}

// CompletionScope names what a position may complete.
type CompletionScope uint8

const (
	// CompletionCode is ordinary code: every candidate applies.
	CompletionCode CompletionScope = iota
	// CompletionNone is text the compiler never resolves -- a string body,
	// a character literal, comment prose -- where nothing applies.
	CompletionNone
	// CompletionDocTag is a doc comment's tag name, such as `@par`.
	CompletionDocTag
	// CompletionDocParameter is a doc tag's parameter-name argument.
	CompletionDocParameter
	// CompletionDocType is a doc tag's type argument, as `@throws` takes.
	CompletionDocType
	// CompletionDocReference is a doc reference: `@see`, `{@link}`, `[KDoc]`.
	CompletionDocReference
)

// CompletionPosition describes what a position may complete.
type CompletionPosition struct {
	Scope CompletionScope
	// DocEnd is the byte offset just past the enclosing doc comment, in the
	// doc scopes: the declaration a doc comment documents begins after it.
	DocEnd int
	// TagStart is the byte offset of the '@' being completed, in
	// CompletionDocTag.
	TagStart int
}

// CompletionPositionAt classifies a cursor for completion.
func CompletionPositionAt(text string, offset int, kotlin bool) CompletionPosition {
	if offset < 0 {
		offset = 0
	}
	if offset > len(text) {
		offset = len(text)
	}
	// A cursor mid-identifier belongs where the identifier begins: in
	// `"$user|"` the name being typed is the template's expression even
	// though the byte at the cursor is the closing quote.
	anchor := offset - len(identifierPrefixBefore(text, offset))
	var innermost *region
	complete := lexRegions(text, kotlin, func(r region) {
		if !r.contains(anchor) {
			return
		}
		if innermost == nil || r.start >= innermost.start && r.end <= innermost.end {
			candidate := r
			innermost = &candidate
		}
	})
	if !complete {
		return CompletionPosition{Scope: CompletionNone}
	}
	if innermost == nil || innermost.kind == regionCode {
		return CompletionPosition{Scope: CompletionCode}
	}
	if innermost.kind != regionDocComment {
		return CompletionPosition{Scope: CompletionNone}
	}
	position := docCompletionPosition(text, innermost.start, offset, kotlin)
	position.DocEnd = innermost.end + len("*/")
	return position
}

// identifierPrefixBefore returns the identifier characters immediately before
// the offset. A '$' ends the run rather than joining it: in Kotlin it opens a
// template and belongs to the string, and anchoring only has to land inside
// the right region, which the name after it already does.
func identifierPrefixBefore(text string, offset int) string {
	start := offset
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(text[:start])
		if r == utf8.RuneError && size == 1 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') {
			break
		}
		start -= size
	}
	return text[start:offset]
}

// docCompletionPosition decides what a cursor inside a doc comment completes,
// from the tag line it sits on.
func docCompletionPosition(text string, bodyStart, offset int, kotlin bool) CompletionPosition {
	lineStart := strings.LastIndexByte(text[:offset], '\n') + 1
	if lineStart < bodyStart {
		lineStart = bodyStart
	}
	line := text[lineStart:offset]
	// A continuation line's leading asterisk is decoration, not content.
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "*") {
		trimmed = strings.TrimLeft(strings.TrimPrefix(trimmed, "*"), " \t")
	}
	// An inline `{@link Owner#member}` or KDoc `[Reference]` wins over the
	// block tag the line started with: it is nearer the cursor.
	if open := lastUnclosedInlineTag(trimmed); open {
		return CompletionPosition{Scope: CompletionDocReference}
	}
	if kotlin {
		if bracket := strings.LastIndexByte(trimmed, '['); bracket >= 0 && !strings.Contains(trimmed[bracket:], "]") {
			return CompletionPosition{Scope: CompletionDocReference}
		}
	}
	if !strings.HasPrefix(trimmed, "@") {
		return CompletionPosition{Scope: CompletionNone}
	}
	name := trimmed[1:]
	argument := ""
	if space := strings.IndexAny(name, " \t"); space >= 0 {
		name, argument = name[:space], strings.TrimLeft(name[space:], " \t")
	} else {
		// Still typing the tag itself.
		return CompletionPosition{Scope: CompletionDocTag, TagStart: offset - len(trimmed)}
	}
	// Only the tag's first argument names a declaration; prose follows it.
	if strings.ContainsAny(strings.TrimRight(argument, " \t"), " \t") {
		return CompletionPosition{Scope: CompletionNone}
	}
	switch name {
	case "param", "property":
		return CompletionPosition{Scope: CompletionDocParameter}
	case "throws", "exception":
		return CompletionPosition{Scope: CompletionDocType}
	case "see", "sample", "link", "linkplain":
		return CompletionPosition{Scope: CompletionDocReference}
	}
	return CompletionPosition{Scope: CompletionNone}
}

// lastUnclosedInlineTag reports whether the text ends inside a `{@link ...}`
// or `{@linkplain ...}`, whose argument is a reference.
func lastUnclosedInlineTag(line string) bool {
	for _, tag := range []string{"{@link ", "{@linkplain ", "{@value ", "{@see "} {
		if open := strings.LastIndex(line, tag); open >= 0 && !strings.Contains(line[open:], "}") {
			return true
		}
	}
	return false
}

// DocTagCompletions lists the doc tags a language accepts, for a cursor on a
// tag name.
func DocTagCompletions(kotlin bool) []string {
	if kotlin {
		return []string{
			"@param", "@return", "@constructor", "@receiver", "@property", "@throws",
			"@exception", "@sample", "@see", "@author", "@since", "@suppress",
		}
	}
	return []string{
		"@param", "@return", "@throws", "@exception", "@see", "@since", "@author",
		"@version", "@deprecated", "@serial", "@serialData", "@serialField",
		"@apiNote", "@implNote", "@implSpec", "@hidden",
	}
}
