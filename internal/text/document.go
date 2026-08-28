package text

import (
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

type Document struct {
	URI        protocol.URI
	LanguageID string
	Version    int
	Text       string
	lines      []int
	sparse     bool
	lineCount  int
}

const (
	maxDenseLineStarts = 1_000_000
	sparseLineStride   = 256
)

// TextEdit is the byte/point form of an applied LSP edit. Columns are UTF-8
// bytes as required by Tree-sitter, not the UTF-16 units used by LSP.
type TextEdit struct {
	StartByte, OldEndByte, NewEndByte int
	StartLine, StartColumn            int
	OldEndLine, OldEndColumn          int
	NewEndLine, NewEndColumn          int
}

func NewDocument(uri protocol.URI, languageID string, version int, content string) *Document {
	d := &Document{URI: uri, LanguageID: languageID, Version: version, Text: content}
	d.reindexLines()
	return d
}

func (d *Document) Clone() *Document {
	lines := make([]int, len(d.lines))
	copy(lines, d.lines)
	return &Document{URI: d.URI, LanguageID: d.LanguageID, Version: d.Version, Text: d.Text, lines: lines, sparse: d.sparse, lineCount: d.lineCount}
}

func (d *Document) LineCount() int { return d.lineCount }

func (d *Document) Position(offset int) protocol.Position {
	if offset < 0 {
		offset = 0
	}
	if offset > len(d.Text) {
		offset = len(d.Text)
	}
	line, start := d.byteLineAtString(offset)
	return protocol.Position{Line: line, Character: utf16Len(d.Text[start:offset])}
}

func (d *Document) Offset(pos protocol.Position) int {
	if pos.Line < 0 {
		return 0
	}
	if pos.Line >= d.lineCount {
		return len(d.Text)
	}
	start, end, _ := d.lineBoundsString(pos.Line)
	target := pos.Character
	if target <= 0 {
		return start
	}
	units := 0
	for i := start; i < end; {
		r, n := utf8.DecodeRuneInString(d.Text[i:end])
		if r == '\n' || r == '\r' {
			break
		}
		step := 1
		if r > 0xffff {
			step = 2
		}
		if units+step > target {
			return i
		}
		units += step
		i += n
		if units == target {
			return i
		}
	}
	return end
}

// strictOffsetBytes converts a client edit position without clamping. Display
// operations may reasonably clamp stale ranges, but mutating text at a nearby
// offset would corrupt the document/client synchronization contract.
func (d *Document) strictOffsetBytes(content []byte, pos protocol.Position) (int, bool) {
	if pos.Line < 0 || pos.Line >= d.lineCount || pos.Character < 0 {
		return 0, false
	}
	start, end, ok := d.lineBoundsBytes(pos.Line, content)
	if !ok {
		return 0, false
	}
	for end > start && (content[end-1] == '\n' || content[end-1] == '\r') {
		end--
	}
	units := 0
	for offset := start; offset < end; {
		if units == pos.Character {
			return offset, true
		}
		r, size := utf8.DecodeRune(content[offset:end])
		step := 1
		if r > 0xffff {
			step = 2
		}
		if units+step > pos.Character {
			return 0, false
		}
		units += step
		offset += size
	}
	if units == pos.Character {
		return end, true
	}
	return 0, false
}

func (d *Document) Range(start, end int) protocol.Range {
	return protocol.Range{Start: d.Position(start), End: d.Position(end)}
}

func (d *Document) Slice(r protocol.Range) string {
	a, b := d.Offset(r.Start), d.Offset(r.End)
	if b < a {
		a, b = b, a
	}
	return d.Text[a:b]
}

func (d *Document) Apply(version int, changes []protocol.TextDocumentContentChangeEvent) error {
	_, err := d.ApplyWithEdits(version, changes)
	return err
}

func (d *Document) ApplyWithEdits(version int, changes []protocol.TextDocumentContentChangeEvent) ([]TextEdit, error) {
	const (
		maxDocumentBytes = 64 << 20
		maxChanges       = 100_000
	)
	if version <= d.Version {
		return nil, errors.New("text document version did not increase")
	}
	if len(d.Text) > maxDocumentBytes || len(changes) > maxChanges {
		return nil, errors.New("text document or change count exceeds its safety limit")
	}
	updated := d.Clone()
	// Keep one mutable buffer for the complete notification. LSP ranges are
	// interpreted sequentially, so applying them to the original immutable
	// string in a batch would be incorrect; a capacity-sized byte buffer gives
	// us those sequential semantics without allocating a complete Go string for
	// every individual content change.
	extra := 0
	for _, change := range changes {
		if len(change.Text) > maxDocumentBytes-extra {
			return nil, errors.New("text replacements exceed their 64 MiB notification safety limit")
		}
		extra += len(change.Text)
	}
	capacity := len(updated.Text) + extra
	if capacity > maxDocumentBytes {
		capacity = maxDocumentBytes
	}
	content := make([]byte, len(updated.Text), capacity)
	copy(content, updated.Text)
	edits := make([]TextEdit, 0, len(changes))
	for _, change := range changes {
		if change.Range == nil {
			if len(change.Text) > maxDocumentBytes {
				return nil, errors.New("replacement document exceeds its 64 MiB safety limit")
			}
			oldLine, oldColumn := updated.bytePoint(content, len(content))
			newLine, newColumn := replacementEndPoint(0, 0, change.Text)
			edits = append(edits, TextEdit{OldEndByte: len(content), NewEndByte: len(change.Text), OldEndLine: oldLine, OldEndColumn: oldColumn, NewEndLine: newLine, NewEndColumn: newColumn})
			content = append(content[:0], change.Text...)
			updated.reindexLineBytes(content)
			continue
		}
		start, startOK := updated.strictOffsetBytes(content, change.Range.Start)
		end, endOK := updated.strictOffsetBytes(content, change.Range.End)
		if !startOK || !endOK || end < start {
			return nil, errors.New("invalid incremental text range")
		}
		startLine, startColumn := updated.bytePoint(content, start)
		oldEndLine, oldEndColumn := updated.bytePoint(content, end)
		newEndLine, newEndColumn := replacementEndPoint(startLine, startColumn, change.Text)
		edits = append(edits, TextEdit{
			StartByte: start, OldEndByte: end, NewEndByte: start + len(change.Text),
			StartLine: startLine, StartColumn: startColumn, OldEndLine: oldEndLine, OldEndColumn: oldEndColumn,
			NewEndLine: newEndLine, NewEndColumn: newEndColumn,
		})
		reindexAfterMutation := updated.replaceLines(start, end, change.Text)
		oldLength := len(content)
		retainedLength := oldLength - (end - start)
		if len(change.Text) > maxDocumentBytes-retainedLength {
			return nil, errors.New("edited document exceeds its 64 MiB safety limit")
		}
		newLength := retainedLength + len(change.Text)
		if newLength > cap(content) {
			grown := make([]byte, oldLength, newLength)
			copy(grown, content)
			content = grown
		}
		if newLength >= oldLength {
			content = content[:newLength]
			copy(content[start+len(change.Text):], content[end:oldLength])
		} else {
			copy(content[start+len(change.Text):], content[end:oldLength])
			content = content[:newLength]
		}
		copy(content[start:start+len(change.Text)], change.Text)
		if reindexAfterMutation {
			updated.reindexLineBytes(content)
		}
	}
	updated.Text = string(content)
	updated.Version = version
	*d = *updated
	return edits, nil
}

func (d *Document) bytePoint(content []byte, offset int) (line, column int) {
	line, start := d.byteLineAtBytes(content, offset)
	return line, offset - start
}

func replacementEndPoint(startLine, startColumn int, replacement string) (line, column int) {
	line, column = startLine, startColumn
	lastLineStart := 0
	for index := 0; index < len(replacement); index++ {
		if replacement[index] == '\n' {
			line++
			lastLineStart = index + 1
		}
	}
	if line == startLine {
		column += len(replacement)
	} else {
		column = len(replacement) - lastLineStart
	}
	return line, column
}

// replace updates the text and line starts from the edited interval. It still
// copies the immutable Go string, but avoids a second full-file line scan for
// every incremental change.
func (d *Document) replaceLines(start, end int, replacement string) bool {
	addedLines := stringsCountByte(replacement, '\n')
	removeFrom := sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > start })
	removeTo := removeFrom
	if end > start {
		removeTo = sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > end })
	}
	if d.sparse || d.lineCount-(removeTo-removeFrom)+addedLines > maxDenseLineStarts {
		return true
	}
	delta := len(replacement) - (end - start)
	lines := make([]int, 0, len(d.lines)-(removeTo-removeFrom)+addedLines)
	lines = append(lines, d.lines[:removeFrom]...)
	for index := 0; index < len(replacement); index++ {
		if replacement[index] == '\n' {
			lines = append(lines, start+index+1)
		}
	}
	for _, line := range d.lines[removeTo:] {
		lines = append(lines, line+delta)
	}
	d.lines = lines
	d.lineCount = len(lines)
	return false
}

func stringsCountByte(value string, target byte) int {
	count := 0
	for index := 0; index < len(value); index++ {
		if value[index] == target {
			count++
		}
	}
	return count
}

func (d *Document) reindexLines() {
	d.reindexLineBytes([]byte(d.Text))
}

func (d *Document) reindexLineBytes(content []byte) {
	lineCount := 1
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			lineCount++
		}
	}
	d.lineCount = lineCount
	d.sparse = lineCount > maxDenseLineStarts
	d.lines = d.lines[:0]
	d.lines = append(d.lines, 0)
	line := 0
	for index, value := range content {
		if value != '\n' {
			continue
		}
		line++
		if !d.sparse || line%sparseLineStride == 0 {
			d.lines = append(d.lines, index+1)
		}
	}
}

func (d *Document) byteLineAtString(offset int) (line, start int) {
	if !d.sparse {
		line = sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > offset }) - 1
		if line < 0 {
			line = 0
		}
		return line, d.lines[line]
	}
	checkpoint := sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > offset }) - 1
	if checkpoint < 0 {
		checkpoint = 0
	}
	line, start = checkpoint*sparseLineStride, d.lines[checkpoint]
	for index := start; index < offset; index++ {
		if d.Text[index] == '\n' {
			line++
			start = index + 1
		}
	}
	return line, start
}

func (d *Document) byteLineAtBytes(content []byte, offset int) (line, start int) {
	if !d.sparse {
		line = sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > offset }) - 1
		if line < 0 {
			line = 0
		}
		return line, d.lines[line]
	}
	checkpoint := sort.Search(len(d.lines), func(index int) bool { return d.lines[index] > offset }) - 1
	if checkpoint < 0 {
		checkpoint = 0
	}
	line, start = checkpoint*sparseLineStride, d.lines[checkpoint]
	for index := start; index < offset; index++ {
		if content[index] == '\n' {
			line++
			start = index + 1
		}
	}
	return line, start
}

func (d *Document) lineBoundsString(line int) (start, end int, ok bool) {
	if line < 0 || line >= d.lineCount {
		return 0, 0, false
	}
	if !d.sparse {
		start = d.lines[line]
		end = len(d.Text)
		if line+1 < len(d.lines) {
			end = d.lines[line+1]
		}
		return start, end, true
	}
	checkpoint := line / sparseLineStride
	if checkpoint >= len(d.lines) {
		return 0, 0, false
	}
	start = d.lines[checkpoint]
	for current := checkpoint * sparseLineStride; current < line; current++ {
		relative := stringsIndexByte(d.Text[start:], '\n')
		if relative < 0 {
			return 0, 0, false
		}
		start += relative + 1
	}
	end = len(d.Text)
	if relative := stringsIndexByte(d.Text[start:], '\n'); relative >= 0 {
		end = start + relative + 1
	}
	return start, end, true
}

func (d *Document) lineBoundsBytes(line int, content []byte) (start, end int, ok bool) {
	if line < 0 || line >= d.lineCount {
		return 0, 0, false
	}
	if !d.sparse {
		start = d.lines[line]
		end = len(content)
		if line+1 < len(d.lines) {
			end = d.lines[line+1]
		}
		return start, end, true
	}
	checkpoint := line / sparseLineStride
	if checkpoint >= len(d.lines) {
		return 0, 0, false
	}
	start = d.lines[checkpoint]
	for current := checkpoint * sparseLineStride; current < line; current++ {
		relative := bytesIndexByte(content[start:], '\n')
		if relative < 0 {
			return 0, 0, false
		}
		start += relative + 1
	}
	end = len(content)
	if relative := bytesIndexByte(content[start:], '\n'); relative >= 0 {
		end = start + relative + 1
	}
	return start, end, true
}

func stringsIndexByte(value string, target byte) int {
	for index := 0; index < len(value); index++ {
		if value[index] == target {
			return index
		}
	}
	return -1
}

func bytesIndexByte(value []byte, target byte) int {
	for index, candidate := range value {
		if candidate == target {
			return index
		}
	}
	return -1
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return n
}
