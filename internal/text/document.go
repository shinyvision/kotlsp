package text

import (
	"errors"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

type Document struct {
	URI        protocol.URI
	LanguageID string
	Version    int
	Text       string
	lines      []int
}

func NewDocument(uri protocol.URI, languageID string, version int, content string) *Document {
	d := &Document{URI: uri, LanguageID: languageID, Version: version, Text: content}
	d.reindexLines()
	return d
}

func (d *Document) Clone() *Document {
	lines := make([]int, len(d.lines))
	copy(lines, d.lines)
	return &Document{URI: d.URI, LanguageID: d.LanguageID, Version: d.Version, Text: d.Text, lines: lines}
}

func (d *Document) LineCount() int { return len(d.lines) }

func (d *Document) Position(offset int) protocol.Position {
	if offset < 0 {
		offset = 0
	}
	if offset > len(d.Text) {
		offset = len(d.Text)
	}
	line := sort.Search(len(d.lines), func(i int) bool { return d.lines[i] > offset }) - 1
	if line < 0 {
		line = 0
	}
	return protocol.Position{Line: line, Character: utf16Len(d.Text[d.lines[line]:offset])}
}

func (d *Document) Offset(pos protocol.Position) int {
	if pos.Line < 0 {
		return 0
	}
	if pos.Line >= len(d.lines) {
		return len(d.Text)
	}
	start := d.lines[pos.Line]
	end := len(d.Text)
	if pos.Line+1 < len(d.lines) {
		end = d.lines[pos.Line+1]
	}
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
	for _, change := range changes {
		if change.Range == nil {
			d.Text = change.Text
			d.reindexLines()
			continue
		}
		start := d.Offset(change.Range.Start)
		end := d.Offset(change.Range.End)
		if start < 0 || end < start || end > len(d.Text) {
			return errors.New("invalid incremental text range")
		}
		d.Text = d.Text[:start] + change.Text + d.Text[end:]
		d.reindexLines()
	}
	d.Version = version
	return nil
}

func (d *Document) reindexLines() {
	d.lines = d.lines[:0]
	d.lines = append(d.lines, 0)
	for i := 0; i < len(d.Text); i++ {
		if d.Text[i] == '\n' {
			d.lines = append(d.lines, i+1)
		}
	}
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += len(utf16.Encode([]rune{r}))
		} else {
			n++
		}
	}
	return n
}
