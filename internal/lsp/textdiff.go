package lsp

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// lineEdits turns a reformatted document into edits that replace only the
// lines that changed, so the client keeps the cursor, marks and folds on the
// lines a formatter left alone. Lines are matched by a longest-common-
// subsequence over the changed middle; very large changes fall back to one
// replacement of that middle.
func lineEdits(doc *textdoc.Document, formatted string) []protocol.TextEdit {
	if doc.Text == formatted {
		return []protocol.TextEdit{}
	}
	before := strings.SplitAfter(doc.Text, "\n")
	after := strings.SplitAfter(formatted, "\n")
	prefix := 0
	for prefix < len(before) && prefix < len(after) && before[prefix] == after[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(before)-prefix && suffix < len(after)-prefix && before[len(before)-1-suffix] == after[len(after)-1-suffix] {
		suffix++
	}
	oldMiddle, newMiddle := before[prefix:len(before)-suffix], after[prefix:len(after)-suffix]
	offset := 0
	for _, line := range before[:prefix] {
		offset += len(line)
	}
	lineOffsets := make([]int, len(oldMiddle)+1)
	lineOffsets[0] = offset
	for index, line := range oldMiddle {
		lineOffsets[index+1] = lineOffsets[index] + len(line)
	}
	replace := func(oldStart, oldEnd int, lines []string) protocol.TextEdit {
		return protocol.TextEdit{Range: doc.Range(lineOffsets[oldStart], lineOffsets[oldEnd]), NewText: strings.Join(lines, "")}
	}
	if len(oldMiddle)*len(newMiddle) > 4_000_000 {
		return []protocol.TextEdit{replace(0, len(oldMiddle), newMiddle)}
	}
	// lengths[i][j] is the LCS length of oldMiddle[i:] and newMiddle[j:].
	lengths := make([][]int32, len(oldMiddle)+1)
	for index := range lengths {
		lengths[index] = make([]int32, len(newMiddle)+1)
	}
	for i := len(oldMiddle) - 1; i >= 0; i-- {
		for j := len(newMiddle) - 1; j >= 0; j-- {
			if oldMiddle[i] == newMiddle[j] {
				lengths[i][j] = lengths[i+1][j+1] + 1
			} else {
				lengths[i][j] = max(lengths[i+1][j], lengths[i][j+1])
			}
		}
	}
	var edits []protocol.TextEdit
	i, j := 0, 0
	for i < len(oldMiddle) || j < len(newMiddle) {
		if i < len(oldMiddle) && j < len(newMiddle) && oldMiddle[i] == newMiddle[j] {
			i, j = i+1, j+1
			continue
		}
		startI, startJ := i, j
		for i < len(oldMiddle) || j < len(newMiddle) {
			if i < len(oldMiddle) && j < len(newMiddle) && oldMiddle[i] == newMiddle[j] {
				break
			}
			if j < len(newMiddle) && (i == len(oldMiddle) || lengths[i][j+1] >= lengths[i+1][j]) {
				j++
			} else {
				i++
			}
		}
		edits = append(edits, replace(startI, i, newMiddle[startJ:j]))
	}
	return edits
}
