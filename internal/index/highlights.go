package index

import (
	"sort"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// DocumentHighlights returns every occurrence of the symbol under the cursor
// within one file: the declarations of its reference family plus the references
// that resolve to them. Writes are reported as writes so an editor can tell an
// assignment from a read at a glance.
func (i *Index) DocumentHighlights(uri protocol.URI, pos protocol.Position) []protocol.DocumentHighlight {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	family := i.referenceFamilyLocked(target)
	members := make(map[string]bool, len(family))
	seen := make(map[protocol.Range]bool)
	out := make([]protocol.DocumentHighlight, 0, len(family))
	add := func(r protocol.Range, kind int) {
		if seen[r] {
			return
		}
		seen[r] = true
		out = append(out, protocol.DocumentHighlight{Range: r, Kind: kind})
	}
	for _, member := range family {
		members[member.ID] = true
		// Only the declarations written in this file are occurrences in it; a
		// family member declared elsewhere is reported by its own file.
		if member.URI == uri {
			add(member.SelectionRange, highlightWrite)
		}
	}
	for index := range file.References {
		reference := &file.References[index]
		if !members[reference.ResolvedID] {
			if reference.ResolvedID != "" {
				continue
			}
			matched := false
			for _, resolved := range i.resolveLocked(file, *reference) {
				if members[resolved.ID] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		add(reference.Range, highlightKind(reference.Role))
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Range.Start.Line == out[b].Range.Start.Line {
			return out[a].Range.Start.Character < out[b].Range.Start.Character
		}
		return out[a].Range.Start.Line < out[b].Range.Start.Line
	})
	return out
}

const (
	highlightText  = 1
	highlightRead  = 2
	highlightWrite = 3
)

func highlightKind(role analysis.ReferenceRole) int {
	switch role {
	case analysis.RoleWrite:
		return highlightWrite
	case analysis.RoleImport, analysis.RoleLabel:
		return highlightText
	default:
		return highlightRead
	}
}
