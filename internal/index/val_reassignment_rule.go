package index

import (
	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Assigning to a val is an error under every interpretation of the program: a
// val has no setter to call and no overload to pick. It needs no type
// inference, only the declaration the write binds to, which makes it one of the
// few things provable from the index alone.
//
// Soundness rests on the binding being certain, so the rule requires the write
// to resolve to exactly one declaration, in this same file, written with val.
// An ambiguous write, a write through a receiver, or a declaration from
// somewhere the index only partly models is left alone.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"VAL_REASSIGNMENT"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     valReassignments,
	})
}

func valReassignments(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	for index := range file.References {
		reference := &file.References[index]
		if reference.Role != analysis.RoleWrite || reference.Qualifier != "" || reference.ArgumentLabel {
			continue
		}
		resolved := i.resolveLocked(file, *reference)
		if len(resolved) != 1 {
			// Ambiguity means the write might bind to something assignable.
			continue
		}
		target := resolved[0]
		if target.URI != file.URI {
			continue
		}
		if target.Kind != analysis.KindProperty && target.Kind != analysis.KindVariable {
			continue
		}
		if !containsString(target.Modifiers, "val") {
			continue
		}
		// A declaration's own initialiser is not a reassignment.
		if reference.StartByte >= target.NameStartByte && reference.EndByte <= target.NameEndByte {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: reference.Range, Severity: 1, Code: "VAL_REASSIGNMENT", Source: "kotlsp",
			Message: "'val' cannot be reassigned.",
			Data:    map[string]any{"name": reference.Name},
		})
	}
	return out
}
