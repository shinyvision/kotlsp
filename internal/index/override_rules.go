package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Both rules here reason about a class's supertypes, and both are sound only
// when the whole hierarchy is Kotlin, in the workspace, and resolved without
// ambiguity: a Java supertype maps properties to getters under different names,
// and a library one may carry members the index does not see. Either case is
// grounds to say nothing.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"NOTHING_TO_OVERRIDE", "ABSTRACT_MEMBER_NOT_IMPLEMENTED"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     hierarchyMismatches,
	})
}

// anyMembers are overridable in every class, declared or not.
var anyMembers = map[string]bool{"equals": true, "hashCode": true, "toString": true}

func hierarchyMismatches(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	text := i.documentTextLocked(file.URI)
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		owner := &file.Symbols[index]
		if owner.Synthetic || owner.Kind != analysis.KindClass && owner.Kind != analysis.KindObject {
			continue
		}
		if containsString(owner.Modifiers, "expect") || containsString(owner.Modifiers, "actual") || containsString(owner.Modifiers, "external") {
			continue
		}
		hierarchy, ok := i.resolvedHierarchyLocked(*owner)
		if !ok {
			continue
		}
		inherited := make(map[string]bool)
		abstractNames := make(map[string]bool)
		concreteNames := make(map[string]bool)
		for _, supertype := range hierarchy {
			for _, member := range i.typeMembersLocked(supertype) {
				inherited[member.Name] = true
				if i.memberIsAbstractLocked(supertype, member) {
					abstractNames[member.Name] = true
				} else {
					concreteNames[member.Name] = true
				}
			}
		}
		own := i.typeMembersLocked(*owner)
		for _, member := range own {
			if !containsString(member.Modifiers, "override") || member.URI != file.URI {
				continue
			}
			if inherited[member.Name] || anyMembers[member.Name] {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: member.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "NOTHING_TO_OVERRIDE",
				Message: "'" + member.Name + "' overrides nothing.",
			})
		}
		if owner.Kind != analysis.KindClass || len(abstractNames) == 0 {
			continue
		}
		if containsString(owner.Modifiers, "abstract") || containsString(owner.Modifiers, "sealed") || containsString(owner.Modifiers, "enum") {
			continue
		}
		header := declarationText(text, owner)
		if brace := strings.IndexByte(header, '{'); brace >= 0 {
			header = header[:brace]
		}
		// Delegation supplies every member of the delegated interface.
		if strings.Contains(header, " by ") {
			continue
		}
		for _, member := range own {
			concreteNames[member.Name] = true
		}
		for name := range abstractNames {
			if concreteNames[name] {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: owner.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "ABSTRACT_MEMBER_NOT_IMPLEMENTED",
				Message: "Class '" + owner.Name + "' is not abstract and does not implement abstract member:",
			})
			break
		}
	}
	return out
}
