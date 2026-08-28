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
// Override compatibility requires substituted callable/property signatures,
// variance, fake overrides, and Java/Kotlin interop. The rule below therefore
// runs only for a fully resolved, workspace-only Kotlin hierarchy and abstains
// when a callable shape mentions an owner type parameter.
func init() {
	registerFastRule(fastRule{
		codes:              []string{"NOTHING_TO_OVERRIDE", "ABSTRACT_MEMBER_NOT_IMPLEMENTED"},
		languages:          []analysis.Language{analysis.LanguageKotlin},
		usesWorkspaceIndex: true,
		apply:              hierarchyMismatches,
	})
}

func hierarchyMismatches(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	text := i.documentTextLocked(file.URI)
	var out []protocol.Diagnostic
	interesting := make(map[string]bool)
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if analysis.IsTypeKind(symbol.Kind) && len(symbol.Supertypes) > 0 {
			interesting[symbol.ID] = true
		}
		if symbol.ContainerID != "" && containsString(symbol.Modifiers, "override") {
			interesting[symbol.ContainerID] = true
		}
	}
	for index := range file.Symbols {
		owner := &file.Symbols[index]
		if owner.Synthetic || owner.Kind != analysis.KindClass && owner.Kind != analysis.KindObject {
			continue
		}
		if !interesting[owner.ID] {
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
		abstractShapes := make(map[string]bool)
		concreteShapes := make(map[string]bool)
		reliableShapes := true
		for _, supertype := range hierarchy {
			for _, member := range i.typeMembersLocked(supertype) {
				shape, reliable := i.overrideShapeLocked(*member)
				if !reliable {
					reliableShapes = false
					continue
				}
				inherited[shape] = true
				if i.memberIsAbstractLocked(supertype, member) {
					abstractShapes[shape] = true
				} else {
					concreteShapes[shape] = true
				}
			}
		}
		own := i.typeMembersLocked(*owner)
		for _, member := range own {
			if !containsString(member.Modifiers, "override") || member.URI != file.URI {
				continue
			}
			shape, reliable := i.overrideShapeLocked(*member)
			if !reliable {
				continue
			}
			if inherited[shape] || overridesAnyMember(*member) {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: member.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "NOTHING_TO_OVERRIDE",
				Message: "'" + member.Name + "' overrides nothing.",
			})
		}
		if owner.Kind != analysis.KindClass || len(abstractShapes) == 0 || !reliableShapes {
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
			if shape, reliable := i.overrideShapeLocked(*member); reliable {
				concreteShapes[shape] = true
			} else {
				reliableShapes = false
			}
		}
		if !reliableShapes {
			continue
		}
		for shape := range abstractShapes {
			if concreteShapes[shape] {
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

func (i *Index) overrideShapeLocked(member analysis.Symbol) (string, bool) {
	if member.Kind == analysis.KindProperty || member.Kind == analysis.KindField {
		return "property:" + member.Name, true
	}
	if !analysis.IsCallableKind(member.Kind) {
		return "", false
	}
	owner := i.symbols[member.ContainerID]
	var out strings.Builder
	out.WriteString("callable:")
	out.WriteString(member.Name)
	out.WriteByte('(')
	for index, parameter := range member.Parameters {
		if parameter.Type == "" || owner != nil && typeMentionsAnyParameter(parameter.Type, owner.TypeParameters) {
			return "", false
		}
		if index > 0 {
			out.WriteByte(',')
		}
		out.WriteString(canonicalJvmType(parameter.Type))
		if parameter.Variadic {
			out.WriteString("...")
		}
	}
	out.WriteByte(')')
	return out.String(), true
}

func typeMentionsAnyParameter(value string, parameters []string) bool {
	for _, parameter := range parameters {
		for at := 0; at+len(parameter) <= len(value); at++ {
			if value[at:at+len(parameter)] != parameter {
				continue
			}
			beforeOK := at == 0 || !isTypeIdentifierByte(value[at-1])
			after := at + len(parameter)
			afterOK := after == len(value) || !isTypeIdentifierByte(value[after])
			if beforeOK && afterOK {
				return true
			}
		}
	}
	return false
}

func isTypeIdentifierByte(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func overridesAnyMember(member analysis.Symbol) bool {
	switch member.Name {
	case "toString", "hashCode":
		return len(member.Parameters) == 0
	case "equals":
		return len(member.Parameters) == 1 && canonicalJvmType(member.Parameters[0].Type) == "java.lang.object"
	default:
		return false
	}
}
