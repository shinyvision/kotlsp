package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Shapes a Kotlin class declaration cannot legally take. Each is decided from
// the declaration's own text plus, where a supertype is involved, a hierarchy
// that resolves entirely to Kotlin declarations in the workspace. The messages
// are the compiler's, captured from a hosted K2 run.
func init() {
	registerFastRule(fastRule{
		codes: []string{
			"SUPERTYPE_NOT_INITIALIZED", "FINAL_SUPERTYPE",
			"VIRTUAL_MEMBER_HIDDEN", "OVERRIDING_FINAL_MEMBER",
			"NON_ABSTRACT_FUNCTION_WITH_NO_BODY", "ABSTRACT_FUNCTION_IN_NON_ABSTRACT_CLASS",
			"INAPPLICABLE_LATEINIT_MODIFIER", "MANY_COMPANION_OBJECTS",
			"DATA_CLASS_WITHOUT_PARAMETERS", "DATA_CLASS_NOT_PROPERTY_PARAMETER",
		},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     kotlinClassShapes,
	})
}

func kotlinClassShapes(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.documentLocked(file.URI)
	if document == nil || document.Text == "" {
		return nil
	}
	c := newUnresolvedNameContext(file)
	c.prepare(i)
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic || symbol.URI != file.URI {
			continue
		}
		switch symbol.Kind {
		case analysis.KindClass, analysis.KindObject, analysis.KindInterface, analysis.KindEnum:
			if hasAnyModifier(symbol, "expect", "actual", "external") {
				continue
			}
			out = append(out, i.supertypeShapes(c, document, symbol)...)
			out = append(out, i.hiddenAndFinalMembers(c, document, symbol)...)
			out = append(out, manyCompanions(c, document, symbol)...)
			out = append(out, dataClassShapes(c, document, symbol)...)
		case analysis.KindFunction, analysis.KindMethod:
			out = append(out, i.memberFunctionShapes(c, document, symbol)...)
		case analysis.KindProperty:
			out = append(out, i.lateinitShapes(c, document, symbol)...)
		}
	}
	return out
}

// headerSpan returns the byte range of a declaration's header: from its start
// to the brace that opens its body, or its end when it has none.
func headerSpan(c *unresolvedNameContext, symbol *analysis.Symbol) (int, int) {
	end := symbol.EndByte
	if brace := indexTopLevel(c.text, c.mask, symbol.NameEndByte, '{'); brace >= 0 && brace < end {
		end = brace
	}
	return symbol.StartByte, end
}

// keywordIn finds a keyword as a whole word in code within a byte range.
func keywordIn(c *unresolvedNameContext, from, to int, keyword string) int {
	if from < 0 || to > len(c.text) || from >= to {
		return -1
	}
	for _, at := range keywordPositions(c.text[from:to], c.mask[from:to], keyword) {
		return from + at
	}
	return -1
}

type supertypeEntry struct {
	base      string
	nameStart int
	hasParens bool
	delegated bool
}

// supertypeEntries parses the list after the colon of a class header.
func supertypeEntries(c *unresolvedNameContext, symbol *analysis.Symbol) []supertypeEntry {
	start, end := headerSpan(c, symbol)
	// The colon introducing supertypes sits after the name, its type
	// parameters, and its primary constructor.
	at := symbol.NameEndByte
	depth := 0
	colon := -1
	for ; at < end; at++ {
		if !c.mask[at] {
			continue
		}
		switch c.text[at] {
		case '(', '<', '[':
			depth++
		case ')', '>', ']':
			depth--
		case ':':
			if depth == 0 {
				colon = at
			}
		}
		if colon >= 0 {
			break
		}
	}
	if colon < 0 || start > colon {
		return nil
	}
	var out []supertypeEntry
	offset := colon + 1
	for _, part := range splitTopLevel(c.text[colon+1:end], ',') {
		leading := len(part) - len(strings.TrimLeft(part, " \t\r\n"))
		entry := strings.TrimSpace(part)
		entryStart := offset + leading
		offset += len(part) + 1
		if entry == "" {
			continue
		}
		base := entry
		if by := strings.Index(base, " by "); by >= 0 {
			base = base[:by]
		}
		delegated := strings.Contains(entry, " by ")
		hasParens := false
		if paren := strings.IndexByte(base, '('); paren >= 0 {
			hasParens = true
			base = base[:paren]
		}
		if angle := strings.IndexByte(base, '<'); angle >= 0 {
			base = base[:angle]
		}
		base = strings.TrimSpace(base)
		out = append(out, supertypeEntry{base: base, nameStart: entryStart, hasParens: hasParens, delegated: delegated})
	}
	return out
}

// workspaceKotlinClassLocked resolves a supertype name to one Kotlin class
// declared in the workspace, with its declaration parsed; anything else --
// a library, Java, an alias, an ambiguity -- returns nil.
func (i *Index) workspaceKotlinClassLocked(file *analysis.ParsedFile, name string) *analysis.Symbol {
	if !isSimpleIdentifier(name) {
		return nil
	}
	resolved := i.resolveTypeSymbolsLocked(file, name)
	if len(resolved) != 1 {
		return nil
	}
	symbol := resolved[0]
	if symbol.Synthetic || symbol.Library || symbol.Language != analysis.LanguageKotlin || i.files[symbol.URI] == nil {
		return nil
	}
	return i.symbols[symbol.ID]
}

func hasAnnotationModifier(symbol *analysis.Symbol) bool {
	for _, modifier := range symbol.Modifiers {
		if modifier != "" && modifier[0] >= 'A' && modifier[0] <= 'Z' {
			return true
		}
	}
	return false
}

func (i *Index) supertypeShapes(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, owner *analysis.Symbol) []protocol.Diagnostic {
	if owner.Kind != analysis.KindClass && owner.Kind != analysis.KindObject {
		return nil
	}
	if hasAnyModifier(owner, "enum", "annotation", "sealed", "inline", "value") {
		return nil
	}
	// A secondary constructor may initialise the supertype itself.
	hasSecondaryConstructor := false
	for _, member := range c.file.Symbols {
		if member.Kind == analysis.KindConstructor && member.ContainerID == owner.ID && strings.HasPrefix(strings.TrimSpace(declarationText(c.text, &member)), "constructor") {
			hasSecondaryConstructor = true
		}
	}
	var out []protocol.Diagnostic
	for _, entry := range supertypeEntries(c, owner) {
		if entry.delegated {
			continue
		}
		supertype := i.workspaceKotlinClassLocked(c.file, entry.base)
		if supertype == nil || supertype.Kind != analysis.KindClass || supertype.ID == owner.ID {
			continue
		}
		if hasAnyModifier(supertype, "expect", "actual", "external", "sealed", "enum", "annotation", "inline", "value", "inner") {
			continue
		}
		nameRange := document.Range(entry.nameStart, entry.nameStart+len(entry.base))
		open := hasAnyModifier(supertype, "open", "abstract")
		switch {
		case !entry.hasParens && open && !hasSecondaryConstructor:
			out = append(out, protocol.Diagnostic{
				Range: nameRange, Severity: 1, Source: "kotlsp",
				Code:    "SUPERTYPE_NOT_INITIALIZED",
				Message: "This type has a constructor, so it must be initialized here.",
			})
		case entry.hasParens && !open && !hasAnnotationModifier(supertype):
			// An annotation on the class may open it through the all-open
			// compiler plugin; an unannotated class without 'open' is final.
			out = append(out, protocol.Diagnostic{
				Range: nameRange, Severity: 1, Source: "kotlsp",
				Code:    "FINAL_SUPERTYPE",
				Message: "This type is final, so it cannot be extended.",
			})
		}
	}
	return out
}

// signatureKey renders a callable's parameter types for comparison, or ""
// when a type parameter is involved and substitution would be needed.
func signatureKey(owner analysis.Symbol, member *analysis.Symbol) (string, bool) {
	var b strings.Builder
	for _, parameter := range member.Parameters {
		base, _ := splitInstantiatedType(parameter.Type)
		base = strings.TrimSpace(strings.TrimSuffix(base, "?"))
		if containsString(owner.TypeParameters, base) || containsString(member.TypeParameters, base) || base == "" {
			return "", false
		}
		if parameter.Variadic {
			b.WriteString("vararg ")
		}
		b.WriteString(strings.ReplaceAll(parameter.Type, " ", ""))
		b.WriteByte(';')
	}
	return b.String(), true
}

func memberIsCallable(member *analysis.Symbol) bool {
	return member.Kind == analysis.KindFunction || member.Kind == analysis.KindMethod
}

func (i *Index) hiddenAndFinalMembers(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, owner *analysis.Symbol) []protocol.Diagnostic {
	if owner.Kind != analysis.KindClass && owner.Kind != analysis.KindObject {
		return nil
	}
	hierarchy, ok := i.resolvedHierarchyLocked(*owner)
	if !ok || len(hierarchy) == 0 {
		return nil
	}
	type inherited struct {
		owner  analysis.Symbol
		member *analysis.Symbol
		key    string
	}
	byName := make(map[string][]inherited)
	for _, supertype := range hierarchy {
		if len(supertype.TypeParameters) > 0 {
			// Members of a generic supertype need substitution to compare.
			return nil
		}
		for _, member := range i.typeMembersLocked(supertype) {
			if containsString(member.Modifiers, "private") || member.ReceiverType != "" {
				continue
			}
			key := "property"
			if memberIsCallable(member) {
				signature, ok := signatureKey(supertype, member)
				if !ok {
					continue
				}
				key = "callable(" + signature + ")"
			}
			byName[member.Name] = append(byName[member.Name], inherited{owner: supertype, member: member, key: key})
		}
	}
	var out []protocol.Diagnostic
	for _, member := range i.typeMembersLocked(*owner) {
		if member.URI != c.file.URI || member.ReceiverType != "" || anyMembers[member.Name] || hasAnyModifier(member, "expect", "actual", "external", "private") {
			continue
		}
		key := "property"
		if memberIsCallable(member) {
			signature, ok := signatureKey(*owner, member)
			if !ok {
				continue
			}
			key = "callable(" + signature + ")"
		}
		var matches []inherited
		for _, candidate := range byName[member.Name] {
			if candidate.key == key && memberIsCallable(candidate.member) == memberIsCallable(member) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			continue
		}
		match := matches[0]
		if !containsString(member.Modifiers, "override") {
			out = append(out, protocol.Diagnostic{
				Range: member.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "VIRTUAL_MEMBER_HIDDEN",
				Message: "'" + member.Name + "' hides member of supertype '" + match.owner.Name + "' and needs an 'override' modifier.",
			})
			continue
		}
		// Final: declared in a class, not open or abstract, and not itself an
		// override (which is open unless marked final).
		if match.owner.Kind == analysis.KindInterface || hasAnyModifier(match.member, "open", "abstract") {
			continue
		}
		if containsString(match.member.Modifiers, "override") && !containsString(match.member.Modifiers, "final") {
			continue
		}
		keyword := keywordIn(c, member.StartByte, member.NameStartByte, "override")
		if keyword < 0 {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: document.Range(keyword, keyword+len("override")), Severity: 1, Source: "kotlsp",
			Code:    "OVERRIDING_FINAL_MEMBER",
			Message: "'" + member.Name + "' in '" + match.owner.Name + "' is final and cannot be overridden.",
		})
	}
	return out
}

func manyCompanions(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, owner *analysis.Symbol) []protocol.Diagnostic {
	var companions []*analysis.Symbol
	for index := range c.file.Symbols {
		member := &c.file.Symbols[index]
		if member.Kind == analysis.KindObject && member.ContainerID == owner.ID && containsString(member.Modifiers, "companion") && !member.Synthetic {
			companions = append(companions, member)
		}
	}
	if len(companions) < 2 {
		return nil
	}
	var out []protocol.Diagnostic
	for _, companion := range companions[1:] {
		keyword := keywordIn(c, companion.StartByte, companion.EndByte, "companion")
		if keyword < 0 {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: document.Range(keyword, keyword+len("companion")), Severity: 1, Source: "kotlsp",
			Code:    "MANY_COMPANION_OBJECTS",
			Message: "Only one companion object is allowed per class.",
		})
	}
	return out
}

func dataClassShapes(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, owner *analysis.Symbol) []protocol.Diagnostic {
	if owner.Kind != analysis.KindClass || !containsString(owner.Modifiers, "data") {
		return nil
	}
	var primary *analysis.Symbol
	for index := range c.file.Symbols {
		member := &c.file.Symbols[index]
		if member.Kind == analysis.KindConstructor && member.ContainerID == owner.ID && !strings.HasPrefix(strings.TrimSpace(declarationText(c.text, member)), "constructor") {
			primary = member
		}
	}
	var out []protocol.Diagnostic
	if primary == nil || len(primary.Parameters) == 0 {
		keyword := keywordIn(c, owner.StartByte, owner.NameStartByte, "class")
		if keyword < 0 {
			return nil
		}
		return append(out, protocol.Diagnostic{
			Range: document.Range(keyword, owner.NameEndByte), Severity: 1, Source: "kotlsp",
			Code:    "DATA_CLASS_WITHOUT_PARAMETERS",
			Message: "Data class must have at least one primary constructor parameter.",
		})
	}
	for _, parameter := range primary.Parameters {
		if parameter.Variadic {
			continue
		}
		for index := range c.file.Symbols {
			member := &c.file.Symbols[index]
			if member.Kind != analysis.KindParameter || member.ContainerID != owner.ID || member.Name != parameter.Name || !containsString(member.Modifiers, "constructor-property") {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: parameter.Range, Severity: 1, Source: "kotlsp",
				Code:    "DATA_CLASS_NOT_PROPERTY_PARAMETER",
				Message: "Primary constructor of data class must only have property ('val' / 'var') parameters.",
			})
		}
	}
	return out
}

func (i *Index) memberFunctionShapes(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, member *analysis.Symbol) []protocol.Diagnostic {
	owner := i.symbols[member.ContainerID]
	if owner == nil || owner.URI != c.file.URI || owner.Synthetic {
		return nil
	}
	if hasAnyModifier(owner, "expect", "actual", "external") || hasAnyModifier(member, "expect", "actual", "external", "override") {
		return nil
	}
	_, hasBody := functionTail(c.text, member)
	if owner.Kind == analysis.KindClass || owner.Kind == analysis.KindObject {
		abstract := containsString(member.Modifiers, "abstract")
		if !hasBody && !abstract {
			return []protocol.Diagnostic{{
				Range: member.Range, Severity: 1, Source: "kotlsp",
				Code:    "NON_ABSTRACT_FUNCTION_WITH_NO_BODY",
				Message: "Function '" + member.Name + "' without a body must be abstract.",
			}}
		}
		if abstract && owner.Kind == analysis.KindClass && !hasAnyModifier(owner, "abstract", "sealed", "enum") {
			keyword := keywordIn(c, member.StartByte, member.NameStartByte, "abstract")
			if keyword < 0 {
				return nil
			}
			return []protocol.Diagnostic{{
				Range: document.Range(keyword, keyword+len("abstract")), Severity: 1, Source: "kotlsp",
				Code:    "ABSTRACT_FUNCTION_IN_NON_ABSTRACT_CLASS",
				Message: "Abstract function '" + member.Name + "' in non-abstract class '" + owner.Name + "'.",
			}}
		}
	}
	return nil
}

var kotlinPrimitiveNames = map[string]bool{
	"Int": true, "Long": true, "Short": true, "Byte": true, "Char": true, "Boolean": true, "Float": true, "Double": true,
}

func (i *Index) lateinitShapes(c *unresolvedNameContext, document interface {
	Range(start, end int) protocol.Range
}, property *analysis.Symbol) []protocol.Diagnostic {
	if !containsString(property.Modifiers, "lateinit") || hasAnyModifier(property, "abstract", "expect", "actual", "external", "constructor-property") {
		return nil
	}
	owner := i.symbols[property.ContainerID]
	if owner != nil && owner.Kind == analysis.KindInterface {
		return nil
	}
	declared := strings.TrimSpace(property.Type)
	declaration := declarationText(c.text, property)
	var messages []string
	if !containsString(property.Modifiers, "var") {
		messages = append(messages, "'lateinit' modifier is allowed only on mutable properties.")
	}
	if declared != "" && strings.HasSuffix(declared, "?") {
		messages = append(messages, "'lateinit' modifier is not allowed on properties of a type with nullable upper bound.")
	}
	if kotlinPrimitiveNames[declared] {
		if resolved, ok := i.resolveOneTypeLocked(c.file, declared); ok && resolved[0].FQN == "kotlin."+declared {
			messages = append(messages, "'lateinit' modifier is not allowed on properties of primitive types.")
		}
	}
	hasInitializer := property.Initializer != "" || strings.Contains(declaration, "=")
	if hasInitializer {
		messages = append(messages, "'lateinit' modifier is not allowed on properties with initializer.")
	}
	if len(messages) != 1 || declared == "" {
		return nil
	}
	if !hasInitializer && propertyHasBodyOrAccessor(declaration) {
		return nil
	}
	keyword := keywordIn(c, property.StartByte, property.NameStartByte, "lateinit")
	if keyword < 0 {
		return nil
	}
	return []protocol.Diagnostic{{
		Range: document.Range(keyword, keyword+len("lateinit")), Severity: 1, Source: "kotlsp",
		Code:    "INAPPLICABLE_LATEINIT_MODIFIER",
		Message: messages[0],
	}}
}
