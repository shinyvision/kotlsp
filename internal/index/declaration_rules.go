package index

import (
	"regexp"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Three shapes a declaration cannot legally take, each decided by what is
// written in the declaration itself.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"VARIABLE_WITH_NO_TYPE_NO_INITIALIZER", "NON_MEMBER_FUNCTION_NO_BODY", "MUST_BE_INITIALIZED_OR_BE_ABSTRACT"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     incompleteDeclarations,
	})
}

// bareLocal matches a local declared as nothing but a keyword and a name: no
// type, no initialiser, and -- because destructuring and loop variables have
// other shapes -- no parentheses.
var bareLocal = regexp.MustCompile(`^(val|var)\s+` + "`?" + `[\p{L}_][\p{L}\p{N}_]*` + "`?" + `\s*$`)

func incompleteDeclarations(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	text := i.documentTextLocked(file.URI)
	if text == "" {
		return nil
	}
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Synthetic {
			continue
		}
		declaration := strings.TrimSpace(declarationText(text, symbol))
		if declaration == "" {
			continue
		}
		switch symbol.Kind {
		case analysis.KindVariable:
			if symbol.Type != "" || symbol.Initializer != "" || !bareLocal.MatchString(declaration) {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: symbol.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "VARIABLE_WITH_NO_TYPE_NO_INITIALIZER",
				Message: "This variable must either have an explicit type or be initialized.",
			})
		case analysis.KindFunction:
			if symbol.ContainerID != "" || hasAnyModifier(symbol, "external", "expect", "actual", "abstract") {
				continue
			}
			if _, hasBody := functionTail(text, symbol); hasBody {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: symbol.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "NON_MEMBER_FUNCTION_NO_BODY",
				Message: "Function '" + symbol.Name + "' must have a body.",
			})
		case analysis.KindProperty:
			if symbol.Initializer != "" {
				continue
			}
			if hasAnyModifier(symbol, "lateinit", "abstract", "override", "expect", "actual", "external", "const", "constructor-property") {
				continue
			}
			container := i.symbols[symbol.ContainerID]
			if container == nil || container.Kind != analysis.KindClass || container.URI != file.URI {
				continue
			}
			if propertyHasBodyOrAccessor(declaration) {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: symbol.SelectionRange, Severity: 1, Source: "kotlsp",
				Code:    "MUST_BE_INITIALIZED_OR_BE_ABSTRACT",
				Message: "Property must be initialized or be abstract.",
			})
		}
	}
	return out
}

func hasAnyModifier(symbol *analysis.Symbol, names ...string) bool {
	for _, name := range names {
		if containsString(symbol.Modifiers, name) {
			return true
		}
	}
	return false
}
