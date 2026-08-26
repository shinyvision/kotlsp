package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A literal's type is fixed by its spelling, and a declared builtin type is
// fixed by its name. When the two disagree there is no reading of the program
// under which it compiles, which makes this provable from the text alone. The
// three rules here are the three places the compiler checks an expression
// against a declared type; each carries the compiler's own wording, so the
// prediction is indistinguishable from the finding that later confirms it.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"INITIALIZER_TYPE_MISMATCH", "ASSIGNMENT_TYPE_MISMATCH", "RETURN_TYPE_MISMATCH", "NULL_FOR_NONNULL_TYPE"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     literalTypeMismatches,
	})
}

func literalTypeMismatches(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.documentLocked(file.URI)
	if document == nil {
		return nil
	}
	text := document.Text
	var out []protocol.Diagnostic
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		// A top-level declaration also carries a synthetic JVM-facade view of
		// itself with the same range; reporting through both doubles it.
		if symbol.Synthetic {
			continue
		}
		switch symbol.Kind {
		case analysis.KindProperty, analysis.KindVariable:
			if symbol.Initializer == "" {
				continue
			}
			start, end, ok := initializerSpan(text, symbol)
			if !ok {
				continue
			}
			if strings.TrimSpace(text[start:end]) == "null" {
				if nonNull := i.nonNullDeclaredTypeLocked(file, symbol.Type); nonNull != "" {
					out = append(out, nullForNonNull(document, start, end, nonNull))
				}
				continue
			}
			expected := i.builtinExpectedTypeLocked(file, symbol.Type)
			if expected == "" {
				continue
			}
			actual := literalKind(text[start:end])
			if literalAcceptedBy(expected, actual) {
				continue
			}
			out = append(out, protocol.Diagnostic{
				Range: document.Range(start, end), Severity: 1, Source: "kotlsp",
				Code:    "INITIALIZER_TYPE_MISMATCH",
				Message: "Initializer type mismatch: expected '" + expected + "', actual '" + actual + "'.",
			})
		case analysis.KindFunction, analysis.KindMethod:
			expected := i.builtinExpectedTypeLocked(file, symbol.Type)
			nonNull := i.nonNullDeclaredTypeLocked(file, symbol.Type)
			if strings.TrimSpace(symbol.Type) == "" {
				// A block body with no declared type returns Unit; any
				// value returned from it is a mismatch.
				if tail, hasBody := functionTail(text, symbol); hasBody {
					if brace := strings.IndexByte(tail, '{'); brace >= 0 && !strings.Contains(tail[:brace], "=") {
						expected = "Unit"
					}
				}
			}
			if expected == "" && nonNull == "" {
				continue
			}
			out = append(out, returnMismatches(document, text, symbol, expected, nonNull)...)
		}
	}
	out = append(out, i.assignmentMismatches(file, document)...)
	return out
}

// returnMismatches checks an expression body, or the returns of a block body
// that contains no nested block. A lambda or local function inside the body
// would give a 'return' a different target, so such bodies are left alone.
func returnMismatches(document interface {
	Range(start, end int) protocol.Range
}, text string, symbol *analysis.Symbol, expected, nonNull string) []protocol.Diagnostic {
	tail, hasBody := functionTail(text, symbol)
	if !hasBody {
		return nil
	}
	tailStart := symbol.EndByte - len(tail)
	report := func(start, end int) []protocol.Diagnostic {
		if strings.TrimSpace(text[start:end]) == "null" {
			if nonNull == "" {
				return nil
			}
			return []protocol.Diagnostic{nullForNonNull(document, start, end, nonNull)}
		}
		if expected == "" {
			return nil
		}
		actual := literalKind(text[start:end])
		if literalAcceptedBy(expected, actual) {
			return nil
		}
		return []protocol.Diagnostic{{
			Range: document.Range(start, end), Severity: 1, Source: "kotlsp",
			Code:    "RETURN_TYPE_MISMATCH",
			Message: "Return type mismatch: expected '" + expected + "', actual '" + actual + "'.",
		}}
	}
	if brace := strings.IndexByte(tail, '{'); brace >= 0 {
		body := tail[brace+1:]
		closing := strings.LastIndexByte(body, '}')
		if strings.Count(body, "{") != 0 || closing < 0 || strings.TrimSpace(body[closing+1:]) != "" {
			return nil
		}
		// Offsets below index into body as sliced, so it is cut, never trimmed.
		body = body[:closing]
		var out []protocol.Diagnostic
		offset := 0
		for offset < len(body) {
			at := strings.Index(body[offset:], "return")
			if at < 0 {
				break
			}
			start := offset + at + len("return")
			if at > 0 && isIdentifierByteFast(body[offset+at-1]) || start < len(body) && isIdentifierByteFast(body[start]) {
				offset = start
				continue
			}
			for start < len(body) && (body[start] == ' ' || body[start] == '\t') {
				start++
			}
			end := start
			for end < len(body) && body[end] != '\n' && body[end] != ';' && body[end] != '}' {
				end++
			}
			literalStart := tailStart + brace + 1 + start
			trimmed := strings.TrimRight(body[start:end], " \t\r")
			if trimmed != "" {
				out = append(out, report(literalStart, literalStart+len(trimmed))...)
			} else if expected != "" && expected != "Unit" {
				// A bare 'return' yields Unit.
				out = append(out, protocol.Diagnostic{
					Range: document.Range(tailStart+brace+1+offset+at, tailStart+brace+1+offset+at+len("return")), Severity: 1, Source: "kotlsp",
					Code:    "RETURN_TYPE_MISMATCH",
					Message: "Return type mismatch: expected '" + expected + "', actual 'Unit'.",
				})
			}
			offset = end
		}
		return out
	}
	eq := strings.IndexByte(tail, '=')
	if eq < 0 {
		return nil
	}
	start := eq + 1
	for start < len(tail) && (tail[start] == ' ' || tail[start] == '\t' || tail[start] == '\n' || tail[start] == '\r') {
		start++
	}
	end := len(tail)
	for end > start && (tail[end-1] == ' ' || tail[end-1] == '\t' || tail[end-1] == '\n' || tail[end-1] == '\r' || tail[end-1] == ';') {
		end--
	}
	if start >= end {
		return nil
	}
	return report(tailStart+start, tailStart+end)
}

func isIdentifierByteFast(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

// assignmentMismatches checks `name = literal` where name binds to exactly one
// declaration in this file with a declared builtin type.
func (i *Index) assignmentMismatches(file *analysis.ParsedFile, document interface {
	Range(start, end int) protocol.Range
}) []protocol.Diagnostic {
	text := i.documentTextLocked(file.URI)
	var out []protocol.Diagnostic
	for index := range file.References {
		reference := &file.References[index]
		if reference.Role != analysis.RoleWrite || reference.Qualifier != "" || reference.ArgumentLabel {
			continue
		}
		resolved := i.resolveLocked(file, *reference)
		if len(resolved) != 1 || resolved[0].URI != file.URI {
			continue
		}
		target := resolved[0]
		if target.Kind != analysis.KindProperty && target.Kind != analysis.KindVariable || !containsString(target.Modifiers, "var") {
			continue
		}
		expected := i.builtinExpectedTypeLocked(file, target.Type)
		if expected == "" && i.nonNullDeclaredTypeLocked(file, target.Type) == "" {
			continue
		}
		// The right-hand side: a plain '=' (not a comparison or compound
		// assignment) followed by a single literal ending the statement.
		at := reference.EndByte
		for at < len(text) && (text[at] == ' ' || text[at] == '\t') {
			at++
		}
		if at >= len(text) || text[at] != '=' || at+1 < len(text) && text[at+1] == '=' {
			continue
		}
		start := at + 1
		for start < len(text) && (text[start] == ' ' || text[start] == '\t') {
			start++
		}
		end := start
		for end < len(text) && text[end] != '\n' && text[end] != ';' && text[end] != '}' {
			end++
		}
		for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\r') {
			end--
		}
		if start >= end {
			continue
		}
		if strings.TrimSpace(text[start:end]) == "null" {
			if nonNull := i.nonNullDeclaredTypeLocked(file, target.Type); nonNull != "" {
				out = append(out, nullForNonNull(document, start, end, nonNull))
			}
			continue
		}
		if expected == "" {
			continue
		}
		actual := literalKind(text[start:end])
		if literalAcceptedBy(expected, actual) {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: document.Range(start, end), Severity: 1, Source: "kotlsp",
			Code:    "ASSIGNMENT_TYPE_MISMATCH",
			Message: "Assignment type mismatch: actual type is '" + actual + "', but '" + expected + "' was expected.",
		})
	}
	return out
}

func nullForNonNull(document interface {
	Range(start, end int) protocol.Range
}, start, end int, declared string) protocol.Diagnostic {
	return protocol.Diagnostic{
		Range: document.Range(start, end), Severity: 1, Source: "kotlsp",
		Code:    "NULL_FOR_NONNULL_TYPE",
		Message: "Null cannot be a value of a non-null type '" + declared + "'.",
	}
}

// nonNullDeclaredTypeLocked returns a declared type when it is a bare class
// name, not nullable, and resolves to one class-like declaration -- the case
// in which the compiler renders it exactly as written.
func (i *Index) nonNullDeclaredTypeLocked(file *analysis.ParsedFile, declared string) string {
	name := strings.TrimSpace(declared)
	if !isSimpleIdentifier(name) {
		return ""
	}
	resolved, ok := i.resolveOneTypeLocked(file, name)
	if !ok || !isKotlinClassLike(resolved[0].Kind) && resolved[0].Kind != analysis.KindRecord {
		return ""
	}
	for _, symbol := range resolved {
		if symbol.Name != name {
			return ""
		}
	}
	return name
}
