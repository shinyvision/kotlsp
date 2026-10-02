package index

import (
	"context"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// NamedArgument is a parameter a Kotlin call at the cursor can still take by
// name: `ColorDto(|` offers `id =`, `ralName =` and the rest.
type NamedArgument struct {
	Name, Type string
	// Required is set when the parameter has no default value.
	Required bool
}

// NamedArgumentsAt returns the parameters of the call whose argument list the
// cursor is in, where an argument can start, minus those already passed by
// name. Parameters of every overload the call resolves to are offered.
func (i *Index) NamedArgumentsAt(ctx context.Context, uri protocol.URI, pos protocol.Position) []NamedArgument {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	doc := i.documentLocked(uri)
	if file == nil || doc == nil || file.Language != analysis.LanguageKotlin {
		return nil
	}
	text, offset := doc.Text, doc.Offset(pos)
	// Only where an argument begins: after `(` or `,`, with at most a partly
	// typed name before the cursor.
	start := offset
	for start > 0 && isIdentifierByteFast(text[start-1]) {
		start--
	}
	before := start - 1
	for before >= 0 && strings.ContainsRune(" \t\r\n", rune(text[before])) {
		before--
	}
	if before < 0 || text[before] != '(' && text[before] != ',' {
		return nil
	}
	var call *analysis.Reference
	callOpen, callClose := -1, -1
	for index := range file.References {
		reference := &file.References[index]
		if reference.Role != analysis.RoleCall || reference.EndByte > offset {
			continue
		}
		open := reference.EndByte
		for open < len(text) && (text[open] == ' ' || text[open] == '\t') {
			open++
		}
		if open >= len(text) || text[open] != '(' || open >= offset {
			continue
		}
		close := lexical.MatchingDelimiter(text, open, "(", ")", true)
		if close >= 0 && close < offset {
			continue
		}
		if call == nil || open > callOpen {
			call, callOpen, callClose = reference, open, close
		}
	}
	if call == nil {
		return nil
	}
	end := len(text)
	if callClose >= 0 {
		end = callClose
	}
	passed := make(map[string]bool)
	for _, argument := range lexical.SplitTopLevelTypes(text[callOpen+1:end], ",", true) {
		if name, _, named := namedArgument(strings.TrimSpace(argument)); named {
			passed[name] = true
		}
	}
	byName := *call
	byName.Arity, byName.Arguments, byName.ResolvedID = -1, nil, ""
	byName.Role = analysis.RoleRead
	seen := make(map[string]bool)
	var out []NamedArgument
	for _, callable := range i.resolveLocked(ctx, file, byName) {
		candidates := []analysis.Symbol{callable}
		if analysis.IsTypeKind(callable.Kind) {
			// A class name calls its constructors.
			candidates = candidates[:0]
			for _, id := range i.byContainerName[callable.ID] {
				if constructor := i.symbols[id]; constructor != nil && constructor.Kind == analysis.KindConstructor && constructor.ContainerID == callable.ID {
					candidates = append(candidates, *constructor)
				}
			}
		}
		for _, candidate := range candidates {
			if !analysis.IsCallableKind(candidate.Kind) {
				continue
			}
			for _, parameter := range candidate.Parameters {
				if parameter.Name == "" || passed[parameter.Name] || seen[parameter.Name] {
					continue
				}
				seen[parameter.Name] = true
				out = append(out, NamedArgument{Name: parameter.Name, Type: i.respellDeclaredTypeLocked(file, candidate, parameter.Type), Required: parameter.Default == ""})
			}
		}
	}
	return out
}
