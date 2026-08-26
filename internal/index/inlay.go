package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

type ParameterHint struct {
	Position       protocol.Position
	Label          string
	Callable       analysis.Symbol
	ParameterIndex int
}

// ParameterHints resolves already-parsed call arguments against the symbol
// index. No parsing or file I/O occurs while the index lock is held.
func (i *Index) ParameterHints(uri protocol.URI, requested protocol.Range) []ParameterHint {
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	var out []ParameterHint
	for _, ref := range file.References {
		if ref.Role != analysis.RoleCall || len(ref.Arguments) == 0 {
			continue
		}
		resolved := i.resolveLocked(file, ref)
		var callable analysis.Symbol
		for _, candidate := range resolved {
			if analysis.IsCallableKind(candidate.Kind) && matchesArityForLanguage(candidate, len(ref.Arguments), file.Language) {
				callable = candidate
				break
			}
		}
		if callable.ID == "" {
			continue
		}
		positional := 0
		for _, argumentRange := range ref.Arguments {
			argument := strings.TrimSpace(doc.Slice(argumentRange))
			parameterIndex := -1
			name, _, isNamed := namedArgument(argument)
			if isNamed {
				for index, parameter := range callable.Parameters {
					if parameter.Name == name {
						parameterIndex = index
						break
					}
				}
			} else if positional < len(callable.Parameters) {
				parameterIndex = positional
				if !callable.Parameters[positional].Variadic {
					positional++
				}
			}
			if parameterIndex < 0 || parameterIndex >= len(callable.Parameters) {
				continue
			}
			if beforeRange(argumentRange.End, requested.Start) || beforeRange(requested.End, argumentRange.Start) {
				continue
			}
			parameter := callable.Parameters[parameterIndex]
			if argument == parameter.Name || isNamed {
				continue
			}
			out = append(out, ParameterHint{Position: argumentRange.Start, Label: parameter.Name + ":", Callable: callable, ParameterIndex: parameterIndex})
		}
	}
	return out
}

func beforeRange(a, b protocol.Position) bool {
	return a.Line < b.Line || a.Line == b.Line && a.Character < b.Character
}
