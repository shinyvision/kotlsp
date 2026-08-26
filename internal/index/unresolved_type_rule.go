package index

import (
	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A type named where it is not in scope cannot compile, whatever else is true
// of the program. That makes it one of the few things the index can prove
// without a compiler, and it is the most common real error there is: a
// forgotten import.
//
// The rule reports only when the type exists somewhere in the index but is not
// reachable by simple name from this file. A name the index has never seen is
// left to the existing check, and a name it can resolve is not an error at all.
//
// Being sound here means being complete about how a simple type name comes into
// scope. The resolver models same-file declarations, explicit and wildcard
// imports, the file's own package, and the language's default imports. Two
// things it does not model are grounds to abstain outright rather than risk
// reporting correct code:
//
//   - A type parameter of an enclosing declaration shadows everything.
//   - A supertype that did not resolve may contribute names this file can use,
//     so nothing about the names in that file is known.
func init() {
	registerFastRule(fastRule{
		codes:     []string{"UNRESOLVED_REFERENCE"},
		languages: []analysis.Language{analysis.LanguageKotlin},
		apply:     unresolvedTypeReferences,
	})
}

func unresolvedTypeReferences(i *Index, file *analysis.ParsedFile) []protocol.Diagnostic {
	// One file names few distinct types but may reference each of them many
	// times, and resolution is the expensive part. Every answer is a function
	// of the name alone within this pass, so each is computed once.
	inScope := make(map[string]bool)
	resolvesInScope := func(name string) bool {
		if answer, known := inScope[name]; known {
			return answer
		}
		answer := len(i.resolveTypeSymbolsLocked(file, name)) > 0
		inScope[name] = answer
		return answer
	}
	if fileHasUnresolvedSupertypeLocked(file, resolvesInScope) {
		return nil
	}
	shadowed := typeParameterNamesLocked(file)
	candidateCache := make(map[string][]string)
	var out []protocol.Diagnostic
	for index := range file.References {
		reference := &file.References[index]
		if reference.Role != analysis.RoleType || reference.Qualifier != "" || reference.ArgumentLabel {
			continue
		}
		if shadowed[reference.Name] {
			continue
		}
		// Cheapest first: a name the index knows no type for is a different
		// finding, reported by the index's own unresolved-reference check, and
		// most references are eliminated here without any resolution at all.
		candidates, known := candidateCache[reference.Name]
		if !known {
			candidates = importableTypeCandidatesLocked(i, reference.Name)
			candidateCache[reference.Name] = candidates
		}
		if len(candidates) == 0 {
			continue
		}
		if resolvesInScope(reference.Name) {
			continue
		}
		if len(i.resolveLocked(file, *reference)) > 0 {
			continue
		}
		out = append(out, protocol.Diagnostic{
			Range: reference.Range, Severity: 1, Code: "UNRESOLVED_REFERENCE", Source: "kotlsp",
			Message: "Unresolved reference '" + reference.Name + "'.",
			Data:    map[string]any{"name": reference.Name, "candidates": candidates},
		})
	}
	return out
}

// importableTypeCandidatesLocked lists qualified names this simple name could
// refer to, so the finding can carry its own fix.
func importableTypeCandidatesLocked(i *Index, name string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 4)
	for _, id := range i.byName[name] {
		symbol := i.symbols[id]
		if symbol == nil || !analysis.IsTypeKind(symbol.Kind) || symbol.FQN == "" || symbol.Synthetic {
			continue
		}
		if seen[symbol.FQN] {
			continue
		}
		seen[symbol.FQN] = true
		out = append(out, symbol.FQN)
	}
	return out
}

// typeParameterNamesLocked collects every type parameter declared anywhere in
// the file. A type parameter shadows a type of the same name, and the reference
// records no binding to tell them apart, so the whole file abstains on that
// name rather than guess.
func typeParameterNamesLocked(file *analysis.ParsedFile) map[string]bool {
	names := make(map[string]bool)
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.Kind == analysis.KindTypeParameter {
			names[symbol.Name] = true
		}
		for _, parameter := range symbol.TypeParameters {
			names[parameter] = true
		}
	}
	return names
}

// fileHasUnresolvedSupertypeLocked reports whether any declaration in the file
// extends something the index could not find. Nothing can be concluded about
// the names available in such a file.
func fileHasUnresolvedSupertypeLocked(file *analysis.ParsedFile, resolves func(string) bool) bool {
	for index := range file.Symbols {
		for _, supertype := range file.Symbols[index].Supertypes {
			if !resolves(supertype) {
				return true
			}
		}
	}
	return false
}
