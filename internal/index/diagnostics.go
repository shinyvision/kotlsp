package index

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

var implicitNames = map[string]bool{
	"Any": true, "Nothing": true, "Unit": true, "String": true, "CharSequence": true,
	"Boolean": true, "Byte": true, "Short": true, "Int": true, "Long": true,
	"Float": true, "Double": true, "Char": true, "Array": true,
	"Object": true, "Class": true, "Throwable": true, "Exception": true,
	"void": true, "boolean": true, "byte": true, "short": true, "int": true,
	"long": true, "float": true, "double": true, "char": true,
	"println": true, "print": true, "error": true, "TODO": true,
	"listOf": true, "mutableListOf": true, "setOf": true, "mutableSetOf": true,
	"mapOf": true, "mutableMapOf": true, "arrayOf": true, "emptyList": true,
}

// Diagnostics augments parser errors with bounded, index-backed semantic
// checks. It performs no I/O and only touches precomputed maps.
func (i *Index) Diagnostics(uri protocol.URI) []protocol.Diagnostic {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	out := append([]protocol.Diagnostic(nil), file.Diagnostics...)
	out = append(out, i.compilerDiagnostics[uri]...)
	out = append(out, i.importDiagnosticsLocked(file)...)
	out = append(out, i.declarationDiagnosticsLocked(file)...)
	out = append(out, i.referenceDiagnosticsLocked(file)...)
	out = append(out, i.springDataDiagnosticsLocked(file)...)
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Range.Start == out[b].Range.Start {
			return out[a].Message < out[b].Message
		}
		if out[a].Range.Start.Line == out[b].Range.Start.Line {
			return out[a].Range.Start.Character < out[b].Range.Start.Character
		}
		return out[a].Range.Start.Line < out[b].Range.Start.Line
	})
	return out
}

func (i *Index) importDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	used := make(map[string]bool)
	for _, ref := range file.References {
		if ref.Role != analysis.RoleImport {
			used[ref.Name] = true
		}
	}
	seen := make(map[string]bool)
	var out []protocol.Diagnostic
	for _, imp := range file.Imports {
		key := imp.Path + "|" + imp.Alias
		if seen[key] {
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 2, Code: "duplicate-import", Source: "kotlsp", Message: "Duplicate import: " + imp.Path, Tags: []int{1}, Data: map[string]any{"kind": "removeImport"}})
			continue
		}
		seen[key] = true
		if !imp.Wildcard && len(i.byFQN[imp.Path]) == 0 && !isImplicitImport(imp.Path, file.Language) {
			if i.generation.Load() > 0 && !i.Progress().Ready {
				// Library archives are published incrementally. Absence is not proof
				// of an invalid import until their authoritative index is complete.
				continue
			}
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 1, Code: "unresolved-import", Source: "kotlsp", Message: "Unresolved import: " + imp.Path, Data: map[string]any{"kind": "removeImport"}})
			continue
		}
		if !imp.Wildcard && !used[imp.LocalName()] {
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 4, Code: "unused-import", Source: "kotlsp", Message: "Unused import: " + imp.Path, Tags: []int{1}, Data: map[string]any{"kind": "removeImport"}})
		}
	}
	return out
}

func (i *Index) declarationDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	seen := make(map[string]analysis.Symbol)
	var out []protocol.Diagnostic
	for _, symbol := range file.Symbols {
		if symbol.Synthetic {
			continue
		}
		if symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindTypeParameter {
			continue
		}
		key := symbol.ContainerID + "|" + symbol.Name + "|" + declarationDiscriminator(symbol)
		if isLexicalSymbol(symbol) {
			// Locals conflict only inside the same lexical block. A nested local
			// is ordinary shadowing even though both declarations share the same
			// callable ContainerID.
			key += fmt.Sprintf("|scope:%d:%d", symbol.ScopeStartByte, symbol.ScopeEndByte)
		}
		if first, exists := seen[key]; exists {
			out = append(out, protocol.Diagnostic{
				Range: symbol.SelectionRange, Severity: 1, Code: "duplicate-declaration", Source: "kotlsp",
				Message:            "Conflicting declaration: " + symbol.Name,
				RelatedInformation: []protocol.DiagnosticRelated{{Location: first.Location(), Message: "First declaration is here"}},
			})
			continue
		}
		seen[key] = symbol
	}
	return out
}

func declarationDiscriminator(symbol analysis.Symbol) string {
	if !analysis.IsCallableKind(symbol.Kind) {
		return "value"
	}
	var b strings.Builder
	b.WriteString("callable(")
	for _, parameter := range symbol.Parameters {
		b.WriteString(simpleType(parameter.Type))
		b.WriteByte(';')
	}
	b.WriteByte(')')
	return b.String()
}

func (i *Index) referenceDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	var out []protocol.Diagnostic
	deprecationCache := make(map[string]bool)
	for _, ref := range file.References {
		reportUnresolved := ref.Role == analysis.RoleType || ref.Qualifier == "" && (ref.Role == analysis.RoleCall || ref.Role == analysis.RoleRead || ref.Role == analysis.RoleWrite)
		if implicitNames[ref.Name] {
			reportUnresolved = false
		}
		if reportUnresolved && file.Language == analysis.LanguageKotlin && ref.Role == analysis.RoleCall && i.generation.Load() > 0 && !i.Progress().Ready && len(i.byName[ref.Name]) == 0 {
			// The stdlib/default-import archive is indexed concurrently with the
			// workspace. Until that authoritative symbol set (or K2) is ready, an
			// unknown call is not yet proven unresolved. Reads/writes stay immediate.
			continue
		}
		if reportUnresolved && i.generation.Load() > 0 && !i.Progress().Ready && i.pendingExplicitImportLocked(file, ref.Name) {
			// An explicit import is authoritative for this local name, but library
			// archives are published incrementally. Avoid a transient unresolved
			// reference until the imported FQN has either appeared or indexing ends.
			continue
		}
		// Qualified receiver chains still require data-flow typing. Unqualified
		// reads/writes are fully constrained by lexical, implicit-receiver,
		// import, package, and top-level lookup and can be diagnosed immediately.
		deprecationKey := ""
		if !reportUnresolved {
			if !i.hasDeprecatedNameLocked(ref.Name) {
				continue
			}
			deprecationKey = i.deprecationCacheKeyLocked(file, ref)
			if deprecationKey != "" {
				if deprecated, cached := deprecationCache[deprecationKey]; cached {
					if deprecated {
						out = append(out, protocol.Diagnostic{Range: ref.Range, Severity: 2, Code: "deprecated", Source: "kotlsp", Message: ref.Name + " is deprecated", Tags: []int{2}})
					}
					continue
				}
			}
		}
		resolved := i.resolveLocked(file, ref)
		if deprecationKey != "" {
			deprecationCache[deprecationKey] = len(resolved) > 0 && resolved[0].Deprecated
		}
		if len(resolved) > 0 {
			if resolved[0].Deprecated {
				out = append(out, protocol.Diagnostic{Range: ref.Range, Severity: 2, Code: "deprecated", Source: "kotlsp", Message: resolved[0].Name + " is deprecated", Tags: []int{2}})
			}
			continue
		}
		// Reads on arbitrary receiver chains need data-flow typing. Type
		// references and unqualified calls are constrained enough to report.
		if !reportUnresolved {
			continue
		}
		compilerReported := false
		for _, diagnostic := range i.compilerDiagnostics[file.URI] {
			if diagnostic.Severity == 1 && rangesOverlap(diagnostic.Range, ref.Range) {
				compilerReported = true
				break
			}
		}
		if compilerReported {
			continue
		}
		data := map[string]any{"name": ref.Name}
		if ids := i.byName[ref.Name]; len(ids) > 0 {
			fqns := make([]string, 0, len(ids))
			seen := map[string]bool{}
			for _, id := range ids {
				symbol := i.symbols[id]
				if symbol.FQN != "" && !seen[symbol.FQN] && analysis.IsTypeKind(symbol.Kind) {
					seen[symbol.FQN] = true
					fqns = append(fqns, symbol.FQN)
				}
			}
			sort.Strings(fqns)
			if len(fqns) > 0 {
				data["candidates"] = fqns
			}
		}
		out = append(out, protocol.Diagnostic{Range: ref.Range, Severity: 1, Code: "unresolved-reference", Source: "kotlsp", Message: "Unresolved reference: " + ref.Name, Data: data})
	}
	return out
}

// deprecationCacheKeyLocked identifies qualified calls whose resolution is
// invariant across source positions in the same enclosing type. Large
// generated files commonly contain tens of thousands of identical primitive
// operator shapes; resolving every occurrence merely to discover the same
// deprecation bit otherwise dominates didOpen. Ambiguous position-sensitive
// cases deliberately return an empty key and take the complete resolver path.
func (i *Index) deprecationCacheKeyLocked(file *analysis.ParsedFile, reference analysis.Reference) string {
	if reference.Qualifier == "" || reference.ArgumentLabel || callableReferenceOperatorBefore(i.documentTextLocked(file.URI), reference.StartByte) {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil || reference.StartByte < 0 || reference.EndByte > len(document.Text) || reference.StartByte >= reference.EndByte || document.Text[reference.StartByte:reference.EndByte] == reference.Name {
		// Cache only parser-synthesized convention references whose source token
		// is an operator/bracket. Ordinary named calls can vary by labels and
		// contextual lambdas even when their coarse argument types match.
		return ""
	}
	for _, symbol := range i.fileSymbolsByName[file.URI][reference.Name] {
		if symbol.ContainerID != "" {
			if owner := i.symbols[symbol.ContainerID]; owner != nil && analysis.IsCallableKind(owner.Kind) {
				return ""
			}
		}
	}
	qualifier := reference.Qualifier
	if document := i.docs[file.URI]; document != nil {
		if textual := expressionQualifierBefore(document.Text, reference.StartByte); textual != "" {
			qualifier = textual
		}
	}
	receiverType := i.typeOfExpressionLocked(file, qualifier, reference.StartByte)
	if receiverType == "" || len(i.fileAnonymousByName[file.URI][strings.TrimSpace(qualifier)]) > 0 {
		return ""
	}
	var key strings.Builder
	key.WriteString(reference.Name)
	key.WriteByte('|')
	key.WriteString(receiverType)
	key.WriteByte('|')
	key.WriteString(fmt.Sprint(reference.Role, ":", reference.Arity))
	if enclosing := i.enclosingTypeLocked(file, reference.StartByte); enclosing.ID != "" {
		key.WriteByte('|')
		key.WriteString(enclosing.ID)
	}
	for _, argument := range reference.Arguments {
		start, end := document.Offset(argument.Start), document.Offset(argument.End)
		if start < 0 || end < start || end > len(document.Text) {
			return ""
		}
		expression := strings.TrimSpace(document.Text[start:end])
		key.WriteByte('|')
		key.WriteString(i.inferExpressionTypeLocked(file, expression, start))
		// Kotlin integer literals are context-sensitive. Record every primitive
		// range they fit so values with different overload applicability never
		// share a cached deprecation result.
		for _, expected := range []string{"Byte", "Short", "Int", "Long", "UByte", "UShort", "UInt", "ULong"} {
			if _, ok := kotlinIntegerLiteralConversionScore(expression, expected); ok {
				key.WriteByte(':')
				key.WriteString(expected)
			}
		}
	}
	return key.String()
}

func (i *Index) pendingExplicitImportLocked(file *analysis.ParsedFile, name string) bool {
	for _, imported := range file.Imports {
		if !imported.Wildcard && imported.LocalName() == name && len(i.byFQN[imported.Path]) == 0 {
			return true
		}
	}
	return false
}

func rangesOverlap(first, second protocol.Range) bool {
	return positionLess(first.Start, second.End) && positionLess(second.Start, first.End)
}

func positionLess(first, second protocol.Position) bool {
	return first.Line < second.Line || first.Line == second.Line && first.Character < second.Character
}

func (i *Index) hasDeprecatedNameLocked(name string) bool {
	for _, id := range i.byName[name] {
		if i.symbols[id].Deprecated {
			return true
		}
	}
	return false
}

func isImplicitImport(path string, language analysis.Language) bool {
	if language == analysis.LanguageJava {
		return strings.HasPrefix(path, "java.lang.")
	}
	for _, prefix := range []string{"kotlin.", "kotlin.annotation.", "kotlin.collections.", "kotlin.comparisons.", "kotlin.io.", "kotlin.ranges.", "kotlin.sequences.", "kotlin.text.", "kotlin.jvm.", "java.lang."} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
