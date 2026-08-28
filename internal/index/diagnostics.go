package index

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

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
	// Predictions the index can prove without a compiler, so the author sees
	// them immediately. The compiler may add findings these did not, but must
	// never contradict one, which the soundness gate asserts. They carry the
	// compiler's own code and wording, so a confirming finding changes nothing.
	var predictions []protocol.Diagnostic
	if file.ParseMode != "large" {
		predictions = append(i.declarationDiagnosticsLocked(file), i.referenceDiagnosticsLocked(file)...)
		predictions = append(predictions, i.fastDiagnosticsLocked(file)...)
		predictions = append(predictions, i.springDataDiagnosticsLocked(file)...)
	}
	predictions, compiler := reconcilePredictions(predictions, i.compilerDiagnostics[uri])
	out = append(out, compiler...)
	if file.ParseMode != "large" {
		out = append(out, i.importDiagnosticsLocked(file)...)
	}
	out = append(out, predictions...)
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Range.Start == out[b].Range.Start {
			return out[a].Message < out[b].Message
		}
		if out[a].Range.Start.Line == out[b].Range.Start.Line {
			return out[a].Range.Start.Character < out[b].Range.Start.Character
		}
		return out[a].Range.Start.Line < out[b].Range.Start.Line
	})
	if len(out) > maxCompilerDiagnosticsPerFile {
		omitted := len(out) - (maxCompilerDiagnosticsPerFile - 1)
		sort.SliceStable(out, func(a, b int) bool {
			if out[a].Severity == out[b].Severity {
				return out[a].Range.Start.Line < out[b].Range.Start.Line
			}
			return out[a].Severity < out[b].Severity
		})
		out = append(append([]protocol.Diagnostic(nil), out[:maxCompilerDiagnosticsPerFile-1]...), protocol.Diagnostic{
			Severity: 2, Source: "kotlsp", Code: "diagnostics-omitted",
			Message: fmt.Sprintf("%d additional diagnostics omitted by the document safety limit.", omitted),
		})
		sort.SliceStable(out, func(a, b int) bool {
			if out[a].Range.Start == out[b].Range.Start {
				return out[a].Message < out[b].Message
			}
			if out[a].Range.Start.Line == out[b].Range.Start.Line {
				return out[a].Range.Start.Character < out[b].Range.Start.Character
			}
			return out[a].Range.Start.Line < out[b].Range.Start.Line
		})
	}
	return out
}

func (i *Index) importDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	usedImports := i.usedImportsLocked(file)
	seen := make(map[string]bool)
	var out []protocol.Diagnostic
	for _, imp := range file.Imports {
		if len(out) >= maxCompilerDiagnosticsPerFile {
			break
		}
		key := imp.Path + "|" + imp.Alias
		if seen[key] {
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 2, Code: "duplicate-import", Source: "kotlsp", Message: "Duplicate import: " + imp.Path, Tags: []int{1}, Data: map[string]any{"kind": "removeImport"}})
			continue
		}
		seen[key] = true
		if !imp.Wildcard && len(i.byFQN[imp.Path]) == 0 && !isImplicitImport(imp.Path, file.Language) {
			if !i.absenceProvesUnresolvedLocked(file) || i.hasUnmodelledGeneratedSourcesFor(file) {
				// Library archives are published incrementally. Absence is not proof
				// of an invalid import until their authoritative index is complete.
				continue
			}
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 1, Code: "unresolved-import", Source: "kotlsp", Message: "Unresolved import: " + imp.Path, Data: map[string]any{"kind": "removeImport"}})
			continue
		}
		if !imp.Wildcard && !usedImports[imp.Path] {
			out = append(out, protocol.Diagnostic{Range: imp.Range, Severity: 4, Code: "unused-import", Source: "kotlsp", Message: "Unused import: " + imp.Path, Tags: []int{1}, Data: map[string]any{"kind": "removeImport"}})
		}
	}
	return out
}

// redeclaration builds the finding for one of two conflicting declarations,
// pointing at the other. kotlinc names the three cases differently; each
// message is its first line, which is all a line-based renderer shows. javac's
// wording carries context the index cannot reproduce, so a Java redeclaration
// stays a plain lint finding.
// redeclarationLocked builds the compiler's own finding for a duplicate. K2
// reports both declarations; javac reports only the later one, and names the
// owner in the message, so a Java first occurrence yields nothing and a Java
// second occurrence yields nothing when javac's wording cannot be reproduced.
func (i *Index) redeclarationLocked(file *analysis.ParsedFile, symbol, other analysis.Symbol, second bool) (protocol.Diagnostic, bool) {
	code, message := "REDECLARATION", "Conflicting declarations:"
	if file.Language == analysis.LanguageKotlin {
		if analysis.IsTypeKind(symbol.Kind) && symbol.Kind != analysis.KindTypeParameter {
			code, message = "CLASSIFIER_REDECLARATION", "Redeclaration:"
		} else if analysis.IsCallableKind(symbol.Kind) {
			code, message = "CONFLICTING_OVERLOADS", "Conflicting overloads:"
		}
	} else {
		if !second {
			return protocol.Diagnostic{}, false
		}
		code = "compiler"
		owner := i.symbols[symbol.ContainerID]
		switch {
		case symbol.ContainerID == "" && analysis.IsTypeKind(symbol.Kind) && symbol.FQN != "":
			message = javaDuplicateClass + symbol.FQN
		case owner == nil:
			return protocol.Diagnostic{}, false
		case symbol.Kind == analysis.KindField && owner.Kind == analysis.KindClass:
			message = "variable " + symbol.Name + javaAlreadyDefined + "class " + owner.Name
		case symbol.Kind == analysis.KindMethod && owner.Kind == analysis.KindClass:
			signature, ok := javaSignature(owner, &symbol)
			if !ok {
				return protocol.Diagnostic{}, false
			}
			message = "method " + signature + javaAlreadyDefined + "class " + owner.Name
		case symbol.Kind == analysis.KindVariable && owner.Kind == analysis.KindMethod:
			signature, ok := javaSignature(i.symbols[owner.ContainerID], owner)
			if !ok {
				return protocol.Diagnostic{}, false
			}
			message = "variable " + symbol.Name + javaAlreadyDefined + "method " + signature
		default:
			return protocol.Diagnostic{}, false
		}
	}
	return protocol.Diagnostic{
		Range: symbol.SelectionRange, Severity: 1, Code: code, Source: "kotlsp",
		Message:            message,
		RelatedInformation: []protocol.DiagnosticRelated{{Location: other.Location(), Message: "Conflicting declaration is here"}},
	}, true
}

func (i *Index) declarationDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	seen := make(map[string]analysis.Symbol)
	reportedFirst := make(map[string]bool)
	var out []protocol.Diagnostic
	for _, symbol := range file.Symbols {
		if len(out) >= maxCompilerDiagnosticsPerFile {
			break
		}
		if symbol.Synthetic {
			continue
		}
		if symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindTypeParameter {
			continue
		}
		// Two companions are a different error (MANY_COMPANION_OBJECTS), and
		// the parser names every companion 'Companion'.
		if symbol.Kind == analysis.KindObject && containsString(symbol.Modifiers, "companion") {
			continue
		}
		key := symbol.ContainerID + "|" + symbol.Name + "|" + declarationDiscriminator(symbol)
		if isLexicalSymbol(symbol) {
			// Locals conflict only inside the same lexical block. A nested local
			// is ordinary shadowing even though both declarations share the same
			// callable ContainerID. A local's scope starts at its own
			// declaration and ends with its block, so the block is the end.
			key += fmt.Sprintf("|scope:%d", symbol.ScopeEndByte)
		}
		if first, exists := seen[key]; exists {
			// The compiler reports both declarations. Reporting only the
			// second would leave the first to appear seconds later.
			if !reportedFirst[key] {
				reportedFirst[key] = true
				if diagnostic, ok := i.redeclarationLocked(file, first, symbol, false); ok {
					out = append(out, diagnostic)
				}
			}
			if diagnostic, ok := i.redeclarationLocked(file, symbol, first, true); ok {
				out = append(out, diagnostic)
			}
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
	scopeContext := newUnresolvedNameContext(file)
	resolvedTypeScope := make(map[string]bool)
	resolvesType := func(name string, at int) bool {
		key := name + "\x00" + fmt.Sprint(i.containerIDAtLocked(file, at))
		if answer, known := resolvedTypeScope[key]; known {
			return answer
		}
		answer := len(i.resolveTypeSymbolsAtLocked(file, name, at)) > 0
		resolvedTypeScope[key] = answer
		return answer
	}
	for _, ref := range file.References {
		if len(out) >= maxCompilerDiagnosticsPerFile {
			break
		}
		reportUnresolved := ref.Role == analysis.RoleType || ref.Qualifier == "" && (ref.Role == analysis.RoleCall || ref.Role == analysis.RoleRead || ref.Role == analysis.RoleWrite)
		if i.generation.Load() > 0 && !i.Progress().Ready {
			reportUnresolved = false
		}
		// An argument label is never unresolved on its own. It binds through
		// its owner, and when the owner cannot be resolved the compiler reports
		// the owner and says nothing about the label.
		if ref.ArgumentLabel {
			reportUnresolved = false
		}
		// Primitive and core default-import types remain language-defined even in
		// a directly opened fragment where no stdlib/JDK archive was indexed.
		// Their absent declarations are never evidence of an unresolved name.
		if languageIntrinsicReference(ref, file.Language) {
			continue
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
		allDeprecated := len(resolved) > 0
		for _, candidate := range resolved {
			allDeprecated = allDeprecated && candidate.Deprecated
		}
		if deprecationKey != "" {
			deprecationCache[deprecationKey] = allDeprecated
		}
		if len(resolved) > 0 {
			if allDeprecated {
				out = append(out, protocol.Diagnostic{Range: ref.Range, Severity: 2, Code: "deprecated", Source: "kotlsp", Message: ref.Name + " is deprecated", Tags: []int{2}})
			}
			continue
		}
		// Reads on arbitrary receiver chains need data-flow typing. Type
		// references and unqualified calls are constrained enough to report.
		if !reportUnresolved {
			continue
		}
		// Not suppressed when the compiler has reported here: the prediction
		// carries the compiler's own wording, and reconciliation keeps whichever
		// copy makes nothing change on screen.
		// A reference recovered from source the parser could not read is not
		// evidence of anything. Where the syntax failed, the surrounding
		// declaration may not have been recognised at all, which turns its own
		// name into an apparently unresolved reference.
		if referenceInUnparsedRegion(file, ref.Range) {
			continue
		}
		// Failing to bind an occurrence is not the same as the name being
		// undefined. Lambda receivers, standard-library extensions, generic
		// scope functions, and annotation attributes on binary declarations all
		// need real type inference to bind, and the index performs none: on
		// ordinary Spring/Kotlin sources reporting them was wrong 98% of the
		// time. A name the index has never seen anywhere is genuinely
		// undefined; a name it knows but could not bind here belongs to the
		// background K2/javac pass, which resolves it correctly and whose
		// findings are already merged into this result.
		// A name absent from the index is evidence of nothing until the index
		// holds the standard library and every dependency. Reporting before
		// then is how a cold start showed errors on kotlin.annotation.Target.
		// An index with no workspace scan at all is a deliberate in-memory
		// one and is complete by construction.
		if !i.absenceProvesUnresolvedLocked(file) || i.hasUnmodelledGeneratedSourcesFor(file) {
			continue
		}
		if !predictionsApplyTo(file) {
			continue
		}
		if ref.Role == analysis.RoleType && referenceInsideUnresolvedSupertypeOwner(file, ref, resolvesType) {
			continue
		}
		// A name the index knows but could not bind here is the common case
		// -- a member of some other class, a property of a sibling controller
		// -- and is exactly what the scope engine exists for: it proves that
		// no declaration of the name can be visible at this position, or it
		// abstains. Type references stay with the type rule.
		// An explicit import declares the name even when the index holds no
		// declaration for it (a top-level function inside a library facade
		// class, for instance). Whether that import resolves is the import
		// rule's question, and the compiler's; the reference itself is bound.
		if importDeclaresName(file, ref.Name) {
			continue
		}
		knownName := len(i.byName[ref.Name]) > 0 || len(i.fileSymbolsByName[file.URI][ref.Name]) > 0
		if knownName && (ref.Role == analysis.RoleType || !i.fastDiagnosticsEligibleLocked(file) || !i.nameProvablyUnresolvedLocked(scopeContext, ref)) {
			continue
		}
		// A name with no declaration anywhere may still be a package: the
		// first segments of `java.io.IOException` are references too.
		packageSegment := scopeContext.isPackageSegment(i, ref.Name)
		if ref.Qualifier == "" {
			packageSegment = scopeContext.isRootPackageSegment(i, ref.Name)
		}
		if packageSegment || scopeContext.isDeclarationName(ref.StartByte) {
			continue
		}
		data := map[string]any{"name": ref.Name}
		if ids := i.byName[ref.Name]; len(ids) > 0 {
			fqns := make([]string, 0, min(len(ids), 64))
			seen := map[string]bool{}
			if len(ids) <= 4096 {
				for _, id := range ids {
					symbol := i.symbols[id]
					if symbol.FQN != "" && !seen[symbol.FQN] && analysis.IsTypeKind(symbol.Kind) {
						seen[symbol.FQN] = true
						fqns = append(fqns, symbol.FQN)
						if len(fqns) >= 64 {
							break
						}
					}
				}
			}
			sort.Strings(fqns)
			if len(fqns) > 0 {
				data["candidates"] = fqns
			}
		}
		// Each compiler's own wording, so its later finding reconciles with
		// this one instead of appearing beside it.
		code, message := "UNRESOLVED_REFERENCE", "Unresolved reference '"+ref.Name+"'."
		if file.Language == analysis.LanguageJava {
			code, message = "compiler", "cannot find symbol"
		}
		out = append(out, protocol.Diagnostic{Range: ref.Range, Severity: 1, Code: code, Source: "kotlsp", Message: message, Data: data})
	}
	return out
}

// referenceInUnparsedRegion reports whether a reference falls inside a span the
// parser flagged as a syntax error.
func referenceInUnparsedRegion(file *analysis.ParsedFile, target protocol.Range) bool {
	owner := protocol.Range{}
	hasOwner := false
	for _, symbol := range file.Symbols {
		if symbol.Synthetic || !rangeContains(symbol.Range, target) {
			continue
		}
		if !hasOwner || rangeContains(owner, symbol.Range) {
			owner, hasOwner = symbol.Range, true
		}
	}
	for _, diagnostic := range file.Diagnostics {
		if diagnostic.Severity == 1 && diagnostic.Code == "syntax" && (rangesOverlap(diagnostic.Range, target) || hasOwner && rangesOverlap(diagnostic.Range, owner)) {
			return true
		}
	}
	return false
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
	if text := i.documentTextLocked(file.URI); text != "" {
		if textual := expressionQualifierBefore(text, reference.StartByte); textual != "" {
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

func languageIntrinsicType(name string, language analysis.Language) bool {
	name = simpleType(name)
	if language == analysis.LanguageJava {
		switch name {
		case "void", "boolean", "byte", "short", "int", "long", "char", "float", "double",
			"Object", "String", "StringBuilder", "StringBuffer", "Class", "System", "Math", "Number",
			"Boolean", "Byte", "Short", "Integer", "Long", "Character", "Float", "Double", "Void",
			"Throwable", "Exception", "RuntimeException", "Error", "Enum", "Iterable", "Runnable", "AutoCloseable", "Deprecated", "Override", "SuppressWarnings":
			return true
		}
		return false
	}
	switch name {
	case "Any", "Nothing", "Unit", "String", "CharSequence", "Throwable", "Cloneable", "Number", "Comparable", "Enum", "Annotation",
		"Boolean", "Char", "Byte", "Short", "Int", "Long", "Float", "Double", "UByte", "UShort", "UInt", "ULong",
		"BooleanArray", "CharArray", "ByteArray", "ShortArray", "IntArray", "LongArray", "FloatArray", "DoubleArray", "UByteArray", "UShortArray", "UIntArray", "ULongArray", "Array",
		"Iterable", "Iterator", "Collection", "List", "MutableList", "Set", "MutableSet", "Map", "MutableMap", "Map.Entry", "Pair", "Triple", "Result",
		"Exception", "RuntimeException", "IllegalArgumentException", "IllegalStateException", "IndexOutOfBoundsException", "UnsupportedOperationException":
		return true
	}
	return false
}

func languageIntrinsicReference(ref analysis.Reference, language analysis.Language) bool {
	if ref.Role == analysis.RoleType {
		return languageIntrinsicType(ref.Name, language)
	}
	if ref.Role == analysis.RoleCall && languageIntrinsicType(ref.Name, language) {
		return true
	}
	if language != analysis.LanguageKotlin || ref.Qualifier != "" || ref.Role != analysis.RoleCall && ref.Role != analysis.RoleRead {
		return false
	}
	switch ref.Name {
	case "TODO", "error", "require", "requireNotNull", "check", "checkNotNull", "lazy", "run", "with",
		"print", "println", "readLine", "arrayOf", "emptyArray", "listOf", "mutableListOf", "emptyList",
		"setOf", "mutableSetOf", "emptySet", "mapOf", "mutableMapOf", "emptyMap", "sequenceOf":
		return true
	}
	return false
}

// absenceProvesUnresolvedLocked reports whether a name or import with no
// declaration anywhere in the index is thereby unresolved. An index populated
// only through Open has no scan in flight and no archive still being
// published: its universe is complete by construction, so absence is proof
// immediately. A scanned workspace must first finish (and be authoritative)
// before a missing declaration can mean anything.
func (i *Index) absenceProvesUnresolvedLocked(file *analysis.ParsedFile) bool {
	if i.generation.Load() == 0 {
		return true
	}
	return i.semanticUniverseCompleteLocked(file)
}

// importDeclaresName reports whether the file explicitly imports name, by its
// own name or by alias. The scope engine treats such a name as bound.
func importDeclaresName(file *analysis.ParsedFile, name string) bool {
	for _, imported := range file.Imports {
		if imported.LocalName() == name || imported.Alias == name {
			return true
		}
	}
	return false
}
