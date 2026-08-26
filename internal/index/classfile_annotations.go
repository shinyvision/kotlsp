package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
)

// applyClassfileAnnotations enriches the navigable source-shaped symbols with
// declaration-level nullability from classfile method, field, and parameter
// annotation attributes. Kotlin emits these as runtime-invisible annotations,
// so source stubs alone cannot retain them without this correlation step.
func applyClassfileAnnotations(parsed *analysis.ParsedFile, class *classfile.Class) {
	ownerFQN := strings.ReplaceAll(strings.ReplaceAll(class.InternalName, "/", "."), "$", ".")
	ownerID, ownerName := "", ""
	for _, symbol := range parsed.Symbols {
		if analysis.IsTypeKind(symbol.Kind) && symbol.FQN == ownerFQN {
			ownerID, ownerName = symbol.ID, symbol.Name
			break
		}
	}
	if ownerID == "" {
		return
	}
	for _, field := range class.Fields {
		if !hasNullableAnnotation(field.Annotations) && len(nullableTypeAnnotations(field.TypeAnnotations, 0x13, -1)) == 0 {
			continue
		}
		for index := range parsed.Symbols {
			symbol := &parsed.Symbols[index]
			if symbol.ContainerID == ownerID && symbol.Name == field.Name && (symbol.Kind == analysis.KindField || symbol.Kind == analysis.KindProperty) {
				if hasNullableAnnotation(field.Annotations) {
					symbol.Type = nullableReferenceType(symbol.Type)
				}
				for _, annotation := range nullableTypeAnnotations(field.TypeAnnotations, 0x13, -1) {
					symbol.Type = nullableTypeAtPath(symbol.Type, annotation.TypePath)
				}
			}
		}
	}
	used := make(map[int]bool)
	for _, method := range class.Methods {
		name := method.Name
		constructor := name == "<init>"
		if constructor {
			name = ownerName
		}
		best := -1
		for index := range parsed.Symbols {
			symbol := &parsed.Symbols[index]
			if used[index] || symbol.ContainerID != ownerID || symbol.Name != name || !analysis.IsCallableKind(symbol.Kind) || constructor != (symbol.Kind == analysis.KindConstructor) || len(symbol.Parameters) != len(method.ParameterTypes) {
				continue
			}
			if binaryCallableTypesMatch(*symbol, method) {
				best = index
				break
			}
			if best < 0 {
				best = index
			}
		}
		if best < 0 {
			continue
		}
		used[best] = true
		symbol := &parsed.Symbols[best]
		if hasNullableAnnotation(method.Annotations) {
			symbol.Type = nullableReferenceType(symbol.Type)
		}
		for _, annotation := range nullableTypeAnnotations(method.TypeAnnotations, 0x14, -1) {
			symbol.Type = nullableTypeAtPath(symbol.Type, annotation.TypePath)
		}
		for parameter := range symbol.Parameters {
			declarationNullable := parameter < len(method.ParameterAnnotations) && hasNullableAnnotation(method.ParameterAnnotations[parameter])
			if declarationNullable {
				symbol.Parameters[parameter].Type = nullableReferenceType(symbol.Parameters[parameter].Type)
			}
			for _, annotation := range nullableTypeAnnotations(method.TypeAnnotations, 0x16, parameter) {
				symbol.Parameters[parameter].Type = nullableTypeAtPath(symbol.Parameters[parameter].Type, annotation.TypePath)
			}
		}
		symbol.Signature = annotatedBinarySignature(*symbol)
	}
}

func annotatedBinarySignature(symbol analysis.Symbol) string {
	var signature strings.Builder
	if symbol.Kind != analysis.KindConstructor && symbol.Type != "" {
		signature.WriteString(symbol.Type)
		signature.WriteByte(' ')
	}
	signature.WriteString(symbol.Name)
	signature.WriteByte('(')
	for index, parameter := range symbol.Parameters {
		if index > 0 {
			signature.WriteString(", ")
		}
		signature.WriteString(parameter.Name)
		if parameter.Type != "" {
			signature.WriteByte(' ')
			signature.WriteString(parameter.Type)
		}
	}
	signature.WriteByte(')')
	return signature.String()
}

func hasNullableTypeAnnotation(annotations []classfile.TypeAnnotation, target byte, parameter int) bool {
	return len(nullableTypeAnnotations(annotations, target, parameter)) > 0
}

func nullableTypeAnnotations(annotations []classfile.TypeAnnotation, target byte, parameter int) []classfile.TypeAnnotation {
	var result []classfile.TypeAnnotation
	for _, annotation := range annotations {
		if annotation.TargetType == target && annotation.ParameterIndex == parameter && hasNullableAnnotation([]string{annotation.Annotation}) {
			result = append(result, annotation)
		}
	}
	return result
}

func nullableTypeAtPath(value string, path []classfile.TypePathEntry) string {
	if len(path) == 0 {
		return nullableReferenceType(value)
	}
	entry := path[0]
	switch entry.Kind {
	case 0: // ARRAY_ELEMENT
		trimmed := strings.TrimSpace(value)
		if strings.HasSuffix(trimmed, "[]") {
			base := strings.TrimSpace(strings.TrimSuffix(trimmed, "[]"))
			return nullableTypeAtPath(base, path[1:]) + "[]"
		}
		if strings.HasSuffix(trimmed, "...") {
			base := strings.TrimSpace(strings.TrimSuffix(trimmed, "..."))
			return nullableTypeAtPath(base, path[1:]) + "..."
		}
	case 2: // WILDCARD_BOUND
		for _, prefix := range []string{"? extends ", "? super ", "out ", "in "} {
			if strings.HasPrefix(strings.TrimSpace(value), prefix) {
				return prefix + nullableTypeAtPath(strings.TrimSpace(value)[len(prefix):], path[1:])
			}
		}
	case 3: // TYPE_ARGUMENT
		open := topLevelGenericOpen(value)
		if open >= 0 {
			close := matchingGenericClose(value, open)
			if close >= 0 {
				ranges := topLevelGenericArgumentRanges(value, open+1, close)
				argument := int(entry.Index)
				if argument < len(ranges) {
					start, end := ranges[argument][0], ranges[argument][1]
					leading := len(value[start:end]) - len(strings.TrimLeft(value[start:end], " \t\n\r"))
					trailing := len(value[start:end]) - len(strings.TrimRight(value[start:end], " \t\n\r"))
					innerStart, innerEnd := start+leading, end-trailing
					updated := nullableTypeAtPath(value[innerStart:innerEnd], path[1:])
					return value[:innerStart] + updated + value[innerEnd:]
				}
			}
		}
	case 1: // INNER_TYPE; dotted source names do not retain the JVM boundary.
		return nullableTypeAtPath(value, path[1:])
	}
	// If a compiler emits a path shape the source renderer cannot structurally
	// represent, retaining nullability on the closest enclosing type is safer
	// than silently discarding the annotation.
	return nullableReferenceType(value)
}

func binaryCallableTypesMatch(symbol analysis.Symbol, method classfile.Method) bool {
	if len(symbol.Parameters) != len(method.ParameterTypes) {
		return false
	}
	for index := range symbol.Parameters {
		if !sameJvmType(symbol.Parameters[index].Type, method.ParameterTypes[index]) {
			return false
		}
	}
	return true
}

func hasNullableAnnotation(annotations []string) bool {
	for _, annotation := range annotations {
		name := annotation
		if open := strings.IndexByte(name, '('); open >= 0 {
			name = name[:open]
		}
		name = strings.TrimPrefix(strings.TrimSpace(name), "@")
		if name == "Nullable" || strings.HasSuffix(name, ".Nullable") || strings.HasSuffix(name, ".CheckForNull") {
			return true
		}
	}
	return false
}

func nullableReferenceType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, "?") {
		return value
	}
	switch simpleType(value) {
	case "byte", "short", "int", "long", "float", "double", "boolean", "char", "void", "Byte", "Short", "Int", "Long", "Float", "Double", "Boolean", "Char", "Unit":
		return value
	default:
		return value + "?"
	}
}
