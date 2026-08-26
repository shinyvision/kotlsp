package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
)

type kotlinMetadataParameter struct {
	Name       string
	HasDefault bool
	Type       kotlinMetadataType
}

type kotlinMetadataType struct {
	Present   bool
	Nullable  bool
	Arguments []kotlinMetadataType
}

type kotlinMetadataCallable struct {
	Name       string
	JVMName    string
	Parameters []kotlinMetadataParameter
	ReturnType kotlinMetadataType
	Receiver   bool
	Visibility string
}

type kotlinBinaryMetadata struct {
	Constructors []kotlinMetadataCallable
	Functions    []kotlinMetadataCallable
	Visibility   string
}

func decodeKotlinBinaryMetadata(metadata *classfile.KotlinMetadata) kotlinBinaryMetadata {
	if metadata == nil || len(metadata.Data1) == 0 {
		return kotlinBinaryMetadata{}
	}
	data := decodeKotlinMetadataBytes(metadata.Data1)
	nameTableSize, prefix := protobufVarint(data)
	if prefix == 0 || nameTableSize > uint64(len(data)-prefix) {
		return kotlinBinaryMetadata{}
	}
	message := data[prefix+int(nameTableSize):]
	var decoded kotlinBinaryMetadata
	protobufFields(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case metadata.Kind == 1 && number == 1 && wire == 0:
			decoded.Visibility = kotlinMetadataVisibility(integer)
		case metadata.Kind == 1 && number == 8 && wire == 2:
			decoded.Constructors = append(decoded.Constructors, decodeKotlinCallable(value, metadata.Data2, true))
		case metadata.Kind == 1 && number == 9 && wire == 2, (metadata.Kind == 2 || metadata.Kind == 5) && number == 3 && wire == 2:
			decoded.Functions = append(decoded.Functions, decodeKotlinCallable(value, metadata.Data2, false))
		}
	})
	return decoded
}

func decodeKotlinMetadataBytes(data []string) []byte {
	if len(data) == 0 {
		return nil
	}
	first := []rune(data[0])
	direct := len(first) > 0 && first[0] == 0
	if direct || len(first) > 0 && first[0] == 0xffff {
		data = append([]string(nil), data...)
		data[0] = string(first[1:])
	}
	bytes := make([]byte, 0)
	for _, part := range data {
		for _, value := range part {
			bytes = append(bytes, byte(value))
		}
	}
	if direct {
		return bytes
	}
	// Legacy metadata stores eight-bit bytes in seven-bit characters after a
	// modulo transform. This is Kotlin's BitEncoding.decodeBytes inverse.
	for index := range bytes {
		bytes[index] = byte((int(bytes[index]) + 127) & 0x7f)
	}
	decoded := make([]byte, 0, len(bytes)*7/8)
	for index, bit := 0, 0; bit+8 <= len(bytes)*7; bit += 8 {
		byteIndex, shift := bit/7, uint(bit%7)
		value := uint16(bytes[byteIndex]) >> shift
		if shift > 0 && byteIndex+1 < len(bytes) {
			value |= uint16(bytes[byteIndex+1]) << (7 - shift)
		}
		decoded = append(decoded, byte(value))
		index++
	}
	return decoded
}

func decodeKotlinCallable(message []byte, stringsTable []string, constructor bool) kotlinMetadataCallable {
	callable := kotlinMetadataCallable{}
	flags, hasCurrentFlags := uint64(6), false
	if constructor {
		callable.Name = "<init>"
	}
	protobufFields(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 9 && wire == 0:
			flags, hasCurrentFlags = integer, true
		case number == 1 && wire == 0 && !hasCurrentFlags:
			flags = integer
		case !constructor && number == 2 && wire == 0:
			callable.Name = kotlinMetadataString(stringsTable, integer)
		case !constructor && number == 3 && wire == 2:
			callable.ReturnType = decodeKotlinMetadataType(value)
		case constructor && number == 2 && wire == 2, !constructor && number == 6 && wire == 2:
			callable.Parameters = append(callable.Parameters, decodeKotlinMetadataParameter(value, stringsTable))
		case !constructor && (number == 5 && wire == 2 || number == 8 && wire == 0):
			callable.Receiver = true
		case !constructor && number == 100 && wire == 2:
			protobufFields(value, func(field int, fieldWire int, fieldInteger uint64, _ []byte) {
				if field == 1 && fieldWire == 0 {
					callable.JVMName = kotlinMetadataString(stringsTable, fieldInteger)
				}
			})
		}
	})
	callable.Visibility = kotlinMetadataVisibility(flags)
	return callable
}

func decodeKotlinMetadataParameter(message []byte, stringsTable []string) kotlinMetadataParameter {
	parameter := kotlinMetadataParameter{}
	protobufFields(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 1 && wire == 0:
			parameter.HasDefault = integer&2 != 0
		case number == 2 && wire == 0:
			parameter.Name = kotlinMetadataString(stringsTable, integer)
		case number == 3 && wire == 2:
			parameter.Type = decodeKotlinMetadataType(value)
		}
	})
	return parameter
}

func decodeKotlinMetadataType(message []byte) kotlinMetadataType {
	typ := kotlinMetadataType{Present: len(message) > 0}
	protobufFields(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 3 && wire == 0:
			typ.Nullable = integer != 0
		case number == 2 && wire == 2:
			argument := kotlinMetadataType{}
			protobufFields(value, func(argumentField int, argumentWire int, _ uint64, argumentValue []byte) {
				if argumentField == 2 && argumentWire == 2 {
					argument = decodeKotlinMetadataType(argumentValue)
				}
			})
			typ.Arguments = append(typ.Arguments, argument)
		}
	})
	return typ
}

func kotlinMetadataVisibility(flags uint64) string {
	switch (flags >> 1) & 7 {
	case 0:
		return "internal"
	case 1, 4:
		return "private"
	case 2:
		return "protected"
	case 3:
		return "public"
	default:
		return ""
	}
}

func kotlinMetadataString(table []string, index uint64) string {
	if index >= uint64(len(table)) {
		return ""
	}
	return table[index]
}

func protobufFields(message []byte, visit func(number int, wire int, integer uint64, value []byte)) {
	for offset := 0; offset < len(message); {
		tag, size := protobufVarint(message[offset:])
		if size == 0 {
			return
		}
		offset += size
		number, wire := int(tag>>3), int(tag&7)
		switch wire {
		case 0:
			integer, length := protobufVarint(message[offset:])
			if length == 0 {
				return
			}
			offset += length
			visit(number, wire, integer, nil)
		case 1:
			if offset+8 > len(message) {
				return
			}
			visit(number, wire, 0, message[offset:offset+8])
			offset += 8
		case 2:
			length, prefix := protobufVarint(message[offset:])
			if prefix == 0 || length > uint64(len(message)-offset-prefix) {
				return
			}
			offset += prefix
			value := message[offset : offset+int(length)]
			offset += int(length)
			visit(number, wire, 0, value)
		case 5:
			if offset+4 > len(message) {
				return
			}
			visit(number, wire, 0, message[offset:offset+4])
			offset += 4
		default:
			return
		}
	}
}

func protobufVarint(data []byte) (uint64, int) {
	var value uint64
	for index, current := range data {
		if index >= 10 {
			return 0, 0
		}
		value |= uint64(current&0x7f) << (7 * index)
		if current&0x80 == 0 {
			return value, index + 1
		}
	}
	return 0, 0
}

func applyKotlinBinaryMetadata(parsed *analysis.ParsedFile, class *classfile.Class) {
	metadata := class.KotlinMetadata
	if metadata == nil {
		return
	}
	decoded := decodeKotlinBinaryMetadata(metadata)
	ownerFQN := strings.ReplaceAll(strings.ReplaceAll(class.InternalName, "/", "."), "$", ".")
	ownerID := ""
	for index := range parsed.Symbols {
		if symbol := &parsed.Symbols[index]; analysis.IsTypeKind(symbol.Kind) && symbol.FQN == ownerFQN {
			ownerID = symbol.ID
			break
		}
	}
	if metadata.Kind == 1 {
		if decoded.Visibility != "" {
			for index := range parsed.Symbols {
				owner := &parsed.Symbols[index]
				if owner.ID != ownerID {
					continue
				}
				applyKotlinDeclarationVisibility(owner, decoded.Visibility)
				if decoded.Visibility == "internal" {
					owner.InteropLanguage = analysis.LanguageJava
				}
				break
			}
		}
		for _, constructor := range decoded.Constructors {
			applyKotlinCallableParameters(parsed.Symbols, ownerID, "", constructor, true)
		}
		for _, function := range decoded.Functions {
			applyKotlinCallableParameters(parsed.Symbols, ownerID, function.Name, function, false)
		}
	}
	if metadata.Kind != 2 && metadata.Kind != 5 {
		return
	}
	for index := range parsed.Symbols {
		if parsed.Symbols[index].ContainerID == ownerID || parsed.Symbols[index].ID == ownerID {
			parsed.Symbols[index].InteropLanguage = analysis.LanguageJava
		}
	}
	packageName := metadata.PackageName
	if packageName == "" {
		if slash := strings.LastIndexByte(class.InternalName, '/'); slash >= 0 {
			packageName = strings.ReplaceAll(class.InternalName[:slash], "/", ".")
		}
	}
	for _, function := range decoded.Functions {
		for _, original := range parsed.Symbols {
			if original.ContainerID != ownerID || original.Name != kotlinMetadataJVMName(function) || !analysis.IsCallableKind(original.Kind) {
				continue
			}
			receiverCount := 0
			if function.Receiver {
				receiverCount = 1
			}
			expected := len(function.Parameters) + receiverCount
			suspend := len(original.Parameters) == expected+1 && isContinuationType(original.Parameters[len(original.Parameters)-1].Type)
			if len(original.Parameters) != expected && !suspend {
				continue
			}
			copy := original
			copy.ID = original.ID + "#kotlin-top-level"
			copy.OriginID = original.ID
			copy.Language = analysis.LanguageKotlin
			copy.InteropLanguage = analysis.LanguageKotlin
			copy.Kind = analysis.KindFunction
			copy.ContainerID, copy.ContainerName = "", ""
			copy.Package = packageName
			copy.FQN = function.Name
			if packageName != "" {
				copy.FQN = packageName + "." + function.Name
			}
			if function.Receiver {
				copy.ReceiverType = kotlinizeBinaryType(original.Parameters[0].Type)
				copy.Parameters = append([]analysis.Parameter(nil), original.Parameters[1:]...)
			} else {
				copy.Parameters = append([]analysis.Parameter(nil), original.Parameters...)
			}
			if suspend && len(copy.Parameters) > 0 {
				continuation := copy.Parameters[len(copy.Parameters)-1].Type
				copy.Parameters = copy.Parameters[:len(copy.Parameters)-1]
				copy.Type = kotlinSuspendReturnType(continuation)
				copy.Modifiers = appendUniqueModifier(copy.Modifiers, "suspend")
			} else {
				copy.Type = kotlinizeBinaryType(copy.Type)
			}
			for parameter := range copy.Parameters {
				copy.Parameters[parameter].Type = kotlinizeBinaryType(copy.Parameters[parameter].Type)
			}
			applyKotlinParameterMetadata(copy.Parameters, function.Parameters)
			copy.Type = applyKotlinMetadataType(copy.Type, function.ReturnType)
			applyKotlinParameterTypes(copy.Parameters, function.Parameters)
			applyKotlinVisibility(&copy, function)
			if function.Visibility == "internal" || function.Visibility == "private" {
				break
			}
			copy.Signature = kotlinBinarySignature(copy)
			parsed.Symbols = append(parsed.Symbols, copy)
			break
		}
	}
	appendKotlinFileProperties(parsed, ownerID, packageName)
}

func applyKotlinCallableParameters(symbols []analysis.Symbol, ownerID, name string, callable kotlinMetadataCallable, constructor bool) {
	for index := range symbols {
		symbol := &symbols[index]
		jvmName := name
		if callable.JVMName != "" {
			jvmName = callable.JVMName
		}
		if symbol.ContainerID != ownerID || constructor != (symbol.Kind == analysis.KindConstructor) || !constructor && symbol.Name != jvmName {
			continue
		}
		receiverCount := 0
		if callable.Receiver {
			receiverCount = 1
		}
		expected := len(callable.Parameters) + receiverCount
		suspend := len(symbol.Parameters) == expected+1 && isContinuationType(symbol.Parameters[len(symbol.Parameters)-1].Type)
		if len(symbol.Parameters) != expected && !suspend {
			continue
		}
		if callable.Receiver && len(symbol.Parameters) > 0 {
			symbol.ReceiverType = kotlinizeBinaryType(symbol.Parameters[0].Type)
			symbol.Parameters = append([]analysis.Parameter(nil), symbol.Parameters[1:]...)
		}
		if suspend && len(symbol.Parameters) > 0 {
			continuation := symbol.Parameters[len(symbol.Parameters)-1].Type
			symbol.Parameters = symbol.Parameters[:len(symbol.Parameters)-1]
			symbol.Type = kotlinSuspendReturnType(continuation)
			symbol.Modifiers = appendUniqueModifier(symbol.Modifiers, "suspend")
		} else {
			symbol.Type = kotlinizeBinaryType(symbol.Type)
		}
		for parameter := range symbol.Parameters {
			symbol.Parameters[parameter].Type = kotlinizeBinaryType(symbol.Parameters[parameter].Type)
		}
		applyKotlinParameterMetadata(symbol.Parameters, callable.Parameters)
		symbol.Type = applyKotlinMetadataType(symbol.Type, callable.ReturnType)
		applyKotlinParameterTypes(symbol.Parameters, callable.Parameters)
		applyKotlinVisibility(symbol, callable)
		if callable.Visibility == "internal" {
			symbol.InteropLanguage = analysis.LanguageJava
		}
		symbol.Signature = kotlinBinarySignature(*symbol)
		return
	}
}

func kotlinMetadataJVMName(callable kotlinMetadataCallable) string {
	if callable.JVMName != "" {
		return callable.JVMName
	}
	return callable.Name
}

func applyKotlinParameterTypes(parameters []analysis.Parameter, metadata []kotlinMetadataParameter) {
	for index := range parameters {
		if index >= len(metadata) {
			break
		}
		parameters[index].Type = applyKotlinMetadataType(parameters[index].Type, metadata[index].Type)
	}
}

func applyKotlinMetadataType(value string, metadata kotlinMetadataType) string {
	if !metadata.Present || value == "" {
		return value
	}
	value = transformGenericTypeArguments(value, metadata.Arguments, applyKotlinMetadataType)
	if metadata.Nullable && !strings.HasSuffix(strings.TrimSpace(value), "?") {
		value += "?"
	}
	return value
}

func applyKotlinVisibility(symbol *analysis.Symbol, callable kotlinMetadataCallable) {
	if symbol == nil || callable.Visibility == "" {
		return
	}
	applyKotlinDeclarationVisibility(symbol, callable.Visibility)
}

func applyKotlinDeclarationVisibility(symbol *analysis.Symbol, visibility string) {
	if symbol == nil || visibility == "" {
		return
	}
	modifiers := symbol.Modifiers[:0]
	for _, modifier := range symbol.Modifiers {
		if modifier != "public" && modifier != "protected" && modifier != "private" && modifier != "internal" {
			modifiers = append(modifiers, modifier)
		}
	}
	symbol.Modifiers = append(modifiers, visibility)
}

func transformGenericTypeArguments[T any](value string, metadata []T, transform func(string, T) string) string {
	if len(metadata) == 0 {
		return value
	}
	open := topLevelGenericOpen(value)
	if open < 0 {
		return value
	}
	close := matchingGenericClose(value, open)
	if close < 0 {
		return value
	}
	ranges := topLevelGenericArgumentRanges(value, open+1, close)
	for index := len(ranges) - 1; index >= 0; index-- {
		if index >= len(metadata) {
			continue
		}
		start, end := ranges[index][0], ranges[index][1]
		leading := len(value[start:end]) - len(strings.TrimLeft(value[start:end], " \t\n\r"))
		trailing := len(value[start:end]) - len(strings.TrimRight(value[start:end], " \t\n\r"))
		innerStart, innerEnd := start+leading, end-trailing
		if innerEnd < innerStart {
			continue
		}
		updated := transform(value[innerStart:innerEnd], metadata[index])
		value = value[:innerStart] + updated + value[innerEnd:]
	}
	return value
}

func topLevelGenericOpen(value string) int {
	for index, char := range value {
		if char == '<' {
			return index
		}
	}
	return -1
}

func matchingGenericClose(value string, open int) int {
	depth := 0
	for index := open; index < len(value); index++ {
		switch value[index] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func topLevelGenericArgumentRanges(value string, start, end int) [][2]int {
	ranges := make([][2]int, 0)
	argumentStart, depth := start, 0
	for index := start; index <= end; index++ {
		if index == end || value[index] == ',' && depth == 0 {
			ranges = append(ranges, [2]int{argumentStart, index})
			argumentStart = index + 1
			continue
		}
		switch value[index] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		}
	}
	return ranges
}

func appendKotlinFileProperties(parsed *analysis.ParsedFile, ownerID, packageName string) {
	existing := make(map[string]bool)
	setters := make(map[string]bool)
	for _, symbol := range parsed.Symbols {
		if symbol.ContainerID == "" && symbol.Kind == analysis.KindProperty {
			existing[symbol.Name] = true
		}
		if symbol.ContainerID == ownerID && symbol.Kind == analysis.KindMethod && strings.HasPrefix(symbol.Name, "set") && len(symbol.Parameters) == 1 {
			if name, ok := decapitalizeBean(strings.TrimPrefix(symbol.Name, "set")); ok {
				setters[name] = true
			}
		}
	}
	initial := len(parsed.Symbols)
	for index := 0; index < initial; index++ {
		getter := parsed.Symbols[index]
		if getter.ContainerID != ownerID || getter.Kind != analysis.KindMethod || len(getter.Parameters) != 0 {
			continue
		}
		name, ok := javaBeanGetterName(getter)
		if !ok || existing[name] {
			continue
		}
		existing[name] = true
		property := getter
		property.ID = getter.ID + "#kotlin-top-level-property"
		property.OriginID = getter.ID
		property.Name, property.Kind = name, analysis.KindProperty
		property.Language, property.InteropLanguage = analysis.LanguageKotlin, analysis.LanguageKotlin
		property.ContainerID, property.ContainerName = "", ""
		property.Package = packageName
		property.FQN = name
		if packageName != "" {
			property.FQN = packageName + "." + name
		}
		property.Type = kotlinizeBinaryType(property.Type)
		property.Parameters = nil
		property.Modifiers = []string{"val"}
		if setters[name] {
			property.Modifiers = []string{"var"}
		}
		property.Signature = property.Modifiers[0] + " " + name + ": " + property.Type
		parsed.Symbols = append(parsed.Symbols, property)
	}
}

func isContinuationType(value string) bool {
	base, _ := splitInstantiatedType(value)
	return simpleType(base) == "Continuation"
}

func kotlinSuspendReturnType(continuation string) string {
	_, arguments := splitInstantiatedType(continuation)
	if len(arguments) != 1 {
		return "Any?"
	}
	result := strings.TrimSpace(arguments[0])
	result = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(result, "? super "), "in "))
	if result == "" || result == "?" {
		return "Any?"
	}
	return kotlinizeBinaryType(result)
}

func kotlinizeBinaryType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	value = kotlinBinaryTypeReplacer.Replace(value)
	words := map[string]string{"byte": "Byte", "short": "Short", "int": "Int", "long": "Long", "float": "Float", "double": "Double", "boolean": "Boolean", "char": "Char", "void": "Unit"}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		word := value[index:end]
		if replacement := words[word]; replacement != "" {
			word = replacement
		}
		result.WriteString(word)
		index = end
	}
	return result.String()
}

var kotlinBinaryTypeReplacer = strings.NewReplacer(
	"java.lang.String", "String", "java.lang.Object", "Any", "java.lang.Boolean", "Boolean",
	"java.lang.Byte", "Byte", "java.lang.Short", "Short", "java.lang.Integer", "Int",
	"java.lang.Long", "Long", "java.lang.Float", "Float", "java.lang.Double", "Double",
	"java.lang.Character", "Char", "java.lang.Void", "Unit", "java.util.List", "List",
	"java.util.Set", "Set", "java.util.Map", "Map", "? extends ", "out ", "? super ", "in ",
)

// KotlinDisplayType renders a JVM/Java type using the concise Kotlin spelling
// used by cross-language signature help while preserving nested nullability.
func KotlinDisplayType(value string) string {
	return kotlinizeBinaryType(value)
}

func appendUniqueModifier(modifiers []string, modifier string) []string {
	for _, existing := range modifiers {
		if existing == modifier {
			return modifiers
		}
	}
	return append(modifiers, modifier)
}

func applyKotlinParameterMetadata(parameters []analysis.Parameter, metadata []kotlinMetadataParameter) {
	for index := range parameters {
		if index >= len(metadata) {
			break
		}
		if metadata[index].Name != "" {
			parameters[index].Name = metadata[index].Name
		}
		if metadata[index].HasDefault {
			parameters[index].Default = "<default>"
		}
	}
}

func kotlinBinarySignature(symbol analysis.Symbol) string {
	var signature strings.Builder
	for _, modifier := range symbol.Modifiers {
		if modifier == "suspend" {
			signature.WriteString("suspend ")
			break
		}
	}
	signature.WriteString("fun ")
	if symbol.ReceiverType != "" {
		signature.WriteString(symbol.ReceiverType)
		signature.WriteByte('.')
	}
	signature.WriteString(symbol.Name)
	signature.WriteByte('(')
	for index, parameter := range symbol.Parameters {
		if index > 0 {
			signature.WriteString(", ")
		}
		signature.WriteString(parameter.Name)
		if parameter.Type != "" {
			signature.WriteString(": ")
			signature.WriteString(parameter.Type)
		}
		if parameter.Default != "" {
			signature.WriteString(" = …")
		}
	}
	signature.WriteByte(')')
	if symbol.Type != "" && symbol.Type != "void" {
		signature.WriteString(": ")
		signature.WriteString(symbol.Type)
	}
	return signature.String()
}
