package index

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
)

type kotlinMetadataParameter struct {
	Name       string
	HasDefault bool
	Type       kotlinMetadataType
	// Vararg is set when the parameter carries a vararg element type.
	Vararg bool
	// VarargElement is that element type.
	VarargElement kotlinMetadataType
}

type kotlinMetadataType struct {
	Present   bool
	Nullable  bool
	Arguments []kotlinMetadataType
	// Suspend marks a suspend function type, whose JVM spelling ends in a
	// Continuation parameter.
	Suspend bool
	// Extension marks a function type with a receiver, `T.() -> Unit`: the
	// type carries @ExtensionFunctionType, which the JVM spelling drops.
	Extension bool
	// TypeParameter is the id of the type parameter this type is, plus one
	// (0: not a type parameter). The JVM spelling erases it to its bound.
	TypeParameter int
	// TypeParameterName is the type parameter's name when the metadata spells
	// it by name (type_parameter_name) instead of by id.
	TypeParameterName string
	// ClassName is the classifier's class id, `kotlin/collections/MutableList`.
	ClassName string
	// Projection is this type's variance as a type argument: 0 in, 1 out,
	// 2 invariant. Star marks a star projection, which has no type.
	Projection int
	Star       bool
}

type kotlinMetadataCallable struct {
	Name       string
	JVMName    string
	Parameters []kotlinMetadataParameter
	ReturnType kotlinMetadataType
	Receiver   bool
	// ReceiverType is the extension receiver's type.
	ReceiverType kotlinMetadataType
	// JVMDescriptor is the method descriptor the metadata records when it
	// differs from the one the Kotlin signature implies.
	JVMDescriptor string
	Visibility    string
	// TypeParameters maps a type parameter id to its name.
	TypeParameters map[int]string
}

type kotlinBinaryMetadata struct {
	Constructors []kotlinMetadataCallable
	Functions    []kotlinMetadataCallable
	Properties   []kotlinMetadataProperty
	// ClassTypeParameters names the class's own type parameters by id; its
	// members' types refer to them.
	ClassTypeParameters map[int]string
	Visibility          string
	Schema              kotlinMetadataSchema
	Valid               bool
}

type kotlinMetadataSchema struct {
	Major int
	Minor int
}

func decodeKotlinBinaryMetadata(metadata *classfile.KotlinMetadata) kotlinBinaryMetadata {
	schema, supported := kotlinMetadataSchemaFor(metadata)
	if metadata == nil || len(metadata.Data1) == 0 || !supported {
		return kotlinBinaryMetadata{}
	}
	data := decodeKotlinMetadataBytes(metadata.Data1)
	nameTableSize, prefix := protobufVarint(data)
	if prefix == 0 || nameTableSize > uint64(len(data)-prefix) {
		return kotlinBinaryMetadata{}
	}
	message := data[prefix+int(nameTableSize):]
	stringTable := resolveKotlinStringTable(data[prefix:prefix+int(nameTableSize)], metadata.Data2)
	decoded := kotlinBinaryMetadata{Schema: schema, Valid: true}
	valid := protobufFieldsStrict(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case metadata.Kind == 1 && number == 1 && wire == 0:
			decoded.Visibility = kotlinMetadataVisibility(integer)
		case metadata.Kind == 1 && number == 5 && wire == 2:
			if id, name, ok := decodeKotlinTypeParameter(value, stringTable); ok {
				if decoded.ClassTypeParameters == nil {
					decoded.ClassTypeParameters = make(map[int]string)
				}
				decoded.ClassTypeParameters[id] = name
			}
		case metadata.Kind == 1 && number == 8 && wire == 2:
			callable, ok := decodeKotlinCallable(value, stringTable, true)
			if !ok {
				decoded.Valid = false
			} else {
				decoded.Constructors = append(decoded.Constructors, callable)
			}
		case metadata.Kind == 1 && number == 10 && wire == 2, (metadata.Kind == 2 || metadata.Kind == 5) && number == 4 && wire == 2:
			if property, ok := decodeKotlinProperty(value, stringTable); ok {
				decoded.Properties = append(decoded.Properties, property)
			}
		case metadata.Kind == 1 && number == 9 && wire == 2, (metadata.Kind == 2 || metadata.Kind == 5) && number == 3 && wire == 2:
			callable, ok := decodeKotlinCallable(value, stringTable, false)
			if !ok {
				decoded.Valid = false
			} else {
				decoded.Functions = append(decoded.Functions, callable)
			}
		}
	})
	decoded.Valid = decoded.Valid && valid
	if !decoded.Valid {
		return kotlinBinaryMetadata{Schema: schema}
	}
	return decoded
}

func supportedKotlinMetadataVersion(version []int) bool {
	_, ok := kotlinMetadataSchemaFor(&classfile.KotlinMetadata{MetadataVersion: version})
	return ok
}

func kotlinMetadataSchemaFor(metadata *classfile.KotlinMetadata) (kotlinMetadataSchema, bool) {
	if metadata == nil || len(metadata.MetadataVersion) < 2 {
		return kotlinMetadataSchema{}, false
	}
	major, minor := metadata.MetadataVersion[0], metadata.MetadataVersion[1]
	// These are the schema families whose field layout this decoder knows.
	// A newer minor can add/reinterpret fields just as a new major can; reject
	// both until a fixture for that schema is added. Patch releases do not alter
	// protobuf layout.
	switch major {
	case 1:
		if minor >= 0 && minor <= 9 {
			return kotlinMetadataSchema{Major: major, Minor: minor}, true
		}
	case 2:
		if minor >= 0 && minor <= 4 {
			return kotlinMetadataSchema{Major: major, Minor: minor}, true
		}
	}
	return kotlinMetadataSchema{Major: major, Minor: minor}, false
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

func decodeKotlinCallable(message []byte, stringsTable []string, constructor bool) (kotlinMetadataCallable, bool) {
	callable := kotlinMetadataCallable{}
	semanticValid := true
	flags, hasCurrentFlags := uint64(6), false
	if constructor {
		callable.Name = "<init>"
	}
	structuralValid := protobufFieldsStrict(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 9 && wire == 0:
			flags, hasCurrentFlags = integer, true
		case number == 1 && wire == 0 && !hasCurrentFlags:
			flags = integer
		case !constructor && number == 2 && wire == 0:
			callable.Name = kotlinMetadataString(stringsTable, integer)
		case !constructor && number == 3 && wire == 2:
			var valid bool
			callable.ReturnType, valid = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
			semanticValid = semanticValid && valid
		case constructor && number == 2 && wire == 2, !constructor && number == 6 && wire == 2:
			parameter, ok := decodeKotlinMetadataParameter(value, stringsTable)
			semanticValid = semanticValid && ok
			callable.Parameters = append(callable.Parameters, parameter)
		case !constructor && number == 5 && wire == 2:
			callable.Receiver = true
			var valid bool
			callable.ReceiverType, valid = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
			semanticValid = semanticValid && valid
		case !constructor && number == 8 && wire == 0:
			callable.Receiver = true
		case !constructor && number == 4 && wire == 2:
			if id, name, ok := decodeKotlinTypeParameter(value, stringsTable); ok {
				if callable.TypeParameters == nil {
					callable.TypeParameters = make(map[int]string)
				}
				callable.TypeParameters[id] = name
			}
		case !constructor && number == 100 && wire == 2:
			if !protobufFieldsStrict(value, func(field int, fieldWire int, fieldInteger uint64, _ []byte) {
				if field == 1 && fieldWire == 0 {
					callable.JVMName = kotlinMetadataString(stringsTable, fieldInteger)
				}
				if field == 2 && fieldWire == 0 {
					callable.JVMDescriptor = kotlinMetadataString(stringsTable, fieldInteger)
				}
			}) {
				semanticValid = false
			}
		}
	})
	callable.Visibility = kotlinMetadataVisibility(flags)
	if !constructor && callable.Name == "" {
		semanticValid = false
	}
	return callable, structuralValid && semanticValid
}

// decodeKotlinTypeParameter reads a TypeParameter message: id (1), name (2).
func decodeKotlinTypeParameter(message []byte, stringsTable []string) (int, string, bool) {
	id, name, hasID := 0, "", false
	protobufFields(message, func(number int, wire int, integer uint64, _ []byte) {
		switch {
		case number == 1 && wire == 0:
			id, hasID = int(integer), true
		case number == 2 && wire == 0:
			name = kotlinMetadataString(stringsTable, integer)
		}
	})
	return id, name, hasID && name != ""
}

func decodeKotlinMetadataParameter(message []byte, stringsTable []string) (kotlinMetadataParameter, bool) {
	parameter := kotlinMetadataParameter{}
	semanticValid := true
	valid := protobufFieldsStrict(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 1 && wire == 0:
			parameter.HasDefault = integer&2 != 0
		case number == 2 && wire == 0:
			parameter.Name = kotlinMetadataString(stringsTable, integer)
		case number == 3 && wire == 2:
			var typeValid bool
			parameter.Type, typeValid = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
			semanticValid = semanticValid && typeValid
		case number == 4 && wire == 2:
			// vararg_element_type: `vararg moreInterfaces: KClass<*>`, an
			// optional argument list rather than a required array.
			parameter.Vararg = true
			parameter.VarargElement, _ = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
		}
	})
	return parameter, valid && semanticValid && parameter.Name != ""
}

func decodeKotlinMetadataType(message []byte) (kotlinMetadataType, bool) {
	return decodeKotlinMetadataTypeWithStrings(message, nil)
}

func decodeKotlinMetadataTypeWithStrings(message []byte, stringsTable []string) (kotlinMetadataType, bool) {
	work := 0
	return decodeKotlinMetadataTypeAt(message, 0, &work, stringsTable)
}

func decodeKotlinMetadataTypeAt(message []byte, depth int, work *int, stringsTable []string) (kotlinMetadataType, bool) {
	if depth > 64 || *work >= 4096 {
		return kotlinMetadataType{}, false
	}
	*work++
	typ := kotlinMetadataType{Present: len(message) > 0}
	semanticValid := true
	structuralValid := protobufFieldsStrict(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 3 && wire == 0:
			typ.Nullable = integer != 0
		case number == 1 && wire == 0:
			// Type flags: bit 0 is SUSPEND.
			typ.Suspend = integer&1 != 0
		case number == 7 && wire == 0:
			typ.TypeParameter = int(integer) + 1
		case number == 9 && wire == 0:
			typ.TypeParameterName = kotlinMetadataString(stringsTable, integer)
		case number == 6 && wire == 0:
			typ.ClassName = kotlinMetadataString(stringsTable, integer)
		case number == 100 && wire == 2:
			// JvmProtoBuf.typeAnnotation: an Annotation whose field 1 names
			// the annotation class in the string table.
			protobufFields(value, func(annotationField int, annotationWire int, annotationInteger uint64, _ []byte) {
				if annotationField == 1 && annotationWire == 0 && strings.Contains(kotlinMetadataString(stringsTable, annotationInteger), "ExtensionFunctionType") {
					typ.Extension = true
				}
			})
		case number == 2 && wire == 2:
			argument, projection := kotlinMetadataType{}, 2
			argumentValid := protobufFieldsStrict(value, func(argumentField int, argumentWire int, argumentInteger uint64, argumentValue []byte) {
				if argumentField == 1 && argumentWire == 0 {
					projection = int(argumentInteger)
				}
				if argumentField == 2 && argumentWire == 2 {
					var valid bool
					argument, valid = decodeKotlinMetadataTypeAt(argumentValue, depth+1, work, stringsTable)
					semanticValid = semanticValid && valid
				}
			})
			argument.Projection, argument.Star = projection, projection == 3
			semanticValid = semanticValid && argumentValid
			typ.Arguments = append(typ.Arguments, argument)
		}
	})
	return typ, structuralValid && semanticValid
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
	_ = protobufFieldsStrict(message, visit)
}

func protobufFieldsStrict(message []byte, visit func(number int, wire int, integer uint64, value []byte)) bool {
	for offset := 0; offset < len(message); {
		tag, size := protobufVarint(message[offset:])
		if size == 0 || tag>>3 == 0 {
			return false
		}
		offset += size
		number, wire := int(tag>>3), int(tag&7)
		switch wire {
		case 0:
			integer, length := protobufVarint(message[offset:])
			if length == 0 {
				return false
			}
			offset += length
			visit(number, wire, integer, nil)
		case 1:
			if offset+8 > len(message) {
				return false
			}
			visit(number, wire, 0, message[offset:offset+8])
			offset += 8
		case 2:
			length, prefix := protobufVarint(message[offset:])
			if prefix == 0 || length > uint64(len(message)-offset-prefix) {
				return false
			}
			offset += prefix
			value := message[offset : offset+int(length)]
			offset += int(length)
			visit(number, wire, 0, value)
		case 5:
			if offset+4 > len(message) {
				return false
			}
			visit(number, wire, 0, message[offset:offset+4])
			offset += 4
		default:
			return false
		}
	}
	return true
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

func applyKotlinBinaryMetadata(parsed *analysis.ParsedFile, class *classfile.Class) error {
	metadata := class.KotlinMetadata
	if metadata == nil {
		return nil
	}
	schema, supported := kotlinMetadataSchemaFor(metadata)
	if !supported {
		return fmt.Errorf("unsupported Kotlin metadata schema %v", metadata.MetadataVersion)
	}
	// A synthetic class (a lambda, `$WhenMappings`, `$DefaultImpls`) and a
	// multi-file facade carry no declarations: the first has no metadata
	// message, the second only names its parts in d1. Neither is malformed.
	if metadata.Kind == 3 || metadata.Kind == 4 {
		return nil
	}
	decoded := decodeKotlinBinaryMetadata(metadata)
	if !decoded.Valid {
		// The bytecode declarations remain authoritative Java-visible symbols.
		// Do not manufacture Kotlin properties/defaults/nullability from an
		// unknown or malformed metadata schema.
		return fmt.Errorf("malformed Kotlin metadata schema %d.%d", schema.Major, schema.Minor)
	}
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
			applyKotlinCallableParameters(parsed.Symbols, ownerID, "", constructor, true, decoded.ClassTypeParameters)
		}
		for _, function := range decoded.Functions {
			applyKotlinCallableParameters(parsed.Symbols, ownerID, function.Name, function, false, decoded.ClassTypeParameters)
		}
		if ownerID != "" {
			applyKotlinProperties(parsed, ownerID, ownerFQN, "", decoded.Properties, decoded.ClassTypeParameters)
		}
	}
	if metadata.Kind != 2 && metadata.Kind != 5 {
		return nil
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
	claimed := make(map[string]bool)
	for _, function := range decoded.Functions {
		for _, original := range kotlinMetadataJVMCandidates(parsed.Symbols, ownerID, function, claimed) {
			receiverCount := 0
			if function.Receiver {
				receiverCount = 1
			}
			expected := len(function.Parameters) + receiverCount
			suspend := len(original.Parameters) == expected+1 && isContinuationType(original.Parameters[len(original.Parameters)-1].Type)
			if len(original.Parameters) != expected && !suspend {
				continue
			}
			claimed[original.ID] = true
			copy := original
			copy.ID = original.ID + "#kotlin-top-level"
			// The Kotlin name, not the @JvmName one: `maxBy` is compiled as
			// maxByOrThrow, and completion offered the latter.
			copy.Name = function.Name
			copy.JVMName = original.Name
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
				copy.ReceiverType = kotlinMetadataReceiverType(original.Parameters[0].Type, function, nil)
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
			copy.Type = applyKotlinMetadataType(copy.Type, function.ReturnType, function.TypeParameters)
			applyKotlinParameterTypes(copy.Parameters, function.Parameters, function.TypeParameters)
			applyKotlinVisibility(&copy, function)
			if function.Visibility == "internal" || function.Visibility == "private" {
				break
			}
			copy.Signature = kotlinBinarySignature(copy)
			parsed.Symbols = append(parsed.Symbols, copy)
			break
		}
	}
	applyKotlinProperties(parsed, ownerID, "", packageName, decoded.Properties, nil)
	return nil
}

func applyKotlinCallableParameters(symbols []analysis.Symbol, ownerID, name string, callable kotlinMetadataCallable, constructor bool, classTypeParameters map[int]string) {
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
			symbol.ReceiverType = kotlinMetadataReceiverType(symbol.Parameters[0].Type, callable, classTypeParameters)
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
		symbol.Type = applyKotlinMetadataType(symbol.Type, callable.ReturnType, callable.TypeParameters, classTypeParameters)
		applyKotlinParameterTypes(symbol.Parameters, callable.Parameters, callable.TypeParameters, classTypeParameters)
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

func applyKotlinParameterTypes(parameters []analysis.Parameter, metadata []kotlinMetadataParameter, names ...map[int]string) {
	for index := range parameters {
		if index >= len(metadata) {
			break
		}
		if metadata[index].Vararg {
			if element, ok := renderKotlinMetadataType(metadata[index].VarargElement, names...); ok {
				parameters[index].Type = "vararg " + element
			}
			continue
		}
		parameters[index].Type = applyKotlinMetadataType(parameters[index].Type, metadata[index].Type, names...)
	}
}

func applyKotlinMetadataType(value string, metadata kotlinMetadataType, names ...map[int]string) string {
	if !metadata.Present || value == "" {
		return value
	}
	if rendered, ok := renderKotlinMetadataType(metadata, names...); ok {
		return rendered
	}
	// The JVM erases a type parameter to its bound: `T?` reads as `Any?`.
	if metadata.TypeParameterName != "" {
		if metadata.Nullable {
			return metadata.TypeParameterName + "?"
		}
		return metadata.TypeParameterName
	}
	if metadata.TypeParameter > 0 {
		for _, table := range names {
			if name := table[metadata.TypeParameter-1]; name != "" {
				if metadata.Nullable {
					return name + "?"
				}
				return name
			}
		}
	}
	value = transformGenericTypeArguments(value, metadata.Arguments, func(argument string, argumentMetadata kotlinMetadataType) string {
		return applyKotlinMetadataType(argument, argumentMetadata, names...)
	})
	if function, ok := kotlinFunctionTypeFromBinary(value, metadata); ok {
		if metadata.Nullable {
			return "(" + function + ")?"
		}
		return function
	}
	if metadata.Nullable && !strings.HasSuffix(strings.TrimSpace(value), "?") {
		value += "?"
	}
	return value
}

// kotlinFunctionTypeFromBinary spells a JVM function interface the way
// Kotlin source does. `Function1<in T, Unit>` with @ExtensionFunctionType is
// `T.() -> Unit` -- the receiver of `apply`'s block, without which nothing
// inside `x.apply { }` resolved -- and a suspend function type drops its
// trailing Continuation parameter for the result it carries.
func kotlinFunctionTypeFromBinary(value string, metadata kotlinMetadataType) (string, bool) {
	base, arguments := splitInstantiatedType(value)
	simple := base[strings.LastIndexByte(base, '.')+1:]
	if !strings.HasPrefix(simple, "Function") || len(arguments) == 0 || base != "kotlin.jvm.functions."+simple && base != "kotlin."+simple && base != simple {
		return "", false
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(simple, "Function")); err != nil {
		return "", false
	}
	for index := range arguments {
		arguments[index] = withoutVariance(arguments[index])
	}
	parameters, result := arguments[:len(arguments)-1], arguments[len(arguments)-1]
	prefix := ""
	if metadata.Suspend && len(parameters) > 0 {
		if continuation, continuationArguments := splitInstantiatedType(parameters[len(parameters)-1]); strings.HasSuffix(continuation, "Continuation") && len(continuationArguments) == 1 {
			result = withoutVariance(continuationArguments[0])
			parameters = parameters[:len(parameters)-1]
		}
		prefix = "suspend "
	}
	receiver := ""
	if metadata.Extension && len(parameters) > 0 {
		receiver, parameters = parameters[0]+".", parameters[1:]
	}
	return prefix + receiver + "(" + strings.Join(parameters, ", ") + ") -> " + result, true
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
	value = strings.ReplaceAll(strings.ReplaceAll(value, "? extends ", "out "), "? super ", "in ")
	// A bare JVM wildcard is Kotlin's star projection: `KClass<?>` is KClass<*>.
	for replaced := bareWildcard.ReplaceAllString(value, "${1}*${2}"); replaced != value; replaced = bareWildcard.ReplaceAllString(value, "${1}*${2}") {
		value = replaced
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isBinaryTypeTokenByte(value[index]) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isBinaryTypeTokenByte(value[end]) {
			end++
		}
		token := value[index:end]
		if replacement := kotlinBinaryTypeAliases[token]; replacement != "" {
			token = replacement
		}
		result.WriteString(token)
		index = end
	}
	return kotlinizeArrayTypes(result.String())
}

var bareWildcard = regexp.MustCompile(`([<,]\s*)\?(\s*[>,])`)

var binaryArraySuffix = regexp.MustCompile(`([A-Za-z_$][\w.$]*(?:<[^<>\[\]]*>)?)\[\]`)

var kotlinPrimitiveArrays = map[string]string{
	"Int": "IntArray", "Long": "LongArray", "Short": "ShortArray", "Byte": "ByteArray",
	"Char": "CharArray", "Boolean": "BooleanArray", "Float": "FloatArray", "Double": "DoubleArray",
}

// kotlinizeArrayTypes spells JVM array types the way Kotlin does: `T[]` is
// Array<T>, `int[]` is IntArray. Without it an extension on `Array<out T>`
// decoded from a class file has the receiver `T[]`, which no Kotlin type ever
// matches, so none of the standard library's array extensions applied.
func kotlinizeArrayTypes(value string) string {
	for pass := 0; pass < 4 && strings.Contains(value, "[]"); pass++ {
		value = binaryArraySuffix.ReplaceAllStringFunc(value, func(match string) string {
			element := strings.TrimSuffix(match, "[]")
			if primitive, ok := kotlinPrimitiveArrays[element]; ok {
				return primitive
			}
			return "Array<" + element + ">"
		})
	}
	return value
}

func isBinaryTypeTokenByte(value byte) bool {
	return value == '_' || value == '$' || value == '.' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

var kotlinBinaryTypeAliases = map[string]string{
	"byte": "Byte", "short": "Short", "int": "Int", "long": "Long",
	"float": "Float", "double": "Double", "boolean": "Boolean", "char": "Char", "void": "Unit",
	"java.lang.String": "String", "java.lang.Object": "Any", "java.lang.Boolean": "Boolean",
	"java.lang.Byte": "Byte", "java.lang.Short": "Short", "java.lang.Integer": "Int",
	"java.lang.Long": "Long", "java.lang.Float": "Float", "java.lang.Double": "Double",
	"java.lang.Character": "Char", "java.lang.Void": "Unit", "java.lang.CharSequence": "CharSequence",
	"java.lang.Number": "Number", "java.lang.Throwable": "Throwable",
	"java.util.Collection": "Collection", "java.util.List": "List", "java.util.Set": "Set", "java.util.Map": "Map",
	"java.lang.Iterable": "Iterable",
}

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
		if metadata[index].Vararg {
			parameters[index].Variadic = true
			parameters[index].Type = "vararg " + kotlinArrayElementType(parameters[index].Type)
		}
	}
}

// kotlinArrayElementType is the element type of an array spelling: `Array<out
// KClass<*>>` holds KClass<*>, `IntArray` holds Int.
func kotlinArrayElementType(value string) string {
	value = strings.TrimSpace(value)
	if base, arguments := splitInstantiatedType(value); (base == "Array" || base == "kotlin.Array") && len(arguments) == 1 {
		return withoutVariance(arguments[0])
	}
	for element, array := range kotlinPrimitiveArrays {
		if value == array || value == "kotlin."+array {
			return element
		}
	}
	return value
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

// kotlinMetadataReceiverType is an extension's receiver as Kotlin declares it.
// The JVM's first parameter erases it: `Result<T>.getOrThrow` took `Object`,
// so it was offered on every value, and `MutableList<T>.sort` took
// `java.util.List`, so it was offered on read-only lists.
func kotlinMetadataReceiverType(jvmType string, callable kotlinMetadataCallable, classTypeParameters map[int]string) string {
	if rendered, ok := renderKotlinMetadataType(callable.ReceiverType, callable.TypeParameters, classTypeParameters); ok {
		return rendered
	}
	return kotlinizeBinaryType(jvmType)
}

// kotlinMetadataJVMCandidates lists the bytecode methods a metadata function
// may describe, best first. Overloads share a JVM name and often an arity
// (`sort` on IntArray and on MutableList), so the descriptor decides when the
// metadata records one, and a method another function already claimed is
// never reused.
func kotlinMetadataJVMCandidates(symbols []analysis.Symbol, ownerID string, function kotlinMetadataCallable, claimed map[string]bool) []analysis.Symbol {
	jvmName := kotlinMetadataJVMName(function)
	var exact, rest []analysis.Symbol
	for _, symbol := range symbols {
		if symbol.ContainerID != ownerID || symbol.Name != jvmName || !analysis.IsCallableKind(symbol.Kind) || claimed[symbol.ID] {
			continue
		}
		if function.JVMDescriptor != "" && symbol.JVMDescriptor != "" {
			if symbol.JVMDescriptor == function.JVMDescriptor {
				exact = append(exact, symbol)
			}
			continue
		}
		rest = append(rest, symbol)
	}
	if function.JVMDescriptor != "" && len(exact) > 0 {
		return exact
	}
	return rest
}

// kotlinJavaCollectionViews are the Kotlin types a Java collection is seen as.
// A Java `List` is the platform type `(Mutable)List`: Kotlin lets you call
// both `add` and every `List` extension on it, which MutableList covers.
var kotlinJavaCollectionViews = map[string]string{
	"java.util.List": "MutableList", "java.util.Collection": "MutableCollection", "java.util.Set": "MutableSet",
	"java.util.Map": "MutableMap", "java.lang.Iterable": "MutableIterable", "java.util.Iterator": "MutableIterator",
	"java.util.ListIterator": "MutableListIterator", "java.util.Map.Entry": "MutableMap.MutableEntry",
}

// kotlinViewOfJavaType spells a type declared in Java the way Kotlin code
// sees it: `java.lang.String` is kotlin.String, whose members and extensions
// apply, rather than the Java class, whose `split(String)` returned an array
// where Kotlin's returns a List.
func kotlinViewOfJavaType(value string) string {
	if !strings.Contains(value, "java.") && !strings.ContainsAny(value, "[") && !strings.Contains(value, "? ") && !kotlinHasJavaPrimitive(value) {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isBinaryTypeTokenByte(value[index]) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isBinaryTypeTokenByte(value[end]) {
			end++
		}
		token := value[index:end]
		if view := kotlinJavaCollectionViews[token]; view != "" {
			token = view
		}
		result.WriteString(token)
		index = end
	}
	return kotlinizeBinaryType(result.String())
}

func kotlinHasJavaPrimitive(value string) bool {
	switch value {
	case "int", "long", "short", "byte", "char", "boolean", "float", "double", "void":
		return true
	}
	return false
}
