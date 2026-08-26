package classfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

const (
	accPublic       = 0x0001
	accPrivate      = 0x0002
	accProtected    = 0x0004
	accStatic       = 0x0008
	accFinal        = 0x0010
	accSynchronized = 0x0020
	accVolatile     = 0x0040
	accTransient    = 0x0080
	accNative       = 0x0100
	accInterface    = 0x0200
	accAbstract     = 0x0400
	accStrict       = 0x0800
	accSynthetic    = 0x1000
	accAnnotation   = 0x2000
	accEnum         = 0x4000
	accBridge       = 0x0040
)

type Class struct {
	InternalName    string
	SourceFile      string
	SuperName       string
	Interfaces      []string
	Signature       string
	Access          uint16
	Deprecated      bool
	Record          bool
	Annotations     []string
	TypeAnnotations []TypeAnnotation
	EnclosingClass  string
	NestHost        string
	NestMembers     []string
	KotlinMetadata  *KotlinMetadata
	Components      []RecordComponent
	InnerClasses    []InnerClass
	Fields          []Field
	Methods         []Method
}

type KotlinMetadata struct {
	Kind            int
	MetadataVersion []int
	Data1           []string
	Data2           []string
	ExtraString     string
	PackageName     string
	ExtraInt        int
}

type RecordComponent struct {
	Name            string
	Descriptor      string
	Signature       string
	Annotations     []string
	TypeAnnotations []TypeAnnotation
}

type TypePathEntry struct {
	Kind  byte
	Index byte
}

// TypeAnnotation preserves the target_info and type_path needed to attach a
// JVM TYPE_USE annotation to a return, formal parameter, field, bound, or
// nested generic component without conflating it with declaration annotations.
type TypeAnnotation struct {
	Annotation     string
	TargetType     byte
	ParameterIndex int
	TypePath       []TypePathEntry
}

type InnerClass struct {
	InternalName string
	OuterName    string
	SimpleName   string
	Access       uint16
}

type Field struct {
	Name            string
	Descriptor      string
	Signature       string
	Type            string
	Access          uint16
	Deprecated      bool
	Constant        string
	Annotations     []string
	TypeAnnotations []TypeAnnotation
}

type Method struct {
	Name           string
	Descriptor     string
	Signature      string
	ParameterTypes []string
	ResultType     string
	Access         uint16
	Deprecated     bool
	ParameterNames []string
	Exceptions     []string
	DefaultValue   string
	Annotations    []string
	// ParameterAnnotations preserves the JVM parameter-table ordinal. Each
	// entry contains declaration annotations from both visible and invisible
	// attributes; an entry may be empty.
	ParameterAnnotations [][]string
	TypeAnnotations      []TypeAnnotation
	LineNumbers          []int
}

type constant struct {
	tag       byte
	text      string
	nameIndex uint16
	integer   int64
	floating  float64
}

type reader struct {
	data []byte
	off  int
	err  error
}

func Parse(data []byte) (*Class, error) {
	r := &reader{data: data}
	if r.u4() != 0xcafebabe {
		return nil, errors.New("invalid class-file magic")
	}
	_ = r.u2()
	_ = r.u2()
	count := int(r.u2())
	pool := make([]constant, count)
	for index := 1; index < count && r.err == nil; index++ {
		tag := r.u1()
		pool[index].tag = tag
		switch tag {
		case 1:
			length := int(r.u2())
			pool[index].text = decodeModifiedUTF8(r.bytes(length))
		case 3:
			pool[index].integer = int64(int32(r.u4()))
		case 4:
			pool[index].floating = float64(math.Float32frombits(r.u4()))
		case 5:
			bits := r.bytes(8)
			if bits != nil {
				pool[index].integer = int64(binary.BigEndian.Uint64(bits))
			}
			index++
		case 6:
			bits := r.bytes(8)
			if bits != nil {
				pool[index].floating = math.Float64frombits(binary.BigEndian.Uint64(bits))
			}
			index++
		case 7, 8, 16, 19, 20:
			pool[index].nameIndex = r.u2()
		case 9, 10, 11, 12, 17, 18:
			r.skip(4)
		case 15:
			r.skip(3)
		default:
			return nil, fmt.Errorf("unsupported constant-pool tag %d", tag)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	utf8 := func(index uint16) string {
		if int(index) >= len(pool) || index == 0 {
			return ""
		}
		return pool[index].text
	}
	className := func(index uint16) string {
		if int(index) >= len(pool) || index == 0 || pool[index].tag != 7 {
			return ""
		}
		return utf8(pool[index].nameIndex)
	}
	annotations := func(payload []byte) []string { return parseAnnotations(payload, pool, utf8) }
	parameterAnnotations := func(payload []byte) [][]string { return parseParameterAnnotations(payload, pool, utf8) }
	typeAnnotations := func(payload []byte) []TypeAnnotation { return parseTypeAnnotations(payload, pool, utf8) }
	constantValue := func(index uint16, descriptor string) string {
		return classConstantLiteral(pool, utf8, index, descriptor)
	}

	result := &Class{Access: r.u2()}
	result.InternalName = className(r.u2())
	result.SuperName = className(r.u2())
	interfaces := int(r.u2())
	result.Interfaces = make([]string, 0, interfaces)
	for range interfaces {
		result.Interfaces = append(result.Interfaces, className(r.u2()))
	}
	fields := int(r.u2())
	result.Fields = make([]Field, 0, fields)
	for range fields {
		field := Field{Access: r.u2(), Name: utf8(r.u2()), Descriptor: utf8(r.u2())}
		readAttributes(r, utf8, func(name string, payload []byte) {
			switch name {
			case "Signature":
				if len(payload) >= 2 {
					field.Signature = utf8(binary.BigEndian.Uint16(payload))
				}
			case "Deprecated":
				field.Deprecated = true
			case "ConstantValue":
				if len(payload) >= 2 {
					field.Constant = constantValue(binary.BigEndian.Uint16(payload), field.Descriptor)
				}
			case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
				field.Annotations = append(field.Annotations, annotations(payload)...)
			case "RuntimeVisibleTypeAnnotations", "RuntimeInvisibleTypeAnnotations":
				field.TypeAnnotations = append(field.TypeAnnotations, typeAnnotations(payload)...)
			}
		})
		field.Type, _, _ = parseType(field.Descriptor, 0)
		if generic, ok := parseFieldSignature(field.Signature); ok {
			field.Type = generic
		}
		result.Fields = append(result.Fields, field)
	}
	methods := int(r.u2())
	result.Methods = make([]Method, 0, methods)
	for range methods {
		method := Method{Access: r.u2(), Name: utf8(r.u2()), Descriptor: utf8(r.u2())}
		readAttributes(r, utf8, func(name string, payload []byte) {
			switch name {
			case "Signature":
				if len(payload) >= 2 {
					method.Signature = utf8(binary.BigEndian.Uint16(payload))
				}
			case "Deprecated":
				method.Deprecated = true
			case "MethodParameters":
				if len(payload) > 0 {
					parameterCount := int(payload[0])
					for offset := 1; parameterCount > 0 && offset+3 < len(payload); parameterCount, offset = parameterCount-1, offset+4 {
						method.ParameterNames = append(method.ParameterNames, utf8(binary.BigEndian.Uint16(payload[offset:offset+2])))
					}
				}
			case "Exceptions":
				if len(payload) >= 2 {
					count := int(binary.BigEndian.Uint16(payload))
					for offset := 2; count > 0 && offset+1 < len(payload); count, offset = count-1, offset+2 {
						method.Exceptions = append(method.Exceptions, className(binary.BigEndian.Uint16(payload[offset:offset+2])))
					}
				}
			case "AnnotationDefault":
				defaultReader := &reader{data: payload}
				method.DefaultValue = parseAnnotationValue(defaultReader, pool, utf8)
			case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
				method.Annotations = append(method.Annotations, annotations(payload)...)
			case "RuntimeVisibleParameterAnnotations", "RuntimeInvisibleParameterAnnotations":
				mergeParameterAnnotations(&method.ParameterAnnotations, parameterAnnotations(payload))
			case "RuntimeVisibleTypeAnnotations", "RuntimeInvisibleTypeAnnotations":
				method.TypeAnnotations = append(method.TypeAnnotations, typeAnnotations(payload)...)
			case "Code":
				code := &reader{data: payload}
				code.skip(4) // max_stack and max_locals
				code.skip(int(code.u4()))
				code.skip(int(code.u2()) * 8)
				readAttributes(code, utf8, func(codeAttribute string, codePayload []byte) {
					if codeAttribute != "LineNumberTable" || len(codePayload) < 2 {
						return
					}
					count := int(binary.BigEndian.Uint16(codePayload))
					seen := make(map[int]bool, count)
					for offset := 2; count > 0 && offset+3 < len(codePayload); count, offset = count-1, offset+4 {
						line := int(binary.BigEndian.Uint16(codePayload[offset+2 : offset+4]))
						if line > 0 && !seen[line] {
							seen[line] = true
							method.LineNumbers = append(method.LineNumbers, line)
						}
					}
				})
				if code.err != nil {
					r.err = code.err
				}
			}
		})
		method.ParameterTypes, method.ResultType, _ = parseMethodDescriptor(method.Descriptor)
		if _, parameters, resultType, _, ok := parseMethodSignature(method.Signature); ok && len(parameters) == len(method.ParameterTypes) {
			method.ParameterTypes, method.ResultType = parameters, resultType
		}
		result.Methods = append(result.Methods, method)
	}
	readAttributes(r, utf8, func(name string, payload []byte) {
		switch name {
		case "Deprecated":
			result.Deprecated = true
		case "Signature":
			if len(payload) >= 2 {
				result.Signature = utf8(binary.BigEndian.Uint16(payload))
			}
		case "SourceFile":
			if len(payload) >= 2 {
				result.SourceFile = utf8(binary.BigEndian.Uint16(payload))
			}
		case "Record":
			result.Record = true
			componentReader := &reader{data: payload}
			componentCount := int(componentReader.u2())
			result.Components = make([]RecordComponent, 0, componentCount)
			for range componentCount {
				component := RecordComponent{Name: utf8(componentReader.u2()), Descriptor: utf8(componentReader.u2())}
				readAttributes(componentReader, utf8, func(attribute string, componentPayload []byte) {
					switch attribute {
					case "Signature":
						if len(componentPayload) >= 2 {
							component.Signature = utf8(binary.BigEndian.Uint16(componentPayload))
						}
					case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
						component.Annotations = append(component.Annotations, annotations(componentPayload)...)
					case "RuntimeVisibleTypeAnnotations", "RuntimeInvisibleTypeAnnotations":
						component.TypeAnnotations = append(component.TypeAnnotations, typeAnnotations(componentPayload)...)
					}
				})
				result.Components = append(result.Components, component)
			}
			if componentReader.err != nil {
				r.err = componentReader.err
			}
		case "InnerClasses":
			innerReader := &reader{data: payload}
			innerCount := int(innerReader.u2())
			for range innerCount {
				entry := InnerClass{
					InternalName: className(innerReader.u2()),
					OuterName:    className(innerReader.u2()),
					SimpleName:   utf8(innerReader.u2()),
					Access:       innerReader.u2(),
				}
				if entry.InternalName != "" && entry.SimpleName != "" {
					result.InnerClasses = append(result.InnerClasses, entry)
				}
			}
			if innerReader.err != nil {
				r.err = innerReader.err
			}
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			result.Annotations = append(result.Annotations, annotations(payload)...)
			if result.KotlinMetadata == nil {
				result.KotlinMetadata = parseKotlinMetadata(payload, pool, utf8)
			}
		case "RuntimeVisibleTypeAnnotations", "RuntimeInvisibleTypeAnnotations":
			result.TypeAnnotations = append(result.TypeAnnotations, typeAnnotations(payload)...)
		case "EnclosingMethod":
			if len(payload) >= 2 {
				result.EnclosingClass = className(binary.BigEndian.Uint16(payload))
			}
		case "NestHost":
			if len(payload) >= 2 {
				result.NestHost = className(binary.BigEndian.Uint16(payload))
			}
		case "NestMembers":
			if len(payload) >= 2 {
				count := int(binary.BigEndian.Uint16(payload))
				for offset := 2; count > 0 && offset+1 < len(payload); count, offset = count-1, offset+2 {
					result.NestMembers = append(result.NestMembers, className(binary.BigEndian.Uint16(payload[offset:offset+2])))
				}
			}
		}
	})
	if r.err != nil {
		return nil, r.err
	}
	if result.InternalName == "" {
		return nil, errors.New("class file has no class name")
	}
	return result, nil
}

func decodeModifiedUTF8(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	runes := make([]rune, 0, len(data))
	for index := 0; index < len(data); {
		value := data[index]
		switch {
		case value&0x80 == 0:
			runes = append(runes, rune(value))
			index++
		case value&0xe0 == 0xc0 && index+1 < len(data):
			runes = append(runes, rune(value&0x1f)<<6|rune(data[index+1]&0x3f))
			index += 2
		case value&0xf0 == 0xe0 && index+2 < len(data):
			first := rune(value&0x0f)<<12 | rune(data[index+1]&0x3f)<<6 | rune(data[index+2]&0x3f)
			index += 3
			if first >= 0xd800 && first <= 0xdbff && index+2 < len(data) && data[index]&0xf0 == 0xe0 {
				second := rune(data[index]&0x0f)<<12 | rune(data[index+1]&0x3f)<<6 | rune(data[index+2]&0x3f)
				if second >= 0xdc00 && second <= 0xdfff {
					runes = append(runes, 0x10000+(first-0xd800)<<10+(second-0xdc00))
					index += 3
					continue
				}
			}
			runes = append(runes, first)
		default:
			return string(data)
		}
	}
	return string(runes)
}

func readAttributes(r *reader, utf8 func(uint16) string, visit func(string, []byte)) {
	count := int(r.u2())
	for range count {
		name := utf8(r.u2())
		length := int(r.u4())
		payload := r.bytes(length)
		if payload != nil {
			visit(name, payload)
		}
	}
}

func parseAnnotations(payload []byte, pool []constant, utf8 func(uint16) string) []string {
	r := &reader{data: payload}
	count := int(r.u2())
	out := make([]string, 0, count)
	for range count {
		if annotation := parseAnnotation(r, pool, utf8); annotation != "" {
			out = append(out, annotation)
		}
	}
	return out
}

func parseParameterAnnotations(payload []byte, pool []constant, utf8 func(uint16) string) [][]string {
	r := &reader{data: payload}
	count := int(r.u1())
	result := make([][]string, count)
	for parameter := 0; parameter < count && r.err == nil; parameter++ {
		annotations := int(r.u2())
		for range annotations {
			if annotation := parseAnnotation(r, pool, utf8); annotation != "" {
				result[parameter] = append(result[parameter], annotation)
			}
		}
	}
	if r.err != nil {
		return nil
	}
	return result
}

func mergeParameterAnnotations(target *[][]string, values [][]string) {
	if len(values) > len(*target) {
		grown := make([][]string, len(values))
		copy(grown, *target)
		*target = grown
	}
	for index := range values {
		(*target)[index] = append((*target)[index], values[index]...)
	}
}

func parseTypeAnnotations(payload []byte, pool []constant, utf8 func(uint16) string) []TypeAnnotation {
	r := &reader{data: payload}
	count := int(r.u2())
	result := make([]TypeAnnotation, 0, count)
	for range count {
		targetType := r.u1()
		annotation := TypeAnnotation{TargetType: targetType, ParameterIndex: -1}
		switch targetType {
		case 0x00, 0x01:
			r.skip(1)
		case 0x10:
			r.skip(2)
		case 0x11, 0x12:
			r.skip(2)
		case 0x13, 0x14, 0x15:
		case 0x16:
			annotation.ParameterIndex = int(r.u1())
		case 0x17:
			r.skip(2)
		case 0x40, 0x41:
			tableLength := int(r.u2())
			r.skip(tableLength * 6)
		case 0x42, 0x43, 0x44, 0x45, 0x46:
			r.skip(2)
		case 0x47, 0x48, 0x49, 0x4a, 0x4b:
			r.skip(3)
		default:
			return nil
		}
		pathLength := int(r.u1())
		annotation.TypePath = make([]TypePathEntry, 0, pathLength)
		for range pathLength {
			annotation.TypePath = append(annotation.TypePath, TypePathEntry{Kind: r.u1(), Index: r.u1()})
		}
		annotation.Annotation = parseAnnotation(r, pool, utf8)
		if r.err != nil {
			return nil
		}
		if annotation.Annotation != "" {
			result = append(result, annotation)
		}
	}
	return result
}

func parseKotlinMetadata(payload []byte, pool []constant, utf8 func(uint16) string) *KotlinMetadata {
	r := &reader{data: payload}
	count := int(r.u2())
	for range count {
		typ := descriptorClassName(utf8(r.u2()))
		pairs := int(r.u2())
		var metadata KotlinMetadata
		for range pairs {
			name := utf8(r.u2())
			value := parseRawAnnotationValue(r, pool, utf8)
			if typ != "kotlin.Metadata" {
				continue
			}
			switch name {
			case "k":
				metadata.Kind, _ = value.(int)
			case "mv":
				metadata.MetadataVersion, _ = value.([]int)
			case "d1":
				metadata.Data1, _ = value.([]string)
			case "d2":
				metadata.Data2, _ = value.([]string)
			case "xs":
				metadata.ExtraString, _ = value.(string)
			case "pn":
				metadata.PackageName, _ = value.(string)
			case "xi":
				metadata.ExtraInt, _ = value.(int)
			}
		}
		if typ == "kotlin.Metadata" && r.err == nil {
			return &metadata
		}
	}
	return nil
}

func parseRawAnnotationValue(r *reader, pool []constant, utf8 func(uint16) string) any {
	tag := r.u1()
	switch tag {
	case 'B', 'C', 'I', 'S', 'Z':
		index := r.u2()
		if index > 0 && int(index) < len(pool) {
			return int(pool[index].integer)
		}
	case 's':
		return utf8(r.u2())
	case 'D', 'F', 'J':
		r.skip(2)
	case 'e':
		r.skip(4)
	case 'c':
		r.skip(2)
	case '@':
		r.skip(2)
		pairs := int(r.u2())
		for range pairs {
			r.skip(2)
			_ = parseRawAnnotationValue(r, pool, utf8)
		}
	case '[':
		count := int(r.u2())
		values := make([]any, 0, count)
		for range count {
			values = append(values, parseRawAnnotationValue(r, pool, utf8))
		}
		allInts, ints := true, make([]int, 0, len(values))
		allStrings, strings := true, make([]string, 0, len(values))
		for _, value := range values {
			integer, integerOK := value.(int)
			text, stringOK := value.(string)
			allInts = allInts && integerOK
			allStrings = allStrings && stringOK
			if integerOK {
				ints = append(ints, integer)
			}
			if stringOK {
				strings = append(strings, text)
			}
		}
		if allInts {
			return ints
		}
		if allStrings {
			return strings
		}
		return values
	}
	return nil
}

func parseAnnotation(r *reader, pool []constant, utf8 func(uint16) string) string {
	typ := descriptorClassName(utf8(r.u2()))
	pairs := int(r.u2())
	values := make([]string, 0, pairs)
	for range pairs {
		name := utf8(r.u2())
		value := parseAnnotationValue(r, pool, utf8)
		if name != "" && value != "" {
			values = append(values, name+" = "+value)
		}
	}
	if typ == "" {
		return ""
	}
	if len(values) == 1 && strings.HasPrefix(values[0], "value = ") {
		values[0] = strings.TrimPrefix(values[0], "value = ")
	}
	if len(values) == 0 {
		return "@" + typ
	}
	return "@" + typ + "(" + strings.Join(values, ", ") + ")"
}

func parseAnnotationValue(r *reader, pool []constant, utf8 func(uint16) string) string {
	tag := r.u1()
	switch tag {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		return classConstantLiteral(pool, utf8, r.u2(), string([]byte{tag}))
	case 's':
		return strconv.Quote(utf8(r.u2()))
	case 'e':
		typ := descriptorClassName(utf8(r.u2()))
		name := utf8(r.u2())
		if typ == "" {
			return name
		}
		return typ + "." + name
	case 'c':
		typ := descriptorClassName(utf8(r.u2()))
		if typ == "" {
			return "java.lang.Object.class"
		}
		return typ + ".class"
	case '@':
		return parseAnnotation(r, pool, utf8)
	case '[':
		count := int(r.u2())
		values := make([]string, 0, count)
		for range count {
			values = append(values, parseAnnotationValue(r, pool, utf8))
		}
		return "{" + strings.Join(values, ", ") + "}"
	default:
		return ""
	}
}

func classConstantLiteral(pool []constant, utf8 func(uint16) string, index uint16, descriptor string) string {
	if index == 0 || int(index) >= len(pool) {
		return ""
	}
	entry := pool[index]
	switch entry.tag {
	case 3:
		switch descriptor {
		case "Z":
			if entry.integer == 0 {
				return "false"
			}
			return "true"
		case "C":
			return strconv.QuoteRune(rune(entry.integer))
		default:
			return strconv.FormatInt(entry.integer, 10)
		}
	case 4:
		return strconv.FormatFloat(entry.floating, 'g', -1, 32) + "f"
	case 5:
		return strconv.FormatInt(entry.integer, 10) + "L"
	case 6:
		return strconv.FormatFloat(entry.floating, 'g', -1, 64)
	case 8:
		return strconv.Quote(utf8(entry.nameIndex))
	case 1:
		return strconv.Quote(entry.text)
	default:
		return ""
	}
}

func descriptorClassName(descriptor string) string {
	if typ, next, ok := parseType(descriptor, 0); ok && next == len(descriptor) {
		return typ
	}
	return strings.ReplaceAll(strings.Trim(descriptor, "L;"), "/", ".")
}

func (r *reader) u1() byte {
	if r.off >= len(r.data) {
		r.err = errors.New("truncated class file")
		return 0
	}
	value := r.data[r.off]
	r.off++
	return value
}
func (r *reader) u2() uint16 {
	data := r.bytes(2)
	if data == nil {
		return 0
	}
	return binary.BigEndian.Uint16(data)
}
func (r *reader) u4() uint32 {
	data := r.bytes(4)
	if data == nil {
		return 0
	}
	return binary.BigEndian.Uint32(data)
}
func (r *reader) bytes(length int) []byte {
	if length < 0 || r.off+length > len(r.data) {
		r.err = errors.New("truncated class file")
		return nil
	}
	result := r.data[r.off : r.off+length]
	r.off += length
	return result
}
func (r *reader) skip(length int) { _ = r.bytes(length) }

func RenderJava(class *Class) string {
	packageName, nestedNames, nestingAccess := classNesting(class)
	simpleName := nestedNames[len(nestedNames)-1]
	outerNames := nestedNames[:len(nestedNames)-1]
	indent := strings.Repeat("    ", len(outerNames))
	var out strings.Builder
	if packageName != "" {
		out.WriteString("package ")
		out.WriteString(packageName)
		out.WriteString(";\n\n")
	}
	for depth, outer := range outerNames {
		out.WriteString(strings.Repeat("    ", depth))
		out.WriteString(modifiers(nestingAccess[depth], true))
		out.WriteString("class ")
		out.WriteString(outer)
		out.WriteString(" {\n")
	}
	writeAnnotations(&out, class.Annotations, indent)
	if class.Deprecated {
		out.WriteString(indent)
		out.WriteString("@Deprecated\n")
	}
	out.WriteString(indent)
	classAccess := class.Access
	if len(nestingAccess) == len(nestedNames) {
		classAccess |= nestingAccess[len(nestingAccess)-1]
	}
	if class.Record {
		classAccess &^= accFinal
	}
	out.WriteString(modifiers(classAccess, true))
	switch {
	case class.Access&accAnnotation != 0:
		out.WriteString("@interface ")
	case class.Access&accEnum != 0:
		out.WriteString("enum ")
	case class.Access&accInterface != 0:
		out.WriteString("interface ")
	case class.Record:
		out.WriteString("record ")
	default:
		out.WriteString("class ")
	}
	out.WriteString(simpleName)
	typeParameters, genericSuper, genericInterfaces, hasGenericClass := parseClassSignature(class.Signature)
	if hasGenericClass {
		out.WriteString(typeParameters)
	}
	superName := javaClassName(class.SuperName)
	interfaces := make([]string, len(class.Interfaces))
	for index, implemented := range class.Interfaces {
		interfaces[index] = javaClassName(implemented)
	}
	if hasGenericClass {
		superName, interfaces = genericSuper, genericInterfaces
	}
	if class.Record {
		out.WriteByte('(')
		for index, component := range class.Components {
			if index > 0 {
				out.WriteString(", ")
			}
			if len(component.Annotations) > 0 {
				out.WriteString(strings.Join(component.Annotations, " "))
				out.WriteByte(' ')
			}
			typ, _, ok := parseType(component.Descriptor, 0)
			if generic, genericOK := parseFieldSignature(component.Signature); genericOK {
				typ, ok = generic, true
			}
			if !ok {
				typ = "java.lang.Object"
			}
			out.WriteString(typ)
			out.WriteByte(' ')
			out.WriteString(component.Name)
		}
		out.WriteByte(')')
	}
	if superName != "" && superName != "java.lang.Object" && class.Access&(accInterface|accAnnotation|accEnum) == 0 && !class.Record {
		out.WriteString(" extends ")
		out.WriteString(superName)
	}
	if len(interfaces) > 0 {
		if class.Access&accInterface != 0 {
			out.WriteString(" extends ")
		} else {
			out.WriteString(" implements ")
		}
		for index, implemented := range interfaces {
			if index > 0 {
				out.WriteString(", ")
			}
			out.WriteString(implemented)
		}
	}
	out.WriteString(" {\n")
	if class.Access&accEnum != 0 {
		out.WriteString(indent)
		out.WriteString("    ;\n")
	}
	for _, field := range class.Fields {
		if field.Access&accSynthetic != 0 || !validJavaIdentifier(field.Name) {
			continue
		}
		if class.Record && recordComponent(class.Components, field.Name, field.Descriptor) {
			continue
		}
		if field.Deprecated {
			out.WriteString(indent)
			out.WriteString("    @Deprecated\n")
		}
		writeAnnotations(&out, field.Annotations, indent+"    ")
		out.WriteString(indent)
		out.WriteString("    ")
		out.WriteString(modifiers(field.Access, false))
		typ, _, ok := parseType(field.Descriptor, 0)
		if generic, genericOK := parseFieldSignature(field.Signature); genericOK {
			typ, ok = generic, true
		}
		if !ok {
			typ = "java.lang.Object"
		}
		out.WriteString(typ)
		out.WriteByte(' ')
		out.WriteString(field.Name)
		if field.Constant != "" {
			out.WriteString(" = ")
			out.WriteString(field.Constant)
		}
		out.WriteString(";\n")
	}
	for _, method := range class.Methods {
		if method.Name == "<clinit>" || method.Access&(accSynthetic|accBridge) != 0 {
			continue
		}
		constructor := method.Name == "<init>"
		if class.Record && (constructor && method.Descriptor == canonicalRecordConstructorDescriptor(class.Components) || recordAccessor(class.Components, method.Name, method.Descriptor)) {
			continue
		}
		if !constructor && !validJavaIdentifier(method.Name) {
			continue
		}
		parameters, result, ok := parseMethodDescriptor(method.Descriptor)
		if !ok {
			continue
		}
		methodTypeParameters, throws := "", make([]string, len(method.Exceptions))
		for index, exception := range method.Exceptions {
			throws[index] = javaClassName(exception)
		}
		if genericTypeParameters, genericParameters, genericResult, genericThrows, genericOK := parseMethodSignature(method.Signature); genericOK && len(genericParameters) == len(parameters) {
			methodTypeParameters, parameters, result = genericTypeParameters, genericParameters, genericResult
			if len(genericThrows) > 0 {
				throws = genericThrows
			}
		}
		if method.Deprecated {
			out.WriteString(indent)
			out.WriteString("    @Deprecated\n")
		}
		writeAnnotations(&out, method.Annotations, indent+"    ")
		out.WriteString(indent)
		out.WriteString("    ")
		out.WriteString(modifiers(method.Access, false))
		if methodTypeParameters != "" {
			out.WriteString(methodTypeParameters)
			out.WriteByte(' ')
		}
		if constructor {
			out.WriteString(simpleName)
		} else {
			out.WriteString(result)
			out.WriteByte(' ')
			out.WriteString(method.Name)
		}
		out.WriteByte('(')
		for index, parameter := range parameters {
			if index > 0 {
				out.WriteString(", ")
			}
			if method.Access&0x0080 != 0 && index == len(parameters)-1 && strings.HasSuffix(parameter, "[]") {
				parameter = strings.TrimSuffix(parameter, "[]") + "..."
			}
			if index < len(method.ParameterAnnotations) && len(method.ParameterAnnotations[index]) > 0 {
				out.WriteString(strings.Join(method.ParameterAnnotations[index], " "))
				out.WriteByte(' ')
			}
			out.WriteString(parameter)
			out.WriteByte(' ')
			name := ""
			if index < len(method.ParameterNames) {
				name = method.ParameterNames[index]
			}
			if !validJavaIdentifier(name) {
				name = fmt.Sprintf("arg%d", index)
			}
			out.WriteString(name)
		}
		out.WriteByte(')')
		if class.Access&accAnnotation != 0 && method.DefaultValue != "" {
			out.WriteString(" default ")
			out.WriteString(method.DefaultValue)
			out.WriteString(";\n")
			continue
		}
		if len(throws) > 0 {
			out.WriteString(" throws ")
			out.WriteString(strings.Join(throws, ", "))
		}
		abstract := class.Access&(accInterface|accAnnotation) != 0 || method.Access&(accAbstract|accNative) != 0
		if abstract && method.Access&accStatic == 0 {
			out.WriteString(";\n")
			continue
		}
		out.WriteString(" {")
		if !constructor && result != "void" {
			out.WriteString(" return ")
			out.WriteString(defaultValue(result))
			out.WriteString(";")
		}
		out.WriteString(" }\n")
	}
	out.WriteString(indent)
	out.WriteString("}\n")
	for depth := len(outerNames) - 1; depth >= 0; depth-- {
		out.WriteString(strings.Repeat("    ", depth))
		out.WriteString("}\n")
	}
	return out.String()
}

func writeAnnotations(out *strings.Builder, annotations []string, indent string) {
	for _, annotation := range annotations {
		if annotation == "" || annotation == "@java.lang.Deprecated" {
			continue
		}
		out.WriteString(indent)
		out.WriteString(annotation)
		out.WriteByte('\n')
	}
}

func classNesting(class *Class) (string, []string, []uint16) {
	relations := make(map[string]InnerClass, len(class.InnerClasses))
	for _, entry := range class.InnerClasses {
		if entry.OuterName != "" {
			relations[entry.InternalName] = entry
		}
	}
	current := class.InternalName
	names := make([]string, 0, 4)
	access := make([]uint16, 0, 4)
	for {
		entry, nested := relations[current]
		if !nested {
			lastSlash := strings.LastIndexByte(current, '/')
			root := current[lastSlash+1:]
			names = append([]string{root}, names...)
			access = append([]uint16{0}, access...)
			packageName := strings.ReplaceAll(current[:max(lastSlash, 0)], "/", ".")
			if lastSlash < 0 {
				packageName = ""
			}
			return packageName, names, access
		}
		names = append([]string{entry.SimpleName}, names...)
		access = append([]uint16{entry.Access}, access...)
		current = entry.OuterName
	}
}

func recordComponent(components []RecordComponent, name, descriptor string) bool {
	for _, component := range components {
		if component.Name == name && component.Descriptor == descriptor {
			return true
		}
	}
	return false
}

func recordAccessor(components []RecordComponent, name, descriptor string) bool {
	for _, component := range components {
		if component.Name == name && descriptor == "()"+component.Descriptor {
			return true
		}
	}
	return false
}

func canonicalRecordConstructorDescriptor(components []RecordComponent) string {
	var descriptor strings.Builder
	descriptor.WriteByte('(')
	for _, component := range components {
		descriptor.WriteString(component.Descriptor)
	}
	descriptor.WriteString(")V")
	return descriptor.String()
}

func splitClassName(qualified string) (string, string) {
	packageName, nested := splitBinaryClassName(qualified)
	return packageName, nested[len(nested)-1]
}

func splitBinaryClassName(qualified string) (string, []string) {
	lastDot := strings.LastIndexByte(qualified, '.')
	packageName, binaryName := "", qualified
	if lastDot >= 0 {
		packageName, binaryName = qualified[:lastDot], qualified[lastDot+1:]
	}
	parts := strings.Split(binaryName, "$")
	for _, part := range parts {
		if !validJavaIdentifier(part) {
			return packageName, []string{binaryName}
		}
	}
	return packageName, parts
}

func javaClassName(internal string) string {
	return strings.ReplaceAll(strings.ReplaceAll(internal, "/", "."), "$", ".")
}

type signatureReader struct {
	value string
	off   int
}

func parseFieldSignature(signature string) (string, bool) {
	if signature == "" {
		return "", false
	}
	reader := &signatureReader{value: signature}
	typ, ok := reader.typ(false)
	return typ, ok && reader.off == len(signature)
}

func parseClassSignature(signature string) (typeParameters, supertype string, interfaces []string, ok bool) {
	if signature == "" {
		return "", "", nil, false
	}
	reader := &signatureReader{value: signature}
	typeParameters, ok = reader.typeParameters()
	if !ok {
		return "", "", nil, false
	}
	supertype, ok = reader.typ(false)
	if !ok {
		return "", "", nil, false
	}
	for reader.off < len(signature) {
		implemented, typeOK := reader.typ(false)
		if !typeOK {
			return "", "", nil, false
		}
		interfaces = append(interfaces, implemented)
	}
	return typeParameters, supertype, interfaces, true
}

func parseMethodSignature(signature string) (typeParameters string, parameters []string, result string, throws []string, ok bool) {
	if signature == "" {
		return "", nil, "", nil, false
	}
	reader := &signatureReader{value: signature}
	typeParameters, ok = reader.typeParameters()
	if !ok || reader.off >= len(signature) || signature[reader.off] != '(' {
		return "", nil, "", nil, false
	}
	reader.off++
	for reader.off < len(signature) && signature[reader.off] != ')' {
		parameter, typeOK := reader.typ(false)
		if !typeOK {
			return "", nil, "", nil, false
		}
		parameters = append(parameters, parameter)
	}
	if reader.off >= len(signature) || signature[reader.off] != ')' {
		return "", nil, "", nil, false
	}
	reader.off++
	result, ok = reader.typ(true)
	if !ok {
		return "", nil, "", nil, false
	}
	for reader.off < len(signature) && signature[reader.off] == '^' {
		reader.off++
		exception, exceptionOK := reader.typ(false)
		if !exceptionOK {
			return "", nil, "", nil, false
		}
		throws = append(throws, exception)
	}
	return typeParameters, parameters, result, throws, reader.off == len(signature)
}

func (reader *signatureReader) typeParameters() (string, bool) {
	if reader.off >= len(reader.value) || reader.value[reader.off] != '<' {
		return "", true
	}
	reader.off++
	var parameters []string
	for reader.off < len(reader.value) && reader.value[reader.off] != '>' {
		start := reader.off
		for reader.off < len(reader.value) && reader.value[reader.off] != ':' {
			reader.off++
		}
		if reader.off == start || reader.off >= len(reader.value) {
			return "", false
		}
		name := reader.value[start:reader.off]
		var bounds []string
		for reader.off < len(reader.value) && reader.value[reader.off] == ':' {
			reader.off++
			if reader.off < len(reader.value) && reader.value[reader.off] == ':' {
				continue
			}
			bound, ok := reader.typ(false)
			if !ok {
				return "", false
			}
			if bound != "java.lang.Object" {
				bounds = append(bounds, bound)
			}
		}
		if len(bounds) > 0 {
			name += " extends " + strings.Join(bounds, " & ")
		}
		parameters = append(parameters, name)
	}
	if reader.off >= len(reader.value) || reader.value[reader.off] != '>' {
		return "", false
	}
	reader.off++
	return "<" + strings.Join(parameters, ", ") + ">", true
}

func (reader *signatureReader) typ(allowVoid bool) (string, bool) {
	arrays := 0
	for reader.off < len(reader.value) && reader.value[reader.off] == '[' {
		arrays++
		reader.off++
	}
	if reader.off >= len(reader.value) {
		return "", false
	}
	primitive := map[byte]string{'B': "byte", 'C': "char", 'D': "double", 'F': "float", 'I': "int", 'J': "long", 'S': "short", 'Z': "boolean"}
	if value, exists := primitive[reader.value[reader.off]]; exists {
		reader.off++
		return value + strings.Repeat("[]", arrays), true
	}
	if reader.value[reader.off] == 'V' && allowVoid && arrays == 0 {
		reader.off++
		return "void", true
	}
	if reader.value[reader.off] == 'T' {
		reader.off++
		start := reader.off
		for reader.off < len(reader.value) && reader.value[reader.off] != ';' {
			reader.off++
		}
		if reader.off == start || reader.off >= len(reader.value) {
			return "", false
		}
		name := reader.value[start:reader.off]
		reader.off++
		return name + strings.Repeat("[]", arrays), true
	}
	if reader.value[reader.off] != 'L' {
		return "", false
	}
	reader.off++
	var name strings.Builder
	for reader.off < len(reader.value) {
		switch reader.value[reader.off] {
		case ';':
			reader.off++
			return name.String() + strings.Repeat("[]", arrays), true
		case '/', '$', '.':
			name.WriteByte('.')
			reader.off++
		case '<':
			arguments, ok := reader.typeArguments()
			if !ok {
				return "", false
			}
			name.WriteString(arguments)
		default:
			name.WriteByte(reader.value[reader.off])
			reader.off++
		}
	}
	return "", false
}

func (reader *signatureReader) typeArguments() (string, bool) {
	if reader.off >= len(reader.value) || reader.value[reader.off] != '<' {
		return "", false
	}
	reader.off++
	var arguments []string
	for reader.off < len(reader.value) && reader.value[reader.off] != '>' {
		if reader.value[reader.off] == '*' {
			arguments = append(arguments, "?")
			reader.off++
			continue
		}
		variance := ""
		if reader.value[reader.off] == '+' {
			variance = "? extends "
			reader.off++
		} else if reader.value[reader.off] == '-' {
			variance = "? super "
			reader.off++
		}
		argument, ok := reader.typ(false)
		if !ok {
			return "", false
		}
		arguments = append(arguments, variance+argument)
	}
	if reader.off >= len(reader.value) || reader.value[reader.off] != '>' {
		return "", false
	}
	reader.off++
	return "<" + strings.Join(arguments, ", ") + ">", true
}

func parseMethodDescriptor(descriptor string) ([]string, string, bool) {
	if len(descriptor) == 0 || descriptor[0] != '(' {
		return nil, "", false
	}
	var parameters []string
	offset := 1
	for offset < len(descriptor) && descriptor[offset] != ')' {
		parameter, next, ok := parseType(descriptor, offset)
		if !ok {
			return nil, "", false
		}
		parameters = append(parameters, parameter)
		offset = next
	}
	if offset >= len(descriptor) || descriptor[offset] != ')' {
		return nil, "", false
	}
	result, _, ok := parseType(descriptor, offset+1)
	return parameters, result, ok
}

func parseType(descriptor string, offset int) (string, int, bool) {
	if offset >= len(descriptor) {
		return "", offset, false
	}
	arrays := 0
	for offset < len(descriptor) && descriptor[offset] == '[' {
		arrays++
		offset++
	}
	if offset >= len(descriptor) {
		return "", offset, false
	}
	var typ string
	switch descriptor[offset] {
	case 'B':
		typ = "byte"
		offset++
	case 'C':
		typ = "char"
		offset++
	case 'D':
		typ = "double"
		offset++
	case 'F':
		typ = "float"
		offset++
	case 'I':
		typ = "int"
		offset++
	case 'J':
		typ = "long"
		offset++
	case 'S':
		typ = "short"
		offset++
	case 'Z':
		typ = "boolean"
		offset++
	case 'V':
		typ = "void"
		offset++
	case 'L':
		end := strings.IndexByte(descriptor[offset:], ';')
		if end < 0 {
			return "", offset, false
		}
		end += offset
		typ = javaClassName(descriptor[offset+1 : end])
		offset = end + 1
	default:
		return "", offset, false
	}
	return typ + strings.Repeat("[]", arrays), offset, true
}

func modifiers(access uint16, class bool) string {
	words := make([]string, 0, 6)
	switch {
	case access&accPublic != 0:
		words = append(words, "public")
	case access&accProtected != 0:
		words = append(words, "protected")
	case access&accPrivate != 0:
		words = append(words, "private")
	}
	if access&accStatic != 0 {
		words = append(words, "static")
	}
	if access&accAbstract != 0 && access&(accInterface|accAnnotation) == 0 {
		words = append(words, "abstract")
	}
	if access&accFinal != 0 && access&accEnum == 0 {
		words = append(words, "final")
	}
	if access&accSynchronized != 0 && !class {
		words = append(words, "synchronized")
	}
	if access&accNative != 0 {
		words = append(words, "native")
	}
	if access&accStrict != 0 {
		words = append(words, "strictfp")
	}
	if access&accTransient != 0 && !class {
		words = append(words, "transient")
	}
	if access&accVolatile != 0 && !class {
		words = append(words, "volatile")
	}
	if len(words) == 0 {
		return ""
	}
	return strings.Join(words, " ") + " "
}

func defaultValue(typ string) string {
	switch typ {
	case "boolean":
		return "false"
	case "byte", "char", "double", "float", "int", "long", "short":
		return "0"
	default:
		return "null"
	}
}

func validJavaIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for index, r := range name {
		if index == 0 {
			if r != '_' && r != '$' && !unicode.IsLetter(r) {
				return false
			}
		} else if r != '_' && r != '$' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
