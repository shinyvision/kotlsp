package index

import (
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// kotlinMetadataProperty is a Property message: a Kotlin property whose JVM
// view is only an accessor (or a field), which Kotlin code never names.
type kotlinMetadataProperty struct {
	Name           string
	Type           kotlinMetadataType
	Receiver       bool
	ReceiverType   kotlinMetadataType
	TypeParameters map[int]string
	Visibility     string
	Var            bool
	Const          bool
	Lateinit       bool
	// GetterName/FieldName are the JVM members the JvmPropertySignature
	// names; empty when they follow the default spelling.
	GetterName string
	FieldName  string
}

// Property flags: has_annotations(1) visibility(3) modality(2) member_kind(2)
// is_var has_getter has_setter is_const is_lateinit ...
const (
	kotlinPropertyFlagVar      = 1 << 8
	kotlinPropertyFlagConst    = 1 << 11
	kotlinPropertyFlagLateinit = 1 << 12
	kotlinPropertyDefaultFlags = 518
)

func decodeKotlinProperty(message []byte, stringsTable []string) (kotlinMetadataProperty, bool) {
	property := kotlinMetadataProperty{}
	flags, hasCurrentFlags := uint64(kotlinPropertyDefaultFlags), false
	valid := protobufFieldsStrict(message, func(number int, wire int, integer uint64, value []byte) {
		switch {
		case number == 11 && wire == 0:
			flags, hasCurrentFlags = integer, true
		case number == 1 && wire == 0 && !hasCurrentFlags:
			flags = integer
		case number == 2 && wire == 0:
			property.Name = kotlinMetadataString(stringsTable, integer)
		case number == 3 && wire == 2:
			property.Type, _ = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
		case number == 4 && wire == 2:
			if id, name, ok := decodeKotlinTypeParameter(value, stringsTable); ok {
				if property.TypeParameters == nil {
					property.TypeParameters = make(map[int]string)
				}
				property.TypeParameters[id] = name
			}
		case number == 5 && wire == 2:
			property.Receiver = true
			property.ReceiverType, _ = decodeKotlinMetadataTypeWithStrings(value, stringsTable)
		case number == 10 && wire == 0:
			property.Receiver = true
		case number == 100 && wire == 2:
			// JvmPropertySignature: field (1), getter (3), each a name/desc pair.
			protobufFields(value, func(field int, fieldWire int, _ uint64, signature []byte) {
				if fieldWire != 2 || field != 1 && field != 3 {
					return
				}
				protobufFields(signature, func(part int, partWire int, partInteger uint64, _ []byte) {
					if part == 1 && partWire == 0 {
						if field == 1 {
							property.FieldName = kotlinMetadataString(stringsTable, partInteger)
						} else {
							property.GetterName = kotlinMetadataString(stringsTable, partInteger)
						}
					}
				})
			})
		}
	})
	property.Visibility = kotlinMetadataVisibility(flags)
	property.Var = flags&kotlinPropertyFlagVar != 0
	property.Const = flags&kotlinPropertyFlagConst != 0
	property.Lateinit = flags&kotlinPropertyFlagLateinit != 0
	return property, valid && property.Name != ""
}

// kotlinDefaultGetterName is the accessor Kotlin generates for a property:
// `isEmpty` keeps its name, everything else gains `get`.
func kotlinDefaultGetterName(name string) string {
	if strings.HasPrefix(name, "is") && len(name) > 2 && !(name[2] >= 'a' && name[2] <= 'z') {
		return name
	}
	return "get" + strings.ToUpper(name[:1]) + name[1:]
}

// applyKotlinProperties gives a library's Kotlin properties symbols of their
// own. Before, only their accessors were indexed, so `pair.second`,
// `list.indices` and `coroutineContext` resolved to nothing in Kotlin while
// completion offered `getSecond()`, which Kotlin rejects. The accessors stay,
// as the Java view of the property.
func applyKotlinProperties(parsed *analysis.ParsedFile, ownerID, ownerFQN, packageName string, properties []kotlinMetadataProperty, classTypeParameters map[int]string) {
	if len(properties) == 0 {
		return
	}
	byName := make(map[string][]int)
	for index, symbol := range parsed.Symbols {
		if symbol.ContainerID == ownerID && (symbol.Kind == analysis.KindMethod || symbol.Kind == analysis.KindField) {
			byName[symbol.Name] = append(byName[symbol.Name], index)
		}
	}
	claimed := make(map[string]bool)
	for _, property := range properties {
		if property.Visibility == "private" || property.Visibility == "internal" {
			continue
		}
		receivers := 0
		if property.Receiver {
			receivers = 1
		}
		getter := property.GetterName
		if getter == "" {
			getter = kotlinDefaultGetterName(property.Name)
		}
		accessor := -1
		for _, index := range byName[getter] {
			if symbol := parsed.Symbols[index]; symbol.Kind == analysis.KindMethod && len(symbol.Parameters) == receivers && !claimed[symbol.ID] {
				accessor = index
				break
			}
		}
		if accessor < 0 && !property.Receiver {
			field := property.FieldName
			if field == "" {
				field = property.Name
			}
			for _, index := range byName[field] {
				if parsed.Symbols[index].Kind == analysis.KindField && !claimed[parsed.Symbols[index].ID] {
					accessor = index
					break
				}
			}
		}
		if accessor < 0 {
			continue
		}
		original := &parsed.Symbols[accessor]
		claimed[original.ID] = true
		if original.Kind == analysis.KindMethod {
			// Kotlin code reaches the property, never its accessor.
			original.InteropLanguage = analysis.LanguageJava
		}
		symbol := *original
		symbol.ID = original.ID + "#kotlin-property"
		symbol.OriginID = original.ID
		symbol.Name = property.Name
		symbol.JVMName = original.Name
		symbol.Kind = analysis.KindProperty
		// A property whose scope outlives its declaration is a local; the
		// accessor's whole-file scope would file this one with them.
		symbol.ScopeStartByte, symbol.ScopeEndByte = 0, 0
		symbol.Language = analysis.LanguageKotlin
		symbol.InteropLanguage = analysis.LanguageKotlin
		symbol.Parameters = nil
		symbol.TypeParameters = nil
		ids := make([]int, 0, len(property.TypeParameters))
		for id := range property.TypeParameters {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			symbol.TypeParameters = append(symbol.TypeParameters, property.TypeParameters[id])
		}
		symbol.TypeParameterBounds = nil
		symbol.ReceiverType = ""
		if property.Receiver && len(original.Parameters) > 0 {
			symbol.ReceiverType = kotlinMetadataReceiverType(original.Parameters[0].Type, kotlinMetadataCallable{ReceiverType: property.ReceiverType, TypeParameters: property.TypeParameters}, classTypeParameters)
		}
		symbol.Type = applyKotlinMetadataType(kotlinizeBinaryType(original.Type), property.Type, property.TypeParameters, classTypeParameters)
		modifiers := []string{property.Visibility}
		if property.Visibility == "" {
			modifiers[0] = "public"
		}
		keyword := "val"
		if property.Var {
			keyword = "var"
		}
		modifiers = append(modifiers, keyword)
		if property.Const {
			modifiers = append(modifiers, "const")
		}
		if property.Lateinit {
			modifiers = append(modifiers, "lateinit")
		}
		if ownerID == "" || ownerFQN == "" {
			symbol.ContainerID, symbol.ContainerName = "", ""
			symbol.Package = packageName
			symbol.FQN = property.Name
			if packageName != "" {
				symbol.FQN = packageName + "." + property.Name
			}
		} else {
			symbol.FQN = ownerFQN + "." + property.Name
		}
		symbol.Modifiers = modifiers
		signature := keyword + " "
		if symbol.ReceiverType != "" {
			signature += symbol.ReceiverType + "."
		}
		symbol.Signature = signature + property.Name + ": " + symbol.Type
		parsed.Symbols = append(parsed.Symbols, symbol)
	}
}
