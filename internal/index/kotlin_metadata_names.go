package index

import (
	"strings"
)

// kotlinPredefinedStrings is JvmNameResolverBase.PREDEFINED_STRINGS: the
// names a StringTableTypes record can refer to by index instead of storing
// them in d2. Kotlin's own class names are almost always written this way, so
// without the table every `MutableList` read as an empty name.
var kotlinPredefinedStrings = []string{
	"kotlin/Any", "kotlin/Nothing", "kotlin/Unit", "kotlin/Throwable", "kotlin/Number",
	"kotlin/Byte", "kotlin/Double", "kotlin/Float", "kotlin/Int", "kotlin/Long", "kotlin/Short", "kotlin/Boolean", "kotlin/Char",
	"kotlin/CharSequence", "kotlin/String", "kotlin/Comparable", "kotlin/Enum",
	"kotlin/Array", "kotlin/ByteArray", "kotlin/DoubleArray", "kotlin/FloatArray", "kotlin/IntArray", "kotlin/LongArray", "kotlin/ShortArray", "kotlin/BooleanArray", "kotlin/CharArray",
	"kotlin/Cloneable", "kotlin/Annotation",
	"kotlin/collections/Iterable", "kotlin/collections/MutableIterable",
	"kotlin/collections/Collection", "kotlin/collections/MutableCollection",
	"kotlin/collections/List", "kotlin/collections/MutableList",
	"kotlin/collections/Set", "kotlin/collections/MutableSet",
	"kotlin/collections/Map", "kotlin/collections/MutableMap",
	"kotlin/collections/Map.Entry", "kotlin/collections/MutableMap.MutableEntry",
	"kotlin/collections/Iterator", "kotlin/collections/MutableIterator",
	"kotlin/collections/ListIterator", "kotlin/collections/MutableListIterator",
}

// resolveKotlinStringTable expands JvmProtoBuf.StringTableTypes (the message
// in front of d1's body) over d2, the way JvmNameResolver does: each record
// covers `range` consecutive indexes and may substitute a literal or a
// predefined string, cut a substring, replace a character, or turn a JVM
// internal name/descriptor into a class id. Indexing d2 directly, as the
// decoder used to, is only right for names that need none of that.
func resolveKotlinStringTable(table []byte, strs []string) []string {
	type record struct {
		rangeSize     int
		predefined    int
		hasPredefined bool
		literal       string
		hasLiteral    bool
		operation     int
		substring     []int
		replaceChar   []int
	}
	var records []record
	protobufFields(table, func(number int, wire int, _ uint64, value []byte) {
		if number != 1 || wire != 2 {
			return
		}
		r := record{rangeSize: 1}
		protobufFields(value, func(field int, fieldWire int, integer uint64, bytes []byte) {
			switch {
			case field == 1 && fieldWire == 0:
				r.rangeSize = int(integer)
			case field == 2 && fieldWire == 0:
				r.predefined, r.hasPredefined = int(integer), true
			case field == 6 && fieldWire == 2:
				r.literal, r.hasLiteral = string(bytes), true
			case field == 3 && fieldWire == 0:
				r.operation = int(integer)
			case field == 4:
				r.substring = appendProtobufInts(r.substring, fieldWire, integer, bytes)
			case field == 5:
				r.replaceChar = appendProtobufInts(r.replaceChar, fieldWire, integer, bytes)
			}
		})
		records = append(records, r)
	})
	if len(records) == 0 {
		return strs
	}
	resolved := make([]string, 0, len(strs))
	for _, r := range records {
		for repeat := 0; repeat < r.rangeSize && len(resolved) < 1<<20; repeat++ {
			index := len(resolved)
			value := ""
			switch {
			case r.hasLiteral:
				value = r.literal
			case r.hasPredefined && r.predefined >= 0 && r.predefined < len(kotlinPredefinedStrings):
				value = kotlinPredefinedStrings[r.predefined]
			case index < len(strs):
				value = strs[index]
			}
			if len(r.substring) >= 2 {
				begin, end := r.substring[0], r.substring[1]
				runes := []rune(value)
				if 0 <= begin && begin <= end && end <= len(runes) {
					value = string(runes[begin:end])
				}
			}
			if len(r.replaceChar) >= 2 {
				value = strings.ReplaceAll(value, string(rune(r.replaceChar[0])), string(rune(r.replaceChar[1])))
			}
			switch r.operation {
			case 1: // INTERNAL_TO_CLASS_ID
				value = strings.ReplaceAll(value, "$", ".")
			case 2: // DESC_TO_CLASS_ID
				if len(value) >= 2 {
					value = value[1 : len(value)-1]
				}
				value = strings.ReplaceAll(value, "$", ".")
			}
			resolved = append(resolved, value)
		}
	}
	for index := len(resolved); index < len(strs); index++ {
		resolved = append(resolved, strs[index])
	}
	return resolved
}

func appendProtobufInts(values []int, wire int, integer uint64, packed []byte) []int {
	if wire == 0 {
		return append(values, int(integer))
	}
	for offset := 0; offset < len(packed); {
		value, size := protobufVarint(packed[offset:])
		if size == 0 {
			break
		}
		values = append(values, int(value))
		offset += size
	}
	return values
}

// kotlinShortClassSpellings are the classes the decoder has always spelled by
// simple name (kotlinizeBinaryType's targets and their Kotlin-only siblings);
// every other class keeps its qualified name so a call site's own `Result` or
// `Entry` can never capture it.
var kotlinShortClassSpellings = map[string]bool{
	"kotlin.Any": true, "kotlin.Nothing": true, "kotlin.Unit": true, "kotlin.Throwable": true, "kotlin.Number": true,
	"kotlin.Byte": true, "kotlin.Double": true, "kotlin.Float": true, "kotlin.Int": true, "kotlin.Long": true, "kotlin.Short": true,
	"kotlin.Boolean": true, "kotlin.Char": true, "kotlin.CharSequence": true, "kotlin.String": true, "kotlin.Comparable": true,
	"kotlin.Array": true, "kotlin.ByteArray": true, "kotlin.DoubleArray": true, "kotlin.FloatArray": true, "kotlin.IntArray": true,
	"kotlin.LongArray": true, "kotlin.ShortArray": true, "kotlin.BooleanArray": true, "kotlin.CharArray": true,
	"kotlin.collections.Iterable": true, "kotlin.collections.MutableIterable": true,
	"kotlin.collections.Collection": true, "kotlin.collections.MutableCollection": true,
	"kotlin.collections.List": true, "kotlin.collections.MutableList": true,
	"kotlin.collections.Set": true, "kotlin.collections.MutableSet": true,
	"kotlin.collections.Map": true, "kotlin.collections.MutableMap": true,
	"kotlin.collections.Iterator": true, "kotlin.collections.MutableIterator": true,
	"kotlin.collections.ListIterator": true, "kotlin.collections.MutableListIterator": true,
}

func kotlinMetadataClassSpelling(className string) (string, bool) {
	if className == "" || strings.HasPrefix(className, ".") {
		// A local class has no name a reader can write.
		return "", false
	}
	fqn := strings.ReplaceAll(className, "/", ".")
	if kotlinShortClassSpellings[fqn] {
		return fqn[strings.LastIndexByte(fqn, '.')+1:], true
	}
	if fqn == "kotlin.collections.Map.Entry" || fqn == "kotlin.collections.MutableMap.MutableEntry" {
		return strings.TrimPrefix(fqn, "kotlin.collections."), true
	}
	return fqn, true
}

// renderKotlinMetadataType spells a metadata type the way Kotlin source
// does, entirely from the metadata. The JVM signature cannot say MutableList
// from List, erases an inline class (`Result<T>` reads as Object) and a type
// parameter to its bound, so wherever the metadata names the class it is the
// authority. ok is false when some part is beyond the metadata (a type id
// into a type table, an unnamed type parameter); callers then keep the JVM
// spelling.
func renderKotlinMetadataType(metadata kotlinMetadataType, names ...map[int]string) (string, bool) {
	return renderKotlinMetadataTypeDepth(metadata, 0, names...)
}

func renderKotlinMetadataTypeDepth(metadata kotlinMetadataType, depth int, names ...map[int]string) (string, bool) {
	if !metadata.Present || depth > 32 {
		return "", false
	}
	nullable := ""
	if metadata.Nullable {
		nullable = "?"
	}
	if metadata.TypeParameterName != "" {
		return metadata.TypeParameterName + nullable, true
	}
	if metadata.TypeParameter > 0 {
		for _, table := range names {
			if name := table[metadata.TypeParameter-1]; name != "" {
				return name + nullable, true
			}
		}
		return "", false
	}
	base, ok := kotlinMetadataClassSpelling(metadata.ClassName)
	if !ok {
		return "", false
	}
	arguments := make([]string, 0, len(metadata.Arguments))
	for _, argument := range metadata.Arguments {
		if argument.Star {
			arguments = append(arguments, "*")
			continue
		}
		rendered, ok := renderKotlinMetadataTypeDepth(argument, depth+1, names...)
		if !ok {
			return "", false
		}
		switch argument.Projection {
		case 0:
			rendered = "in " + rendered
		case 1:
			rendered = "out " + rendered
		}
		arguments = append(arguments, rendered)
	}
	value := base
	if len(arguments) > 0 {
		value += "<" + strings.Join(arguments, ", ") + ">"
	}
	if function, ok := kotlinFunctionTypeFromBinary(value, metadata); ok {
		if metadata.Nullable {
			return "(" + function + ")?", true
		}
		return function, true
	}
	return value + nullable, true
}
