package index

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// interopSymbols materializes the JVM source views which IntelliJ exposes
// across the Java/Kotlin boundary. They intentionally point back at the
// original declaration range and are hidden from document/workspace symbols.
func interopSymbols(file *analysis.ParsedFile) []analysis.Symbol {
	owners := make(map[string]bool)
	ownerSymbols := make(map[string]analysis.Symbol)
	recordOwners := make(map[string]bool)
	for _, symbol := range file.Symbols {
		if analysis.IsTypeKind(symbol.Kind) {
			owners[symbol.ID] = true
			ownerSymbols[symbol.ID] = symbol
			if symbol.Kind == analysis.KindRecord {
				recordOwners[symbol.ID] = true
			}
		}
	}
	var out []analysis.Symbol
	out = append(out, generatedSourceAPISymbols(file, ownerSymbols)...)
	if file.Language == analysis.LanguageKotlin {
		for _, property := range file.Symbols {
			if property.Kind != analysis.KindProperty || property.ContainerID == "" || !owners[property.ContainerID] || containsString(property.Modifiers, "JvmField") {
				continue
			}
			getter, setter := kotlinAccessorNames(property)
			out = append(out, interopSymbol(property, getter, analysis.KindMethod, property.Type, nil, analysis.LanguageJava))
			if containsString(property.Modifiers, "var") {
				parameter := analysis.Parameter{Name: "value", Type: property.Type, Range: property.SelectionRange}
				out = append(out, interopSymbol(property, setter, analysis.KindMethod, "void", []analysis.Parameter{parameter}, analysis.LanguageJava))
			}
		}
		var topLevel []analysis.Symbol
		for _, symbol := range file.Symbols {
			if symbol.ContainerID == "" && (analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty) {
				topLevel = append(topLevel, symbol)
			}
		}
		if len(topLevel) > 0 {
			facadeName := kotlinFacadeName(file)
			anchor := topLevel[0]
			facade := analysis.Symbol{ID: analysis.SymbolID(file.URI, anchor.StartByte, analysis.KindClass, facadeName), Name: facadeName, FQN: facadeName, Kind: analysis.KindClass, Language: analysis.LanguageKotlin, URI: file.URI, Range: anchor.Range, SelectionRange: anchor.SelectionRange, StartByte: anchor.StartByte, EndByte: anchor.EndByte, NameStartByte: anchor.NameStartByte, NameEndByte: anchor.NameEndByte, Package: file.Package, Modifiers: []string{"public", "final"}, Synthetic: true, InteropLanguage: analysis.LanguageJava, Signature: "class " + facadeName}
			if file.Package != "" {
				facade.FQN = file.Package + "." + facadeName
			}
			out = append(out, facade)
			for _, symbol := range topLevel {
				if analysis.IsCallableKind(symbol.Kind) {
					for overload, parameters := range jvmOverloadParameterSets(symbol) {
						name := symbol.Name
						if symbol.JVMName != "" {
							name = symbol.JVMName
						}
						projection := jvmMemberProjection(symbol, facade, name, analysis.KindMethod, symbol.Type, parameters, true)
						projection.ID += "#facade:" + itoa(overload)
						out = append(out, projection)
					}
				} else if containsString(symbol.Modifiers, "JvmField") || containsString(symbol.Modifiers, "const") {
					out = append(out, jvmMemberProjection(symbol, facade, symbol.Name, analysis.KindField, symbol.Type, nil, true))
				} else {
					getter, setter := kotlinAccessorNames(symbol)
					out = append(out, jvmMemberProjection(symbol, facade, getter, analysis.KindMethod, symbol.Type, nil, true))
					if containsString(symbol.Modifiers, "var") {
						out = append(out, jvmMemberProjection(symbol, facade, setter, analysis.KindMethod, "void", []analysis.Parameter{{Name: "value", Type: symbol.Type, Range: symbol.SelectionRange}}, true))
					}
				}
			}
		}
		for _, owner := range file.Symbols {
			if owner.Kind != analysis.KindObject {
				continue
			}
			if containsString(owner.Modifiers, "companion") {
				if enclosing, ok := ownerSymbols[owner.ContainerID]; ok {
					out = append(out, jvmMemberProjection(owner, enclosing, "Companion", analysis.KindField, owner.Name, nil, true))
				}
			} else {
				out = append(out, jvmMemberProjection(owner, owner, "INSTANCE", analysis.KindField, owner.Name, nil, true))
			}
		}
		for _, symbol := range file.Symbols {
			owner, hasOwner := ownerSymbols[symbol.ContainerID]
			if !hasOwner {
				continue
			}
			jvmName := symbol.Name
			if symbol.JVMName != "" {
				jvmName = symbol.JVMName
			}
			if analysis.IsCallableKind(symbol.Kind) && containsString(symbol.Modifiers, "JvmStatic") {
				projectionOwner, valid := owner, owner.Kind == analysis.KindObject && !containsString(owner.Modifiers, "companion")
				if containsString(owner.Modifiers, "companion") {
					projectionOwner, valid = ownerSymbols[owner.ContainerID]
				}
				if valid {
					for overload, parameters := range jvmOverloadParameterSets(symbol) {
						projection := jvmMemberProjection(symbol, projectionOwner, jvmName, analysis.KindMethod, symbol.Type, parameters, true)
						projection.ID += "#static:" + itoa(overload)
						out = append(out, projection)
					}
				}
				continue
			}
			if symbol.Kind == analysis.KindProperty && containsString(symbol.Modifiers, "JvmField") && containsString(owner.Modifiers, "companion") {
				if enclosing, ok := ownerSymbols[owner.ContainerID]; ok {
					out = append(out, jvmMemberProjection(symbol, enclosing, symbol.Name, analysis.KindField, symbol.Type, nil, true))
				}
				continue
			}
			if analysis.IsCallableKind(symbol.Kind) && symbol.JVMName != "" && !containsString(symbol.Modifiers, "JvmStatic") {
				for overload, parameters := range jvmOverloadParameterSets(symbol) {
					projection := jvmMemberProjection(symbol, owner, jvmName, analysis.KindMethod, symbol.Type, parameters, false)
					projection.ID += "#jvmname:" + itoa(overload)
					out = append(out, projection)
				}
				continue
			}
			if analysis.IsCallableKind(symbol.Kind) && containsString(symbol.Modifiers, "JvmOverloads") && !containsString(symbol.Modifiers, "JvmStatic") {
				sets := jvmOverloadParameterSets(symbol)
				for overload := 1; overload < len(sets); overload++ {
					projection := jvmMemberProjection(symbol, owner, symbol.Name, analysis.KindMethod, symbol.Type, sets[overload], false)
					projection.ID += "#overload:" + itoa(overload)
					out = append(out, projection)
				}
			}
		}
		return out
	}
	if file.Language != analysis.LanguageJava {
		return nil
	}
	for _, component := range file.Symbols {
		if component.Kind == analysis.KindProperty && recordOwners[component.ContainerID] {
			out = append(out, interopSymbol(component, component.Name, analysis.KindMethod, component.Type, nil, analysis.LanguageUnknown))
		}
	}
	// Prefer a getter as the navigation target. A write-only JavaBean still
	// contributes a Kotlin synthetic property through its setter.
	properties := make(map[string]analysis.Symbol)
	for _, method := range file.Symbols {
		if method.Kind != analysis.KindMethod || method.ContainerID == "" || !owners[method.ContainerID] || len(method.Parameters) != 0 {
			continue
		}
		name, ok := javaBeanGetterName(method)
		if ok {
			properties[method.ContainerID+"\x00"+name] = interopSymbol(method, name, analysis.KindProperty, kotlinizeBinaryType(method.Type), nil, analysis.LanguageKotlin)
		}
	}
	for _, method := range file.Symbols {
		if method.Kind != analysis.KindMethod || method.ContainerID == "" || !owners[method.ContainerID] || len(method.Parameters) != 1 || !strings.HasPrefix(method.Name, "set") {
			continue
		}
		name, ok := decapitalizeBean(method.Name[len("set"):])
		if !ok {
			continue
		}
		key := method.ContainerID + "\x00" + name
		if _, exists := properties[key]; !exists {
			properties[key] = interopSymbol(method, name, analysis.KindProperty, kotlinizeBinaryType(method.Parameters[0].Type), nil, analysis.LanguageKotlin)
		}
	}
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, properties[key])
	}
	return out
}

func kotlinFacadeName(file *analysis.ParsedFile) string {
	if file.JVMFacadeName != "" {
		return sanitizeJVMName(file.JVMFacadeName)
	}
	path, ok := uriutil.Path(file.URI)
	if !ok {
		path = string(file.URI)
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		name = "File"
	}
	name = sanitizeJVMName(name)
	if name == "" {
		name = "_"
	}
	runes := []rune(name)
	if runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] -= 'a' - 'A'
	}
	return string(runes) + "Kt"
}

func sanitizeJVMName(value string) string {
	var out strings.Builder
	for index, r := range value {
		valid := r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || index > 0 && r >= '0' && r <= '9'
		if valid {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

// generatedSourceAPISymbols exposes members which exist in compiler output
// even though no declaration node exists in source. They deliberately
// navigate to the owning type (or primary property for copy parameters),
// matching the useful source location an IDE can provide.
func generatedSourceAPISymbols(file *analysis.ParsedFile, owners map[string]analysis.Symbol) []analysis.Symbol {
	existing := make(map[string]bool)
	properties := make(map[string][]analysis.Symbol)
	for _, symbol := range file.Symbols {
		if symbol.ContainerID != "" {
			existing[symbol.ContainerID+"\x00"+symbol.Name+"\x00"+itoa(len(symbol.Parameters))] = true
		}
		if symbol.Kind == analysis.KindProperty && containsString(symbol.Modifiers, "constructor-property") {
			properties[symbol.ContainerID] = append(properties[symbol.ContainerID], symbol)
		}
	}
	var out []analysis.Symbol
	add := func(owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, modifiers ...string) {
		key := owner.ID + "\x00" + name + "\x00" + itoa(len(parameters))
		if existing[key] {
			return
		}
		existing[key] = true
		out = append(out, generatedMember(owner, name, kind, typ, parameters, modifiers))
	}
	for _, owner := range owners {
		if owner.Kind == analysis.KindEnum {
			arrayType := "Array<" + owner.Name + ">"
			if owner.Language == analysis.LanguageJava {
				arrayType = owner.Name + "[]"
			}
			add(owner, "values", analysis.KindMethod, arrayType, nil, "public", "static")
			add(owner, "valueOf", analysis.KindMethod, owner.Name, []analysis.Parameter{{Name: "value", Type: "String", Range: owner.SelectionRange}}, "public", "static")
			if owner.Language == analysis.LanguageKotlin {
				add(owner, "entries", analysis.KindProperty, "EnumEntries<"+owner.Name+">", nil, "public", "static", "val")
			}
		}
		if owner.Language != analysis.LanguageKotlin || owner.Kind != analysis.KindClass || !containsString(owner.Modifiers, "data") {
			continue
		}
		constructorProperties := properties[owner.ID]
		parameters := make([]analysis.Parameter, 0, len(constructorProperties))
		for index, property := range constructorProperties {
			parameters = append(parameters, analysis.Parameter{Name: property.Name, Type: property.Type, Default: "<default>", Range: property.SelectionRange})
			add(owner, "component"+itoa(index+1), analysis.KindMethod, property.Type, nil, "public", "operator")
		}
		add(owner, "copy", analysis.KindMethod, owner.Name, parameters, "public")
		add(owner, "equals", analysis.KindMethod, "Boolean", []analysis.Parameter{{Name: "other", Type: "Any?", Range: owner.SelectionRange}}, "public", "override")
		add(owner, "hashCode", analysis.KindMethod, "Int", nil, "public", "override")
		add(owner, "toString", analysis.KindMethod, "String", nil, "public", "override")
	}
	return out
}

func generatedMember(owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, modifiers []string) analysis.Symbol {
	member := analysis.Symbol{
		ID: owner.ID + "#generated:" + name + ":" + itoa(len(parameters)), Name: name,
		FQN: owner.FQN + "." + name, Kind: kind, Language: owner.Language,
		URI: owner.URI, Range: owner.Range, SelectionRange: owner.SelectionRange,
		StartByte: owner.StartByte, EndByte: owner.EndByte, NameStartByte: owner.NameStartByte, NameEndByte: owner.NameEndByte,
		ContainerID: owner.ID, ContainerName: owner.Name, Package: owner.Package,
		Type: typ, Parameters: parameters, Modifiers: append([]string(nil), modifiers...),
		Synthetic: true, OriginID: owner.ID, SourceURI: owner.URI, SourceRange: owner.SelectionRange,
	}
	var signature strings.Builder
	if kind == analysis.KindProperty {
		signature.WriteString(name + ": " + typ)
	} else {
		signature.WriteString(name)
		signature.WriteByte('(')
		for index, parameter := range parameters {
			if index > 0 {
				signature.WriteString(", ")
			}
			signature.WriteString(parameter.Name + ": " + parameter.Type)
			if parameter.Default != "" {
				signature.WriteString(" = " + parameter.Default)
			}
		}
		signature.WriteString("): " + typ)
	}
	member.Signature = signature.String()
	return member
}

func jvmOverloadParameterSets(symbol analysis.Symbol) [][]analysis.Parameter {
	full := make([]analysis.Parameter, len(symbol.Parameters))
	copy(full, symbol.Parameters)
	for index := range full {
		full[index].Default = ""
	}
	sets := [][]analysis.Parameter{full}
	if !containsString(symbol.Modifiers, "JvmOverloads") {
		return sets
	}
	for end := len(symbol.Parameters) - 1; end >= 0 && symbol.Parameters[end].Default != ""; end-- {
		parameters := make([]analysis.Parameter, end)
		copy(parameters, full[:end])
		sets = append(sets, parameters)
	}
	return sets
}

func jvmMemberProjection(origin, owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, static bool) analysis.Symbol {
	projection := interopSymbol(origin, name, kind, typ, parameters, analysis.LanguageJava)
	projection.ContainerID, projection.ContainerName = owner.ID, owner.Name
	projection.FQN = owner.FQN + "." + name
	projection.ID = analysis.SymbolID(origin.URI, origin.StartByte, kind, owner.Name+"."+name)
	if static && !containsString(projection.Modifiers, "static") {
		projection.Modifiers = append(projection.Modifiers, "static")
	}
	return projection
}

func interopSymbol(origin analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, visibleIn analysis.Language) analysis.Symbol {
	originID := origin.ID
	originalName := origin.Name
	origin.ID = analysis.SymbolID(origin.URI, origin.StartByte, kind, name)
	origin.Name = name
	if origin.FQN != "" {
		origin.FQN = strings.TrimSuffix(origin.FQN, "."+originalName) + "." + name
	}
	origin.Kind, origin.Type, origin.Parameters = kind, typ, parameters
	origin.Initializer, origin.ReceiverType = "", ""
	origin.Synthetic, origin.InteropLanguage = true, visibleIn
	if visibleIn != analysis.LanguageUnknown {
		origin.Language = visibleIn
	}
	origin.OriginID = originID
	if analysis.IsCallableKind(kind) {
		var signature strings.Builder
		signature.WriteString(name)
		signature.WriteByte('(')
		for index, parameter := range parameters {
			if index > 0 {
				signature.WriteString(", ")
			}
			signature.WriteString(parameter.Name)
			signature.WriteString(": ")
			signature.WriteString(parameter.Type)
		}
		signature.WriteByte(')')
		if typ != "" {
			signature.WriteString(": ")
			signature.WriteString(typ)
		}
		origin.Signature = signature.String()
	} else {
		origin.Signature = name + ": " + typ
	}
	return origin
}

func kotlinAccessorNames(property analysis.Symbol) (string, string) {
	name := property.Name
	if strings.HasPrefix(name, "is") && len(name) > 2 && name[2] >= 'A' && name[2] <= 'Z' && sameJvmType(property.Type, "boolean") {
		return name, "set" + name[2:]
	}
	stem := name
	if len(stem) > 0 && stem[0] >= 'a' && stem[0] <= 'z' {
		stem = strings.ToUpper(stem[:1]) + stem[1:]
	}
	return "get" + stem, "set" + stem
}

func javaBeanGetterName(method analysis.Symbol) (string, bool) {
	if strings.HasPrefix(method.Name, "get") && !sameJvmType(method.Type, "void") {
		return decapitalizeBean(method.Name[len("get"):])
	}
	if strings.HasPrefix(method.Name, "is") && sameJvmType(method.Type, "boolean") {
		return decapitalizeBean(method.Name[len("is"):])
	}
	return "", false
}

func decapitalizeBean(stem string) (string, bool) {
	if stem == "" || stem[0] < 'A' || stem[0] > 'Z' {
		return "", false
	}
	if len(stem) > 1 && stem[1] >= 'A' && stem[1] <= 'Z' {
		return stem, true // JavaBeans Introspector.decapitalize rule.
	}
	return strings.ToLower(stem[:1]) + stem[1:], true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
