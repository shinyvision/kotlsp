package index

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Spring Data derives repository queries from method names.  This model follows
// the clean-room reference algorithm in IntelliJ's PartTree, Part and
// PropertyPath implementations: split the subject at By, split predicates at
// uppercase-keyword boundaries, remove the operation suffix, then resolve the
// longest property name before recursively trying camel-case tails.

var springDataQueryPrefixes = []string{
	"find", "read", "get", "query", "stream", "search", "count", "update", "exists", "delete", "remove",
}

// Order matters only when two suffixes can end at the same byte.  Keeping the
// longest first makes the intent explicit and also covers newer Spring Data
// releases which add a longer spelling before an older short spelling.
var springDataOperationSuffixes = func() []string {
	values := []string{
		"IsNotContaining", "NotContaining", "IsStartingWith", "IsGreaterThanEqual", "GreaterThanEqual",
		"IsLessThanEqual", "LessThanEqual", "IsEndingWith", "StartingWith", "IsNotEmpty", "NotEmpty",
		"IsContaining", "NotContains", "Containing", "IsNotNull", "IsBetween", "IsGreaterThan",
		"GreaterThan", "IsLessThan", "LessThan", "EndingWith", "IsNotLike", "IsNotIn", "MatchesRegex",
		"StartsWith", "EndsWith", "IsWithin", "IsBefore", "IsAfter", "NotLike", "NotNull", "Between",
		"IsNot", "IsEmpty", "IsNull", "IsLike", "IsNear", "IsTrue", "IsFalse", "NotIn", "Matches",
		"Contains", "Within", "Before", "After", "NotEmpty", "Not", "Empty", "Null", "Like", "Near",
		"True", "False", "Regex", "Exists", "IsIn", "In", "Equals", "Is",
	}
	sort.SliceStable(values, func(a, b int) bool { return len(values[a]) > len(values[b]) })
	return values
}()

type springDataPropertySegment struct {
	start, end int
	symbol     analysis.Symbol
	valid      bool
}

func (i *Index) springDataDefinitionLocked(file *analysis.ParsedFile, offset int) ([]analysis.Symbol, bool) {
	for index := range file.Symbols {
		method := &file.Symbols[index]
		if !analysis.IsCallableKind(method.Kind) || method.ContainerID == "" || offset < method.NameStartByte || offset > method.NameEndByte {
			continue
		}
		segments, derived := i.springDataMethodSegmentsLocked(file, *method)
		if !derived {
			continue
		}
		for _, segment := range segments {
			if segment.start <= offset && offset <= segment.end {
				if segment.valid {
					return []analysis.Symbol{segment.symbol}, true
				}
				return nil, true
			}
		}
		// The subject and operation keywords are part of a derived method but do
		// not denote the method declaration.  Reporting this as handled prevents
		// definition from incorrectly returning the declaration itself.
		return nil, true
	}
	return nil, false
}

func (i *Index) springDataDiagnosticsLocked(file *analysis.ParsedFile) []protocol.Diagnostic {
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return nil
	}
	var result []protocol.Diagnostic
	for _, method := range file.Symbols {
		if !analysis.IsCallableKind(method.Kind) || method.ContainerID == "" {
			continue
		}
		segments, derived := i.springDataMethodSegmentsLocked(file, method)
		if !derived {
			continue
		}
		for _, segment := range segments {
			if segment.valid || segment.start < 0 || segment.end <= segment.start {
				continue
			}
			name := document.Text[segment.start:segment.end]
			result = append(result, protocol.Diagnostic{
				Range:    document.Range(segment.start, segment.end),
				Severity: 1,
				Code:     "spring-data-invalid-property",
				Source:   "kotlsp",
				Message:  "Cannot resolve property '" + lowerFirst(name) + "' for Spring Data repository query",
				Data:     map[string]any{"name": lowerFirst(name), "kind": "springDataProperty"},
			})
		}
	}
	return result
}

func (i *Index) springDataMethodSegmentsLocked(file *analysis.ParsedFile, method analysis.Symbol) ([]springDataPropertySegment, bool) {
	container := i.symbols[method.ContainerID]
	if container == nil || !analysis.IsTypeKind(container.Kind) || i.springDataMethodHasExplicitQueryLocked(file, method) {
		return nil, false
	}
	domainType, repository := i.springDataRepositoryDomainLocked(file, *container)
	if !repository || domainType == "" {
		return nil, false
	}
	name := method.Name
	by := springDataSubjectEnd(name)
	if by < 0 {
		return nil, false
	}
	predicateStart := by + len("By")
	if predicateStart >= len(name) {
		return nil, true
	}
	predicate := name[predicateStart:]
	if suffix := springDataTrailingKeyword(predicate, "AllIgnoreCase", "AllIgnoringCase"); suffix != "" {
		predicate = predicate[:len(predicate)-len(suffix)]
	}
	criteria, order := predicate, ""
	if at := springDataKeywordIndex(criteria, "OrderBy"); at >= 0 {
		criteria, order = criteria[:at], criteria[at+len("OrderBy"):]
	}
	absolute := method.NameStartByte + predicateStart
	result := i.springDataCriteriaSegmentsLocked(file, domainType, criteria, absolute, method.NameStartByte)
	if order != "" {
		orderAbsolute := absolute + len(criteria) + len("OrderBy")
		result = append(result, i.springDataOrderSegmentsLocked(file, domainType, order, orderAbsolute, method.NameStartByte)...)
	}
	return result, true
}

func (i *Index) springDataCriteriaSegmentsLocked(file *analysis.ParsedFile, domainType, source string, absolute, at int) []springDataPropertySegment {
	parts := springDataSplitKeywords(source, "Or", "And")
	result := make([]springDataPropertySegment, 0, len(parts))
	for _, part := range parts {
		property := strings.TrimSuffix(strings.TrimSuffix(part.text, "IgnoreCase"), "IgnoringCase")
		for _, suffix := range springDataOperationSuffixes {
			if strings.HasSuffix(property, suffix) {
				property = property[:len(property)-len(suffix)]
				break
			}
		}
		if property == "" {
			continue
		}
		result = append(result, i.resolveSpringDataPropertyPathLocked(file, domainType, property, absolute+part.start, at)...)
	}
	return result
}

func (i *Index) springDataOrderSegmentsLocked(file *analysis.ParsedFile, domainType, source string, absolute, at int) []springDataPropertySegment {
	var result []springDataPropertySegment
	for cursor := 0; cursor < len(source); {
		direction := -1
		directionLength := 0
		for search := cursor; search < len(source); {
			relative := springDataKeywordIndex(source[search:], "Asc")
			desc := springDataKeywordIndex(source[search:], "Desc")
			if relative < 0 || desc >= 0 && desc < relative {
				relative, directionLength = desc, len("Desc")
			} else {
				directionLength = len("Asc")
			}
			if relative < 0 {
				break
			}
			direction = search + relative
			break
		}
		end := len(source)
		if direction >= cursor {
			end = direction
		}
		if end > cursor {
			result = append(result, i.resolveSpringDataPropertyPathLocked(file, domainType, source[cursor:end], absolute+cursor, at)...)
		}
		if direction < 0 {
			break
		}
		cursor = direction + directionLength
	}
	return result
}

type springDataTextPart struct {
	text       string
	start, end int
}

func springDataSplitKeywords(source string, keywords ...string) []springDataTextPart {
	result := make([]springDataTextPart, 0, 2)
	start := 0
	for cursor := 0; cursor < len(source); {
		matched := ""
		for _, keyword := range keywords {
			if strings.HasPrefix(source[cursor:], keyword) && springDataKeywordBoundaryAfter(source, cursor+len(keyword)) {
				matched = keyword
				break
			}
		}
		if matched == "" {
			_, size := utf8.DecodeRuneInString(source[cursor:])
			cursor += size
			continue
		}
		if cursor > start {
			result = append(result, springDataTextPart{text: source[start:cursor], start: start, end: cursor})
		}
		cursor += len(matched)
		start = cursor
	}
	if start < len(source) {
		result = append(result, springDataTextPart{text: source[start:], start: start, end: len(source)})
	}
	return result
}

func springDataSubjectEnd(name string) int {
	prefixLength := 0
	for _, prefix := range springDataQueryPrefixes {
		if strings.HasPrefix(name, prefix) {
			prefixLength = len(prefix)
			break
		}
	}
	if prefixLength == 0 || prefixLength < len(name) && !springDataUpperAt(name, prefixLength) {
		return -1
	}
	for cursor := prefixLength; cursor+2 <= len(name); cursor++ {
		if name[cursor:cursor+2] == "By" && springDataKeywordBoundaryAfter(name, cursor+2) {
			return cursor
		}
	}
	return -1
}

func springDataKeywordIndex(source, keyword string) int {
	for cursor := 0; cursor+len(keyword) <= len(source); cursor++ {
		if strings.HasPrefix(source[cursor:], keyword) && springDataKeywordBoundaryAfter(source, cursor+len(keyword)) {
			return cursor
		}
	}
	return -1
}

func springDataKeywordBoundaryAfter(source string, end int) bool {
	return end == len(source) || springDataUpperAt(source, end)
}

func springDataUpperAt(source string, at int) bool {
	if at < 0 || at >= len(source) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(source[at:])
	return unicode.IsUpper(r) || r > unicode.MaxASCII
}

func springDataTrailingKeyword(source string, values ...string) string {
	for _, value := range values {
		if strings.HasSuffix(source, value) {
			return value
		}
	}
	return ""
}

func (i *Index) springDataRepositoryDomainLocked(file *analysis.ParsedFile, repository analysis.Symbol) (string, bool) {
	start := repository.FQN
	if start == "" {
		start = repository.Name
	}
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, start) {
		name := instantiated.symbol.FQN
		if name == "" {
			name = instantiated.symbol.Name
		}
		if springDataRepositoryType(name) && len(instantiated.arguments) > 0 {
			return instantiated.arguments[0], true
		}
	}
	// During incremental library publication the Spring type may not yet have a
	// symbol.  A direct, well-known repository supertype is still authoritative.
	for _, supertype := range repository.Supertypes {
		base, arguments := splitInstantiatedType(supertype)
		if springDataRepositoryType(base) && len(arguments) > 0 {
			return arguments[0], true
		}
	}
	return "", false
}

func springDataRepositoryType(name string) bool {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "org.springframework.data.") && strings.HasSuffix(name, "Repository") {
		return true
	}
	switch simpleType(name) {
	case "Repository", "CrudRepository", "ListCrudRepository", "PagingAndSortingRepository", "ListPagingAndSortingRepository", "ReactiveCrudRepository", "ReactiveSortingRepository", "RxJava3CrudRepository", "JpaRepository":
		return true
	default:
		return false
	}
}

func (i *Index) resolveSpringDataPropertyPathLocked(file *analysis.ParsedFile, ownerType, source string, absolute, at int) []springDataPropertySegment {
	if source == "" {
		return nil
	}
	// Underscore and dot are explicit traversal delimiters in PropertyPath.
	for cursor := 0; cursor < len(source); cursor++ {
		if source[cursor] != '_' && source[cursor] != '.' {
			continue
		}
		head := source[:cursor]
		resolved, nextType := i.springDataPropertyLocked(file, ownerType, head, at)
		segment := springDataPropertySegment{start: absolute, end: absolute + len(head), symbol: resolved, valid: resolved.ID != ""}
		if !segment.valid {
			return []springDataPropertySegment{segment}
		}
		return append([]springDataPropertySegment{segment}, i.resolveSpringDataPropertyPathLocked(file, nextType, source[cursor+1:], absolute+cursor+1, at)...)
	}
	if resolved, _ := i.springDataPropertyLocked(file, ownerType, source, at); resolved.ID != "" {
		return []springDataPropertySegment{{start: absolute, end: absolute + len(source), symbol: resolved, valid: true}}
	}
	// PropertyPath tries camel-case heads from right to left so addressZip wins
	// over address when both can lead to a valid path.
	boundaries := springDataCamelBoundaries(source)
	for boundaryIndex := len(boundaries) - 1; boundaryIndex >= 0; boundaryIndex-- {
		boundary := boundaries[boundaryIndex]
		head, tail := source[:boundary], source[boundary:]
		resolved, nextType := i.springDataPropertyLocked(file, ownerType, head, at)
		if resolved.ID == "" {
			continue
		}
		tailSegments := i.resolveSpringDataPropertyPathLocked(file, nextType, tail, absolute+boundary, at)
		if len(tailSegments) > 0 && tailSegments[len(tailSegments)-1].valid {
			return append([]springDataPropertySegment{{start: absolute, end: absolute + boundary, symbol: resolved, valid: true}}, tailSegments...)
		}
	}
	return []springDataPropertySegment{{start: absolute, end: absolute + len(source), valid: false}}
}

func springDataCamelBoundaries(source string) []int {
	var result []int
	for cursor := 1; cursor < len(source); {
		r, size := utf8.DecodeRuneInString(source[cursor:])
		if unicode.IsUpper(r) {
			result = append(result, cursor)
		}
		cursor += size
	}
	return result
}

func (i *Index) springDataPropertyLocked(file *analysis.ParsedFile, ownerType, encodedName string, at int) (analysis.Symbol, string) {
	propertyName := encodedName
	if !springDataAllUpper(encodedName) {
		propertyName = lowerFirst(encodedName)
	}
	ownerType = springDataCollectionElement(ownerType)
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, ownerType) {
		owner, arguments := instantiated.symbol, instantiated.arguments
		var getter *analysis.Symbol
		for _, candidateName := range []string{propertyName, "get" + upperFirst(propertyName), "is" + upperFirst(propertyName)} {
			for _, id := range i.byContainerMember[memberKey(owner.Name, candidateName)] {
				member := i.symbols[id]
				if member == nil || member.ContainerID != owner.ID || !i.accessibleLocked(file, *member, at) {
					continue
				}
				if candidateName == propertyName && !analysis.IsCallableKind(member.Kind) {
					return *member, substituteTypeParameters(member.Type, owner.TypeParameters, arguments)
				}
				if candidateName != propertyName && analysis.IsCallableKind(member.Kind) && len(member.Parameters) == 0 {
					getter = member
				}
			}
		}
		if getter != nil {
			return *getter, substituteTypeParameters(getter.Type, owner.TypeParameters, arguments)
		}
	}
	return analysis.Symbol{}, ""
}

func springDataCollectionElement(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
	if strings.HasSuffix(value, "[]") {
		return strings.TrimSpace(strings.TrimSuffix(value, "[]"))
	}
	base, arguments := splitInstantiatedType(value)
	if len(arguments) == 0 {
		return value
	}
	switch simpleType(base) {
	case "Collection", "Iterable", "List", "Set", "SortedSet", "NavigableSet", "Sequence", "Stream", "Optional":
		return arguments[0]
	default:
		return value
	}
}

func springDataAllUpper(value string) bool {
	hasLetter := false
	for _, r := range value {
		if unicode.IsLetter(r) {
			hasLetter = true
			if unicode.IsLower(r) {
				return false
			}
		}
	}
	return hasLetter
}

func lowerFirst(value string) string {
	if value == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(value)
	return string(unicode.ToLower(r)) + value[size:]
}

func upperFirst(value string) string {
	if value == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(value)
	return string(unicode.ToUpper(r)) + value[size:]
}

func (i *Index) springDataMethodHasExplicitQueryLocked(file *analysis.ParsedFile, method analysis.Symbol) bool {
	isDefault := false
	for _, modifier := range method.Modifiers {
		if modifier == "default" {
			isDefault = true
			break
		}
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	// Constructors deliberately reuse their owner's name range, and recovery
	// declarations can likewise begin after their recovered name.  Neither has
	// a sliceable declaration prefix.
	if document == nil || method.StartByte < 0 || method.StartByte > method.NameStartByte || method.NameStartByte > len(document.Text) {
		return isDefault
	}
	prefix := document.Text[method.StartByte:method.NameStartByte]
	if strings.Contains(prefix, "@Query") || strings.Contains(prefix, "@org.springframework.data.") && strings.Contains(prefix, ".Query") {
		return true
	}
	return isDefault
}
