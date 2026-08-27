package dap

import (
	"regexp"
	"strconv"
	"strings"
)

// Variable inspection: JDB's `dump` only exposes raw VM fields, so expanding a
// collection would show elementData/table/modCount instead of its elements,
// and expanding an array would show nothing at all. The inspector classifies
// the runtime type of an expression first (via the `instance of X[N]` hint a
// parent expansion already produced, or `getClass().getName()` plus the
// side-effect-free `class` command) and then synthesizes logical children:
// array elements, list/collection elements, and map entries. Everything else
// falls back to `dump`, including class-qualified inherited fields.
//
// JDB expression evaluation has no working `instanceof` (it answers
// "operation not yet supported") and method calls that throw at runtime poison
// the stopped frame, so classification never probes by invoking possibly
// missing methods; only parse-time failures are tolerated, and those degrade
// to a plain variable carrying the error text instead of failing the request.

const (
	// maxInspectedChildren bounds JDB roundtrips per expansion; huge
	// collections would otherwise stall the debug session.
	maxInspectedChildren = 200
	// maxPreviewLength keeps toString previews from flooding the client.
	maxPreviewLength = 200
)

type inspectKind int

const (
	kindUnknown inspectKind = iota
	kindList
	kindCollection
	kindMap
	kindCharSequence
	kindObject
)

// valueHint is the parsed form of JDB's `instance of X (id=N)` rendering,
// including the array form `instance of int[3] (id=N)` which conveniently
// carries the length.
type valueHint struct {
	typeName string // display type, e.g. Probe$Body or int[3]
	baseType string // class name without array dimensions
	isArray  bool
	length   int // array length when the hint carries it, else -1
}

var instanceHintPattern = regexp.MustCompile(`^instance of ([\w$.]+)((?:\[\d*\])*)\s*(?:\(id=\d+\))?$`)
var firstDimPattern = regexp.MustCompile(`\[(\d+)\]`)

func parseInstanceHint(value string) (valueHint, bool) {
	match := instanceHintPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return valueHint{}, false
	}
	hint := valueHint{typeName: match[1] + match[2], baseType: match[1], length: -1}
	if match[2] != "" {
		hint.isArray = true
		if dim := firstDimPattern.FindStringSubmatch(match[2]); dim != nil {
			hint.length, _ = strconv.Atoi(dim[1])
		}
	}
	return hint, true
}

// dumpFieldPattern accepts the class-qualified names JDB uses for inherited
// fields (`Probe$Organ.name`, `java.util.AbstractList.modCount`) as well as
// plain field names and constant-style statics.
var dumpFieldPattern = regexp.MustCompile(`^([\w$]+(?:\.[\w$]+)*)\s*:\s*(.*?),?$`)

type dumpField struct {
	name  string
	value string
}

// parseDumpFields reads the body of a `dump` on an object: everything between
// the `expr = {` opener and the closing brace, one `name: value` per line.
func parseDumpFields(lines []string) []dumpField {
	fields := make([]dumpField, 0)
	open := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !open {
			if strings.HasSuffix(trimmed, "= {") {
				open = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		match := dumpFieldPattern.FindStringSubmatch(trimmed)
		if match == nil {
			continue
		}
		fields = append(fields, dumpField{name: match[1], value: strings.TrimSpace(match[2])})
	}
	return fields
}

// splitArrayElements reads the body of a `dump` on an array: comma-separated
// values with no element names, possibly quoted strings containing commas.
func splitArrayElements(lines []string) ([]string, bool) {
	open := false
	var content strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !open {
			if strings.HasSuffix(trimmed, "= {") {
				open = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		content.WriteString(trimmed)
		content.WriteByte('\n')
	}
	if !open {
		return nil, false
	}
	return splitTopLevelElements(content.String()), true
}

func splitTopLevelElements(text string) []string {
	parts := make([]string, 0)
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, r := range text {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case inQuote && r == '\\':
			current.WriteRune(r)
			escaped = true
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ',' && !inQuote:
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
		case r == '\n' && !inQuote:
			// JDB wraps long element lists across lines; the newline is not
			// part of any element.
		default:
			current.WriteRune(r)
		}
	}
	if last := strings.TrimSpace(current.String()); last != "" {
		parts = append(parts, last)
	}
	return parts
}

// parseClassDetails extracts the direct superclass and interfaces from the
// output of JDB's `class <name>` command.
func parseClassDetails(lines []string) (superclass string, interfaces []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, "extends: "); ok {
			superclass = rest
		}
		if rest, ok := strings.CutPrefix(trimmed, "implements: "); ok {
			interfaces = append(interfaces, rest)
		}
	}
	return superclass, interfaces
}

func matchKnownKind(name string) inspectKind {
	switch name {
	case "java.util.List", "java.util.AbstractList":
		return kindList
	case "java.util.Map", "java.util.AbstractMap":
		return kindMap
	case "java.util.Collection", "java.util.AbstractCollection",
		"java.util.Set", "java.util.AbstractSet",
		"java.util.Queue", "java.util.Deque", "java.lang.Iterable":
		return kindCollection
	case "java.lang.CharSequence":
		return kindCharSequence
	}
	return kindUnknown
}

// jdbErrorText recognizes the failure lines JDB interleaves with command
// output, e.g. `com.sun.tools.example.debug.expr.ParseException: Name unknown:
// x` followed by an `x = null` echo.
func jdbErrorText(lines []string) string {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "operation not yet supported" {
			return trimmed
		}
		// Evaluating while no thread is suspended: surfaced when the client
		// hovers/evaluates without an active stop.
		if trimmed == "No frames on the current call stack" {
			return trimmed
		}
		if strings.HasPrefix(trimmed, "com.sun.") && strings.Contains(trimmed, "Exception:") {
			return trimmed
		}
	}
	return ""
}

// expandableResult decides whether an evaluate result is worth a
// variablesReference. Quoted values qualify on purpose: JDB renders every
// object with a toString() as a quoted preview (`"Probe$Body@4a8b1bab"`), so
// quotes cannot distinguish a plain String from an expandable object; the
// inspector resolves that lazily if the client actually expands it.
func expandableResult(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed != "null" && trimmed != "true" && trimmed != "false" && !allDigits(trimmed)
}

// childExpression composes the JDB expression for a child variable. Indexed
// children (`[0]`) append directly; inherited fields keep their unqualified
// name because JDB resolves it through the superclass (`print body.name`).
func childExpression(parent, name string) string {
	if strings.HasPrefix(name, "[") {
		return parent + name
	}
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		name = name[dot+1:]
	}
	return parent + "." + name
}

type inspector struct {
	debugger *jdbProcess
	session  *session
	frameID  int
	kinds    map[string]inspectKind
}

func (s *session) inspectVariables(debugger *jdbProcess, frameID int, expression, hint string) []map[string]any {
	insp := &inspector{debugger: debugger, session: s, frameID: frameID, kinds: make(map[string]inspectKind)}
	return insp.expand(expression, hint)
}

func plainVariable(name, value string) map[string]any {
	return map[string]any{"name": name, "value": value, "variablesReference": 0}
}

// print evaluates an expression and reports the value, or the JDB error text
// when evaluation failed. It never propagates an error to the DAP layer.
func (insp *inspector) print(expression string) (string, bool) {
	lines, err := insp.debugger.execute("print " + expression)
	if err != nil {
		return err.Error(), false
	}
	if text := jdbErrorText(lines); text != "" {
		return text, false
	}
	return parsePrintedValue(lines), true
}

func (insp *inspector) printLength(expression string) (int, bool) {
	value, ok := insp.print(expression)
	if !ok {
		return 0, false
	}
	length, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return length, true
}

func (insp *inspector) dumpElements(expression string) ([]string, bool) {
	lines, err := insp.debugger.execute("dump " + expression)
	if err != nil || jdbErrorText(lines) != "" {
		return nil, false
	}
	return splitArrayElements(lines)
}

// classNameOf asks the runtime class of an expression. Arrays do not support
// getClass in JDB's expression evaluator, so array classification always
// comes from the parent's instance-of hint instead.
func (insp *inspector) classNameOf(expression string) (string, bool) {
	value, ok := insp.print(expression + ".getClass().getName()")
	if !ok {
		return "", false
	}
	return strings.Trim(value, "\""), true
}

// classKind walks the superclass and interface chain with the side-effect-free
// `class` command until a known collection/string contract appears. One walk
// usually suffices: the common JDK implementations declare the interface
// directly.
func (insp *inspector) classKind(className string) inspectKind {
	if kind, ok := insp.kinds[className]; ok {
		return kind
	}
	kind := matchKnownKind(className)
	if kind == kindUnknown {
		kind = kindObject
		queue := []string{className}
		visited := make(map[string]bool)
		for depth := 0; depth < 8 && len(queue) > 0 && kind == kindObject; depth++ {
			current := queue[0]
			queue = queue[1:]
			if visited[current] {
				continue
			}
			visited[current] = true
			lines, err := insp.debugger.execute("class " + current)
			if err != nil || jdbErrorText(lines) != "" {
				continue
			}
			superclass, interfaces := parseClassDetails(lines)
			for _, related := range append([]string{superclass}, interfaces...) {
				if match := matchKnownKind(related); match != kindUnknown {
					kind = match
					break
				}
			}
			if kind == kindObject {
				if superclass != "" {
					queue = append(queue, superclass)
				}
				queue = append(queue, interfaces...)
			}
		}
	}
	insp.kinds[className] = kind
	return kind
}

// expand produces the DAP variables for an expression. hint is the parent-
// provided rendering of the expression's value (`instance of X (id=N)`,
// quoted text, `null`, ...) and saves a roundtrip when present.
func (insp *inspector) expand(expression, hint string) []map[string]any {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		value, ok := insp.print(expression)
		if !ok {
			return []map[string]any{plainVariable("error", value)}
		}
		hint = value
	}
	if parsed, ok := parseInstanceHint(hint); ok {
		if parsed.isArray {
			return insp.expandArray(expression, parsed)
		}
		return insp.expandObjectKind(expression, parsed.baseType)
	}
	if hint == "null" || hint == "true" || hint == "false" || allDigits(hint) {
		return []map[string]any{}
	}
	// Quoted or free-form text (a toString preview, a map entry's "arm=2"):
	// the runtime class decides whether there is anything to expand.
	className, ok := insp.classNameOf(expression)
	if !ok || className == "java.lang.String" {
		return []map[string]any{}
	}
	return insp.expandObjectKind(expression, className)
}

func (insp *inspector) expandObjectKind(expression, className string) []map[string]any {
	switch insp.classKind(className) {
	case kindList:
		return insp.expandList(expression)
	case kindCollection:
		return insp.expandCollection(expression)
	case kindMap:
		return insp.expandMap(expression)
	case kindCharSequence:
		return []map[string]any{}
	default:
		return insp.expandObject(expression)
	}
}

// child builds a variable whose value is an already-known rendering. Values
// carrying an instance-of hint become expandable; their display value is
// upgraded to the short toString preview when one is available.
func (insp *inspector) child(name, evaluateName, value string) map[string]any {
	variable := plainVariable(name, value)
	variable["evaluateName"] = evaluateName
	if _, ok := parseInstanceHint(value); !ok {
		return variable
	}
	return insp.upgrade(variable, evaluateName, value)
}

// upgrade attaches a variablesReference and type from the instance-of hint
// and swaps in the toString preview.
func (insp *inspector) upgrade(variable map[string]any, evaluateName, hint string) map[string]any {
	parsed, _ := parseInstanceHint(hint)
	variable["type"] = parsed.typeName
	variable["variablesReference"] = insp.session.addVariableContext(variableContext{frameID: insp.frameID, expression: evaluateName, hint: hint})
	if preview, ok := insp.print(evaluateName); ok && preview != "" && len(preview) <= maxPreviewLength {
		if _, isInstance := parseInstanceHint(preview); !isInstance {
			variable["value"] = preview
		}
	}
	return variable
}

func capChildren(children []map[string]any, total int) []map[string]any {
	if total <= maxInspectedChildren {
		return children
	}
	overflow := "… " + strconv.Itoa(total-maxInspectedChildren) + " more"
	return append(children, plainVariable(overflow, ""))
}

func (insp *inspector) expandArray(expression string, hint valueHint) []map[string]any {
	length := hint.length
	if length < 0 {
		n, ok := insp.printLength(expression + ".length")
		if !ok {
			return []map[string]any{}
		}
		length = n
	}
	elements, bulk := insp.dumpElements(expression)
	shown := min(length, maxInspectedChildren)
	children := make([]map[string]any, 0, shown)
	for i := 0; i < shown; i++ {
		name := "[" + strconv.Itoa(i) + "]"
		evaluateName := expression + name
		value := ""
		if bulk && i < len(elements) {
			value = elements[i]
		}
		if value == "" {
			if printed, ok := insp.print(evaluateName); ok {
				value = printed
			}
		}
		children = append(children, insp.child(name, evaluateName, value))
	}
	return capChildren(children, length)
}

// expandSequence lists the elements of a List (indexed through get) or any
// other Collection (indexed through a snapshot array). One `dump` of
// toArray() fetches every element rendering in a single roundtrip.
func (insp *inspector) expandSequence(expression string, isList bool) []map[string]any {
	size, ok := insp.printLength(expression + ".size()")
	if !ok {
		return insp.expandObject(expression)
	}
	elements, bulk := insp.dumpElements(expression + ".toArray()")
	shown := min(size, maxInspectedChildren)
	children := make([]map[string]any, 0, shown)
	for i := 0; i < shown; i++ {
		name := "[" + strconv.Itoa(i) + "]"
		evaluateName := expression + ".toArray()" + name
		if isList {
			evaluateName = expression + ".get(" + strconv.Itoa(i) + ")"
		}
		value := ""
		if bulk && i < len(elements) {
			value = elements[i]
		}
		if value == "" {
			if printed, ok := insp.print(evaluateName); ok {
				value = printed
			}
		}
		children = append(children, insp.child(name, evaluateName, value))
	}
	return capChildren(children, size)
}

func (insp *inspector) expandList(expression string) []map[string]any {
	return insp.expandSequence(expression, true)
}

func (insp *inspector) expandCollection(expression string) []map[string]any {
	return insp.expandSequence(expression, false)
}

// expandMap lists entries as `[i] = key=value`. Each entry keeps a
// variablesReference (the bulk dump of the entry array supplies its
// instance-of hint) so it can be expanded into key/value fields.
func (insp *inspector) expandMap(expression string) []map[string]any {
	size, ok := insp.printLength(expression + ".size()")
	if !ok {
		return insp.expandObject(expression)
	}
	entriesExpression := expression + ".entrySet().toArray()"
	hints, bulk := insp.dumpElements(entriesExpression)
	shown := min(size, maxInspectedChildren)
	children := make([]map[string]any, 0, shown)
	for i := 0; i < shown; i++ {
		name := "[" + strconv.Itoa(i) + "]"
		evaluateName := entriesExpression + name
		hint := ""
		if bulk && i < len(hints) {
			hint = hints[i]
		}
		value, ok := insp.print(evaluateName)
		if !ok || value == "" {
			value = hint
		}
		variable := plainVariable(name, value)
		variable["evaluateName"] = evaluateName
		if _, isInstance := parseInstanceHint(hint); isInstance {
			variable = insp.upgrade(variable, evaluateName, hint)
			variable["value"] = value
		}
		children = append(children, variable)
	}
	return capChildren(children, size)
}

// expandObject falls back to `dump`, keeping every field including statics
// and class-qualified inherited fields: for unknown types the raw internals
// are exactly what the user wants to see.
func (insp *inspector) expandObject(expression string) []map[string]any {
	lines, err := insp.debugger.execute("dump " + expression)
	if err != nil {
		return []map[string]any{plainVariable("error", err.Error())}
	}
	if text := jdbErrorText(lines); text != "" {
		return []map[string]any{plainVariable("error", text)}
	}
	fields := parseDumpFields(lines)
	shown := min(len(fields), maxInspectedChildren)
	children := make([]map[string]any, 0, shown)
	for _, field := range fields[:shown] {
		children = append(children, insp.child(field.name, childExpression(expression, field.name), field.value))
	}
	return capChildren(children, len(fields))
}
