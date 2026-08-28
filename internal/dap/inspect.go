package dap

import (
	"context"
	"strings"
)

// Variable inspection is implemented by JDI field reads and
// ArrayReference.getValues. It never calls getClass, toString, collection
// methods, accessors, or any other target method. Explicit DAP evaluate is the
// only operation routed through the JDK expression evaluator.

const maxInspectedChildren = 200

func expandableResult(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed != "null" && trimmed != "true" && trimmed != "false" && !allDigits(trimmed)
}

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
	debugger *jdiProcess
	session  *session
	frameID  int
	start    int
	count    int
	filter   string
}

func (s *session) inspectVariables(debugger *jdiProcess, frameID int, handle, _ string, start, count int, filter string, contexts ...context.Context) []map[string]any {
	insp := &inspector{debugger: debugger, session: s, frameID: frameID, start: start, count: count, filter: filter}
	values, err := debugger.children(handle, normalizedChildStart(start), normalizedChildCount(count), filter, contexts...)
	if err != nil {
		return []map[string]any{plainVariable("error", err.Error())}
	}
	variables := make([]map[string]any, 0, len(values))
	for _, value := range values {
		variables = append(variables, insp.child(value))
	}
	return variables
}

func normalizedChildStart(start int) int {
	if start < 0 {
		return 0
	}
	return start
}

func normalizedChildCount(count int) int {
	if count <= 0 || count > maxInspectedChildren {
		return maxInspectedChildren
	}
	return count
}

func plainVariable(name, value string) map[string]any {
	return map[string]any{"name": name, "value": value, "variablesReference": 0}
}

func (insp *inspector) child(value debugValue) map[string]any {
	variable := plainVariable(value.name, value.value)
	if value.evaluateName != "" {
		variable["evaluateName"] = value.evaluateName
	}
	if value.typeName != "" {
		variable["type"] = value.typeName
	}
	if value.indexed > 0 {
		variable["indexedVariables"] = value.indexed
	}
	if value.expandable {
		variable["variablesReference"] = insp.session.addVariableContext(variableContext{
			frameID: insp.frameID, expression: value.evaluateName, handle: value.handle, hint: value.value,
		})
	}
	return variable
}

func (insp *inspector) page(total int) (int, int) {
	start := normalizedChildStart(insp.start)
	if start > total {
		start = total
	}
	end := start + normalizedChildCount(insp.count)
	if end > total {
		end = total
	}
	return start, end
}
