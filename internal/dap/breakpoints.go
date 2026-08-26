package dap

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

type requestedBreakpoint struct {
	Line         int    `json:"line"`
	Column       int    `json:"column"`
	Condition    string `json:"condition"`
	HitCondition string `json:"hitCondition"`
	LogMessage   string `json:"logMessage"`
}

type breakpointRequest struct {
	Source struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"source"`
	Breakpoints []requestedBreakpoint `json:"breakpoints"`
	Lines       []int                 `json:"lines"`
}

type breakpointHitCondition struct {
	operator string
	value    int
}

func parseHitCondition(value string) (breakpointHitCondition, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return breakpointHitCondition{}, nil
	}
	operator := "=="
	for _, candidate := range []string{">=", "<=", "==", ">", "<", "%"} {
		if strings.HasPrefix(value, candidate) {
			operator = candidate
			value = strings.TrimSpace(value[len(candidate):])
			break
		}
	}
	count, err := strconv.Atoi(value)
	if err != nil || count <= 0 {
		return breakpointHitCondition{}, fmt.Errorf("invalid hit condition; expected a positive count, %% count, or comparison")
	}
	return breakpointHitCondition{operator: operator, value: count}, nil
}

func (condition breakpointHitCondition) matches(hits int) bool {
	if condition.value == 0 {
		return true
	}
	switch condition.operator {
	case ">=":
		return hits >= condition.value
	case "<=":
		return hits <= condition.value
	case ">":
		return hits > condition.value
	case "<":
		return hits < condition.value
	case "%":
		return hits%condition.value == 0
	default:
		return hits == condition.value
	}
}

func (s *session) setBreakpoints(raw json.RawMessage) (any, bool, string) {
	var args breakpointRequest
	if json.Unmarshal(raw, &args) != nil || args.Source.Path == "" && args.Source.Name == "" {
		return nil, false, "setBreakpoints requires a source"
	}
	path := args.Source.Path
	if path == "" {
		path = args.Source.Name
	}
	if args.Source.Name == "" {
		args.Source.Name = filepath.Base(path)
	}
	source := map[string]any{"name": args.Source.Name, "path": path}
	s.stateMu.Lock()
	s.sourceByName[args.Source.Name] = path
	previous := append([]sourceBreakpoint(nil), s.breakpoints[path]...)
	s.stateMu.Unlock()
	debugger := s.currentDebugger()
	if debugger != nil {
		for _, old := range previous {
			_, _ = debugger.execute("clear " + old.Class + ":" + strconv.Itoa(old.Line))
		}
	}
	s.stateMu.Lock()
	classPaths := append([]string(nil), s.classPaths...)
	s.stateMu.Unlock()
	classesByLine, bytecodeAvailable := executableBytecodeClasses(path, classPaths)
	classes := sourceClasses(path)
	requested := args.Breakpoints
	if len(requested) == 0 {
		requested = make([]requestedBreakpoint, len(args.Lines))
		for index, line := range args.Lines {
			requested[index].Line = line
		}
	}
	response := make([]map[string]any, 0, len(requested))
	installed := make([]sourceBreakpoint, 0, len(requested)*len(classes))
	for index, requestedBreakpoint := range requested {
		line := requestedBreakpoint.Line
		hitCondition, hitErr := parseHitCondition(requestedBreakpoint.HitCondition)
		verified := false
		message := ""
		if debugger == nil {
			message = "debugger is not attached"
		} else if line <= 0 {
			message = "line must be positive"
		} else if hitErr != nil {
			message = hitErr.Error()
		} else {
			lineClasses := classes
			if bytecodeAvailable {
				lineClasses = classesByLine[line]
				if len(lineClasses) == 0 {
					message = "no executable bytecode at requested source line"
				}
			}
			for _, className := range lineClasses {
				lines, err := debugger.execute("stop at " + className + ":" + strconv.Itoa(line))
				if err != nil {
					message = err.Error()
					continue
				}
				text := strings.ToLower(strings.Join(lines, ""))
				if strings.Contains(text, "set breakpoint") || strings.Contains(text, "deferring breakpoint") {
					verified = true
					installed = append(installed, sourceBreakpoint{Class: className, Line: line, Source: source, Condition: requestedBreakpoint.Condition, HitCondition: hitCondition, LogMessage: requestedBreakpoint.LogMessage})
				} else if strings.Contains(text, "unable") || strings.Contains(text, "not found") {
					message = strings.TrimSpace(strings.Join(lines, ""))
				} else if strings.TrimSpace(strings.Join(lines, "")) != "" {
					message = strings.TrimSpace(strings.Join(lines, ""))
				}
			}
		}
		entry := map[string]any{"id": index + 1, "verified": verified, "line": line, "column": 1, "source": source}
		if message != "" && !verified {
			entry["message"] = message
		}
		response = append(response, entry)
	}
	s.stateMu.Lock()
	s.breakpoints[path] = installed
	s.stateMu.Unlock()
	return map[string]any{"breakpoints": response}, true, ""
}

func (s *session) setFunctionBreakpoints(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Breakpoints []struct {
			Name string `json:"name"`
		} `json:"breakpoints"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid function breakpoints"
	}
	debugger := s.currentDebugger()
	response := make([]map[string]any, 0, len(args.Breakpoints))
	for index, breakpoint := range args.Breakpoints {
		verified := false
		message := ""
		if debugger == nil {
			message = "debugger is not attached"
		} else if breakpoint.Name == "" {
			message = "function name is empty"
		} else {
			lines, err := debugger.execute("stop in " + breakpoint.Name)
			if err != nil {
				message = err.Error()
			} else {
				text := strings.ToLower(strings.Join(lines, ""))
				verified = strings.Contains(text, "set breakpoint") || strings.Contains(text, "deferring breakpoint")
				if !verified {
					message = strings.TrimSpace(strings.Join(lines, ""))
				}
			}
		}
		entry := map[string]any{"id": index + 1, "verified": verified}
		if message != "" {
			entry["message"] = message
		}
		response = append(response, entry)
	}
	return map[string]any{"breakpoints": response}, true, ""
}

func (s *session) setExceptionBreakpoints(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Filters []string `json:"filters"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid exception breakpoints"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"breakpoints": []any{}}, true, ""
	}
	_, _ = debugger.execute("ignore caught java.lang.Throwable")
	_, _ = debugger.execute("ignore uncaught java.lang.Throwable")
	for _, filter := range args.Filters {
		if filter == "caught" || filter == "uncaught" {
			_, _ = debugger.execute("catch " + filter + " java.lang.Throwable")
		}
	}
	return map[string]any{"breakpoints": []any{}}, true, ""
}

func breakpointLocations(raw json.RawMessage, classPaths ...string) (any, bool, string) {
	var args struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Line    int `json:"line"`
		EndLine int `json:"endLine"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Line <= 0 {
		return nil, false, "invalid breakpointLocations arguments"
	}
	end := args.EndLine
	if end < args.Line {
		end = args.Line
	}
	executable, bytecodeAvailable := executableBytecodeLines(args.Source.Path, classPaths)
	if !bytecodeAvailable {
		executable = executableSourceLines(args.Source.Path)
	}
	breakpoints := make([]map[string]any, 0, end-args.Line+1)
	for line := args.Line; line <= end; line++ {
		if executable[line] {
			breakpoints = append(breakpoints, map[string]any{"line": line, "column": 1})
		}
	}
	return map[string]any{"breakpoints": breakpoints}, true, ""
}

func executableBytecodeLines(sourcePath string, classPaths []string) (map[int]bool, bool) {
	classes, available := executableBytecodeClasses(sourcePath, classPaths)
	lines := make(map[int]bool)
	for line := range classes {
		lines[line] = true
	}
	return lines, available
}

func executableBytecodeClasses(sourcePath string, classPaths []string) (map[int][]string, bool) {
	lines := make(map[int][]string)
	if sourcePath == "" {
		return lines, false
	}
	classNames := sourceClasses(sourcePath)
	seenFiles := make(map[string]bool)
	var classFiles []string
	for _, className := range classNames {
		tail := className
		if dot := strings.LastIndexByte(tail, '.'); dot >= 0 {
			tail = tail[dot+1:]
		}
		candidate := filepath.Join(filepath.Dir(sourcePath), tail+".class")
		if !seenFiles[candidate] {
			seenFiles[candidate] = true
			classFiles = append(classFiles, candidate)
		}
	}
	base := strings.TrimSuffix(filepath.Base(sourcePath), filepath.Ext(sourcePath))
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(sourcePath), base+"*.class")); len(matches) > 0 {
		for _, candidate := range matches {
			if !seenFiles[candidate] {
				seenFiles[candidate] = true
				classFiles = append(classFiles, candidate)
			}
		}
	}
	available := false
	consume := func(data []byte) {
		parsed, err := classfile.Parse(data)
		if err != nil || parsed.SourceFile != "" && parsed.SourceFile != filepath.Base(sourcePath) {
			return
		}
		available = true
		className := strings.ReplaceAll(parsed.InternalName, "/", ".")
		for _, method := range parsed.Methods {
			for _, line := range method.LineNumbers {
				lines[line] = appendUniqueString(lines[line], className)
			}
		}
	}
	for _, candidate := range classFiles {
		if data, err := os.ReadFile(candidate); err == nil {
			consume(data)
		}
	}
	for _, root := range classPaths {
		info, err := os.Stat(root)
		if err == nil && info.IsDir() {
			for _, className := range classNames {
				candidate := filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(className, ".", "/"))+".class")
				base := strings.TrimSuffix(filepath.Base(candidate), ".class")
				matches, _ := filepath.Glob(filepath.Join(filepath.Dir(candidate), base+"*.class"))
				for _, match := range matches {
					if data, readErr := os.ReadFile(match); readErr == nil {
						consume(data)
					}
				}
			}
			continue
		}
		archive, openErr := zip.OpenReader(root)
		if openErr != nil {
			continue
		}
		wanted := make([]string, 0, len(classNames))
		for _, className := range classNames {
			wanted = append(wanted, strings.ReplaceAll(className, ".", "/"))
		}
		for _, entry := range archive.File {
			classPath := strings.TrimSuffix(entry.Name, ".class")
			matched := false
			for _, prefix := range wanted {
				if classPath == prefix || strings.HasPrefix(classPath, prefix+"$") {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			reader, readErr := entry.Open()
			if readErr != nil {
				continue
			}
			data := make([]byte, entry.UncompressedSize64)
			_, readErr = io.ReadFull(reader, data)
			_ = reader.Close()
			if readErr == nil {
				consume(data)
			}
		}
		_ = archive.Close()
	}
	for line := range lines {
		sort.Strings(lines[line])
	}
	return lines, available
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func executableSourceLines(path string) map[int]bool {
	result := make(map[int]bool)
	if path == "" {
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	doc := textdoc.NewDocument(uriutil.File(path), strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), "."), 0, string(data))
	parsed := analysis.Parse(context.Background(), doc)
	callables := make([]analysis.Symbol, 0)
	for _, symbol := range parsed.Symbols {
		if analysis.IsCallableKind(symbol.Kind) {
			callables = append(callables, symbol)
		}
		if symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindProperty {
			result[symbol.SelectionRange.Start.Line+1] = true
		}
	}
	for _, reference := range parsed.References {
		for _, callable := range callables {
			if callable.StartByte <= reference.StartByte && reference.EndByte <= callable.EndByte {
				result[reference.Range.Start.Line+1] = true
				break
			}
		}
	}
	lines := strings.Split(doc.Text, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "{" || trimmed == "}" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "package ") || strings.HasPrefix(trimmed, "import ") {
			continue
		}
		if strings.HasPrefix(trimmed, "return ") || strings.HasPrefix(trimmed, "throw ") || strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "if(") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "for(") || strings.HasPrefix(trimmed, "while ") || strings.HasPrefix(trimmed, "while(") || strings.Contains(trimmed, "=") && !strings.Contains(trimmed, " class ") {
			result[index+1] = true
		}
	}
	return result
}

var packagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
var javaTypePattern = regexp.MustCompile(`\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)`)
var kotlinTypePattern = regexp.MustCompile(`\b(?:class|interface|object|enum\s+class|annotation\s+class)\s+([A-Za-z_$][\w$]*)`)
var kotlinFileJVMNamePattern = regexp.MustCompile(`(?m)@file:(?:kotlin\.jvm\.)?JvmName\s*\(\s*"([^"]+)"\s*\)`)

func sourceClasses(path string) []string {
	data, _ := os.ReadFile(path)
	text := string(data)
	packageName := ""
	if match := packagePattern.FindStringSubmatch(text); len(match) == 2 {
		packageName = match[1]
	}
	prefix := ""
	if packageName != "" {
		prefix = packageName + "."
	}
	extension := strings.ToLower(filepath.Ext(path))
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	names := make([]string, 0, 8)
	if extension == ".kt" || extension == ".kts" {
		facade := kotlinFacadeName(base, text)
		names = append(names, prefix+facade)
	} else {
		_ = javaTypePattern // retained for the malformed-source fallback below.
	}
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uriutil.File(path), strings.TrimPrefix(extension, "."), 0, text))
	byID := make(map[string]analysis.Symbol, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		byID[symbol.ID] = symbol
	}
	for _, symbol := range parsed.Symbols {
		if analysis.IsTypeKind(symbol.Kind) {
			names = append(names, binarySourceClass(symbol, byID))
		}
	}
	if extension != ".kt" && extension != ".kts" && len(names) == 0 {
		for _, match := range javaTypePattern.FindAllStringSubmatch(text, -1) {
			names = append(names, prefix+match[1])
		}
		if len(names) == 0 && base != "" {
			names = append(names, prefix+base)
		}
	}
	sort.Strings(names)
	return uniqueStrings(names)
}

func binarySourceClass(symbol analysis.Symbol, byID map[string]analysis.Symbol) string {
	names := []string{symbol.Name}
	current := symbol
	for current.ContainerID != "" {
		parent, ok := byID[current.ContainerID]
		if !ok || !analysis.IsTypeKind(parent.Kind) {
			break
		}
		names = append(names, parent.Name)
		current = parent
	}
	for left, right := 0, len(names)-1; left < right; left, right = left+1, right-1 {
		names[left], names[right] = names[right], names[left]
	}
	result := strings.Join(names, "$")
	if current.Package != "" {
		result = current.Package + "." + result
	}
	return result
}

func kotlinFacadeName(base, source string) string {
	if match := kotlinFileJVMNamePattern.FindStringSubmatch(source); len(match) == 2 {
		return sanitizeClassIdentifier(match[1])
	}
	base = sanitizeClassIdentifier(base)
	if base == "" {
		base = "_"
	}
	runes := []rune(base)
	if runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] -= 'a' - 'A'
	}
	return string(runes) + "Kt"
}

func sanitizeClassIdentifier(value string) string {
	var out strings.Builder
	for index, r := range value {
		if r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || index > 0 && r >= '0' && r <= '9' {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

func uniqueStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if value == "" || len(result) > 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}
