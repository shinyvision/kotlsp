package dap

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/archiveio"
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

const (
	maxRequestedBreakpoints = 4096
	maxInstalledBreakpoints = 100_000
	maxSourceClasses        = 4096
	maxSourceBytes          = 64 << 20
	maxBreakpointTextBytes  = 64 << 10
	maxBreakpointPathBytes  = 32 << 10
)

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

func (s *session) setBreakpoints(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args breakpointRequest
	if decodeDAPArguments(raw, &args) != nil || args.Source.Path == "" && args.Source.Name == "" {
		return nil, false, "setBreakpoints requires a source"
	}
	if len(args.Source.Path) > maxBreakpointPathBytes || len(args.Source.Name) > maxBreakpointPathBytes || strings.IndexByte(args.Source.Path, 0) >= 0 || strings.IndexByte(args.Source.Name, 0) >= 0 {
		return nil, false, "breakpoint source name/path exceeds its size or NUL-safety limit"
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
	s.rememberSourceLocked(args.Source.Name, path)
	_, pathKnown := s.breakpoints[path]
	previous := append([]sourceBreakpoint(nil), s.breakpoints[path]...)
	s.stateMu.Unlock()
	debugger := s.currentDebugger()
	s.stateMu.Lock()
	classPaths := append([]string(nil), s.classPaths...)
	s.stateMu.Unlock()
	classesByLine, bytecodeAvailable, scanErr := s.cachedExecutableBytecodeClasses(requestContext(contexts), path, classPaths)
	if scanErr != nil {
		return nil, false, scanErr.Error()
	}
	ctx := requestContext(contexts)
	classes, classErr := sourceClassesContext(ctx, path)
	if classErr != nil {
		return nil, false, classErr.Error()
	}
	requested := args.Breakpoints
	if len(requested) == 0 {
		requested = make([]requestedBreakpoint, len(args.Lines))
		for index, line := range args.Lines {
			requested[index].Line = line
		}
	}
	if len(requested) > maxRequestedBreakpoints {
		return nil, false, "setBreakpoints exceeds its 4096-breakpoint safety limit"
	}
	response := make([]map[string]any, 0, len(requested))
	installedCapacity := len(requested) * min(len(classes), maxInstalledBreakpoints/max(1, len(requested)))
	installed := make([]sourceBreakpoint, 0, installedCapacity)
	seenLines := make(map[int]bool, len(requested))
	for index, requestedBreakpoint := range requested {
		line := requestedBreakpoint.Line
		textInvalid := len(requestedBreakpoint.Condition) > maxBreakpointTextBytes || len(requestedBreakpoint.LogMessage) > maxBreakpointTextBytes || len(requestedBreakpoint.HitCondition) > 256 || strings.IndexByte(requestedBreakpoint.Condition, 0) >= 0 || strings.IndexByte(requestedBreakpoint.LogMessage, 0) >= 0 || strings.IndexByte(requestedBreakpoint.HitCondition, 0) >= 0
		var hitCondition breakpointHitCondition
		var hitErr error
		if !textInvalid {
			hitCondition, hitErr = parseHitCondition(requestedBreakpoint.HitCondition)
		}
		verified := false
		message := ""
		if debugger == nil {
			message = "debugger is not attached"
		} else if line <= 0 {
			message = "line must be positive"
		} else if textInvalid {
			message = "breakpoint condition, hit condition, or log message exceeds its size/NUL safety limit"
		} else if hitErr != nil {
			message = hitErr.Error()
		} else if seenLines[line] {
			message = "duplicate source breakpoint line was ignored"
		} else {
			seenLines[line] = true
			lineClasses := classes
			if bytecodeAvailable {
				lineClasses = classesByLine[line]
				if len(lineClasses) == 0 {
					message = "no executable bytecode at requested source line"
				}
			}
			for _, className := range lineClasses {
				if len(installed) >= maxInstalledBreakpoints {
					return nil, false, "expanded source breakpoints exceed their 100000-location safety limit"
				}
				verified = true
				installed = append(installed, sourceBreakpoint{Class: className, Line: line, Source: source, Condition: requestedBreakpoint.Condition, HitCondition: hitCondition, LogMessage: requestedBreakpoint.LogMessage})
			}
		}
		entry := map[string]any{"id": index + 1, "verified": verified, "line": line, "column": 1, "source": source}
		if message != "" && !verified {
			entry["message"] = message
		}
		response = append(response, entry)
	}
	s.stateMu.Lock()
	totalInstalled := len(installed)
	for existingPath, values := range s.breakpoints {
		if existingPath != path {
			totalInstalled += len(values)
		}
		if totalInstalled > maxInstalledBreakpoints {
			break
		}
	}
	pathCount := len(s.breakpoints)
	s.stateMu.Unlock()
	if totalInstalled > maxInstalledBreakpoints {
		return nil, false, "session breakpoints exceed their 100000-location safety limit"
	}
	if !pathKnown && pathCount >= maxRememberedPath {
		return nil, false, "breakpoint source files exceed their 8192-path safety limit"
	}
	if debugger != nil {
		oldSpecs := make([]lineBreakpointSpec, 0, len(previous))
		for _, breakpoint := range previous {
			oldSpecs = append(oldSpecs, lineBreakpointSpec{Class: breakpoint.Class, Line: breakpoint.Line})
		}
		newSpecs := make([]lineBreakpointSpec, 0, len(installed))
		for _, breakpoint := range installed {
			newSpecs = append(newSpecs, lineBreakpointSpec{Class: breakpoint.Class, Line: breakpoint.Line})
		}
		if err := debugger.replaceLineBreakpoints(oldSpecs, newSpecs, contexts...); err != nil {
			return nil, false, "staged breakpoint replacement failed; Go metadata was not published: " + err.Error()
		}
	}
	s.stateMu.Lock()
	s.breakpoints[path] = installed
	s.stateMu.Unlock()
	return map[string]any{"breakpoints": response}, true, ""
}

func (s *session) setFunctionBreakpoints(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		Breakpoints []struct {
			Name string `json:"name"`
		} `json:"breakpoints"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid function breakpoints"
	}
	if len(args.Breakpoints) > maxRequestedBreakpoints {
		return nil, false, "function breakpoints exceed their 4096-item safety limit"
	}
	debugger := s.currentDebugger()
	names := make([]string, 0, len(args.Breakpoints))
	seen := make(map[string]bool, len(args.Breakpoints))
	for _, breakpoint := range args.Breakpoints {
		if breakpoint.Name == "" || len(breakpoint.Name) > maxBreakpointTextBytes || strings.IndexByte(breakpoint.Name, 0) >= 0 {
			continue
		}
		if !seen[breakpoint.Name] {
			seen[breakpoint.Name] = true
			names = append(names, breakpoint.Name)
		}
	}
	s.stateMu.Lock()
	previous := append([]string(nil), s.functionBreakpoints...)
	s.stateMu.Unlock()
	statuses := make(map[string][]string)
	if debugger != nil {
		var replaceErr error
		statuses, replaceErr = debugger.replaceFunctionBreakpoints(previous, names, contexts...)
		if replaceErr != nil {
			return nil, false, "staged function-breakpoint replacement failed; Go metadata was not published: " + replaceErr.Error()
		}
		s.stateMu.Lock()
		s.functionBreakpoints = append([]string(nil), names...)
		s.stateMu.Unlock()
	}
	response := make([]map[string]any, 0, len(args.Breakpoints))
	for index, breakpoint := range args.Breakpoints {
		verified := false
		message := ""
		if debugger == nil {
			message = "debugger is not attached"
		} else if breakpoint.Name == "" || len(breakpoint.Name) > maxBreakpointTextBytes || strings.IndexByte(breakpoint.Name, 0) >= 0 {
			message = "function name is empty or exceeds its safety limit"
		} else {
			status := statuses[breakpoint.Name]
			verified = len(status) >= 2 && status[0] == "true"
			if len(status) >= 2 {
				message = status[1]
			} else {
				message = "function breakpoint was not accepted by the debugger bridge"
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

func (s *session) setExceptionBreakpoints(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		Filters []string `json:"filters"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid exception breakpoints"
	}
	if len(args.Filters) > 32 {
		return nil, false, "exception breakpoint filters exceed their 32-item safety limit"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"breakpoints": []any{}}, true, ""
	}
	caught, uncaught := false, false
	for _, filter := range args.Filters {
		caught = caught || filter == "caught"
		uncaught = uncaught || filter == "uncaught"
	}
	if err := debugger.configureExceptions(caught, uncaught, contexts...); err != nil {
		return nil, false, err.Error()
	}
	return map[string]any{"breakpoints": []any{}}, true, ""
}

func breakpointLocations(raw json.RawMessage, classPaths ...string) (any, bool, string) {
	return (&session{breakpointCache: make(map[string]breakpointClassCacheEntry)}).breakpointLocationsContext(context.Background(), raw, classPaths...)
}

func (s *session) breakpointLocations(raw json.RawMessage, classPaths ...string) (any, bool, string) {
	return s.breakpointLocationsContext(context.Background(), raw, classPaths...)
}

func (s *session) breakpointLocationsContext(ctx context.Context, raw json.RawMessage, classPaths ...string) (any, bool, string) {
	var args struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Line    int `json:"line"`
		EndLine int `json:"endLine"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.Line <= 0 {
		return nil, false, "invalid breakpointLocations arguments"
	}
	if len(args.Source.Path) > maxBreakpointPathBytes || strings.IndexByte(args.Source.Path, 0) >= 0 {
		return nil, false, "breakpointLocations source path exceeds its size or NUL-safety limit"
	}
	end := args.EndLine
	if end < args.Line {
		end = args.Line
	}
	if end-args.Line > 10_000 {
		return nil, false, "breakpointLocations exceeds its 10000-line safety limit"
	}
	classes, bytecodeAvailable, scanErr := s.cachedExecutableBytecodeClasses(ctx, args.Source.Path, classPaths)
	if scanErr != nil {
		return nil, false, scanErr.Error()
	}
	executable := make(map[int]bool, len(classes))
	for line := range classes {
		executable[line] = true
	}
	if !bytecodeAvailable {
		executable, scanErr = executableSourceLinesContext(ctx, args.Source.Path)
		if scanErr != nil {
			return nil, false, scanErr.Error()
		}
	}
	breakpoints := make([]map[string]any, 0, end-args.Line+1)
	for line := args.Line; line <= end; line++ {
		if executable[line] {
			breakpoints = append(breakpoints, map[string]any{"line": line, "column": 1})
		}
	}
	return map[string]any{"breakpoints": breakpoints}, true, ""
}

type breakpointClassCacheEntry struct {
	lines     map[int][]string
	available bool
}

func (s *session) cachedExecutableBytecodeClasses(ctx context.Context, sourcePath string, classPaths []string) (map[int][]string, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(classPaths) > 4096 {
		return nil, false, fmt.Errorf("debug classpath exceeds its 4096-root safety limit")
	}
	var key strings.Builder
	for index, path := range append([]string{sourcePath}, classPaths...) {
		if index&63 == 0 && ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		key.WriteString(filepath.Clean(path))
		if info, err := os.Stat(path); err == nil {
			key.WriteString("|")
			key.WriteString(strconv.FormatInt(info.Size(), 10))
			key.WriteString("|")
			key.WriteString(info.ModTime().UTC().Format("20060102150405.000000000"))
		}
		key.WriteByte(0)
	}
	cacheKey := key.String()
	s.breakpointMu.Lock()
	if cached, ok := s.breakpointCache[cacheKey]; ok {
		s.breakpointMu.Unlock()
		return cached.lines, cached.available, nil
	}
	s.breakpointMu.Unlock()
	lines, available, err := executableBytecodeClassesContext(ctx, sourcePath, classPaths)
	if err != nil {
		return nil, false, err
	}
	s.breakpointMu.Lock()
	if len(s.breakpointCache) >= 128 {
		s.breakpointCache = make(map[string]breakpointClassCacheEntry)
	}
	s.breakpointCache[cacheKey] = breakpointClassCacheEntry{lines: lines, available: available}
	s.breakpointMu.Unlock()
	return lines, available, nil
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
	lines, available, _ := executableBytecodeClassesContext(context.Background(), sourcePath, classPaths)
	return lines, available
}

func executableBytecodeClassesContext(ctx context.Context, sourcePath string, classPaths []string) (map[int][]string, bool, error) {
	lines := make(map[int][]string)
	if sourcePath == "" {
		return lines, false, nil
	}
	if len(classPaths) > 4096 {
		return nil, false, fmt.Errorf("debug classpath exceeds its 4096-root safety limit")
	}
	classNames, classErr := sourceClassesContext(ctx, sourcePath)
	if classErr != nil {
		return nil, false, classErr
	}
	localBases := []string{strings.TrimSuffix(filepath.Base(sourcePath), filepath.Ext(sourcePath))}
	for _, className := range classNames {
		tail := className
		if dot := strings.LastIndexByte(tail, '.'); dot >= 0 {
			tail = tail[dot+1:]
		}
		localBases = appendUniqueString(localBases, tail)
	}
	classFiles, siblingErr := boundedSiblingClassFamilies(ctx, filepath.Dir(sourcePath), localBases)
	if siblingErr != nil {
		return nil, false, siblingErr
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
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if data, err := readBoundedFile(candidate, archiveio.MaxEntryBytes); err == nil {
			consume(data)
		}
	}
	const maxClasspathArchives = 512
	const maxArchiveEntries = 250_000
	archives, entries := 0, 0
	exhausted := false
classpathScan:
	for _, root := range classPaths {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		info, err := os.Stat(root)
		if err == nil && info.IsDir() {
			directoryBases := make(map[string][]string)
			for _, className := range classNames {
				if ctx.Err() != nil {
					return nil, false, ctx.Err()
				}
				candidate := filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(className, ".", "/"))+".class")
				directory := filepath.Dir(candidate)
				directoryBases[directory] = appendUniqueString(directoryBases[directory], strings.TrimSuffix(filepath.Base(candidate), ".class"))
			}
			for directory, bases := range directoryBases {
				matches, siblingErr := boundedSiblingClassFamilies(ctx, directory, bases)
				if siblingErr != nil {
					return nil, false, siblingErr
				}
				for _, match := range matches {
					if data, readErr := readBoundedFile(match, archiveio.MaxEntryBytes); readErr == nil {
						consume(data)
					}
				}
			}
			if available {
				break classpathScan
			}
			continue
		}
		if archives >= maxClasspathArchives {
			exhausted = true
			break
		}
		archive, openErr := zip.OpenReader(root)
		if openErr != nil {
			continue
		}
		budget, validateErr := archiveio.NewBudget(archive.File)
		if validateErr != nil {
			_ = archive.Close()
			return nil, false, validateErr
		}
		archives++
		wanted := make(map[string]bool, len(classNames))
		for _, className := range classNames {
			wanted[strings.ReplaceAll(className, ".", "/")] = true
		}
		for _, entry := range archive.File {
			entries++
			if entries&255 == 0 && ctx.Err() != nil {
				_ = archive.Close()
				return nil, false, ctx.Err()
			}
			if entries > maxArchiveEntries {
				exhausted = true
				break
			}
			classPath := strings.TrimSuffix(entry.Name, ".class")
			matched := wanted[classPath]
			for candidate := classPath; !matched; {
				nested := strings.LastIndexByte(candidate, '$')
				if nested < 0 {
					break
				}
				candidate = candidate[:nested]
				matched = wanted[candidate]
			}
			if !matched {
				continue
			}
			data, readErr := budget.ReadContext(ctx, entry, archiveio.MaxEntryBytes)
			if readErr == nil {
				consume(data)
			} else if errors.Is(readErr, archiveio.ErrArchiveBudget) {
				_ = archive.Close()
				return nil, false, readErr
			}
		}
		_ = archive.Close()
		if exhausted {
			break
		}
		// Classpath order is authoritative. Once one root supplies classes for
		// this source file, later duplicate artifacts cannot be the loaded copy.
		if available {
			break
		}
	}
	if exhausted {
		return nil, false, fmt.Errorf("executable-bytecode scan exceeded %d archives or %d entries", maxClasspathArchives, maxArchiveEntries)
	}
	for line := range lines {
		sort.Strings(lines[line])
	}
	return lines, available, nil
}

func requestContext(contexts []context.Context) context.Context {
	if len(contexts) > 0 && contexts[0] != nil {
		return contexts[0]
	}
	return context.Background()
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil {
		return nil, statErr
	} else if info.Size() > limit {
		return nil, archiveio.ErrEntryTooLarge
	}
	reader := &io.LimitedReader{R: file, N: limit + 1}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, archiveio.ErrEntryTooLarge
	}
	return data, nil
}

func boundedSiblingClassFamilies(ctx context.Context, directory string, bases []string) ([]string, error) {
	const (
		maxDirectoryEntries = 100_000
		maxClassMatches     = 4096
	)
	directoryHandle, err := os.Open(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer directoryHandle.Close()
	var out []string
	visited := 0
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		entries, readErr := directoryHandle.ReadDir(256)
		for _, entry := range entries {
			visited++
			if visited > maxDirectoryEntries {
				return nil, fmt.Errorf("class directory exceeds its 100000-entry safety limit")
			}
			name := entry.Name()
			matched := false
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(name), ".class") {
				stem := name[:len(name)-len(".class")]
				for _, base := range bases {
					if stem == base || strings.HasPrefix(stem, base+"$") {
						matched = true
						break
					}
				}
			}
			if matched {
				if len(out) >= maxClassMatches {
					return nil, fmt.Errorf("source class family exceeds its 4096-file safety limit")
				}
				out = append(out, filepath.Join(directory, name))
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	sort.Strings(out)
	return out, nil
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
	lines, _ := executableSourceLinesContext(context.Background(), path)
	return lines
}

func executableSourceLinesContext(ctx context.Context, path string) (map[int]bool, error) {
	result := make(map[int]bool)
	if path == "" {
		return result, nil
	}
	data, err := readBoundedFile(path, maxSourceBytes)
	if err != nil {
		return result, err
	}
	doc := textdoc.NewDocument(uriutil.File(path), strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), "."), 0, string(data))
	parsed := analysis.Parse(ctx, doc)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	callables := make([]analysis.Symbol, 0)
	for index, symbol := range parsed.Symbols {
		if index&255 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if analysis.IsCallableKind(symbol.Kind) {
			callables = append(callables, symbol)
		}
		if symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindProperty {
			result[symbol.SelectionRange.Start.Line+1] = true
		}
	}
	for index, reference := range parsed.References {
		if index&255 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		for _, callable := range callables {
			if callable.StartByte <= reference.StartByte && reference.EndByte <= callable.EndByte {
				result[reference.Range.Start.Line+1] = true
				break
			}
		}
	}
	lines := strings.Split(doc.Text, "\n")
	for index, line := range lines {
		if index&255 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "{" || trimmed == "}" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "package ") || strings.HasPrefix(trimmed, "import ") {
			continue
		}
		if strings.HasPrefix(trimmed, "return ") || strings.HasPrefix(trimmed, "throw ") || strings.HasPrefix(trimmed, "if ") || strings.HasPrefix(trimmed, "if(") || strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "for(") || strings.HasPrefix(trimmed, "while ") || strings.HasPrefix(trimmed, "while(") || strings.Contains(trimmed, "=") && !strings.Contains(trimmed, " class ") {
			result[index+1] = true
		}
	}
	return result, nil
}

var packagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`)
var javaTypePattern = regexp.MustCompile(`\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)`)
var kotlinTypePattern = regexp.MustCompile(`\b(?:class|interface|object|enum\s+class|annotation\s+class)\s+([A-Za-z_$][\w$]*)`)
var kotlinFileJVMNamePattern = regexp.MustCompile(`(?m)@file:(?:kotlin\.jvm\.)?JvmName\s*\(\s*"([^"]+)"\s*\)`)

func sourceClasses(path string) []string {
	classes, _ := sourceClassesContext(context.Background(), path)
	return classes
}

func sourceClassesContext(ctx context.Context, path string) ([]string, error) {
	data, err := readBoundedFile(path, maxSourceBytes)
	if err != nil {
		if os.IsNotExist(err) {
			base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			if base != "" {
				return []string{base}, nil
			}
		}
		return nil, err
	}
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
	parsed := analysis.Parse(ctx, textdoc.NewDocument(uriutil.File(path), strings.TrimPrefix(extension, "."), 0, text))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	byID := make(map[string]analysis.Symbol, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		byID[symbol.ID] = symbol
	}
	for _, symbol := range parsed.Symbols {
		if analysis.IsTypeKind(symbol.Kind) {
			if len(names) >= maxSourceClasses {
				return nil, fmt.Errorf("source declares more than %d debug-visible classes", maxSourceClasses)
			}
			names = append(names, binarySourceClass(symbol, byID))
		}
	}
	if extension != ".kt" && extension != ".kts" && len(names) == 0 {
		for _, match := range javaTypePattern.FindAllStringSubmatch(text, maxSourceClasses+1) {
			if len(names) >= maxSourceClasses {
				return nil, fmt.Errorf("source declares more than %d debug-visible classes", maxSourceClasses)
			}
			names = append(names, prefix+match[1])
		}
		if len(names) == 0 && base != "" {
			names = append(names, prefix+base)
		}
	}
	sort.Strings(names)
	return uniqueStrings(names), nil
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
