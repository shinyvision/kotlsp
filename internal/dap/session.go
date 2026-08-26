package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type debugFrame struct {
	threadToken string
	threadID    int
	index       int
	name        string
}

type variableContext struct {
	frameID    int
	expression string
}

type sourceBreakpoint struct {
	Class        string
	Line         int
	Source       map[string]any
	Condition    string
	HitCondition breakpointHitCondition
	LogMessage   string
	Hits         int
}

type session struct {
	ctx    context.Context
	cancel context.CancelFunc
	writer *bufio.Writer
	write  sync.Mutex
	seq    int

	debugMu  sync.Mutex
	debug    *jdbProcess
	debuggee *exec.Cmd
	launched bool

	stateMu       sync.Mutex
	threadIDs     map[string]int
	threadTokens  map[int]string
	nextThreadID  int
	frames        map[int]debugFrame
	nextFrameID   int
	variables     map[int]variableContext
	nextVariable  int
	breakpoints   map[string][]sourceBreakpoint
	sourceByName  map[string]string
	sourceRoots   []string
	sourceCache   map[string]string
	classPaths    []string
	lastException string
	lastStop      string
	terminated    atomic.Bool
}

func newSession(parent context.Context, writer *bufio.Writer) *session {
	ctx, cancel := context.WithCancel(parent)
	return &session{
		ctx: ctx, cancel: cancel, writer: writer, seq: 1,
		threadIDs: make(map[string]int), threadTokens: make(map[int]string), nextThreadID: 1,
		frames: make(map[int]debugFrame), nextFrameID: 1,
		variables: make(map[int]variableContext), nextVariable: 1,
		breakpoints: make(map[string][]sourceBreakpoint), sourceByName: make(map[string]string), sourceCache: make(map[string]string),
	}
}

func (s *session) close() {
	s.cancel()
	s.debugMu.Lock()
	if s.debug != nil {
		s.debug.close()
		s.debug = nil
	}
	if s.debuggee != nil && s.debuggee.Process != nil {
		_ = s.debuggee.Process.Kill()
	}
	s.debugMu.Unlock()
}

func (s *session) respond(request message, body any, success bool, responseText string) error {
	response := map[string]any{"type": "response", "request_seq": request.Seq, "success": success, "command": request.Command}
	if body != nil {
		response["body"] = body
	}
	if responseText != "" {
		response["message"] = responseText
	}
	return s.send(response)
}

func (s *session) event(name string, body any) error {
	event := map[string]any{"type": "event", "event": name}
	if body != nil {
		event["body"] = body
	}
	return s.send(event)
}

func (s *session) send(value map[string]any) error {
	s.write.Lock()
	defer s.write.Unlock()
	value["seq"] = s.seq
	s.seq++
	return writeMessage(s.writer, value)
}

func (s *session) dispatch(command string, raw json.RawMessage) (any, bool, string) {
	switch command {
	case "initialize":
		return dapCapabilities(), true, ""
	case "attach":
		return s.attach(raw)
	case "launch":
		return s.launch(raw)
	case "configurationDone":
		if debugger := s.currentDebugger(); debugger != nil {
			if err := debugger.send("cont"); err != nil {
				return nil, false, err.Error()
			}
			_ = s.event("continued", map[string]any{"threadId": 0, "allThreadsContinued": true})
		}
		return map[string]any{}, true, ""
	case "setBreakpoints":
		return s.setBreakpoints(raw)
	case "setFunctionBreakpoints":
		return s.setFunctionBreakpoints(raw)
	case "setExceptionBreakpoints":
		return s.setExceptionBreakpoints(raw)
	case "breakpointLocations":
		s.stateMu.Lock()
		classPaths := append([]string(nil), s.classPaths...)
		s.stateMu.Unlock()
		return breakpointLocations(raw, classPaths...)
	case "threads":
		return s.threads()
	case "stackTrace":
		return s.stackTrace(raw)
	case "scopes":
		return s.scopes(raw)
	case "variables":
		return s.variableValues(raw)
	case "evaluate":
		return s.evaluate(raw)
	case "setVariable":
		return s.setVariable(raw)
	case "setExpression":
		return s.setExpression(raw)
	case "continue":
		return s.resume("cont", raw, true)
	case "next":
		return s.resume("next", raw, false)
	case "stepIn":
		return s.resume("step", raw, false)
	case "stepOut":
		return s.resume("step up", raw, false)
	case "pause":
		return s.pause(raw)
	case "disconnect":
		s.disconnect(raw, false)
		return map[string]any{}, true, ""
	case "terminate":
		s.disconnect(raw, true)
		return map[string]any{}, true, ""
	case "loadedSources":
		return s.loadedSources(), true, ""
	case "modules":
		return map[string]any{"modules": []any{}, "totalModules": 0}, true, ""
	case "source":
		return nil, false, "sourceReference is not available; source paths are returned directly"
	case "completions":
		return s.completions(raw)
	case "exceptionInfo":
		return s.exceptionInfo(), true, ""
	case "cancel":
		return map[string]any{}, true, ""
	case "setDataBreakpoints", "setInstructionBreakpoints":
		return map[string]any{"breakpoints": []any{}}, true, ""
	case "dataBreakpointInfo":
		return map[string]any{"dataId": nil, "description": "JVM data breakpoints are unavailable"}, true, ""
	case "gotoTargets":
		return map[string]any{"targets": []any{}}, true, ""
	case "stepInTargets":
		return s.stepInTargets(raw)
	case "restartFrame":
		return s.restartFrame(raw)
	case "restart", "stepBack", "reverseContinue", "goto", "terminateThreads", "readMemory", "writeMemory", "disassemble", "locations":
		return nil, false, "debug request is not supported by the JDK debugger bridge: " + command
	default:
		return nil, false, "debug request is not supported: " + command
	}
}

func dapCapabilities() map[string]any {
	return map[string]any{
		"supportsConfigurationDoneRequest":   true,
		"supportsFunctionBreakpoints":        true,
		"supportsConditionalBreakpoints":     true,
		"supportsHitConditionalBreakpoints":  true,
		"supportsEvaluateForHovers":          true,
		"supportsStepBack":                   false,
		"supportsSetVariable":                true,
		"supportsRestartFrame":               true,
		"supportsGotoTargetsRequest":         false,
		"supportsStepInTargetsRequest":       true,
		"supportsCompletionsRequest":         true,
		"completionTriggerCharacters":        []string{"."},
		"supportsModulesRequest":             false,
		"supportsRestartRequest":             false,
		"supportsExceptionInfoRequest":       false,
		"supportTerminateDebuggee":           true,
		"supportsLoadedSourcesRequest":       false,
		"supportsLogPoints":                  true,
		"supportsTerminateThreadsRequest":    false,
		"supportsSetExpression":              false,
		"supportsTerminateRequest":           true,
		"supportsDataBreakpoints":            false,
		"supportsReadMemoryRequest":          false,
		"supportsWriteMemoryRequest":         false,
		"supportsDisassembleRequest":         false,
		"supportsCancelRequest":              false,
		"supportsBreakpointLocationsRequest": true,
		"supportsInstructionBreakpoints":     false,
		"exceptionBreakpointFilters": []any{
			map[string]any{"filter": "uncaught", "label": "Uncaught exceptions", "default": true},
			map[string]any{"filter": "caught", "label": "Caught exceptions", "default": false},
		},
	}
}

func (s *session) attach(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Port int    `json:"port"`
		Host string `json:"host"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Port <= 0 || args.Port > 65535 {
		return nil, false, "attach requires a valid JDWP port"
	}
	if args.Host == "" {
		args.Host = "127.0.0.1"
	}
	debugger, err := startJDB(s.ctx, "jdb", []string{"-attach", net.JoinHostPort(args.Host, strconv.Itoa(args.Port))}, "", nil, s.handleJDBOutput)
	if err != nil {
		return nil, false, err.Error()
	}
	s.debugMu.Lock()
	if s.debug != nil {
		s.debug.close()
	}
	s.debug = debugger
	s.launched = false
	s.debugMu.Unlock()
	return map[string]any{}, true, ""
}

type launchArguments struct {
	NoDebug          bool              `json:"noDebug"`
	MainClass        string            `json:"mainClass"`
	ModuleName       string            `json:"moduleName"`
	Args             []string          `json:"args"`
	VMArgs           []string          `json:"vmArgs"`
	ClassPaths       []string          `json:"classPaths"`
	ModulePaths      []string          `json:"modulePaths"`
	SourcePaths      []string          `json:"sourcePaths"`
	JavaExec         string            `json:"javaExec"`
	CWD              string            `json:"cwd"`
	Env              map[string]string `json:"env"`
	AdapterArguments *struct {
		MainClass   string            `json:"mainClass"`
		ModuleName  string            `json:"moduleName"`
		Args        []string          `json:"args"`
		VMArgs      []string          `json:"vmArgs"`
		ClassPaths  []string          `json:"classPaths"`
		ModulePaths []string          `json:"modulePaths"`
		SourcePaths []string          `json:"sourcePaths"`
		JavaExec    string            `json:"javaExec"`
		CWD         string            `json:"cwd"`
		Env         map[string]string `json:"env"`
	} `json:"adapterArguments"`
}

func (s *session) launch(raw json.RawMessage) (any, bool, string) {
	var args launchArguments
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, false, "invalid launch arguments: " + err.Error()
	}
	if args.AdapterArguments != nil {
		adapter := args.AdapterArguments
		args.MainClass, args.ModuleName, args.Args, args.VMArgs = adapter.MainClass, adapter.ModuleName, adapter.Args, adapter.VMArgs
		args.ClassPaths, args.ModulePaths, args.SourcePaths, args.JavaExec, args.CWD, args.Env = adapter.ClassPaths, adapter.ModulePaths, adapter.SourcePaths, adapter.JavaExec, adapter.CWD, adapter.Env
	}
	if args.MainClass == "" {
		return nil, false, "launch requires adapterArguments.mainClass"
	}
	searchPaths := append([]string(nil), args.ClassPaths...)
	searchPaths = append(searchPaths, args.ModulePaths...)
	for index, path := range searchPaths {
		if !filepath.IsAbs(path) && args.CWD != "" {
			searchPaths[index] = filepath.Join(args.CWD, path)
		}
	}
	s.stateMu.Lock()
	s.classPaths = searchPaths
	s.sourceRoots = debugSourceRoots(args.CWD, args.SourcePaths)
	s.sourceCache = make(map[string]string)
	s.stateMu.Unlock()
	javaExec := args.JavaExec
	if javaExec == "" {
		javaExec = "java"
	}
	javaArgs := append([]string(nil), args.VMArgs...)
	port := 0
	if !args.NoDebug {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, false, err.Error()
		}
		port = listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		javaArgs = append(javaArgs, fmt.Sprintf("-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:%d", port))
	}
	if len(args.ClassPaths) > 0 {
		javaArgs = append(javaArgs, "-classpath", strings.Join(args.ClassPaths, string(os.PathListSeparator)))
	}
	if len(args.ModulePaths) > 0 {
		javaArgs = append(javaArgs, "--module-path", strings.Join(args.ModulePaths, string(os.PathListSeparator)))
	}
	if args.ModuleName != "" {
		javaArgs = append(javaArgs, "--module", args.ModuleName+"/"+args.MainClass)
	} else {
		javaArgs = append(javaArgs, args.MainClass)
	}
	javaArgs = append(javaArgs, args.Args...)
	command := exec.CommandContext(s.ctx, javaExec, javaArgs...)
	command.Dir = args.CWD
	command.Env = mergedEnvironment(args.Env)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, false, err.Error()
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return nil, false, err.Error()
	}
	if err = command.Start(); err != nil {
		return nil, false, err.Error()
	}
	s.debugMu.Lock()
	s.debuggee = command
	s.launched = true
	s.debugMu.Unlock()
	go s.streamDebuggee(stdout, "stdout")
	go s.streamDebuggee(stderr, "stderr")
	go s.waitDebuggee(command)
	if args.NoDebug {
		return map[string]any{}, true, ""
	}

	jdbExec := "jdb"
	if filepath.IsAbs(javaExec) {
		candidate := filepath.Join(filepath.Dir(javaExec), "jdb")
		if _, statErr := os.Stat(candidate); statErr == nil {
			jdbExec = candidate
		}
	}
	var debugger *jdbProcess
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*25) * time.Millisecond)
		}
		debugger, err = startJDB(s.ctx, jdbExec, []string{"-attach", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}, args.CWD, mergedEnvironment(args.Env), s.handleJDBOutput)
		if err == nil {
			break
		}
	}
	if err != nil {
		_ = command.Process.Kill()
		return nil, false, "attach launched JVM: " + err.Error()
	}
	s.debugMu.Lock()
	s.debug = debugger
	s.debugMu.Unlock()
	return map[string]any{}, true, ""
}

func mergedEnvironment(values map[string]string) []string {
	environment := append([]string(nil), os.Environ()...)
	for key, value := range values {
		prefix := key + "="
		replaced := false
		for index := range environment {
			if strings.HasPrefix(environment[index], prefix) {
				environment[index] = prefix + value
				replaced = true
				break
			}
		}
		if !replaced {
			environment = append(environment, prefix+value)
		}
	}
	return environment
}

func (s *session) streamDebuggee(reader io.Reader, category string) {
	buffered := bufio.NewReader(reader)
	for {
		line, err := buffered.ReadString('\n')
		if line != "" {
			_ = s.event("output", map[string]any{"category": category, "output": line})
		}
		if err != nil {
			if err != io.EOF {
				_ = s.event("output", map[string]any{"category": "stderr", "output": "debuggee output error: " + err.Error() + "\n"})
			}
			return
		}
	}
}

func (s *session) waitDebuggee(command *exec.Cmd) {
	err := command.Wait()
	exitCode := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
		} else {
			exitCode = -1
		}
	}
	_ = s.event("exited", map[string]any{"exitCode": exitCode})
	s.emitTerminated()
}

func (s *session) currentDebugger() *jdbProcess {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	return s.debug
}

func (s *session) disconnect(raw json.RawMessage, force bool) {
	var args struct {
		TerminateDebuggee bool `json:"terminateDebuggee"`
	}
	_ = json.Unmarshal(raw, &args)
	s.debugMu.Lock()
	if s.debug != nil {
		s.debug.close()
		s.debug = nil
	}
	if s.debuggee != nil && s.debuggee.Process != nil && (force || args.TerminateDebuggee) {
		_ = s.debuggee.Process.Kill()
	}
	s.debugMu.Unlock()
	if force || args.TerminateDebuggee {
		s.emitTerminated()
	}
}

func (s *session) emitTerminated() {
	if s.terminated.CompareAndSwap(false, true) {
		_ = s.event("terminated", map[string]any{})
	}
}

var stoppedThreadPattern = regexp.MustCompile(`thread=([^",]+)`)
var stoppedLinePattern = regexp.MustCompile(`\bline=(\d+)\b`)
var stoppedClassPattern = regexp.MustCompile(`,\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\.[A-Za-z_$<][\w$<>]*\(\),\s*line=`)
var stoppedFramePattern = regexp.MustCompile(`,\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\.[A-Za-z_$<][\w$<>]*)\(\),\s*line=(\d+)`)

func (s *session) handleJDBOutput(output string) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || isJDBPrompt(output) {
		return
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "the application exited") || strings.Contains(lower, "vm disconnected") {
		s.emitTerminated()
		return
	}
	if strings.Contains(trimmed, "Exception occurred:") {
		s.stateMu.Lock()
		s.lastException = trimmed
		s.stateMu.Unlock()
	}
	reason := ""
	switch {
	case strings.Contains(trimmed, "Breakpoint hit:"):
		reason = "breakpoint"
	case strings.Contains(trimmed, "Step completed:"):
		reason = "step"
	case strings.Contains(trimmed, "Exception occurred:"):
		reason = "exception"
	case strings.Contains(trimmed, "Interrupted:"):
		reason = "pause"
	}
	if reason != "" {
		s.stateMu.Lock()
		s.lastStop = trimmed
		s.stateMu.Unlock()
		token := "main"
		if match := stoppedThreadPattern.FindStringSubmatch(trimmed); len(match) == 2 {
			token = strings.TrimSpace(match[1])
		}
		threadID := s.threadID(token)
		if reason == "breakpoint" {
			go s.handleBreakpointStop(trimmed, token, threadID)
			return
		}
		_ = s.event("stopped", map[string]any{"reason": reason, "threadId": threadID, "allThreadsStopped": true, "description": trimmed})
		return
	}
	_ = s.event("output", map[string]any{"category": "console", "output": output})
}

func (s *session) handleBreakpointStop(description, token string, threadID int) {
	// The event line is emitted immediately before JDB's prompt. Let the reader
	// publish that prompt before issuing condition/logpoint commands.
	time.Sleep(5 * time.Millisecond)
	line := 0
	if match := stoppedLinePattern.FindStringSubmatch(description); len(match) == 2 {
		line, _ = strconv.Atoi(match[1])
	}
	className := ""
	if match := stoppedClassPattern.FindStringSubmatch(description); len(match) == 2 {
		className = match[1]
	}
	var breakpoint sourceBreakpoint
	found := false
	s.stateMu.Lock()
	for path, values := range s.breakpoints {
		for index := range values {
			if line != 0 && values[index].Line != line || className != "" && values[index].Class != className {
				continue
			}
			values[index].Hits++
			breakpoint = values[index]
			s.breakpoints[path] = values
			found = true
			break
		}
		if found {
			break
		}
	}
	s.stateMu.Unlock()
	debugger := s.currentDebugger()
	if !found || debugger == nil {
		_ = s.event("stopped", map[string]any{"reason": "breakpoint", "threadId": threadID, "allThreadsStopped": true, "description": description})
		return
	}
	if !breakpoint.HitCondition.matches(breakpoint.Hits) {
		_ = debugger.send("cont")
		return
	}
	if breakpoint.Condition != "" {
		lines, err := debugger.execute("print " + breakpoint.Condition)
		if err == nil && !strings.EqualFold(strings.TrimSpace(parsePrintedValue(lines)), "true") {
			_ = debugger.send("cont")
			return
		}
	}
	if breakpoint.LogMessage != "" {
		message := s.renderLogPoint(debugger, breakpoint.LogMessage)
		_ = s.event("output", map[string]any{"category": "console", "output": message + "\n"})
		_ = debugger.send("cont")
		return
	}
	_ = s.event("stopped", map[string]any{"reason": "breakpoint", "threadId": threadID, "allThreadsStopped": true, "description": description})
}

func (s *session) renderLogPoint(debugger *jdbProcess, message string) string {
	var output strings.Builder
	for len(message) > 0 {
		open := strings.IndexByte(message, '{')
		if open < 0 {
			output.WriteString(message)
			break
		}
		close := strings.IndexByte(message[open+1:], '}')
		if close < 0 {
			output.WriteString(message)
			break
		}
		close += open + 1
		output.WriteString(message[:open])
		expression := strings.TrimSpace(message[open+1 : close])
		if expression != "" {
			if lines, err := debugger.execute("print " + expression); err == nil {
				output.WriteString(parsePrintedValue(lines))
			}
		}
		message = message[close+1:]
	}
	return output.String()
}

func (s *session) threadID(token string) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if id := s.threadIDs[token]; id != 0 {
		return id
	}
	id := s.nextThreadID
	s.nextThreadID++
	s.threadIDs[token] = id
	s.threadTokens[id] = token
	return id
}

func (s *session) threadIdentity(token, name string) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if id := s.threadIDs[token]; id != 0 {
		s.threadIDs[name] = id
		s.threadTokens[id] = token
		return id
	}
	if id := s.threadIDs[name]; id != 0 {
		s.threadIDs[token] = id
		s.threadTokens[id] = token
		return id
	}
	id := s.nextThreadID
	s.nextThreadID++
	s.threadIDs[token] = id
	s.threadIDs[name] = id
	s.threadTokens[id] = token
	return id
}

var threadPattern = regexp.MustCompile(`\)\s*(0x[0-9a-fA-F]+|\S+)\s+([^\s]+)\s+(?:running|sleeping|waiting|cond\. waiting|zombie)`)

func (s *session) threads() (any, bool, string) {
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"threads": []any{}}, true, ""
	}
	lines, err := debugger.execute("threads")
	if err != nil {
		return nil, false, err.Error()
	}
	threads := make([]map[string]any, 0)
	seen := map[string]bool{}
	for _, line := range lines {
		match := threadPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 || seen[match[1]] {
			continue
		}
		seen[match[1]] = true
		threads = append(threads, map[string]any{"id": s.threadIdentity(match[1], match[2]), "name": match[2]})
	}
	if len(threads) == 0 {
		// A stop event already carries a reliable JDB thread token. Some JDK
		// builds occasionally emit only a prompt for the immediately following
		// `threads` command; retain the observed stopped thread instead of
		// transiently reporting an empty VM.
		s.stateMu.Lock()
		seenIDs := make(map[int]bool)
		for name, id := range s.threadIDs {
			if id == 0 || seenIDs[id] || strings.HasPrefix(name, "0x") {
				continue
			}
			seenIDs[id] = true
			threads = append(threads, map[string]any{"id": id, "name": name})
		}
		s.stateMu.Unlock()
	}
	return map[string]any{"threads": threads}, true, ""
}

var framePattern = regexp.MustCompile(`^\s*\[(\d+)]\s+([^\s(]+)\s+\(([^():]+)(?::(\d+))?\)`)

func (s *session) stackTrace(raw json.RawMessage) (any, bool, string) {
	var args struct {
		ThreadID   int `json:"threadId"`
		StartFrame int `json:"startFrame"`
		Levels     int `json:"levels"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid stackTrace arguments"
	}
	token := s.tokenForThread(args.ThreadID)
	if token == "" {
		token = "main"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	whereCommand := "where"
	if validJDBThreadToken(token) {
		whereCommand += " " + token
	}
	lines, err := debugger.execute(whereCommand)
	if err != nil {
		return nil, false, err.Error()
	}
	frames := make([]map[string]any, 0)
	for _, line := range lines {
		match := framePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 0 {
			continue
		}
		index, _ := strconv.Atoi(match[1])
		lineNumber, _ := strconv.Atoi(match[4])
		if index-1 < args.StartFrame {
			continue
		}
		if args.Levels > 0 && len(frames) >= args.Levels {
			break
		}
		frameID := s.addFrame(debugFrame{threadToken: token, threadID: args.ThreadID, index: index, name: match[2]})
		source := map[string]any{"name": match[3]}
		if path := s.pathForSource(match[3], match[2]); path != "" {
			source["path"] = path
		}
		frames = append(frames, map[string]any{"id": frameID, "name": match[2], "source": source, "line": lineNumber, "column": 1})
	}
	if len(frames) == 0 {
		// JDB occasionally emits a bare prompt for the first `where` immediately
		// after a stop. The stop notification itself contains the top frame and
		// source line, so preserve that complete observable state.
		s.stateMu.Lock()
		stop := s.lastStop
		s.stateMu.Unlock()
		if match := stoppedFramePattern.FindStringSubmatch(stop); len(match) == 3 {
			lineNumber, _ := strconv.Atoi(match[2])
			name := match[1]
			sourceName := name
			if dot := strings.LastIndexByte(sourceName, '.'); dot >= 0 {
				sourceName = sourceName[:dot]
			}
			if dot := strings.LastIndexByte(sourceName, '.'); dot >= 0 {
				sourceName = sourceName[dot+1:]
			}
			sourceName += ".java"
			source := map[string]any{"name": sourceName}
			if path := s.pathForSource(sourceName, name); path != "" {
				source["path"] = path
			}
			frameID := s.addFrame(debugFrame{threadToken: token, threadID: args.ThreadID, index: 1, name: name})
			frames = append(frames, map[string]any{"id": frameID, "name": name, "source": source, "line": lineNumber, "column": 1})
		}
	}
	return map[string]any{"stackFrames": frames, "totalFrames": len(frames)}, true, ""
}

func (s *session) tokenForThread(id int) string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.threadTokens[id]
}

func (s *session) addFrame(frame debugFrame) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	id := s.nextFrameID
	s.nextFrameID++
	s.frames[id] = frame
	return id
}

func (s *session) scopes(raw json.RawMessage) (any, bool, string) {
	var args struct {
		FrameID int `json:"frameId"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid scopes arguments"
	}
	s.stateMu.Lock()
	_, ok := s.frames[args.FrameID]
	s.stateMu.Unlock()
	if !ok {
		return nil, false, "unknown stack frame"
	}
	reference := s.addVariableContext(variableContext{frameID: args.FrameID})
	return map[string]any{"scopes": []any{map[string]any{"name": "Locals", "presentationHint": "locals", "variablesReference": reference, "expensive": false}}}, true, ""
}

func (s *session) addVariableContext(value variableContext) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	id := s.nextVariable
	s.nextVariable++
	s.variables[id] = value
	return id
}

var localPattern = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*=\s*(.*)$`)
var fieldPattern = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*:\s*(.*?)[,}]?$`)

func (s *session) variableValues(raw json.RawMessage) (any, bool, string) {
	var args struct {
		VariablesReference int `json:"variablesReference"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid variables arguments"
	}
	s.stateMu.Lock()
	contextValue, ok := s.variables[args.VariablesReference]
	s.stateMu.Unlock()
	if !ok {
		return nil, false, "unknown variables reference"
	}
	frame, ok := s.selectFrame(contextValue.frameID)
	if !ok {
		return nil, false, "unknown stack frame"
	}
	command := "locals"
	pattern := localPattern
	if contextValue.expression != "" {
		command = "dump " + contextValue.expression
		pattern = fieldPattern
	}
	debugger := s.currentDebugger()
	lines, err := debugger.execute(command)
	if err != nil {
		return nil, false, err.Error()
	}
	variables := make([]map[string]any, 0)
	for _, line := range lines {
		match := pattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		name, value := match[1], strings.TrimSpace(match[2])
		expression := name
		if contextValue.expression != "" {
			expression = contextValue.expression + "." + name
		}
		reference := 0
		if looksExpandable(value) {
			reference = s.addVariableContext(variableContext{frameID: contextValue.frameID, expression: expression})
		}
		variables = append(variables, map[string]any{"name": name, "value": value, "variablesReference": reference, "evaluateName": expression})
	}
	_ = frame
	return map[string]any{"variables": variables}, true, ""
}

func looksExpandable(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "null" && !strings.HasPrefix(value, "\"") && value != "true" && value != "false" && !allDigits(value)
}

func allDigits(value string) bool {
	value = strings.TrimSuffix(strings.TrimSuffix(value, "L"), "l")
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

func (s *session) selectFrame(frameID int) (debugFrame, bool) {
	s.stateMu.Lock()
	frame, ok := s.frames[frameID]
	s.stateMu.Unlock()
	if !ok {
		return debugFrame{}, false
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return debugFrame{}, false
	}
	if validJDBThreadToken(frame.threadToken) {
		if _, err := debugger.execute("thread " + frame.threadToken); err != nil {
			return debugFrame{}, false
		}
	}
	if frame.index > 1 {
		if _, err := debugger.execute("up " + strconv.Itoa(frame.index-1)); err != nil {
			return debugFrame{}, false
		}
	}
	return frame, true
}

func validJDBThreadToken(token string) bool {
	return strings.HasPrefix(token, "0x") || allDigits(token)
}

func (s *session) restartFrame(raw json.RawMessage) (any, bool, string) {
	var args struct {
		FrameID int `json:"frameId"`
	}
	if json.Unmarshal(raw, &args) != nil || args.FrameID <= 0 {
		return nil, false, "restartFrame requires a frameId"
	}
	_, ok := s.selectFrame(args.FrameID)
	if !ok {
		return nil, false, "unknown stack frame"
	}
	debugger := s.currentDebugger()
	lines, err := debugger.execute("reenter")
	if err != nil {
		return nil, false, err.Error()
	}
	joined := strings.ToLower(strings.Join(lines, ""))
	if strings.Contains(joined, "error") || strings.Contains(joined, "cannot") {
		return nil, false, strings.TrimSpace(strings.Join(lines, ""))
	}
	return map[string]any{}, true, ""
}

func (s *session) stepInTargets(raw json.RawMessage) (any, bool, string) {
	var args struct {
		FrameID int `json:"frameId"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid stepInTargets arguments"
	}
	s.stateMu.Lock()
	frame, ok := s.frames[args.FrameID]
	s.stateMu.Unlock()
	if !ok {
		return map[string]any{"targets": []any{}}, true, ""
	}
	return map[string]any{"targets": []any{map[string]any{"id": args.FrameID, "label": frame.name}}}, true, ""
}

func (s *session) completions(raw json.RawMessage) (any, bool, string) {
	var args struct {
		FrameID int    `json:"frameId"`
		Text    string `json:"text"`
		Column  int    `json:"column"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid completions arguments"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"targets": []any{}}, true, ""
	}
	lines, err := debugger.execute("locals")
	if err != nil {
		return nil, false, err.Error()
	}
	prefix := args.Text
	if args.Column > 0 && args.Column-1 < len(prefix) {
		prefix = prefix[:args.Column-1]
	}
	for len(prefix) > 0 {
		last := prefix[len(prefix)-1]
		if last == '_' || last == '$' || last >= 'a' && last <= 'z' || last >= 'A' && last <= 'Z' || last >= '0' && last <= '9' {
			break
		}
		prefix = prefix[:len(prefix)-1]
	}
	if at := strings.LastIndexAny(prefix, " .()[]{};,+-*/=!<>"); at >= 0 {
		prefix = prefix[at+1:]
	}
	targets := make([]map[string]any, 0)
	seen := make(map[string]bool)
	for _, line := range lines {
		match := localPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 || seen[match[1]] || !strings.HasPrefix(match[1], prefix) {
			continue
		}
		seen[match[1]] = true
		targets = append(targets, map[string]any{"label": match[1], "text": match[1], "type": "variable"})
	}
	return map[string]any{"targets": targets}, true, ""
}

func (s *session) evaluate(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Expression string `json:"expression"`
		FrameID    int    `json:"frameId"`
	}
	if json.Unmarshal(raw, &args) != nil || strings.TrimSpace(args.Expression) == "" {
		return nil, false, "evaluate requires an expression"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	lines, err := debugger.execute("print " + args.Expression)
	if err != nil {
		return nil, false, err.Error()
	}
	value := parsePrintedValue(lines)
	reference := 0
	if args.FrameID != 0 && looksExpandable(value) {
		reference = s.addVariableContext(variableContext{frameID: args.FrameID, expression: args.Expression})
	}
	return map[string]any{"result": value, "variablesReference": reference}, true, ""
}

func parsePrintedValue(lines []string) string {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if at := strings.Index(trimmed, " = "); at >= 0 {
			return strings.TrimSpace(trimmed[at+3:])
		}
	}
	return strings.TrimSpace(strings.Join(lines, ""))
}

func (s *session) setVariable(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Name               string `json:"name"`
		Value              string `json:"value"`
		VariablesReference int    `json:"variablesReference"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Name == "" {
		return nil, false, "invalid setVariable arguments"
	}
	s.stateMu.Lock()
	variable := s.variables[args.VariablesReference]
	s.stateMu.Unlock()
	if _, ok := s.selectFrame(variable.frameID); !ok {
		return nil, false, "unknown stack frame"
	}
	expression := args.Name
	if variable.expression != "" {
		expression = variable.expression + "." + args.Name
	}
	return s.assignExpression(expression, args.Value)
}

func (s *session) setExpression(raw json.RawMessage) (any, bool, string) {
	var args struct {
		Expression string `json:"expression"`
		Value      string `json:"value"`
		FrameID    int    `json:"frameId"`
	}
	if json.Unmarshal(raw, &args) != nil || args.Expression == "" {
		return nil, false, "invalid setExpression arguments"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	return s.assignExpression(args.Expression, args.Value)
}

func (s *session) assignExpression(expression, value string) (any, bool, string) {
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	lines, err := debugger.execute("set " + expression + " = " + value)
	if err != nil {
		return nil, false, err.Error()
	}
	result := parsePrintedValue(lines)
	if result == "" {
		result = value
	}
	return map[string]any{"value": result, "variablesReference": 0}, true, ""
}

func (s *session) resume(command string, raw json.RawMessage, includeBody bool) (any, bool, string) {
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	if err := debugger.send(command); err != nil {
		return nil, false, err.Error()
	}
	var args struct {
		ThreadID int `json:"threadId"`
	}
	_ = json.Unmarshal(raw, &args)
	_ = s.event("continued", map[string]any{"threadId": args.ThreadID, "allThreadsContinued": true})
	if includeBody {
		return map[string]any{"allThreadsContinued": true}, true, ""
	}
	return map[string]any{}, true, ""
}

func (s *session) pause(raw json.RawMessage) (any, bool, string) {
	var args struct {
		ThreadID int `json:"threadId"`
	}
	if json.Unmarshal(raw, &args) != nil {
		return nil, false, "invalid pause arguments"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	command := "suspend"
	if token := s.tokenForThread(args.ThreadID); validJDBThreadToken(token) {
		command += " " + token
	}
	lines, err := debugger.execute(command)
	if err != nil {
		return nil, false, err.Error()
	}
	joined := strings.ToLower(strings.Join(lines, ""))
	if strings.Contains(joined, "unrecognized command") || strings.Contains(joined, "no such thread") || strings.Contains(joined, "invalid thread") {
		return nil, false, strings.TrimSpace(strings.Join(lines, ""))
	}
	threadID := args.ThreadID
	if threadID <= 0 {
		threadID = s.threadID("main")
	}
	go func() {
		// dispatch writes the request response immediately after this function
		// returns; the short handoff preserves normal DAP response/event order.
		time.Sleep(time.Millisecond)
		_ = s.event("stopped", map[string]any{"reason": "pause", "threadId": threadID, "allThreadsStopped": !strings.Contains(command, " "), "description": "Paused by client"})
	}()
	return map[string]any{}, true, ""
}

func (s *session) pathForSource(name string, frameNames ...string) string {
	s.stateMu.Lock()
	if path := s.sourceByName[name]; path != "" {
		s.stateMu.Unlock()
		return path
	}
	frameName := ""
	if len(frameNames) > 0 {
		frameName = frameNames[0]
	}
	cacheKey := frameName + "\x00" + name
	if path := s.sourceCache[cacheKey]; path != "" {
		s.stateMu.Unlock()
		return path
	}
	roots := append([]string(nil), s.sourceRoots...)
	s.stateMu.Unlock()

	relative := sourceRelativePath(frameName, name)
	for _, root := range roots {
		for _, candidate := range []string{filepath.Join(root, relative), filepath.Join(root, name)} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				candidate = filepath.Clean(candidate)
				s.stateMu.Lock()
				s.sourceCache[cacheKey] = candidate
				s.sourceByName[name] = candidate
				s.stateMu.Unlock()
				return candidate
			}
		}
	}
	return ""
}

func debugSourceRoots(cwd string, configured []string) []string {
	values := append([]string(nil), configured...)
	if cwd != "" {
		values = append(values, cwd,
			filepath.Join(cwd, "src"), filepath.Join(cwd, "src", "main", "java"), filepath.Join(cwd, "src", "main", "kotlin"),
			filepath.Join(cwd, "src", "test", "java"), filepath.Join(cwd, "src", "test", "kotlin"))
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if !filepath.IsAbs(value) && cwd != "" {
			value = filepath.Join(cwd, value)
		}
		value = filepath.Clean(value)
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func sourceRelativePath(frameName, sourceName string) string {
	className := frameName
	if dot := strings.LastIndexByte(className, '.'); dot >= 0 {
		className = className[:dot]
	}
	if dollar := strings.IndexByte(className, '$'); dollar >= 0 {
		className = className[:dollar]
	}
	if dot := strings.LastIndexByte(className, '.'); dot >= 0 {
		return filepath.Join(filepath.FromSlash(strings.ReplaceAll(className[:dot], ".", "/")), sourceName)
	}
	return sourceName
}

func (s *session) loadedSources() any {
	s.stateMu.Lock()
	paths := make([]string, 0, len(s.sourceByName))
	for _, path := range s.sourceByName {
		paths = append(paths, path)
	}
	s.stateMu.Unlock()
	sort.Strings(paths)
	sources := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		sources = append(sources, map[string]any{"name": filepath.Base(path), "path": path})
	}
	return map[string]any{"sources": sources}
}

func (s *session) exceptionInfo() any {
	s.stateMu.Lock()
	description := s.lastException
	s.stateMu.Unlock()
	if description == "" {
		description = "No exception information is available"
	}
	return map[string]any{"exceptionId": "java.lang.Throwable", "description": description, "breakMode": "always"}
}
