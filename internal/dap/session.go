package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	handle     string
	// hint is the already-known rendering of the expression's value (e.g.
	// `instance of int[3] (id=12)`); the inspector uses it to classify the
	// runtime type without re-evaluating the expression.
	hint string
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

const (
	maxDAPThreads     = 4096
	maxThreadIDKeys   = maxDAPThreads * 2
	maxDAPStackFrames = 200
	maxStopHandles    = 100_000
	maxRememberedPath = 8192
	maxInspectText    = 64 << 10
)

type session struct {
	ctx            context.Context
	cancel         context.CancelFunc
	writer         *bufio.Writer
	write          sync.Mutex
	seq            int
	postResponseMu sync.Mutex
	postResponse   map[int][]func()
	requestMu      sync.Mutex
	requests       map[int]*dapRequestState
	lifecycleMu    sync.Mutex
	closing        bool
	workers        sync.WaitGroup
	debuggeePipes  []io.Closer

	debugMu          sync.Mutex
	debugOperationMu sync.Mutex
	debug            *jdiProcess
	debuggee         *exec.Cmd
	debuggeeDone     chan struct{}
	launched         bool
	leaveDebuggee    bool

	stateMu             sync.Mutex
	threadIDs           map[string]int
	threadTokens        map[int]string
	threadNames         map[int]string
	nextThreadID        int
	frames              map[int]debugFrame
	nextFrameID         int
	variables           map[int]variableContext
	nextVariable        int
	breakpoints         map[string][]sourceBreakpoint
	functionBreakpoints []string
	sourceByName        map[string]string
	sourceRoots         []string
	sourceCache         map[string]string
	sources             *sourceStore
	classPaths          []string
	lastException       string
	lastStop            string
	terminated          atomic.Bool
	sourceResolver      SourceResolver
	stepTargets         map[int]stepTarget
	breakpointMu        sync.Mutex
	breakpointCache     map[string]breakpointClassCacheEntry
}

func newSession(parent context.Context, writer *bufio.Writer) *session {
	ctx, cancel := context.WithCancel(parent)
	return &session{
		ctx: ctx, cancel: cancel, writer: writer, seq: 1,
		threadIDs: make(map[string]int), threadTokens: make(map[int]string), threadNames: make(map[int]string), nextThreadID: 1,
		frames: make(map[int]debugFrame), nextFrameID: 1,
		variables: make(map[int]variableContext), nextVariable: 1,
		breakpoints: make(map[string][]sourceBreakpoint), sourceByName: make(map[string]string), sourceCache: make(map[string]string),
		sources:         newSourceStore(),
		breakpointCache: make(map[string]breakpointClassCacheEntry),
		requests:        make(map[int]*dapRequestState),
		postResponse:    make(map[int][]func()),
	}
}

type dapRequestState struct {
	request   message
	ctx       context.Context
	cancel    context.CancelFunc
	responded bool
}

type dapRequestSequenceKey struct{}

func (s *session) registerRequest(request message) bool {
	ctx, cancel := context.WithCancel(context.WithValue(s.ctx, dapRequestSequenceKey{}, request.Seq))
	s.requestMu.Lock()
	if _, exists := s.requests[request.Seq]; exists {
		s.requestMu.Unlock()
		cancel()
		return false
	}
	s.requests[request.Seq] = &dapRequestState{request: request, ctx: ctx, cancel: cancel}
	s.requestMu.Unlock()
	return true
}

func (s *session) cancelRequest(requestID int) {
	s.requestMu.Lock()
	state := s.requests[requestID]
	if state == nil || state.responded {
		s.requestMu.Unlock()
		return
	}
	state.responded = true
	state.cancel()
	request := state.request
	delete(s.requests, requestID)
	s.requestMu.Unlock()
	_ = s.respond(request, nil, false, "request cancelled")
	s.discardPostResponse(requestID)
}

func (s *session) cancelOutstandingRequests(except int) {
	s.requestMu.Lock()
	ids := make([]int, 0, len(s.requests))
	for id, state := range s.requests {
		if id != except && state != nil && !state.responded {
			ids = append(ids, id)
		}
	}
	s.requestMu.Unlock()
	for _, id := range ids {
		s.cancelRequest(id)
	}
}

func (s *session) rejectQueuedRequest(request message, reason string) {
	s.requestMu.Lock()
	state := s.requests[request.Seq]
	if state != nil {
		state.responded = true
		state.cancel()
		delete(s.requests, request.Seq)
	}
	s.requestMu.Unlock()
	_ = s.respond(request, nil, false, reason)
	s.discardPostResponse(request.Seq)
}

func (s *session) handleRequest(request message) {
	s.requestMu.Lock()
	state := s.requests[request.Seq]
	if state == nil || state.responded || state.ctx.Err() != nil {
		s.requestMu.Unlock()
		return
	}
	requestContext := state.ctx
	s.requestMu.Unlock()
	started := time.Now()
	body, success, responseText := s.dispatchContext(requestContext, request.Command, request.Arguments)
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		fmt.Fprintf(os.Stderr, "kotlsp dap: slow dispatch: %s took %s\n", request.Command, elapsed)
	}
	s.requestMu.Lock()
	state = s.requests[request.Seq]
	if state == nil || state.responded {
		s.requestMu.Unlock()
		s.discardPostResponse(request.Seq)
		return
	}
	state.responded = true
	state.cancel()
	delete(s.requests, request.Seq)
	s.requestMu.Unlock()
	if err := s.respond(request, body, success, responseText); err != nil {
		s.discardPostResponse(request.Seq)
		return
	}
	s.flushPostResponse(request.Seq)
	if request.Command == "initialize" {
		_ = s.event("initialized", nil)
	}
}

func (s *session) close() {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		s.workers.Wait()
		return
	}
	s.closing = true
	pipes := append([]io.Closer(nil), s.debuggeePipes...)
	s.debuggeePipes = nil
	s.lifecycleMu.Unlock()
	s.cancel()
	s.debugMu.Lock()
	debugger := s.debug
	s.debug = nil
	debuggee, leave := s.debuggee, s.leaveDebuggee
	s.debugMu.Unlock()
	for _, pipe := range pipes {
		_ = pipe.Close()
	}
	if debugger != nil {
		debugger.close()
	}
	if debuggee != nil && debuggee.Process != nil && !leave {
		_ = debuggee.Process.Kill()
	}
	s.workers.Wait()
}

func (s *session) startWorker(action func()) bool {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		return false
	}
	s.workers.Add(1)
	s.lifecycleMu.Unlock()
	go func() {
		defer s.workers.Done()
		action()
	}()
	return true
}

func (s *session) closeDebuggeePipes() {
	s.lifecycleMu.Lock()
	pipes := append([]io.Closer(nil), s.debuggeePipes...)
	s.debuggeePipes = nil
	s.lifecycleMu.Unlock()
	for _, pipe := range pipes {
		_ = pipe.Close()
	}
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

func (s *session) queuePostResponse(ctx context.Context, action func()) {
	sequence, _ := ctx.Value(dapRequestSequenceKey{}).(int)
	if sequence <= 0 {
		return
	}
	s.postResponseMu.Lock()
	s.postResponse[sequence] = append(s.postResponse[sequence], action)
	s.postResponseMu.Unlock()
}

func (s *session) flushPostResponse(sequence int) {
	s.postResponseMu.Lock()
	actions := s.postResponse[sequence]
	delete(s.postResponse, sequence)
	s.postResponseMu.Unlock()
	for _, action := range actions {
		action()
	}
}

func (s *session) discardPostResponse(sequence int) {
	s.postResponseMu.Lock()
	delete(s.postResponse, sequence)
	s.postResponseMu.Unlock()
}

func (s *session) dispatch(command string, raw json.RawMessage) (any, bool, string) {
	return s.dispatchContext(s.ctx, command, raw)
}

func decodeDAPArguments(raw json.RawMessage, target any) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		trimmed = "{}"
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("arguments must be a JSON object")
	}
	return json.Unmarshal([]byte(trimmed), target)
}

func (s *session) dispatchContext(ctx context.Context, command string, raw json.RawMessage) (any, bool, string) {
	handler, ok := dapRequestRegistry[command]
	if !ok {
		return nil, false, "debug request is not registered: " + command
	}
	return handler(s, ctx, raw)
}

type dapRequestHandler func(*session, context.Context, json.RawMessage) (any, bool, string)

// dapRequestRegistry is both the adapter's dispatch table and its protocol
// surface. Capability flags below are projections of this exact table, so a
// request cannot be advertised without an executable handler registration.
var dapRequestRegistry = map[string]dapRequestHandler{
	"initialize": func(_ *session, _ context.Context, _ json.RawMessage) (any, bool, string) {
		return dapCapabilities(), true, ""
	},
	"attach": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.attach(ctx, raw)
	},
	"launch": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.launch(ctx, raw)
	},
	"configurationDone": func(s *session, ctx context.Context, _ json.RawMessage) (any, bool, string) {
		return s.configurationDone(ctx)
	},
	"setBreakpoints": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.setBreakpoints(raw, ctx)
	},
	"setFunctionBreakpoints": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.setFunctionBreakpoints(raw, ctx)
	},
	"setExceptionBreakpoints": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.setExceptionBreakpoints(raw, ctx)
	},
	"breakpointLocations": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		s.stateMu.Lock()
		classPaths := append([]string(nil), s.classPaths...)
		s.stateMu.Unlock()
		return s.breakpointLocationsContext(ctx, raw, classPaths...)
	},
	"threads": func(s *session, ctx context.Context, _ json.RawMessage) (any, bool, string) {
		return s.threads(ctx)
	},
	"stackTrace": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.stackTrace(raw, ctx)
	},
	"scopes": func(s *session, _ context.Context, raw json.RawMessage) (any, bool, string) {
		return s.scopes(raw)
	},
	"variables": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.variableValues(raw, ctx)
	},
	"evaluate": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.evaluate(raw, ctx)
	},
	"setVariable": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.setVariable(raw, ctx)
	},
	"setExpression": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.setExpression(raw, ctx)
	},
	"continue": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.resume("cont", raw, true, ctx)
	},
	"next": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.resume("next", raw, false, ctx)
	},
	"stepIn": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.resume("step", raw, false, ctx)
	},
	"stepOut": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.resume("step up", raw, false, ctx)
	},
	"pause": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.pause(raw, ctx)
	},
	"disconnect": func(s *session, _ context.Context, raw json.RawMessage) (any, bool, string) {
		if err := s.disconnect(raw, false); err != nil {
			return nil, false, err.Error()
		}
		return map[string]any{}, true, ""
	},
	"terminate": func(s *session, _ context.Context, raw json.RawMessage) (any, bool, string) {
		if err := s.disconnect(raw, true); err != nil {
			return nil, false, err.Error()
		}
		return map[string]any{}, true, ""
	},
	"loadedSources": func(s *session, _ context.Context, _ json.RawMessage) (any, bool, string) {
		return s.loadedSources(), true, ""
	},
	"source": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.sourceContent(ctx, raw)
	},
	"completions": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.completions(raw, ctx)
	},
	"exceptionInfo": func(s *session, ctx context.Context, _ json.RawMessage) (any, bool, string) {
		return s.exceptionInfo(ctx), true, ""
	},
	// Cancel is consumed before ordinary dispatch because it targets another
	// in-flight request. Keeping that transport handler in this table makes the
	// advertised capability part of the same registered surface.
	"cancel": func(_ *session, _ context.Context, _ json.RawMessage) (any, bool, string) {
		return nil, false, "request cancellation is handled by the DAP transport"
	},
	"stepInTargets": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.stepInTargets(raw, ctx)
	},
	"restartFrame": func(s *session, ctx context.Context, raw json.RawMessage) (any, bool, string) {
		return s.restartFrame(raw, ctx)
	},
}

func dapSupports(request string) bool {
	switch request {
	case "configurationDone", "setFunctionBreakpoints", "setBreakpoints", "evaluate", "setVariable", "restartFrame", "stepInTargets", "completions", "loadedSources", "source", "cancel", "breakpointLocations", "setExpression", "terminate", "disconnect", "exceptionInfo":
		return true
	default:
		return false
	}
}

func dapCapabilities() map[string]any {
	return map[string]any{
		"supportsConfigurationDoneRequest":   dapSupports("configurationDone"),
		"supportsFunctionBreakpoints":        dapSupports("setFunctionBreakpoints"),
		"supportsConditionalBreakpoints":     dapSupports("setBreakpoints"),
		"supportsHitConditionalBreakpoints":  dapSupports("setBreakpoints"),
		"supportsEvaluateForHovers":          dapSupports("evaluate"),
		"supportsStepBack":                   false,
		"supportsSetVariable":                dapSupports("setVariable"),
		"supportsRestartFrame":               dapSupports("restartFrame"),
		"supportsGotoTargetsRequest":         false,
		"supportsStepInTargetsRequest":       dapSupports("stepInTargets"),
		"supportsCompletionsRequest":         dapSupports("completions"),
		"completionTriggerCharacters":        []string{"."},
		"supportsModulesRequest":             false,
		"supportsRestartRequest":             false,
		"supportsExceptionInfoRequest":       dapSupports("exceptionInfo"),
		"supportTerminateDebuggee":           dapSupports("disconnect") && dapSupports("terminate"),
		"supportsLoadedSourcesRequest":       dapSupports("loadedSources") && dapSupports("source"),
		"supportsLogPoints":                  dapSupports("setBreakpoints"),
		"supportsTerminateThreadsRequest":    false,
		"supportsSetExpression":              dapSupports("setExpression"),
		"supportsTerminateRequest":           dapSupports("terminate"),
		"supportsDataBreakpoints":            false,
		"supportsReadMemoryRequest":          false,
		"supportsWriteMemoryRequest":         false,
		"supportsDisassembleRequest":         false,
		"supportsCancelRequest":              dapSupports("cancel"),
		"supportsBreakpointLocationsRequest": dapSupports("breakpointLocations"),
		"supportsInstructionBreakpoints":     false,
		"exceptionBreakpointFilters": []any{
			map[string]any{"filter": "uncaught", "label": "Uncaught exceptions", "default": true},
			map[string]any{"filter": "caught", "label": "Caught exceptions", "default": false},
		},
	}
}

func (s *session) configurationDone(ctx context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	if debugger := s.currentDebugger(); debugger != nil {
		if err := debugger.resume("continue", "", ctx); err != nil {
			return nil, false, err.Error()
		}
		s.stateMu.Lock()
		s.invalidateStopHandlesLocked()
		s.stateMu.Unlock()
		s.queuePostResponse(ctx, func() {
			_ = s.event("continued", map[string]any{"threadId": 0, "allThreadsContinued": true})
		})
	}
	return map[string]any{}, true, ""
}

func (s *session) attach(ctx context.Context, raw json.RawMessage) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	if s.debugSessionActive() {
		return nil, false, "a debug target is already active on this DAP connection"
	}
	var args struct {
		Port int    `json:"port"`
		Host string `json:"host"`
		// hostName is the VS Code Java debugger's name for host.
		HostName    string   `json:"hostName"`
		JavaExec    string   `json:"javaExec"`
		SourcePaths []string `json:"sourcePaths"`
		ClassPaths  []string `json:"classPaths"`
		CWD         string   `json:"cwd"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.Port <= 0 || args.Port > 65535 {
		return nil, false, "attach requires a valid JDWP port"
	}
	if args.Host == "" {
		args.Host = args.HostName
	}
	if len(args.Host) > 4096 || len(args.JavaExec) > 4096 || strings.IndexByte(args.Host, 0) >= 0 || strings.IndexByte(args.JavaExec, 0) >= 0 {
		return nil, false, "attach host or Java executable exceeds its size/NUL safety limit"
	}
	if args.Host == "" {
		args.Host = "127.0.0.1"
	}
	debugger, err := startJDI(ctx, s.ctx, args.JavaExec, args.Host, args.Port, "", nil, s.handleJDIEvent)
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
	// The same source and class lookup as a launch: stack frames map to
	// these sources, and breakpoints narrow to the classes with code there.
	classPaths := append([]string(nil), args.ClassPaths...)
	for index, path := range classPaths {
		if !filepath.IsAbs(path) && args.CWD != "" {
			classPaths[index] = filepath.Join(args.CWD, path)
		}
	}
	s.stateMu.Lock()
	s.classPaths = classPaths
	s.sourceRoots = debugSourceRoots(args.CWD, args.SourcePaths)
	s.sourceCache = make(map[string]string)
	s.stateMu.Unlock()
	s.sources.reset()
	s.breakpointMu.Lock()
	s.breakpointCache = make(map[string]breakpointClassCacheEntry)
	s.breakpointMu.Unlock()
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

func (s *session) launch(ctx context.Context, raw json.RawMessage) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	if s.debugSessionActive() {
		return nil, false, "a debug target is already active on this DAP connection"
	}
	var args launchArguments
	if err := decodeDAPArguments(raw, &args); err != nil {
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
	if limitation := validateLaunchArguments(args); limitation != "" {
		return nil, false, limitation
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
	s.sources.reset()
	s.breakpointMu.Lock()
	s.breakpointCache = make(map[string]breakpointClassCacheEntry)
	s.breakpointMu.Unlock()
	javaExec := args.JavaExec
	if javaExec == "" {
		javaExec = "java"
	}
	javaArgs := append([]string(nil), args.VMArgs...)
	if !args.NoDebug {
		// Let JDWP bind port zero and report the socket it actually owns. Binding
		// and closing a probe listener left a race in which an unrelated process
		// could claim the selected port before the debuggee.
		javaArgs = append(javaArgs, "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:0")
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
	// DAP permits disconnect with terminateDebuggee=false. Binding this process
	// to the connection context would kill it even after an explicit detach;
	// close still terminates by default unless disconnect records that choice.
	environment, environmentErr := mergedEnvironment(args.Env)
	if environmentErr != nil {
		return nil, false, environmentErr.Error()
	}
	command := exec.Command(javaExec, javaArgs...)
	command.Dir = args.CWD
	command.Env = environment
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
	jdwpPort := make(chan int, 1)
	if !s.startDebuggeeWorkers(command, stdout, stderr, args.NoDebug, jdwpPort) {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, false, "debug session closed during launch"
	}
	launchSucceeded := false
	defer func() {
		if !launchSucceeded {
			s.killAndReapDebuggee(command)
		}
	}()
	if args.NoDebug {
		launchSucceeded = true
		return map[string]any{}, true, ""
	}
	s.debugMu.Lock()
	debuggeeDone := s.debuggeeDone
	s.debugMu.Unlock()
	port := 0
	select {
	case port = <-jdwpPort:
	case <-debuggeeDone:
		return nil, false, "debuggee exited before opening its JDWP listener"
	case <-time.After(10 * time.Second):
		return nil, false, "debuggee did not report its JDWP listener within 10 seconds"
	case <-ctx.Done():
		return nil, false, ctx.Err().Error()
	}
	if port <= 0 {
		_ = command.Process.Kill()
		return nil, false, "debuggee exited before opening its JDWP listener"
	}

	var debugger *jdiProcess
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt*25) * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				_ = command.Process.Kill()
				return nil, false, ctx.Err().Error()
			}
		}
		debugger, err = startJDI(ctx, s.ctx, javaExec, "127.0.0.1", port, args.CWD, environment, s.handleJDIEvent)
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
	launchSucceeded = true
	return map[string]any{}, true, ""
}

func validateLaunchArguments(args launchArguments) string {
	const (
		maxLaunchListItems  = 4096
		maxLaunchValueBytes = 1 << 20
	)
	lists := [][]string{args.Args, args.VMArgs, args.ClassPaths, args.ModulePaths, args.SourcePaths}
	for _, values := range lists {
		if len(values) > maxLaunchListItems {
			return "launch argument list exceeds its 4096-item safety limit"
		}
		for _, value := range values {
			if len(value) > maxLaunchValueBytes || strings.IndexByte(value, 0) >= 0 {
				return "launch argument exceeds its size or NUL-safety limit"
			}
		}
	}
	if len(args.ClassPaths)+len(args.ModulePaths) > maxLaunchListItems || len(args.Env) > maxLaunchListItems {
		return "launch classpath/module-path/environment exceeds its 4096-item safety limit"
	}
	for _, value := range []string{args.MainClass, args.ModuleName, args.JavaExec, args.CWD} {
		if len(value) > maxLaunchValueBytes || strings.IndexByte(value, 0) >= 0 {
			return "launch scalar argument exceeds its size or NUL-safety limit"
		}
	}
	return ""
}

func mergedEnvironment(values map[string]string) ([]string, error) {
	environment := append([]string(nil), os.Environ()...)
	positions := make(map[string]int, len(environment))
	for index, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		positions[key] = index
	}
	for key, value := range values {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("launch environment contains an invalid name or NUL byte")
		}
		prefix := key + "="
		if index, replaced := positions[key]; replaced {
			environment[index] = prefix + value
		} else {
			positions[key] = len(environment)
			environment = append(environment, prefix+value)
		}
	}
	return environment, nil
}

func (s *session) streamDebuggee(reader io.Reader, category string) {
	buffered := bufio.NewReaderSize(reader, 32<<10)
	for {
		line, truncated, err := readDebuggeeLine(buffered)
		if line != "" || truncated {
			if truncated {
				line += "\n[kotlsp: debuggee output line truncated]\n"
			}
			_ = s.event("output", map[string]any{"category": category, "output": line})
		}
		if err != nil {
			// A pipe this adapter closed at shutdown is not an output error.
			if err != io.EOF && !errors.Is(err, os.ErrClosed) {
				_ = s.event("output", map[string]any{"category": "stderr", "output": "debuggee output error: " + err.Error() + "\n"})
			}
			return
		}
	}
}

func readDebuggeeLine(reader *bufio.Reader) (string, bool, error) {
	const maxDebuggeeLineBytes = 1 << 20
	var line strings.Builder
	truncated := false
	for {
		fragment, err := reader.ReadSlice('\n')
		remaining := maxDebuggeeLineBytes - line.Len()
		if remaining > 0 {
			line.Write(fragment[:min(remaining, len(fragment))])
		}
		if len(fragment) > remaining {
			truncated = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line.String(), truncated, err
	}
}

var jdwpListeningPattern = regexp.MustCompile(`Listening for transport dt_socket at address:\s*(?:[^:[:space:]]+:)?(\d+)`)

func (s *session) streamDebuggeeJDWP(reader io.Reader, category string, port chan<- int) {
	buffered := bufio.NewReaderSize(reader, 32<<10)
	for {
		line, truncated, err := readDebuggeeLine(buffered)
		if line != "" || truncated {
			if match := jdwpListeningPattern.FindStringSubmatch(line); len(match) == 2 {
				value, _ := strconv.Atoi(match[1])
				select {
				case port <- value:
				default:
				}
				// The JVM's own notice of the debug port is not the
				// program's output.
				if strings.TrimSpace(line) == strings.TrimSpace(match[0]) {
					line, truncated = "", false
				}
			}
			if truncated {
				line += "\n[kotlsp: debuggee output line truncated]\n"
			}
			if line != "" {
				_ = s.event("output", map[string]any{"category": category, "output": line})
			}
		}
		if err != nil {
			// A pipe this adapter closed at shutdown is not an output error.
			if err != io.EOF && !errors.Is(err, os.ErrClosed) {
				_ = s.event("output", map[string]any{"category": "stderr", "output": "debuggee output error: " + err.Error() + "\n"})
			}
			return
		}
	}
}

func (s *session) killAndReapDebuggee(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
	s.debugMu.Lock()
	done := s.debuggeeDone
	s.debugMu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func waitDebuggeeProcess(command *exec.Cmd) int {
	err := command.Wait()
	exitCode := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return exitCode
}

func (s *session) startDebuggeeWorkers(command *exec.Cmd, stdout, stderr io.ReadCloser, noDebug bool, jdwpPort chan<- int) bool {
	s.lifecycleMu.Lock()
	if s.closing {
		s.lifecycleMu.Unlock()
		return false
	}
	s.debuggeePipes = append(s.debuggeePipes, stdout, stderr)
	s.workers.Add(3)
	s.lifecycleMu.Unlock()
	exited := make(chan int, 1)
	done := make(chan struct{})
	s.debugMu.Lock()
	s.debuggeeDone = done
	s.debugMu.Unlock()
	// Cmd.Wait cannot be canceled without terminating the child. Keep the
	// mandatory OS reaper state-free: on an intentional detach it may live as
	// long as the transferred process, but it owns no session, pipe, or writer.
	go func() {
		exited <- waitDebuggeeProcess(command)
		close(done)
	}()
	go func() {
		defer s.workers.Done()
		if noDebug {
			s.streamDebuggee(stdout, "stdout")
		} else {
			s.streamDebuggeeJDWP(stdout, "stdout", jdwpPort)
		}
	}()
	go func() {
		defer s.workers.Done()
		if noDebug {
			s.streamDebuggee(stderr, "stderr")
		} else {
			s.streamDebuggeeJDWP(stderr, "stderr", jdwpPort)
		}
	}()
	go func() {
		defer s.workers.Done()
		select {
		case exitCode := <-exited:
			_ = s.event("exited", map[string]any{"exitCode": exitCode})
			s.emitTerminated()
		case <-s.ctx.Done():
		}
	}()
	return true
}

func (s *session) currentDebugger() *jdiProcess {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	return s.debug
}

func (s *session) debugSessionActive() bool {
	if s.terminated.Load() {
		return true
	}
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	if s.debug != nil {
		return true
	}
	return s.debuggee != nil && s.debuggee.Process != nil && s.debuggee.ProcessState == nil
}

func (s *session) disconnect(raw json.RawMessage, force bool) error {
	var args struct {
		TerminateDebuggee bool `json:"terminateDebuggee"`
	}
	if err := decodeDAPArguments(raw, &args); err != nil {
		return fmt.Errorf("invalid disconnect arguments: %w", err)
	}
	s.debugMu.Lock()
	terminate := force || args.TerminateDebuggee
	s.leaveDebuggee = s.launched && !terminate
	debugger := s.debug
	s.debug = nil
	if s.debuggee != nil && s.debuggee.Process != nil && terminate {
		_ = s.debuggee.Process.Kill()
	}
	s.debugMu.Unlock()
	s.closeDebuggeePipes()
	if debugger != nil {
		debugger.close()
	}
	if terminate {
		s.emitTerminated()
	}
	return nil
}

func (s *session) emitTerminated() {
	if s.terminated.CompareAndSwap(false, true) {
		_ = s.event("terminated", map[string]any{})
		// A dead VM leaves JDI unable to answer; an open bridge turns every
		// later request into a 30s timeout. Kill it asynchronously (this runs
		// on the bridge event worker, which must never wait on commandMu).
		s.startWorker(func() {
			s.debugMu.Lock()
			debugger := s.debug
			s.debug = nil
			s.debugMu.Unlock()
			if debugger != nil {
				debugger.kill()
				debugger.close()
			}
		})
	}
}

func (s *session) handleJDIEvent(event debugEvent) {
	switch event.kind {
	case "TERMINATED":
		s.emitTerminated()
		return
	case "ERROR":
		if event.protocolError != "" {
			_ = s.event("output", map[string]any{"category": "stderr", "output": "JDI bridge: " + event.protocolError + "\n"})
		}
		return
	case "SKIPPED":
		_ = s.event("output", map[string]any{"category": "console", "output": "Skipped a stop at " + event.protocolError + " reached while evaluating an expression\n"})
		return
	case "STOP":
	default:
		return
	}
	// Bridge breakpoint requests and their Go metadata share the debugger
	// operation lane. A stop from a newly enabled request therefore waits until
	// both halves of publication are visible.
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	description := event.description
	if event.className != "" {
		description = fmt.Sprintf("%s at %s.%s:%d", event.description, event.className, event.methodName, event.line)
	}
	s.stateMu.Lock()
	s.lastStop = description
	if event.reason == "exception" {
		s.lastException = description
	}
	s.invalidateStopHandlesLocked()
	s.stateMu.Unlock()
	threadID := s.threadIdentity(event.threadToken, event.threadName)
	if event.reason == "breakpoint" || event.reason == "breakpoint+step" {
		s.handleBreakpointStop(event, threadID, description)
		return
	}
	_ = s.event("stopped", map[string]any{"reason": event.reason, "threadId": threadID, "allThreadsStopped": true, "description": description})
}

// handleBreakpointStop applies a breakpoint's hit condition, condition and
// log message. A breakpoint reached by a step ("breakpoint+step") only decides
// how the stop is reported: the step has stopped the thread either way.
func (s *session) handleBreakpointStop(event debugEvent, threadID int, description string) {
	stepped := event.reason == "breakpoint+step"
	stepStop := func() {
		_ = s.event("stopped", map[string]any{"reason": "step", "threadId": threadID, "allThreadsStopped": true, "description": fmt.Sprintf("Step completed at %s.%s:%d", event.className, event.methodName, event.line)})
	}
	var breakpoint sourceBreakpoint
	found := false
	s.stateMu.Lock()
	for path, values := range s.breakpoints {
		for index := range values {
			if event.line != 0 && values[index].Line != event.line || event.className != "" && values[index].Class != event.className {
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
		if stepped {
			stepStop()
			return
		}
		reason := "breakpoint"
		s.stateMu.Lock()
		for _, name := range s.functionBreakpoints {
			if name == event.className+"."+event.methodName || strings.HasSuffix(event.className+"."+event.methodName, "."+name) {
				reason = "function breakpoint"
				break
			}
		}
		s.stateMu.Unlock()
		_ = s.event("stopped", map[string]any{"reason": reason, "threadId": threadID, "allThreadsStopped": true, "description": description})
		return
	}
	if !breakpoint.HitCondition.matches(breakpoint.Hits) {
		if stepped {
			stepStop()
			return
		}
		_ = debugger.resume("continue", "")
		return
	}
	decision, logMessage, conditionError := "stop", "", ""
	debugger.transaction(func(transaction *jdiTransaction) {
		if breakpoint.Condition != "" {
			// A condition that cannot be evaluated stops, with the reason: read
			// as false, a typo in it silently disabled the breakpoint.
			value, err := transaction.evaluate(breakpoint.Condition)
			switch {
			case err != nil:
				conditionError = err.Error()
			case !strings.EqualFold(strings.TrimSpace(value.value), "true"):
				decision = "continue"
			}
		}
		if decision == "stop" && breakpoint.LogMessage != "" {
			logMessage = s.renderLogPointTransaction(transaction, breakpoint.LogMessage)
			decision = "log"
		}
		if decision != "stop" && !stepped {
			_ = transaction.resume()
		}
	})
	if conditionError != "" {
		_ = s.event("output", map[string]any{"category": "console", "output": fmt.Sprintf("Breakpoint condition %q at %s:%d could not be evaluated: %s\n", breakpoint.Condition, event.className, event.line, conditionError)})
	}
	if decision == "log" {
		_ = s.event("output", map[string]any{"category": "console", "output": logMessage + "\n"})
	}
	if decision != "stop" {
		if stepped {
			stepStop()
		}
		return
	}
	_ = s.event("stopped", map[string]any{"reason": "breakpoint", "threadId": threadID, "allThreadsStopped": true, "description": description})
}

func (s *session) renderLogPointTransaction(debugger *jdiTransaction, message string) string {
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
			if value, err := debugger.evaluate(expression); err == nil {
				output.WriteString(value.value)
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
	if len(s.threadIDs) >= maxThreadIDKeys {
		s.threadIDs = make(map[string]int)
		s.threadTokens = make(map[int]string)
		s.threadNames = make(map[int]string)
	}
	if s.nextThreadID <= 0 || s.nextThreadID == int(^uint(0)>>1) {
		return 0
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
		s.threadTokens[id] = token
		s.threadNames[id] = name
		return id
	}
	if len(s.threadIDs) >= maxThreadIDKeys {
		s.threadIDs = make(map[string]int)
		s.threadTokens = make(map[int]string)
		s.threadNames = make(map[int]string)
	}
	if s.nextThreadID <= 0 || s.nextThreadID == int(^uint(0)>>1) {
		return 0
	}
	id := s.nextThreadID
	s.nextThreadID++
	s.threadIDs[token] = id
	s.threadTokens[id] = token
	s.threadNames[id] = name
	return id
}

// DestroyJavaVM is the husk of a returned main thread. JDI reports zombie as
// status zero; neither has a usable stack and both are omitted from DAP.
func unusableThread(name, state string) bool {
	return name == "DestroyJavaVM" || state == "0"
}

func (s *session) threads(contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"threads": []any{}}, true, ""
	}
	values, err := debugger.threads(contexts...)
	if err != nil {
		return nil, false, err.Error()
	}
	threads := make([]map[string]any, 0)
	seen := map[string]bool{}
	for _, thread := range values {
		if seen[thread.token] {
			continue
		}
		seen[thread.token] = true
		if unusableThread(thread.name, thread.state) {
			continue
		}
		if len(threads) >= maxDAPThreads {
			return nil, false, "thread snapshot exceeds its 4096-item safety limit"
		}
		threads = append(threads, map[string]any{"id": s.threadIdentity(thread.token, thread.name), "name": thread.name})
	}
	if len(threads) == 0 {
		// A stop event already carries a reliable JDI thread identity. Preserve
		// it if the VM concurrently removes the thread before this snapshot.
		s.stateMu.Lock()
		seenIDs := make(map[int]bool)
		for id, name := range s.threadNames {
			if id == 0 || seenIDs[id] {
				continue
			}
			if len(threads) >= maxDAPThreads {
				s.stateMu.Unlock()
				return nil, false, "remembered thread snapshot exceeds its 4096-item safety limit"
			}
			seenIDs[id] = true
			threads = append(threads, map[string]any{"id": id, "name": name})
		}
		s.stateMu.Unlock()
	}
	return map[string]any{"threads": threads}, true, ""
}

func (s *session) stackTrace(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		ThreadID   int `json:"threadId"`
		StartFrame int `json:"startFrame"`
		Levels     int `json:"levels"`
	}
	if decodeDAPArguments(raw, &args) != nil {
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
	start := max(0, args.StartFrame)
	levels := args.Levels
	if levels <= 0 || levels > maxDAPStackFrames {
		levels = maxDAPStackFrames
	}
	values, err := debugger.stack(token, start, levels, contexts...)
	if err != nil {
		return nil, false, err.Error()
	}
	frames := make([]map[string]any, 0)
	totalFrames := 0
	if len(values) > 0 {
		totalFrames = values[0].total
	}
	for _, value := range values {
		if len(frames) >= levels {
			break
		}
		frameID := s.addFrame(debugFrame{threadToken: token, threadID: args.ThreadID, index: value.index, name: value.name})
		if frameID == 0 {
			return nil, false, "stack-frame handles exceed their 100000-item safety limit"
		}
		source := s.frameSource(value.sourceName, value.name, requestContext(contexts))
		frames = append(frames, map[string]any{"id": frameID, "name": value.name, "source": source, "line": value.line, "column": 1})
	}
	return map[string]any{"stackFrames": frames, "totalFrames": totalFrames}, true, ""
}

func (s *session) tokenForThread(id int) string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.threadTokens[id]
}

func (s *session) addFrame(frame debugFrame) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if len(s.frames) >= maxStopHandles || s.nextFrameID <= 0 || s.nextFrameID == int(^uint(0)>>1) {
		return 0
	}
	id := s.nextFrameID
	s.nextFrameID++
	s.frames[id] = frame
	return id
}

func (s *session) scopes(raw json.RawMessage) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		FrameID int `json:"frameId"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid scopes arguments"
	}
	s.stateMu.Lock()
	_, ok := s.frames[args.FrameID]
	s.stateMu.Unlock()
	if !ok {
		return nil, false, "unknown stack frame"
	}
	reference := s.addVariableContext(variableContext{frameID: args.FrameID})
	if reference == 0 {
		return nil, false, "variable handles exceed their 100000-item safety limit"
	}
	return map[string]any{"scopes": []any{map[string]any{"name": "Locals", "presentationHint": "locals", "variablesReference": reference, "expensive": false}}}, true, ""
}

func (s *session) addVariableContext(value variableContext) int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if len(s.variables) >= maxStopHandles || s.nextVariable <= 0 || s.nextVariable == int(^uint(0)>>1) {
		return 0
	}
	id := s.nextVariable
	s.nextVariable++
	s.variables[id] = value
	return id
}

func (s *session) variableValues(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		VariablesReference int    `json:"variablesReference"`
		Start              int    `json:"start"`
		Count              int    `json:"count"`
		Filter             string `json:"filter"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid variables arguments"
	}
	s.stateMu.Lock()
	contextValue, ok := s.variables[args.VariablesReference]
	s.stateMu.Unlock()
	if !ok {
		return nil, false, "unknown variables reference"
	}
	if _, ok := s.selectFrame(contextValue.frameID, contexts...); !ok {
		return nil, false, "unknown stack frame"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	if contextValue.handle != "" {
		variables := s.inspectVariables(debugger, contextValue.frameID, contextValue.handle, contextValue.expression, args.Start, args.Count, args.Filter, contexts...)
		return map[string]any{"variables": variables}, true, ""
	}
	values, err := debugger.locals(contexts...)
	if err != nil {
		return nil, false, err.Error()
	}
	if args.Filter == "indexed" {
		return map[string]any{"variables": []any{}}, true, ""
	}
	insp := &inspector{debugger: debugger, session: s, frameID: contextValue.frameID, start: args.Start, count: args.Count, filter: args.Filter}
	start, end := insp.page(len(values))
	variables := make([]map[string]any, 0, end-start)
	for _, value := range values[start:end] {
		variables = append(variables, insp.child(value))
	}
	return map[string]any{"variables": variables}, true, ""
}

func (s *session) selectFrame(frameID int, contexts ...context.Context) (debugFrame, bool) {
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
	if err := debugger.selectFrame(frame.threadToken, frame.index, contexts...); err != nil {
		return debugFrame{}, false
	}
	return frame, true
}

func (s *session) restartFrame(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		FrameID int `json:"frameId"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.FrameID <= 0 {
		return nil, false, "restartFrame requires a frameId"
	}
	frame, ok := s.selectFrame(args.FrameID, contexts...)
	if !ok {
		return nil, false, "unknown stack frame"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	if err := debugger.restartFrame(contexts...); err != nil {
		return nil, false, err.Error()
	}
	s.stateMu.Lock()
	s.invalidateStopHandlesLocked()
	s.stateMu.Unlock()
	// The frame's thread is stopped at the start of the restarted call; the
	// client learns that, and drops what it showed, from a stopped event
	// after this response.
	threadID := frame.threadID
	s.queuePostResponse(requestContext(contexts), func() {
		_ = s.event("stopped", map[string]any{"reason": "restart", "threadId": threadID, "allThreadsStopped": true, "description": "Frame restarted"})
	})
	return map[string]any{}, true, ""
}

// stepTarget is one call stepInTargets offered: stepIn with its id stops on
// entering that method.
type stepTarget struct {
	className, method, signature string
}

func (s *session) stepInTargets(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		FrameID int `json:"frameId"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid stepInTargets arguments"
	}
	if _, ok := s.selectFrame(args.FrameID, contexts...); !ok {
		return nil, false, "unknown stack frame"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	rows, err := debugger.requestFor(contexts, "STEP_TARGETS")
	if err != nil {
		return nil, false, err.Error()
	}
	targets := make([]any, 0, len(rows))
	s.stateMu.Lock()
	s.stepTargets = make(map[int]stepTarget, len(rows))
	for index, row := range rows {
		if len(row) < 4 {
			continue
		}
		id := index + 1
		s.stepTargets[id] = stepTarget{className: row[1], method: row[2], signature: row[3]}
		targets = append(targets, map[string]any{"id": id, "label": row[0]})
	}
	s.stateMu.Unlock()
	return map[string]any{"targets": targets}, true, ""
}

func (s *session) completions(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		FrameID int    `json:"frameId"`
		Text    string `json:"text"`
		Column  int    `json:"column"`
	}
	if decodeDAPArguments(raw, &args) != nil {
		return nil, false, "invalid completions arguments"
	}
	if len(args.Text) > maxInspectText || strings.IndexByte(args.Text, 0) >= 0 {
		return nil, false, "completion text exceeds its size or NUL-safety limit"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID, contexts...); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return map[string]any{"targets": []any{}}, true, ""
	}
	text := args.Text
	if args.Column > 0 && args.Column-1 < len(text) {
		text = text[:args.Column-1]
	}
	receiver, prefix := completionReceiver(text)
	targets := make([]map[string]any, 0)
	seen := make(map[string]bool)
	add := func(label, kind, detail string) {
		if len(targets) >= 4096 || label == "" || seen[label] || !strings.HasPrefix(label, prefix) {
			return
		}
		seen[label] = true
		target := map[string]any{"label": label, "text": label, "type": kind}
		if detail != "" {
			target["detail"] = detail
		}
		targets = append(targets, target)
	}
	if receiver == "" {
		values, err := debugger.locals(contexts...)
		if err != nil {
			return nil, false, err.Error()
		}
		for _, value := range values {
			add(value.name, "variable", value.typeName)
		}
	}
	// Members of the receiver after `expr.`, or of the frame's own class.
	members, err := debugger.members(receiver, contexts...)
	if err != nil && receiver == "" {
		return nil, false, err.Error()
	}
	for _, member := range members {
		add(member.name, member.kind, member.detail)
	}
	return map[string]any{"targets": targets}, true, ""
}

// completionReceiver splits the text before the cursor into the expression
// a member is being completed on and the partial name typed so far:
// `user.na` is ("user", "na"), `names.get(0).len` is ("names.get(0)", "len"),
// and `coun` is ("", "coun").
func completionReceiver(text string) (string, string) {
	end := len(text)
	start := end
	for start > 0 {
		c := text[start-1]
		if c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			start--
			continue
		}
		break
	}
	prefix := text[start:end]
	if start == 0 || text[start-1] != '.' {
		return "", prefix
	}
	dot := start - 1
	depth := 0
	begin := dot
	for begin > 0 {
		c := text[begin-1]
		if c == ')' || c == ']' {
			depth++
		} else if c == '(' || c == '[' {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && !(c == '_' || c == '$' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			break
		}
		begin--
	}
	return strings.TrimSpace(text[begin:dot]), prefix
}

func (s *session) evaluate(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		Expression string `json:"expression"`
		FrameID    int    `json:"frameId"`
	}
	if decodeDAPArguments(raw, &args) != nil || strings.TrimSpace(args.Expression) == "" {
		return nil, false, "evaluate requires an expression"
	}
	if len(args.Expression) > maxInspectText || strings.IndexByte(args.Expression, 0) >= 0 {
		return nil, false, "evaluate expression exceeds its size or NUL-safety limit"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID, contexts...); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	value, err := debugger.evaluate(args.Expression, contexts...)
	if err != nil {
		return nil, false, err.Error()
	}
	if value.value == "" {
		return nil, false, "no value for expression: " + args.Expression
	}
	reference := 0
	if args.FrameID != 0 && value.expandable {
		reference = s.addVariableContext(variableContext{frameID: args.FrameID, expression: args.Expression, handle: value.handle, hint: value.value})
		if reference == 0 {
			return nil, false, "variable handles exceed their 100000-item safety limit"
		}
	}
	body := map[string]any{"result": value.value, "variablesReference": reference}
	if value.typeName != "" {
		body["type"] = value.typeName
	}
	return body, true, ""
}

func (s *session) setVariable(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		Name               string `json:"name"`
		Value              string `json:"value"`
		VariablesReference int    `json:"variablesReference"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.Name == "" {
		return nil, false, "invalid setVariable arguments"
	}
	if len(args.Name) > maxInspectText || len(args.Value) > maxInspectText || strings.IndexByte(args.Name, 0) >= 0 || strings.IndexByte(args.Value, 0) >= 0 {
		return nil, false, "setVariable name/value exceeds its size or NUL-safety limit"
	}
	s.stateMu.Lock()
	variable := s.variables[args.VariablesReference]
	s.stateMu.Unlock()
	if _, ok := s.selectFrame(variable.frameID, contexts...); !ok {
		return nil, false, "unknown stack frame"
	}
	expression := args.Name
	if variable.expression != "" {
		expression = childExpression(variable.expression, args.Name)
	}
	// The row the Variables view shows knows the real expression: a Kotlin
	// local shown as "total" is $total, a list element is list.get(0).
	real, typeName := s.childEvaluateName(variable, args.Name, contexts...)
	if real != "" {
		expression = real
	}
	value := boxedLiteral(typeName, args.Value)
	// A collection element is changed through the collection, the one
	// target method call setVariable makes -- and only because the user
	// asked for the change.
	if match := collectionElement.FindStringSubmatch(expression); match != nil {
		debugger := s.currentDebugger()
		if debugger == nil {
			return nil, false, "debugger is not attached"
		}
		method := "put"
		if _, err := strconv.Atoi(match[2]); err == nil && strings.HasPrefix(args.Name, "[") {
			method = "set"
		}
		if _, err := debugger.evaluate(fmt.Sprintf("%s.%s(%s, %s)", match[1], method, match[2], value), contexts...); err != nil {
			return nil, false, err.Error()
		}
		value, err := debugger.evaluate(expression, contexts...)
		if err != nil {
			return nil, false, err.Error()
		}
		body := map[string]any{"value": value.value, "variablesReference": 0}
		if value.typeName != "" {
			body["type"] = value.typeName
		}
		return body, true, ""
	}
	return s.assignExpression(expression, value, contexts...)
}

// boxedLiteral boxes a primitive literal assigned to a boxed variable: the
// JDK evaluator does not, and an Integer field or map value refused "5".
func boxedLiteral(typeName, value string) string {
	switch typeName {
	case "java.lang.Integer", "java.lang.Long", "java.lang.Short", "java.lang.Byte", "java.lang.Double", "java.lang.Float", "java.lang.Boolean", "java.lang.Character":
	default:
		return value
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "null" || !(trimmed[0] == '-' || trimmed[0] == '\'' || trimmed[0] >= '0' && trimmed[0] <= '9' || trimmed == "true" || trimmed == "false") {
		return value
	}
	return typeName + ".valueOf(" + trimmed + ")"
}

var collectionElement = regexp.MustCompile(`^(.+)\.get\((.+)\)$`)

// childEvaluateName is the evaluateName of the child called name under a
// variables reference, as the Variables view showed it, or "".
func (s *session) childEvaluateName(parent variableContext, name string, contexts ...context.Context) (string, string) {
	debugger := s.currentDebugger()
	if debugger == nil {
		return "", ""
	}
	if parent.handle == "" {
		values, err := debugger.locals(contexts...)
		if err != nil {
			return "", ""
		}
		for _, value := range values {
			if value.name == name {
				return value.evaluateName, value.typeName
			}
		}
		return "", ""
	}
	start, count := 0, maxInspectedChildren
	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		if index, err := strconv.Atoi(name[1 : len(name)-1]); err == nil {
			start, count = index, 1
		}
	}
	values, err := debugger.children(parent.handle, start, count, "", contexts...)
	if err != nil {
		return "", ""
	}
	for _, value := range values {
		if value.name != name {
			continue
		}
		suffix := value.evaluateName
		if strings.HasPrefix(suffix, ".") || strings.HasPrefix(suffix, "[") {
			if parent.expression == "" {
				return "", value.typeName
			}
			return parent.expression + suffix, value.typeName
		}
		return suffix, value.typeName
	}
	return "", ""
}

func (s *session) setExpression(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		Expression string `json:"expression"`
		Value      string `json:"value"`
		FrameID    int    `json:"frameId"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.Expression == "" {
		return nil, false, "invalid setExpression arguments"
	}
	if len(args.Expression) > maxInspectText || len(args.Value) > maxInspectText || strings.IndexByte(args.Expression, 0) >= 0 || strings.IndexByte(args.Value, 0) >= 0 {
		return nil, false, "setExpression input exceeds its size or NUL-safety limit"
	}
	if args.FrameID != 0 {
		if _, ok := s.selectFrame(args.FrameID, contexts...); !ok {
			return nil, false, "unknown stack frame"
		}
	}
	return s.assignExpression(args.Expression, args.Value, contexts...)
}

func (s *session) assignExpression(expression, value string, contexts ...context.Context) (any, bool, string) {
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	result, err := debugger.assign(expression, value, contexts...)
	if err != nil {
		return nil, false, err.Error()
	}
	if result.value == "" {
		result.value = value
	}
	return map[string]any{"value": result.value, "type": result.typeName, "variablesReference": 0}, true, ""
}

func (s *session) resume(command string, raw json.RawMessage, includeBody bool, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	mode := map[string]string{"cont": "continue", "next": "next", "step": "stepIn", "step up": "stepOut"}[command]
	var args struct {
		ThreadID int `json:"threadId"`
		TargetID int `json:"targetId"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.ThreadID <= 0 {
		return nil, false, "resume requires a valid threadId"
	}
	var resumeArguments []string
	if command == "step" && args.TargetID > 0 {
		s.stateMu.Lock()
		target, ok := s.stepTargets[args.TargetID]
		s.stateMu.Unlock()
		if !ok {
			return nil, false, "unknown step-in target"
		}
		mode, resumeArguments = "target", []string{target.className, target.method, target.signature}
	}
	if err := debugger.resumeWith(mode, s.tokenForThread(args.ThreadID), resumeArguments, contexts...); err != nil {
		return nil, false, err.Error()
	}
	s.stateMu.Lock()
	s.invalidateStopHandlesLocked()
	s.stateMu.Unlock()
	s.queuePostResponse(requestContext(contexts), func() {
		_ = s.event("continued", map[string]any{"threadId": args.ThreadID, "allThreadsContinued": true})
	})
	if includeBody {
		return map[string]any{"allThreadsContinued": true}, true, ""
	}
	return map[string]any{}, true, ""
}

func (s *session) pause(raw json.RawMessage, contexts ...context.Context) (any, bool, string) {
	s.debugOperationMu.Lock()
	defer s.debugOperationMu.Unlock()
	var args struct {
		ThreadID int `json:"threadId"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.ThreadID <= 0 {
		return nil, false, "invalid pause arguments"
	}
	debugger := s.currentDebugger()
	if debugger == nil {
		return nil, false, "debugger is not attached"
	}
	token := s.tokenForThread(args.ThreadID)
	if err := debugger.pause(token, contexts...); err != nil {
		return nil, false, err.Error()
	}
	threadID := args.ThreadID
	if threadID <= 0 {
		threadID = s.threadID("main")
	}
	s.stateMu.Lock()
	s.invalidateStopHandlesLocked()
	s.stateMu.Unlock()
	s.queuePostResponse(requestContext(contexts), func() {
		_ = s.event("stopped", map[string]any{"reason": "pause", "threadId": threadID, "allThreadsStopped": token == "", "description": "Paused by client"})
	})
	return map[string]any{}, true, ""
}

// frameSource builds the DAP source object for a stack frame: a disk path
// when the file lives under a source root, otherwise a sourceReference into
// the dependency's sources jar so the client can fetch it via the source
// request. Frames with neither keep just a display name.
func (s *session) frameSource(sourceName, frameName string, contexts ...context.Context) map[string]any {
	source := map[string]any{"name": sourceName}
	s.stateMu.Lock()
	classPaths := append([]string(nil), s.classPaths...)
	s.stateMu.Unlock()
	if s.sourceResolver != nil {
		if path, ok := s.sourceResolver(requestContext(contexts), classPaths, frameClassName(frameName), sourceName); ok {
			source["path"] = path
			s.stateMu.Lock()
			s.rememberSourceLocked(sourceName, path)
			s.stateMu.Unlock()
			return source
		}
	}
	if path := s.pathForSource(sourceName, frameName); path != "" {
		source["path"] = path
		return source
	}
	if ref, origin := s.sources.referenceFor(classPaths, frameName, sourceName, contexts...); ref > 0 {
		source["sourceReference"] = ref
		source["origin"] = origin
	}
	return source
}

func (s *session) invalidateStopHandlesLocked() {
	s.frames = make(map[int]debugFrame)
	s.variables = make(map[int]variableContext)
}

// sourceContent answers the DAP source request for a reference handed out by
// frameSource, streaming the entry from the sources jar.
func (s *session) sourceContent(ctx context.Context, raw json.RawMessage) (any, bool, string) {
	var args struct {
		SourceReference int `json:"sourceReference"`
	}
	if decodeDAPArguments(raw, &args) != nil || args.SourceReference <= 0 {
		return nil, false, "invalid source arguments"
	}
	content, ok := s.sources.contentFor(args.SourceReference, ctx)
	if !ok {
		return nil, false, "source content is not available for this reference"
	}
	return map[string]any{"content": content}, true, ""
}

func (s *session) pathForSource(name string, frameNames ...string) string {
	s.stateMu.Lock()
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
		for _, candidateRelative := range []string{relative, name} {
			candidate, ok := sourceCandidateUnderRoot(root, candidateRelative)
			if ok {
				s.stateMu.Lock()
				if _, exists := s.sourceCache[cacheKey]; exists || len(s.sourceCache) < maxRememberedPath {
					s.sourceCache[cacheKey] = candidate
				}
				s.rememberSourceLocked(name, candidate)
				s.stateMu.Unlock()
				return candidate
			}
		}
	}
	return ""
}

func sourceCandidateUnderRoot(root, relative string) (string, bool) {
	if root == "" || relative == "" || strings.IndexByte(relative, 0) >= 0 {
		return "", false
	}
	relative = filepath.Clean(filepath.FromSlash(relative))
	if relative == "." || relative == ".." || filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	root = filepath.Clean(root)
	candidate := filepath.Clean(filepath.Join(root, relative))
	contained, err := filepath.Rel(root, candidate)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", false
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	resolvedCandidate, candidateErr := filepath.EvalSymlinks(candidate)
	if rootErr != nil || candidateErr != nil {
		return "", false
	}
	contained, err = filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", false
	}
	info, err := os.Stat(resolvedCandidate)
	if err != nil || info.IsDir() {
		return "", false
	}
	return filepath.Clean(resolvedCandidate), true
}

func (s *session) rememberSourceLocked(name, path string) {
	if name == "" || path == "" {
		return
	}
	if _, exists := s.sourceByName[name]; !exists && len(s.sourceByName) >= maxRememberedPath {
		return
	}
	s.sourceByName[name] = path
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
		if len(out) >= 4096 {
			break
		}
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

func (s *session) exceptionInfo(contexts ...context.Context) any {
	s.stateMu.Lock()
	description := s.lastException
	s.stateMu.Unlock()
	if description == "" {
		description = "No exception information is available"
	}
	info := map[string]any{"exceptionId": "java.lang.Throwable", "description": description, "breakMode": "always"}
	debugger := s.currentDebugger()
	if debugger == nil {
		return info
	}
	rows, err := debugger.requestFor(contexts, "EXCEPTION")
	if err != nil || len(rows) == 0 || len(rows[0]) < 4 {
		return info
	}
	typeName, message, uncaught, stack := rows[0][0], rows[0][1], rows[0][2] == "true", rows[0][3]
	info["exceptionId"] = typeName
	if message != "" {
		info["description"] = message
	} else {
		info["description"] = typeName
	}
	if uncaught {
		info["breakMode"] = "unhandled"
	}
	simple := typeName
	if dot := strings.LastIndexByte(simple, '.'); dot >= 0 {
		simple = simple[dot+1:]
	}
	details := map[string]any{"typeName": simple, "fullTypeName": typeName, "stackTrace": stack}
	if message != "" {
		details["message"] = message
	}
	info["details"] = details
	return info
}
