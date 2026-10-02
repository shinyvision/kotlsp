package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// End-to-end tests drive the adapter the way an editor does: over its TCP
// connection, against programs compiled here from testdata/e2e. They need a
// JDK (and kotlinc for the Kotlin test) and nothing else from the machine.

// dapClient is an editor-side DAP connection.
type dapClient struct {
	t       *testing.T
	writer  *bufio.Writer
	mu      sync.Mutex
	seq     int
	waiters map[int]chan map[string]any
	events  []map[string]any
	used    map[int]bool
	// disconnected is set once a disconnect was answered; the adapter then
	// closes the connection.
	disconnected bool
}

func requireJDK(t *testing.T) {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires the JDK debugger")
	}
	for _, tool := range []string{"java", "javac"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is unavailable")
		}
	}
}

// e2eProgram compiles testdata/e2e/App.java and returns the class directory
// and the source path breakpoints name.
func e2eProgram(t *testing.T) (string, string) {
	t.Helper()
	requireJDK(t)
	source, err := filepath.Abs(filepath.Join("testdata", "e2e", "App.java"))
	if err != nil {
		t.Fatal(err)
	}
	classes := t.TempDir()
	if output, err := exec.Command("javac", "-g", "-d", classes, source).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	return classes, source
}

func connectDAP(t *testing.T) *dapClient {
	t.Helper()
	server, err := Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", server.Port()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &dapClient{t: t, writer: bufio.NewWriter(conn), seq: 1, waiters: map[int]chan map[string]any{}, used: map[int]bool{}}
	go func() {
		reader := bufio.NewReader(conn)
		for {
			payload, err := readMessage(reader)
			if err != nil {
				return
			}
			var m map[string]any
			if json.Unmarshal(payload, &m) != nil {
				continue
			}
			c.mu.Lock()
			if m["type"] == "response" {
				if ch := c.waiters[int(m["request_seq"].(float64))]; ch != nil {
					ch <- m
				}
			} else {
				c.events = append(c.events, m)
			}
			c.mu.Unlock()
		}
	}()
	c.request("initialize", map[string]any{"adapterID": "kotlsp", "linesStartAt1": true, "columnsStartAt1": true, "pathFormat": "path"})
	c.event("initialized", 5*time.Second)
	return c
}

// disconnect ends the session unless the test already did.
func (c *dapClient) disconnect() {
	c.mu.Lock()
	done := c.disconnected
	c.mu.Unlock()
	if !done {
		c.request("disconnect", map[string]any{"terminateDebuggee": true})
	}
}

// request sends a request and returns its response.
func (c *dapClient) request(command string, arguments any) map[string]any {
	c.t.Helper()
	c.mu.Lock()
	seq := c.seq
	c.seq++
	ch := make(chan map[string]any, 1)
	c.waiters[seq] = ch
	c.mu.Unlock()
	message := map[string]any{"seq": seq, "type": "request", "command": command}
	if arguments != nil {
		message["arguments"] = arguments
	}
	if err := writeMessage(c.writer, message); err != nil {
		c.t.Fatalf("%s: %v", command, err)
	}
	select {
	case response := <-ch:
		if command == "disconnect" && response["success"] == true {
			c.mu.Lock()
			c.disconnected = true
			c.mu.Unlock()
		}
		return response
	case <-time.After(20 * time.Second):
		c.t.Fatalf("%s: no response within 20s", command)
		return nil
	}
}

// ok sends a request that must succeed and returns its body.
func (c *dapClient) ok(command string, arguments any) map[string]any {
	c.t.Helper()
	response := c.request(command, arguments)
	if response["success"] != true {
		c.t.Fatalf("%s failed: %v", command, response["message"])
	}
	body, _ := response["body"].(map[string]any)
	return body
}

// event waits for the first not yet consumed event called name; nil when
// none arrives in time.
func (c *dapClient) event(name string, timeout time.Duration) map[string]any {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		for index, event := range c.events {
			if event["event"] == name && !c.used[index] {
				c.used[index] = true
				c.mu.Unlock()
				body, _ := event["body"].(map[string]any)
				if body == nil {
					body = map[string]any{}
				}
				return body
			}
		}
		c.mu.Unlock()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *dapClient) stopped() map[string]any {
	c.t.Helper()
	stop := c.event("stopped", 15*time.Second)
	if stop == nil {
		c.t.Fatal("no stopped event")
	}
	return stop
}

// pendingStops counts stopped events nobody waited for.
func (c *dapClient) pendingStops() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for index, event := range c.events {
		if event["event"] == "stopped" && !c.used[index] {
			count++
		}
	}
	return count
}

func (c *dapClient) output(category string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out strings.Builder
	for _, event := range c.events {
		if event["event"] != "output" {
			continue
		}
		body, _ := event["body"].(map[string]any)
		if category == "" || body["category"] == category {
			out.WriteString(fmt.Sprint(body["output"]))
		}
	}
	return out.String()
}

func (c *dapClient) breakpoints(source string, breakpoints ...map[string]any) []any {
	c.t.Helper()
	list := make([]any, len(breakpoints))
	for index, breakpoint := range breakpoints {
		list[index] = breakpoint
	}
	body := c.ok("setBreakpoints", map[string]any{"source": map[string]any{"path": source, "name": filepath.Base(source)}, "breakpoints": list})
	return body["breakpoints"].([]any)
}

type topFrame struct {
	id, line int
	name     string
}

func (c *dapClient) top(thread int) topFrame {
	c.t.Helper()
	frames := c.ok("stackTrace", map[string]any{"threadId": thread, "levels": 1})["stackFrames"].([]any)
	if len(frames) == 0 {
		c.t.Fatal("no stack frames")
	}
	frame := frames[0].(map[string]any)
	return topFrame{id: int(frame["id"].(float64)), line: int(frame["line"].(float64)), name: frame["name"].(string)}
}

func (c *dapClient) variables(reference any, filter ...string) []map[string]any {
	c.t.Helper()
	arguments := map[string]any{"variablesReference": reference}
	if len(filter) > 0 {
		arguments["filter"] = filter[0]
	}
	var out []map[string]any
	for _, value := range c.ok("variables", arguments)["variables"].([]any) {
		out = append(out, value.(map[string]any))
	}
	return out
}

// locals returns the frame's Locals scope reference and its variables by name.
func (c *dapClient) locals(frame int) (any, map[string]map[string]any) {
	c.t.Helper()
	scopes := c.ok("scopes", map[string]any{"frameId": frame})["scopes"].([]any)
	reference := scopes[0].(map[string]any)["variablesReference"]
	byName := map[string]map[string]any{}
	for _, variable := range c.variables(reference) {
		byName[variable["name"].(string)] = variable
	}
	return reference, byName
}

func (c *dapClient) evaluate(frame int, expression string) (string, string) {
	c.t.Helper()
	response := c.request("evaluate", map[string]any{"expression": expression, "frameId": frame, "context": "repl"})
	if response["success"] != true {
		return "", fmt.Sprint(response["message"])
	}
	return fmt.Sprint(response["body"].(map[string]any)["result"]), ""
}

func threadOf(stop map[string]any) int {
	id, _ := stop["threadId"].(float64)
	return int(id)
}

func launchApp(t *testing.T, programArguments ...string) (*dapClient, string) {
	t.Helper()
	classes, source := e2eProgram(t)
	c := connectDAP(t)
	c.ok("launch", map[string]any{"mainClass": "e2e.App", "args": programArguments, "classPaths": []string{classes}, "sourcePaths": []string{filepath.Dir(filepath.Dir(source))}})
	t.Cleanup(func() { c.disconnect() })
	return c, source
}

// A step that ends on a breakpoint's line arrives with that breakpoint. Its
// false condition used to resume the thread the step had stopped, and every
// later stop then showed the previous position.
func TestStepOntoConditionalBreakpointStaysStopped(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 37}, map[string]any{"line": 19, "condition": "a == 3"})
	c.ok("configurationDone", nil)
	thread := threadOf(c.stopped())
	for _, step := range []struct {
		command string
		want    string
		line    int
	}{
		{"stepIn", "e2e.App.square", 24},
		{"stepOut", "e2e.App.work", 37},
		{"stepIn", "e2e.App.add", 19},
		{"next", "e2e.App.add", 20},
	} {
		c.ok(step.command, map[string]any{"threadId": thread})
		stop := c.stopped()
		top := c.top(thread)
		if stop["reason"] != "step" || top.name != step.want || top.line != step.line {
			t.Fatalf("%s: stopped %v at %s:%d, want a step at %s:%d", step.command, stop, top.name, top.line, step.want, step.line)
		}
		time.Sleep(200 * time.Millisecond)
		if extra := c.pendingStops(); extra != 0 {
			t.Fatalf("%s: %d extra stopped events", step.command, extra)
		}
	}
}

// Evaluation runs methods in the target. A breakpoint the call reaches is
// skipped rather than suspending the VM under the invocation.
func TestEvaluateCallsMethodsAndLogicalOperators(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 19, "condition": "a == 3 && b == 9"}, map[string]any{"line": 24, "hitCondition": "100"})
	c.ok("configurationDone", nil)
	stop := c.stopped()
	top := c.top(threadOf(stop))
	_, locals := c.locals(top.id)
	if locals["a"]["value"] != "3" || locals["b"]["value"] != "9" {
		t.Fatalf("the && condition stopped at a=%v b=%v", locals["a"]["value"], locals["b"]["value"])
	}
	for expression, want := range map[string]string{
		"a + b * 2":                   "21",
		"this.add(1, 2)":              "3",
		"add(1, 2)":                   "3",
		"square(4)":                   "16",
		"label.length()":              "3",
		"a == 3 || nonexistent":       "true",
		"a == 1 && nonexistent":       "false",
		"!(a > 2)":                    "false",
		"a > 2 ? \"big\" : \"small\"": `"big"`,
	} {
		if got, failure := c.evaluate(top.id, expression); got != want {
			t.Errorf("%s = %q (%s), want %s", expression, got, failure, want)
		}
	}
	// square has a breakpoint the call reaches; it is skipped and said so.
	if got, failure := c.evaluate(top.id, "square(5)"); got != "25" {
		t.Fatalf("square(5) = %q (%s)", got, failure)
	}
	if output := c.output("console"); !strings.Contains(output, "Skipped a stop at e2e.App.square:24") {
		t.Fatalf("no notice of the skipped breakpoint: %q", output)
	}
}

func TestCompletionsOfferLocalsFieldsAndMembers(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 19})
	c.ok("configurationDone", nil)
	top := c.top(threadOf(c.stopped()))
	labels := func(text string) []string {
		var out []string
		for _, target := range c.ok("completions", map[string]any{"frameId": top.id, "text": text, "column": len(text) + 1})["targets"].([]any) {
			out = append(out, target.(map[string]any)["label"].(string))
		}
		return out
	}
	for text, want := range map[string]string{"la": "label", "this.co": "counter", "this.": "square", "a": "add", "label.len": "length"} {
		if got := labels(text); !containsString(got, want) {
			t.Errorf("completions of %q = %v, want %s among them", text, got, want)
		}
	}
}

func TestVariablesShowThisElementsAndBoxedValues(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 39})
	c.ok("configurationDone", nil)
	top := c.top(threadOf(c.stopped()))
	_, locals := c.locals(top.id)
	fields := map[string]string{}
	for _, field := range c.variables(locals["this"]["variablesReference"]) {
		fields[field["name"].(string)] = field["value"].(string) + " " + fmt.Sprint(field["evaluateName"])
	}
	if fields["counter"] != "7 this.counter" || fields["label"] != `"app" this.label` {
		t.Fatalf("this = %v", fields)
	}
	names := locals["names"]
	if names["indexedVariables"] != float64(2) || !strings.HasSuffix(names["value"].(string), "size=2") {
		t.Fatalf("names = %v", names)
	}
	elements := c.variables(names["variablesReference"], "indexed")
	if len(elements) != 2 || elements[1]["value"] != `"b"` || elements[1]["evaluateName"] != "names.get(1)" {
		t.Fatalf("names elements = %v", elements)
	}
	if raw := c.variables(names["variablesReference"], "named"); len(raw) != 1 || raw[0]["name"] != "[raw]" {
		t.Fatalf("names named children = %v", raw)
	}
	entries := c.variables(locals["ages"]["variablesReference"], "indexed")
	if len(entries) != 1 || entries[0]["name"] != `"x"` || entries[0]["value"] != "1" || entries[0]["variablesReference"] != float64(0) {
		t.Fatalf("ages entries = %v", entries)
	}
}

func TestStepInSkipsJDKAndStepsIntoTargets(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 37})
	c.ok("configurationDone", nil)
	thread := threadOf(c.stopped())
	top := c.top(thread)
	var labels []string
	addID := 0.0
	for _, target := range c.ok("stepInTargets", map[string]any{"frameId": top.id})["targets"].([]any) {
		entry := target.(map[string]any)
		labels = append(labels, entry["label"].(string))
		if entry["label"] == "App.add" {
			addID = entry["id"].(float64)
		}
	}
	if strings.Join(labels, ",") != "App.square,App.add" {
		t.Fatalf("step-in targets = %v", labels)
	}
	c.ok("stepIn", map[string]any{"threadId": thread, "targetId": addID})
	c.stopped()
	if top = c.top(thread); top.name != "e2e.App.add" || top.line != 19 {
		t.Fatalf("stepping into App.add stopped at %s:%d", top.name, top.line)
	}
	// Stepping into println goes through string concatenation in the JDK;
	// the step filters land on the program's next line instead.
	c.breakpoints(source, map[string]any{"line": 39})
	c.ok("continue", map[string]any{"threadId": thread})
	c.stopped()
	c.ok("stepIn", map[string]any{"threadId": thread})
	c.stopped()
	if top = c.top(thread); top.name != "e2e.App.work" || top.line != 40 {
		t.Fatalf("stepIn on println stopped at %s:%d", top.name, top.line)
	}
}

func TestSetVariableOnLocalsFieldsArraysListsAndMaps(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 39})
	c.ok("configurationDone", nil)
	top := c.top(threadOf(c.stopped()))
	scope, locals := c.locals(top.id)
	for _, change := range []struct {
		reference        any
		name, value, get string
		want             string
	}{
		{scope, "total", "77", "total", "77"},
		{locals["this"]["variablesReference"], "counter", "123", "this.counter", "123"},
		{locals["numbers"]["variablesReference"], "[0]", "42", "numbers[0]", "42"},
		{locals["names"]["variablesReference"], "[0]", `"q"`, "names.get(0)", `"q"`},
		{locals["ages"]["variablesReference"], `"x"`, "5", `ages.get("x")`, "5"},
	} {
		c.ok("setVariable", map[string]any{"variablesReference": change.reference, "name": change.name, "value": change.value})
		if got, failure := c.evaluate(top.id, change.get); got != change.want {
			t.Errorf("after setting %s: %s = %q (%s), want %s", change.name, change.get, got, failure, change.want)
		}
	}
}

// A condition that cannot be evaluated stops and says why; read as false, a
// typo in it silently disabled the breakpoint.
func TestBreakpointConditionErrorStops(t *testing.T) {
	c, source := launchApp(t)
	c.breakpoints(source, map[string]any{"line": 46, "condition": "nonexistent > 1"})
	c.ok("configurationDone", nil)
	if top := c.top(threadOf(c.stopped())); top.line != 46 {
		t.Fatalf("stopped at line %d", top.line)
	}
	if output := c.output("console"); !strings.Contains(output, `Breakpoint condition "nonexistent > 1"`) {
		t.Fatalf("no condition error reported: %q", output)
	}
}

func TestRestartFrameExceptionsAndTermination(t *testing.T) {
	c, _ := launchApp(t, "crash")
	c.ok("setExceptionBreakpoints", map[string]any{"filters": []string{"uncaught"}})
	c.ok("setFunctionBreakpoints", map[string]any{"breakpoints": []any{map[string]any{"name": "e2e.App.square"}}})
	c.ok("configurationDone", nil)
	stop := c.stopped()
	thread := threadOf(stop)
	if stop["reason"] != "function breakpoint" {
		t.Fatalf("function breakpoint stop = %v", stop)
	}
	c.ok("restartFrame", map[string]any{"frameId": c.top(thread).id})
	if stop = c.stopped(); stop["reason"] != "restart" {
		t.Fatalf("restartFrame was followed by %v", stop)
	}
	c.ok("setFunctionBreakpoints", map[string]any{"breakpoints": []any{}})
	c.ok("continue", map[string]any{"threadId": thread})
	if stop = c.stopped(); stop["reason"] != "exception" {
		t.Fatalf("uncaught exception stop = %v", stop)
	}
	info := c.ok("exceptionInfo", map[string]any{"threadId": thread})
	details, _ := info["details"].(map[string]any)
	if info["exceptionId"] != "java.lang.IllegalArgumentException" || info["breakMode"] != "unhandled" || details["message"] != "uncaught one" || !strings.Contains(fmt.Sprint(details["stackTrace"]), "e2e.App.main(App.java:69)") {
		t.Fatalf("exceptionInfo = %v", info)
	}
	c.ok("continue", map[string]any{"threadId": thread})
	if exited := c.event("exited", 15*time.Second); exited == nil || exited["exitCode"] != float64(1) {
		t.Fatalf("exited = %v", exited)
	}
	if c.event("terminated", 5*time.Second) == nil {
		t.Fatal("no terminated event")
	}
	if output := c.output(""); strings.Contains(output, "Listening for transport") || strings.Contains(output, "debuggee output error") {
		t.Fatalf("adapter noise in program output: %q", output)
	}
}

// terminate ends the debuggee; the client's disconnect after it must still
// be answered, not left to time out.
func TestDisconnectAfterTerminateIsAnswered(t *testing.T) {
	c, _ := launchApp(t, "loop")
	c.ok("configurationDone", nil)
	time.Sleep(500 * time.Millisecond)
	c.ok("pause", map[string]any{"threadId": 1})
	if stop := c.stopped(); stop["reason"] != "pause" {
		t.Fatalf("pause stop = %v", stop)
	}
	c.ok("terminate", map[string]any{})
	if c.event("terminated", 10*time.Second) == nil {
		t.Fatal("no terminated event")
	}
	started := time.Now()
	c.ok("disconnect", map[string]any{})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("disconnect took %s", elapsed)
	}
}

// Attached to a running VM, a file's classes are loaded, and a line names
// every class the file declares. One without code there (App$Inner for a
// line of App) must not fail the request.
func TestAttachSetsBreakpointsInLoadedClasses(t *testing.T) {
	classes, source := e2eProgram(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	command := exec.Command("java", fmt.Sprintf("-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:%d", port), "-cp", classes, "e2e.App", "loop")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = command.Wait(); close(exited) }()
	t.Cleanup(func() { _ = command.Process.Kill(); <-exited })
	c := connectDAP(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		response := c.request("attach", map[string]any{"hostName": "127.0.0.1", "port": port, "sourcePaths": []string{filepath.Dir(filepath.Dir(source))}})
		if response["success"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("attach: %v", response["message"])
		}
		time.Sleep(200 * time.Millisecond)
	}
	result := c.breakpoints(source, map[string]any{"line": 65}, map[string]any{"line": 22})
	if result[0].(map[string]any)["verified"] != true || result[1].(map[string]any)["verified"] != false {
		t.Fatalf("breakpoints = %v", result)
	}
	c.ok("configurationDone", nil)
	thread := threadOf(c.stopped())
	frames := c.ok("stackTrace", map[string]any{"threadId": thread, "levels": 1})["stackFrames"].([]any)
	if path := frames[0].(map[string]any)["source"].(map[string]any)["path"]; path != source {
		t.Fatalf("frame source = %v, want %s", path, source)
	}
	c.breakpoints(source)
	c.ok("disconnect", map[string]any{"terminateDebuggee": false})
	select {
	case <-exited:
		t.Fatal("the debuggee did not survive the disconnect")
	case <-time.After(time.Second):
	}
}

func TestKotlinBreakpointsLinesAndLocals(t *testing.T) {
	requireJDK(t)
	if _, err := exec.LookPath("kotlinc"); err != nil {
		t.Skip("kotlinc is unavailable")
	}
	source, err := filepath.Abs(filepath.Join("testdata", "e2e", "Main.kt"))
	if err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(t.TempDir(), "app.jar")
	if output, err := exec.Command("kotlinc", source, "-include-runtime", "-d", jar).CombinedOutput(); err != nil {
		t.Fatalf("kotlinc: %v\n%s", err, output)
	}
	c := connectDAP(t)
	c.ok("launch", map[string]any{"mainClass": "e2e.kt.MainKt", "classPaths": []string{jar}, "sourcePaths": []string{filepath.Dir(filepath.Dir(filepath.Dir(source)))}})
	t.Cleanup(func() { c.disconnect() })
	var requested []map[string]any
	for _, line := range []int{12, 16, 20, 35, 42} {
		requested = append(requested, map[string]any{"line": line})
	}
	for _, result := range c.breakpoints(source, requested...) {
		if result.(map[string]any)["verified"] != true {
			t.Fatalf("breakpoint not verified: %v", result)
		}
	}
	c.ok("configurationDone", nil)
	type visit struct {
		line   int
		locals string
	}
	var visits []visit
	for {
		stop := c.event("stopped", 15*time.Second)
		if stop == nil {
			break
		}
		thread := threadOf(stop)
		top := c.top(thread)
		_, locals := c.locals(top.id)
		var names []string
		for name := range locals {
			names = append(names, name)
		}
		sort.Strings(names)
		visits = append(visits, visit{top.line, strings.Join(names, ",")})
		if top.line == 42 {
			break
		}
		c.ok("continue", map[string]any{"threadId": thread})
	}
	// Line 16 once per call (Kotlin restates it after inlined code), line 12
	// once per list element; inline bookkeeping locals hidden, an extension
	// receiver shown as this and a captured value by its own name.
	want := []visit{
		{16, "this"},
		{12, "item,this"},
		{12, "item,this"},
		{20, "this"},
		{35, "total,x"},
		{42, "action,label,names,result,store,total,upper"},
	}
	if fmt.Sprint(visits) != fmt.Sprint(want) {
		t.Fatalf("stops = %v\nwant    %v", visits, want)
	}
}
