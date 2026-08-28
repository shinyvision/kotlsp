package dap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSourceClassesForJavaAndKotlin(t *testing.T) {
	javaClasses := sourceClasses(filepath.Join("testdata", "Debuggee.java"))
	if len(javaClasses) != 1 || javaClasses[0] != "dapfixture.Debuggee" {
		t.Fatalf("Java classes = %#v", javaClasses)
	}
	kotlinPath := filepath.Join("testdata", "Worker.kt")
	kotlinClasses := sourceClasses(kotlinPath)
	for _, expected := range []string{"demo.Registry", "demo.Worker", "demo.WorkerKt"} {
		if !containsString(kotlinClasses, expected) {
			t.Fatalf("Kotlin classes missing %s: %#v", expected, kotlinClasses)
		}
	}
}

func TestPathForSourceRejectsTraversalAndSymlinkEscape(t *testing.T) {
	temporary := t.TempDir()
	root := filepath.Join(temporary, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(temporary, "secret.kt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	defer s.close()
	s.sourceRoots = []string{root}
	if path := s.pathForSource(filepath.Join("..", "secret.kt")); path != "" {
		t.Fatalf("traversal source resolved outside root: %s", path)
	}
	link := filepath.Join(root, "linked.kt")
	if err := os.Symlink(outside, link); err == nil {
		if path := s.pathForSource("linked.kt"); path != "" {
			t.Fatalf("symlink source resolved outside root: %s", path)
		}
	}
}

func TestInitializeAdvertisesOnlyImplementedDebuggerFeatures(t *testing.T) {
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	defer s.close()
	result, ok, message := s.dispatch("initialize", json.RawMessage(`{}`))
	if !ok || message != "" {
		t.Fatalf("initialize failed: %s", message)
	}
	capabilities := result.(map[string]any)
	for _, name := range []string{"supportsConfigurationDoneRequest", "supportsFunctionBreakpoints", "supportsEvaluateForHovers", "supportsSetVariable", "supportsTerminateRequest"} {
		if capabilities[name] != true {
			t.Fatalf("missing capability %s: %#v", name, capabilities)
		}
	}
	if capabilities["supportTerminateDebuggee"] != true || capabilities["supportsSetExpression"] != true || capabilities["supportsExceptionInfoRequest"] != true || capabilities["supportsLoadedSourcesRequest"] != true || capabilities["supportsCancelRequest"] != true {
		t.Fatalf("OpenKotlin capability parity mismatch: %#v", capabilities)
	}
	triggers, ok := capabilities["completionTriggerCharacters"].([]string)
	if !ok || len(triggers) != 1 || triggers[0] != "." {
		t.Fatalf("completion trigger characters = %#v", capabilities["completionTriggerCharacters"])
	}
}

func TestDisconnectCanLeaveLaunchedDebuggeeRunning(t *testing.T) {
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	s.debugMu.Lock()
	s.launched = true
	s.debugMu.Unlock()
	s.disconnect(json.RawMessage(`{"terminateDebuggee":false}`), false)
	s.debugMu.Lock()
	leave := s.leaveDebuggee
	s.leaveDebuggee = false // restore ordinary cleanup semantics for the test
	s.debugMu.Unlock()
	if !leave {
		t.Fatal("disconnect ignored terminateDebuggee=false")
	}
	s.close()
}

func TestSessionCloseJoinsOwnedWorkers(t *testing.T) {
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	started := make(chan struct{})
	finished := make(chan struct{})
	if !s.startWorker(func() {
		close(started)
		<-s.ctx.Done()
		close(finished)
	}) {
		t.Fatal("worker was rejected before close")
	}
	<-started
	s.close()
	select {
	case <-finished:
	default:
		t.Fatal("session close returned before its worker exited")
	}
	if s.startWorker(func() {}) {
		t.Fatal("session accepted a worker after close")
	}
}

func TestCancelledLaunchKillsDebuggeeBeforeJDWPIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a small POSIX test executable")
	}
	executable := filepath.Join(t.TempDir(), "fake-java")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newSession(ctx, bufio.NewWriter(io.Discard))
	done := make(chan string, 1)
	launch := mustRaw(t, map[string]any{"mainClass": "NeverStarts", "javaExec": executable})
	go func() {
		_, _, message := s.launch(ctx, launch)
		done <- message
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.debugMu.Lock()
		started := s.debuggee != nil && s.debuggee.Process != nil
		s.debugMu.Unlock()
		if started || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case message := <-done:
		if !strings.Contains(message, context.Canceled.Error()) {
			t.Fatalf("cancelled launch message = %q", message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled launch did not return")
	}
	s.debugMu.Lock()
	process := s.debuggee.Process
	s.debugMu.Unlock()
	if process != nil && process.Kill() == nil {
		t.Fatal("debuggee survived cancelled launch")
	}
	s.close()
}

func TestBreakpointLocationsReturnsEveryExecutableLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Many.java")
	var source strings.Builder
	source.WriteString("class Many { void run() {\n")
	for line := range 700 {
		source.WriteString("int value")
		source.WriteString(strconv.Itoa(line))
		source.WriteString(" = ")
		source.WriteString(strconv.Itoa(line))
		source.WriteString(";\n")
	}
	source.WriteString("} }\n")
	if err := os.WriteFile(path, []byte(source.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	result, ok, message := breakpointLocations(mustRaw(t, map[string]any{
		"source": map[string]any{"path": path}, "line": 1, "endLine": 702,
	}))
	if !ok {
		t.Fatal(message)
	}
	locations := result.(map[string]any)["breakpoints"].([]map[string]any)
	if len(locations) < 700 {
		t.Fatalf("breakpointLocations returned %d executable lines, want at least 700", len(locations))
	}
}

func TestBreakpointLocationsUseClassLineNumberTables(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac unavailable")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "BreakConditional.java")
	source := "class BreakConditional {\n" +
		"static final int VALUE = 1;\n" +
		"void run(int x) {\n" +
		"while (x > 0) {\n" +
		"if (x == 2) break;\n" +
		"x--;\n" +
		"}\n" +
		"}\n" +
		"}\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("javac", "-g", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("javac: %v: %s", err, output)
	}
	result, ok, message := breakpointLocations(mustRaw(t, map[string]any{
		"source": map[string]any{"path": path}, "line": 2, "endLine": 6,
	}))
	if !ok {
		t.Fatal(message)
	}
	locations := result.(map[string]any)["breakpoints"].([]map[string]any)
	found := make(map[int]bool)
	for _, location := range locations {
		found[location["line"].(int)] = true
	}
	if found[2] {
		t.Fatalf("ConstantValue-only field was reported executable: %#v", locations)
	}
	if !found[5] {
		t.Fatalf("conditional break line missing from LineNumberTable result: %#v", locations)
	}
}

func TestBreakpointLocationsIncludeGeneratedNestedClassesOnLaunchClasspath(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac unavailable")
	}
	sourceDir := t.TempDir()
	classes := t.TempDir()
	path := filepath.Join(sourceDir, "NestedLines.java")
	source := "class NestedLines {\n" +
		"  Runnable make() {\n" +
		"    return new Runnable() {\n" +
		"      public void run() {\n" +
		"        System.out.println(\"nested\");\n" +
		"      }\n" +
		"    };\n" +
		"  }\n" +
		"}\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("javac", "-g", "-d", classes, path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("javac: %v: %s", err, output)
	}
	result, ok, message := breakpointLocations(mustRaw(t, map[string]any{
		"source": map[string]any{"path": path}, "line": 5, "endLine": 5,
	}), classes)
	if !ok {
		t.Fatal(message)
	}
	locations := result.(map[string]any)["breakpoints"].([]map[string]any)
	if len(locations) != 1 || locations[0]["line"] != 5 {
		t.Fatalf("generated nested class executable line missing: %#v", locations)
	}
	classesByLine, available := executableBytecodeClasses(path, []string{classes})
	if !available || len(classesByLine[5]) != 1 || !strings.Contains(classesByLine[5][0], "NestedLines$1") {
		t.Fatalf("generated breakpoint class for line 5 = %#v (available=%v)", classesByLine[5], available)
	}
}

func TestDebuggeeOutputAndBridgeBufferDoNotSilentlyTruncate(t *testing.T) {
	var wire bytes.Buffer
	writer := bufio.NewWriter(&wire)
	s := newSession(context.Background(), writer)
	defer s.close()
	longLine := strings.Repeat("z", 70<<10)
	s.streamDebuggee(strings.NewReader(longLine+"\ntail-without-newline"), "stdout")
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if output := wire.String(); !strings.Contains(output, longLine) || !strings.Contains(output, "tail-without-newline") {
		t.Fatalf("debuggee output was incomplete: %d wire bytes", len(output))
	}

	var bridge boundedBridgeBuffer
	_, _ = bridge.Write([]byte(strings.Repeat("x", 2<<20)))
	if !bridge.truncated || !strings.Contains(bridge.String(), "output truncated") {
		t.Fatal("bounded bridge diagnostics did not disclose truncation")
	}
}

func TestJDIBridgeLaunchBreakpointStackAndEvaluate(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires the JDK debugger")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java is unavailable")
	}
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac is unavailable")
	}
	classes := t.TempDir()
	source, err := filepath.Abs(filepath.Join("testdata", "Debuggee.java"))
	if err != nil {
		t.Fatal(err)
	}
	compile := exec.Command("javac", "-g", "-d", classes, source)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := newSession(ctx, bufio.NewWriter(io.Discard))
	defer s.close()
	launch := mustRaw(t, map[string]any{"mainClass": "dapfixture.Debuggee", "classPaths": []string{classes}})
	if _, ok, message := s.dispatch("launch", launch); !ok {
		t.Fatalf("launch failed: %s", message)
	}
	breakpointArgs := mustRaw(t, map[string]any{"source": map[string]any{"name": "Debuggee.java", "path": source}, "breakpoints": []any{map[string]any{"line": 7}}})
	result, ok, message := s.dispatch("setBreakpoints", breakpointArgs)
	if !ok || !strings.Contains(string(mustRaw(t, result)), `"verified":true`) {
		t.Fatalf("setBreakpoints failed: %s %#v", message, result)
	}
	if _, ok, message = s.dispatch("configurationDone", json.RawMessage(`{}`)); !ok {
		t.Fatalf("configurationDone failed: %s", message)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.stateMu.Lock()
		stopped := len(s.threadIDs) > 0
		s.stateMu.Unlock()
		if stopped {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	threadsResult, ok, message := s.dispatch("threads", json.RawMessage(`{}`))
	if !ok {
		t.Fatalf("threads failed: %s", message)
	}
	encoded := string(mustRaw(t, threadsResult))
	if !strings.Contains(encoded, `"name":"main"`) {
		t.Fatalf("main thread not found: %s", encoded)
	}
	mainID := s.threadID("main")
	stackResult, ok, message := s.dispatch("stackTrace", mustRaw(t, map[string]any{"threadId": mainID}))
	if !ok || !strings.Contains(string(mustRaw(t, stackResult)), "Debuggee.main") {
		t.Fatalf("stackTrace failed: %s %#v", message, stackResult)
	}
	s.stateMu.Lock()
	frameID := 0
	for id := range s.frames {
		frameID = id
		break
	}
	s.stateMu.Unlock()
	evaluation, ok, message := s.dispatch("evaluate", mustRaw(t, map[string]any{"frameId": frameID, "expression": "value"}))
	if !ok || !strings.Contains(string(mustRaw(t, evaluation)), "42") {
		t.Fatalf("evaluate failed: %s %#v", message, evaluation)
	}
	s.disconnect(json.RawMessage(`{"terminateDebuggee":true}`), true)
}

func mustRaw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func findVariable(t *testing.T, variables []map[string]any, name string) map[string]any {
	t.Helper()
	for _, variable := range variables {
		if variable["name"] == name {
			return variable
		}
	}
	t.Fatalf("variable %s not found in %#v", name, variables)
	return nil
}

func fetchVariables(t *testing.T, s *session, reference int) []map[string]any {
	t.Helper()
	result, ok, message := s.dispatch("variables", mustRaw(t, map[string]any{"variablesReference": reference}))
	if !ok {
		t.Fatalf("variables(%d) failed: %s", reference, message)
	}
	return result.(map[string]any)["variables"].([]map[string]any)
}

func TestVariableInspectionExpandsObjectsCollectionsArraysAndMaps(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires the JDK debugger")
	}
	for _, tool := range []string{"java", "javac"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is unavailable")
		}
	}
	classes := t.TempDir()
	source, err := filepath.Abs(filepath.Join("testdata", "Inspection.java"))
	if err != nil {
		t.Fatal(err)
	}
	compile := exec.Command("javac", "-g", "-d", classes, source)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := newSession(ctx, bufio.NewWriter(io.Discard))
	defer s.close()
	launch := mustRaw(t, map[string]any{"mainClass": "dapfixture.Inspection", "classPaths": []string{classes}})
	if _, ok, message := s.dispatch("launch", launch); !ok {
		t.Fatalf("launch failed: %s", message)
	}
	breakpointArgs := mustRaw(t, map[string]any{"source": map[string]any{"name": "Inspection.java", "path": source}, "breakpoints": []any{map[string]any{"line": 22}}})
	if _, ok, message := s.dispatch("setBreakpoints", breakpointArgs); !ok {
		t.Fatalf("setBreakpoints failed: %s", message)
	}
	if _, ok, message := s.dispatch("configurationDone", json.RawMessage(`{}`)); !ok {
		t.Fatalf("configurationDone failed: %s", message)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.stateMu.Lock()
		stopped := len(s.threadIDs) > 0
		s.stateMu.Unlock()
		if stopped {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mainID := s.threadID("main")
	if _, ok, message := s.dispatch("stackTrace", mustRaw(t, map[string]any{"threadId": mainID})); !ok {
		t.Fatalf("stackTrace failed: %s", message)
	}
	s.stateMu.Lock()
	frameID := 0
	for id := range s.frames {
		frameID = id
		break
	}
	s.stateMu.Unlock()
	scopesResult, ok, message := s.dispatch("scopes", mustRaw(t, map[string]any{"frameId": frameID}))
	if !ok {
		t.Fatalf("scopes failed: %s", message)
	}
	scopes := scopesResult.(map[string]any)["scopes"].([]any)
	localsReference := scopes[0].(map[string]any)["variablesReference"].(int)

	locals := fetchVariables(t, s, localsReference)
	body := findVariable(t, locals, "body")
	if body["type"] != "dapfixture.Inspection$Body" {
		t.Fatalf("body type = %#v", body["type"])
	}
	bodyReference := body["variablesReference"].(int)
	if bodyReference == 0 {
		t.Fatalf("body is not expandable: %#v", body)
	}
	if preview, _ := body["value"].(string); !strings.HasPrefix(preview, "instance of dapfixture.Inspection$Body") {
		t.Fatalf("body JDI rendering = %#v", body["value"])
	}
	text := findVariable(t, locals, "text")
	if text["value"] != `"scalpel"` || text["variablesReference"] != 0 {
		t.Fatalf("text local = %#v", text)
	}

	fields := fetchVariables(t, s, bodyReference)
	if tag := findVariable(t, fields, "tag"); tag["value"] != `"body"` {
		t.Fatalf("tag field = %#v", tag)
	}
	if inherited := findVariable(t, fields, "name"); inherited["value"] != `"heart"` {
		t.Fatalf("inherited name field = %#v", inherited)
	}
	if missing := findVariable(t, fields, "missing"); missing["value"] != "null" || missing["variablesReference"] != 0 {
		t.Fatalf("null field = %#v", missing)
	}

	parts := findVariable(t, fields, "parts")
	if parts["type"] != "java.util.ArrayList" || parts["variablesReference"] == 0 {
		t.Fatalf("parts field = %#v", parts)
	}
	partFields := fetchVariables(t, s, parts["variablesReference"].(int))
	if size := findVariable(t, partFields, "size"); size["value"] != "2" {
		t.Fatalf("ArrayList size field = %#v", size)
	}
	elementData := findVariable(t, partFields, "elementData")
	if elementData["variablesReference"] == 0 {
		t.Fatalf("ArrayList backing array is not expandable: %#v", elementData)
	}
	elements := fetchVariables(t, s, elementData["variablesReference"].(int))
	if len(elements) < 2 || elements[0]["value"] != `"arm"` || elements[1]["value"] != `"leg"` {
		t.Fatalf("ArrayList backing elements = %#v", elements)
	}

	sizes := findVariable(t, fields, "sizes")
	if sizes["type"] != "java.util.HashMap" || sizes["variablesReference"] == 0 {
		t.Fatalf("sizes field = %#v", sizes)
	}
	mapFields := fetchVariables(t, s, sizes["variablesReference"].(int))
	if size := findVariable(t, mapFields, "size"); size["value"] != "2" {
		t.Fatalf("HashMap size field = %#v", size)
	}

	nums := findVariable(t, locals, "nums")
	if nums["type"] != "int[]" || nums["variablesReference"] == 0 || nums["indexedVariables"] != 3 {
		t.Fatalf("nums local = %#v", nums)
	}
	arrayElements := fetchVariables(t, s, nums["variablesReference"].(int))
	if len(arrayElements) != 3 {
		t.Fatalf("array elements = %#v", arrayElements)
	}
	for index, want := range []string{"7", "8", "9"} {
		if arrayElements[index]["name"] != "["+strconv.Itoa(index)+"]" || arrayElements[index]["value"] != want {
			t.Fatalf("array element %d = %#v", index, arrayElements[index])
		}
	}
	// Explicit evaluation returns a structured object identity without calling
	// toString, and remains expandable in place.
	evaluation, ok, message := s.dispatch("evaluate", mustRaw(t, map[string]any{"frameId": frameID, "expression": "body.parts"}))
	if !ok {
		t.Fatalf("evaluate failed: %s", message)
	}
	evalBody := evaluation.(map[string]any)
	if !strings.HasPrefix(evalBody["result"].(string), "instance of java.util.ArrayList") {
		t.Fatalf("evaluate result = %#v", evalBody["result"])
	}
	evalReference := evalBody["variablesReference"].(int)
	if evalReference == 0 {
		t.Fatalf("evaluate result is not expandable: %#v", evalBody)
	}
	evalFields := fetchVariables(t, s, evalReference)
	if size := findVariable(t, evalFields, "size"); size["value"] != "2" {
		t.Fatalf("evaluate expansion = %#v", evalFields)
	}
	s.disconnect(json.RawMessage(`{"terminateDebuggee":true}`), true)
}
