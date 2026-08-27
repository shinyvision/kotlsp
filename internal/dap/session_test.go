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
	if capabilities["supportTerminateDebuggee"] != true || capabilities["supportsSetExpression"] != false || capabilities["supportsExceptionInfoRequest"] != false || capabilities["supportsLoadedSourcesRequest"] != false {
		t.Fatalf("OpenKotlin capability parity mismatch: %#v", capabilities)
	}
	triggers, ok := capabilities["completionTriggerCharacters"].([]string)
	if !ok || len(triggers) != 1 || triggers[0] != "." {
		t.Fatalf("completion trigger characters = %#v", capabilities["completionTriggerCharacters"])
	}
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

func TestDebuggeeOutputAndJDBRelayDoNotTruncateLongOrNoisyStreams(t *testing.T) {
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

	process := &jdbProcess{incoming: make(chan string), chunks: make(chan string)}
	go process.relayChunks()
	go func() {
		for number := range 700 {
			process.incoming <- strconv.Itoa(number)
		}
		close(process.incoming)
	}()
	count := 0
	for chunk := range process.chunks {
		if chunk != strconv.Itoa(count) {
			t.Fatalf("JDB relay chunk %d = %q", count, chunk)
		}
		count++
	}
	if count != 700 {
		t.Fatalf("JDB relay returned %d chunks, want 700", count)
	}
}

func TestJDBBridgeLaunchBreakpointStackAndEvaluate(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("requires the JDK debugger")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java is unavailable")
	}
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac is unavailable")
	}
	if _, err := exec.LookPath("jdb"); err != nil {
		t.Skip("jdb is unavailable")
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

func TestDevtoolsRestartStopDetection(t *testing.T) {
	restart := `Exception occurred: org.springframework.boot.devtools.restart.SilentExitExceptionHandler$SilentExitException (uncaught)"thread=main", org.springframework.boot.devtools.restart.SilentExitExceptionHandler.exitCurrentThread(), line=94 bci=16`
	if !isDevtoolsRestartStop(restart) {
		t.Fatal("devtools restart stop was not detected")
	}
	real := `Exception occurred: java.lang.NullPointerException (uncaught)"thread=main", com.acme.Widget.run(), line=3 bci=4`
	if isDevtoolsRestartStop(real) {
		t.Fatal("ordinary exception misdetected as devtools restart")
	}
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
	for _, tool := range []string{"java", "javac", "jdb"} {
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
	// Expandable locals show the toString preview instead of the raw hint.
	if preview, _ := body["value"].(string); !strings.HasPrefix(preview, `"dapfixture.Inspection$Body@`) {
		t.Fatalf("body preview = %#v", body["value"])
	}
	text := findVariable(t, locals, "text")
	if text["value"] != `"scalpel"` || text["variablesReference"] != 0 {
		t.Fatalf("text local = %#v", text)
	}

	fields := fetchVariables(t, s, bodyReference)
	if tag := findVariable(t, fields, "tag"); tag["value"] != `"body"` {
		t.Fatalf("tag field = %#v", tag)
	}
	if inherited := findVariable(t, fields, "dapfixture.Inspection$Organ.name"); inherited["value"] != `"heart"` {
		t.Fatalf("inherited name field = %#v", inherited)
	}
	if missing := findVariable(t, fields, "missing"); missing["value"] != "null" || missing["variablesReference"] != 0 {
		t.Fatalf("null field = %#v", missing)
	}

	parts := findVariable(t, fields, "parts")
	if parts["type"] != "java.util.ArrayList" || parts["variablesReference"] == 0 {
		t.Fatalf("parts field = %#v", parts)
	}
	elements := fetchVariables(t, s, parts["variablesReference"].(int))
	if len(elements) != 2 {
		t.Fatalf("list elements = %#v", elements)
	}
	if elements[0]["name"] != "[0]" || elements[0]["value"] != `"arm"` || elements[1]["value"] != `"leg"` {
		t.Fatalf("list elements = %#v", elements)
	}

	sizes := findVariable(t, fields, "sizes")
	if sizes["type"] != "java.util.HashMap" || sizes["variablesReference"] == 0 {
		t.Fatalf("sizes field = %#v", sizes)
	}
	entries := fetchVariables(t, s, sizes["variablesReference"].(int))
	if len(entries) != 2 {
		t.Fatalf("map entries = %#v", entries)
	}
	var armEntry map[string]any
	for _, entry := range entries {
		if entry["value"] == `"arm=2"` {
			armEntry = entry
		}
	}
	if armEntry == nil {
		t.Fatalf("map entries = %#v", entries)
	}
	entryReference := armEntry["variablesReference"].(int)
	if entryReference == 0 {
		t.Fatalf("map entry is not expandable: %#v", armEntry)
	}
	entryFields := fetchVariables(t, s, entryReference)
	if key := findVariable(t, entryFields, "key"); key["value"] != `"arm"` {
		t.Fatalf("entry key = %#v", key)
	}

	nums := findVariable(t, locals, "nums")
	if nums["type"] != "int[3]" || nums["variablesReference"] == 0 {
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
	// An evaluate result is a quoted toString preview; it must still be
	// expandable in place (hover/watch/REPL).
	evaluation, ok, message := s.dispatch("evaluate", mustRaw(t, map[string]any{"frameId": frameID, "expression": "body.parts"}))
	if !ok {
		t.Fatalf("evaluate failed: %s", message)
	}
	evalBody := evaluation.(map[string]any)
	if evalBody["result"] != `"[arm, leg]"` {
		t.Fatalf("evaluate result = %#v", evalBody["result"])
	}
	evalReference := evalBody["variablesReference"].(int)
	if evalReference == 0 {
		t.Fatalf("evaluate result is not expandable: %#v", evalBody)
	}
	evalElements := fetchVariables(t, s, evalReference)
	if len(evalElements) != 2 || evalElements[0]["value"] != `"arm"` || evalElements[1]["value"] != `"leg"` {
		t.Fatalf("evaluate expansion = %#v", evalElements)
	}
	s.disconnect(json.RawMessage(`{"terminateDebuggee":true}`), true)
}
