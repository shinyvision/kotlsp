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
