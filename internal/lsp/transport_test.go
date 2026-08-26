package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/jsonrpc"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func TestExtractCommandCompletesBidirectionalStdioApplyEdit(t *testing.T) {
	clientRead, serverWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	serverRead, clientWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer clientRead.Close()
	defer serverWrite.Close()
	defer serverRead.Close()
	defer clientWrite.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, serverRead, serverWrite, "") }()
	reader := bufio.NewReader(clientRead)
	request := func(id int, method string, params any) jsonrpc.Message {
		t.Helper()
		writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		for {
			message := readLSPFrame(t, reader)
			if len(message.ID) == 0 {
				continue
			}
			if message.Method != "" {
				t.Fatalf("unexpected server request before executeCommand: %s", message.Method)
			}
			var responseID int
			if json.Unmarshal(message.ID, &responseID) == nil && responseID == id {
				if message.Error != nil {
					t.Fatalf("%s: %v", method, message.Error)
				}
				return message
			}
		}
	}
	request(100, "initialize", map[string]any{"capabilities": map[string]any{}})
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{}})
	uri := protocol.URI("file:///virtual/ExtractWire.kt")
	source := "class ExtractWire { fun value(): Int { return 1 + 2 } }\n"
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "kotlin", "version": 1, "text": source}}})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	start := strings.Index(source, "1 + 2")
	selection := doc.Range(start, start+len("1 + 2"))
	actionsMessage := request(101, "textDocument/codeAction", map[string]any{
		"textDocument": map[string]any{"uri": uri}, "range": selection,
		"context": map[string]any{"diagnostics": []any{}},
	})
	var actions []protocol.CodeAction
	if err := json.Unmarshal(actionsMessage.Result, &actions); err != nil {
		t.Fatal(err)
	}
	var command *protocol.Command
	for _, action := range actions {
		if action.Kind == "refactor.extract.variable" {
			command = action.Command
			if action.Edit != nil {
				t.Fatal("extract code action embedded an edit")
			}
		}
	}
	if command == nil || len(command.Arguments) != 2 {
		t.Fatalf("extract command = %#v", command)
	}
	first, _ := json.Marshal(command.Arguments[0])
	second, _ := json.Marshal(command.Arguments[1])
	if string(first) != `"file:///virtual/ExtractWire.kt"` || !strings.Contains(string(second), `"type":"com.jetbrains.ls.api.features.impl.common.extract.LSExtractMemberProviderBase.Payload.Data"`) {
		t.Fatalf("extract arguments = %s, %s", first, second)
	}
	started := time.Now()
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "id": 102, "method": "workspace/executeCommand", "params": map[string]any{"command": command.Command, "arguments": command.Arguments}})
	applyRequest := readLSPFrame(t, reader)
	for len(applyRequest.ID) == 0 {
		applyRequest = readLSPFrame(t, reader)
	}
	if applyRequest.Method != "workspace/applyEdit" || len(applyRequest.ID) == 0 {
		t.Fatalf("server-initiated message = %#v", applyRequest)
	}
	var applyParams struct {
		Label string                 `json:"label"`
		Edit  protocol.WorkspaceEdit `json:"edit"`
	}
	if err := json.Unmarshal(applyRequest.Params, &applyParams); err != nil || applyParams.Label != "Extract variable" || len(applyParams.Edit.Changes[uri]) == 0 {
		t.Fatalf("workspace/applyEdit params = %s (%v)", applyRequest.Params, err)
	}
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(applyRequest.ID), "result": map[string]any{"applied": true}})
	response := readLSPFrame(t, reader)
	if string(response.ID) != "102" || response.Error != nil || string(response.Result) != "true" {
		t.Fatalf("executeCommand response = %#v", response)
	}
	if elapsed := time.Since(started); elapsed >= testLatencyLimit {
		t.Fatalf("extract command/applyEdit round trip took %s", elapsed)
	}
	cancel()
	_ = clientWrite.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdio server did not stop")
	}
}

func TestStdioRoundTripsAndDocumentNotificationsStayBelowLatencyLimit(t *testing.T) {
	clientRead, serverWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	serverRead, clientWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer clientRead.Close()
	defer serverWrite.Close()
	defer serverRead.Close()
	defer clientWrite.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, serverRead, serverWrite, "") }()
	reader := bufio.NewReader(clientRead)
	nextID := 1
	request := func(method string, params any) jsonrpc.Message {
		t.Helper()
		id := nextID
		nextID++
		started := time.Now()
		writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		for {
			message := readLSPFrame(t, reader)
			if len(message.ID) == 0 { // diagnostics and other server notifications
				continue
			}
			var responseID int
			if err := json.Unmarshal(message.ID, &responseID); err != nil || responseID != id {
				t.Fatalf("response id = %s, want %d", message.ID, id)
			}
			if message.Error != nil {
				t.Fatalf("%s returned %d: %s", method, message.Error.Code, message.Error.Message)
			}
			if elapsed := time.Since(started); elapsed >= testLatencyLimit {
				t.Fatalf("%s stdio round trip took %s", method, elapsed)
			}
			return message
		}
	}

	request("initialize", map[string]any{"capabilities": map[string]any{}})
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{}})
	uri := "file:///virtual/Latency.kt"
	source := "package demo\n\nclass Latency {\n    fun value(): Int {\n        val answer = 1 + 2\n        return answer\n    }\n}\n"
	started := time.Now()
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "kotlin", "version": 1, "text": source}}})
	request("textDocument/hover", map[string]any{"textDocument": map[string]any{"uri": uri}, "position": map[string]int{"line": 2, "character": 8}})
	if elapsed := time.Since(started); elapsed >= testLatencyLimit {
		t.Fatalf("didOpen plus observable probe took %s", elapsed)
	}

	for version := 2; version <= 25; version++ {
		changed := strings.Replace(source, "1 + 2", fmt.Sprintf("1 + %d", version%10), 1)
		started = time.Now()
		writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "textDocument/didChange", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "version": version}, "contentChanges": []any{map[string]any{"text": changed}}}})
		request("textDocument/diagnostic", map[string]any{"textDocument": map[string]any{"uri": uri}})
		if elapsed := time.Since(started); elapsed >= testLatencyLimit {
			t.Fatalf("didChange version %d plus observable probe took %s", version, elapsed)
		}
	}

	const burst = 32
	startedByID := make(map[int]time.Time, burst)
	for n := 0; n < burst; n++ {
		id := nextID
		nextID++
		startedByID[id] = time.Now()
		writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "id": id, "method": "textDocument/completion", "params": map[string]any{"textDocument": map[string]any{"uri": uri}, "position": map[string]int{"line": 4, "character": 12}}})
	}
	for len(startedByID) > 0 {
		message := readLSPFrame(t, reader)
		if len(message.ID) == 0 {
			continue
		}
		var id int
		if err := json.Unmarshal(message.ID, &id); err != nil {
			t.Fatal(err)
		}
		started, ok := startedByID[id]
		if !ok {
			t.Fatalf("unexpected response id %d", id)
		}
		if message.Error != nil {
			t.Fatalf("completion %d returned %v", id, message.Error)
		}
		if elapsed := time.Since(started); elapsed >= testLatencyLimit {
			t.Fatalf("concurrent completion %d stdio round trip took %s", id, elapsed)
		}
		delete(startedByID, id)
	}

	request("shutdown", map[string]any{})
	writeLSPFrame(t, clientWrite, map[string]any{"jsonrpc": "2.0", "method": "exit"})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stdio server did not stop after exit while client input remained open")
	}
}

func TestInitializeBackgroundIndexOutlivesRequestContext(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "Persistent.kt")
	if err := os.WriteFile(source, []byte("package persistent\nclass SurvivesInitialize\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, responseErr := s.Request(requestCtx, "initialize", mustJSON(map[string]any{
		"rootUri": uriutil.File(root), "capabilities": map[string]any{},
	})); responseErr != nil {
		t.Fatalf("initialize: %v", responseErr)
	}
	if !waitUntil(2*time.Second, func() bool {
		return len(s.index.WorkspaceSymbols("SurvivesInitialize", 10)) == 1
	}) {
		t.Fatal("workspace index inherited the completed request context")
	}
	if symbols := s.index.WorkspaceSymbols("SurvivesInitialize", 10); len(symbols) != 1 {
		t.Fatalf("background index symbols = %#v", symbols)
	}
}

func TestInitializedRegistersWorkspaceFileWatchers(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	type clientRequest struct {
		method      string
		params      any
		hasDeadline bool
	}
	requests := make(chan clientRequest, 1)
	s.clientCall = func(ctx context.Context, method string, params, _ any) error {
		_, hasDeadline := ctx.Deadline()
		requests <- clientRequest{method: method, params: params, hasDeadline: hasDeadline}
		return nil
	}
	if _, responseErr := s.Request(context.Background(), "initialize", mustJSON(map[string]any{
		"capabilities": map[string]any{"workspace": map[string]any{"didChangeWatchedFiles": map[string]any{"dynamicRegistration": true}}},
	})); responseErr != nil {
		t.Fatal(responseErr)
	}
	s.Notify(context.Background(), "initialized", nil)
	select {
	case request := <-requests:
		if request.method != "client/registerCapability" {
			t.Fatalf("client method = %q", request.method)
		}
		if request.hasDeadline {
			t.Fatal("watcher registration has an arbitrary deadline")
		}
		encoded, _ := json.Marshal(request.params)
		text := string(encoded)
		for _, expected := range []string{"workspace/didChangeWatchedFiles", "**/*.kt", "**/*.java", "**/*.jar", "**/pom.xml", "**/BUILD.bazel"} {
			if !strings.Contains(text, expected) {
				t.Fatalf("watcher registration omitted %q: %s", expected, text)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("watcher registration was not sent")
	}
}

func TestServerEnforcesLSPInitializationAndShutdownLifecycle(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	if _, responseErr := s.Request(context.Background(), "textDocument/hover", mustJSON(map[string]any{})); responseErr == nil || responseErr.Code != jsonrpc.ServerNotInitialized {
		t.Fatalf("pre-initialize request error = %#v", responseErr)
	}
	initialize := mustJSON(map[string]any{"capabilities": map[string]any{}})
	if _, responseErr := s.Request(context.Background(), "initialize", initialize); responseErr != nil {
		t.Fatalf("initialize: %v", responseErr)
	}
	if _, responseErr := s.Request(context.Background(), "initialize", initialize); responseErr == nil || responseErr.Code != jsonrpc.InvalidRequest {
		t.Fatalf("repeated initialize error = %#v", responseErr)
	}
	if _, responseErr := s.Request(context.Background(), "workspace/symbol", mustJSON(map[string]any{"query": "x"})); responseErr == nil || responseErr.Code != jsonrpc.ServerNotInitialized {
		t.Fatalf("pre-initialized-notification request error = %#v", responseErr)
	}
	s.Notify(context.Background(), "initialized", nil)
	if _, responseErr := s.Request(context.Background(), "workspace/symbol", mustJSON(map[string]any{"query": "x"})); responseErr != nil {
		t.Fatalf("initialized request: %v", responseErr)
	}
	if _, responseErr := s.Request(context.Background(), "shutdown", nil); responseErr != nil {
		t.Fatalf("shutdown: %v", responseErr)
	}
	if _, responseErr := s.Request(context.Background(), "workspace/symbol", mustJSON(map[string]any{"query": "x"})); responseErr == nil || responseErr.Code != jsonrpc.InvalidRequest {
		t.Fatalf("post-shutdown request error = %#v", responseErr)
	}
}

func TestInitializationDefaultSDKDrivesJavaExecutable(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	javaName := "java"
	if runtime.GOOS == "windows" {
		javaName = "java.exe"
	}
	java := filepath.Join(home, "bin", javaName)
	if err := os.WriteFile(java, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, responseErr := s.Request(context.Background(), "initialize", mustJSON(map[string]any{
		"capabilities": map[string]any{}, "initializationOptions": map[string]any{"defaultSdk": home},
	})); responseErr != nil {
		t.Fatal(responseErr)
	}
	s.Notify(context.Background(), "initialized", nil)
	result, responseErr := s.Request(context.Background(), "workspace/executeCommand", mustJSON(map[string]any{"command": "intellij.java.resolveJavaExecutable", "arguments": []any{}}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	resolved := result.(map[string]any)["javaExec"]
	if resolved != java {
		t.Fatalf("resolved Java executable = %v, want %s", resolved, java)
	}
	if got := s.index.DefaultJavaHome(); got != home {
		t.Fatalf("index default Java home = %q, want %q", got, home)
	}
}

func waitUntil(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return condition()
}

func writeLSPFrame(t *testing.T, writer io.Writer, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(body); err != nil {
		t.Fatal(err)
	}
}

func readLSPFrame(t *testing.T, reader *bufio.Reader) jsonrpc.Message {
	t.Helper()
	length := -1
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			length, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if length < 0 {
		t.Fatal("missing Content-Length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatal(err)
	}
	var message jsonrpc.Message
	if err := json.Unmarshal(body, &message); err != nil {
		t.Fatal(err)
	}
	return message
}
