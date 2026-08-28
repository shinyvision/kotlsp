package dap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBridgeRowsRoundTripBoundaries(t *testing.T) {
	payload := "1\x1ffirst value\x1e2\x1fsecond\tvalue"
	rows := decodeBridgeRows(payload)
	if len(rows) != 2 || len(rows[0]) != 2 || rows[0][1] != "first value" || rows[1][1] != "second\tvalue" {
		t.Fatalf("decoded rows = %#v", rows)
	}
}

func TestStructuredResponseRoutesByRequestID(t *testing.T) {
	answer := make(chan bridgeResponse, 1)
	process := &jdiProcess{pending: map[uint64]chan bridgeResponse{42: answer}}
	payload := base64.StdEncoding.EncodeToString([]byte("name\x1fvalue"))
	process.readResponse([]string{"R", "42", "OK", payload})
	response := <-answer
	if response.err != nil || len(response.rows) != 1 || response.rows[0][1] != "value" {
		t.Fatalf("response = %#v", response)
	}
	if len(process.pending) != 0 {
		t.Fatal("completed request was retained")
	}
}

func TestStructuredRequestTimesOutWithoutResponse(t *testing.T) {
	process := &jdiProcess{
		ctx: context.Background(), stdin: bufio.NewWriter(io.Discard),
		pending: make(map[uint64]chan bridgeResponse), commandLimit: 25 * time.Millisecond,
	}
	started := time.Now()
	if _, err := process.request("THREADS"); err == nil {
		t.Fatal("request without a response must time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout was not enforced promptly: %s", elapsed)
	}
}

func TestBridgeRejectsOversizedPendingSet(t *testing.T) {
	process := &jdiProcess{ctx: context.Background(), stdin: bufio.NewWriter(io.Discard), pending: make(map[uint64]chan bridgeResponse), commandLimit: time.Second}
	for id := uint64(1); id <= 128; id++ {
		process.pending[id] = make(chan bridgeResponse, 1)
	}
	if _, err := process.request("PING"); err == nil || !strings.Contains(err.Error(), "too many pending") {
		t.Fatalf("pending bound error = %v", err)
	}
}

func TestCanceledDebuggerRequestDoesNotReachBridge(t *testing.T) {
	var wire bytes.Buffer
	process := &jdiProcess{ctx: context.Background(), stdin: bufio.NewWriter(&wire), pending: make(map[uint64]chan bridgeResponse), commandLimit: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := process.requestFor([]context.Context{ctx}, "EVAL", "slow()"); err == nil {
		t.Fatal("canceled debugger request succeeded")
	}
	if wire.Len() != 0 || len(process.pending) != 0 {
		t.Fatalf("canceled request reached bridge: wire=%q pending=%d", wire.String(), len(process.pending))
	}
}

func TestDebugValueRecordsAreTyped(t *testing.T) {
	values := decodeDebugValues([][]string{{"items", "instance", "java.util.List", "body.items", "true", "17"}})
	if len(values) != 1 || !values[0].expandable || values[0].indexed != 17 || values[0].evaluateName != "body.items" {
		t.Fatalf("values = %#v", values)
	}
}

func TestUnusableThreadFilter(t *testing.T) {
	if !unusableThread("DestroyJavaVM", "1") {
		t.Fatal("DestroyJavaVM must be filtered")
	}
	if !unusableThread("main", strconv.Itoa(0)) {
		t.Fatal("zombie threads must be filtered")
	}
	if unusableThread("http-nio-8080-exec-1", "4") {
		t.Fatal("ordinary worker thread must stay visible")
	}
}

func TestBridgeUsesJDIAndStructuredOperations(t *testing.T) {
	for _, marker := range []string{"Bootstrap.virtualMachineManager", "THREADS", "FRAMES", "LOCALS", "CHILDREN", "BREAK_LINE"} {
		if !strings.Contains(jdiBridgeSource, marker) {
			t.Fatalf("bridge source missing %s", marker)
		}
	}
	for _, forbidden := range []string{"main[1]", "Breakpoint hit:", "waitForPrompt"} {
		if strings.Contains(jdiBridgeSource, forbidden) {
			t.Fatalf("bridge source contains human jdb marker %q", forbidden)
		}
	}
}

func TestEmbeddedJDIBridgeCompiles(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is unavailable")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "KotLSPJDI.java")
	if err = os.WriteFile(source, []byte(jdiBridgeSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(javac, "--add-modules", "jdk.jdi", "-encoding", "UTF-8", "-d", directory, source)
	if output, compileErr := command.CombinedOutput(); compileErr != nil {
		t.Fatalf("embedded JDI helper does not compile: %v\n%s", compileErr, output)
	}
}
