package index

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

type testWriteCloser struct{ io.Writer }

func (testWriteCloser) Close() error { return nil }

func TestCompilerHostValidatesResponseTrailer(t *testing.T) {
	for _, test := range []struct {
		name    string
		trailer string
		wantErr bool
	}{
		{"ok", "EXIT OK", false},
		{"compilation error is a valid compiler result", "EXIT COMPILATION_ERROR", false},
		{"internal failure", "EXIT INTERNAL_ERROR", true},
		{"missing marker", "DONE OK", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var request bytes.Buffer
			host := &compilerHost{
				stdin:  testWriteCloser{&request},
				stdout: bufio.NewReader(strings.NewReader("OUTPUT 3\nabc" + test.trailer + "\n")),
			}
			output, err := host.compile([]string{"source.kt"})
			if (err != nil) != test.wantErr {
				t.Fatalf("compile error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && string(output) != "abc" {
				t.Fatalf("output = %q", output)
			}
		})
	}
}

func TestCompilerHostCancellationDiscardsInFlightStream(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()
	t.Cleanup(func() {
		_ = requestReader.Close()
		_ = responseWriter.Close()
	})
	host := &compilerHost{
		stdin:        requestWriter,
		stdout:       bufio.NewReader(responseReader),
		stdoutCloser: responseReader,
	}
	pool := &compilerHostPool{host: host, key: "\x00"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pool.run(ctx, kotlinCompiler{embedded: true}, "", []string{"source.kt"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run error = %v", err)
	}
	if pool.host != nil {
		t.Fatal("canceled in-flight host remained reusable")
	}
}

func TestCompilerCommandCompletedRejectsInfrastructureFailure(t *testing.T) {
	if !compilerCommandCompleted(context.Background(), nil) {
		t.Fatal("successful command was rejected")
	}
	if compilerCommandCompleted(context.Background(), errors.New("could not start")) {
		t.Fatal("startup failure was treated as a diagnostic result")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if compilerCommandCompleted(ctx, nil) {
		t.Fatal("canceled command was treated as complete")
	}
	if compilerCommandCompleted(context.Background(), errCompilerOutputLimit) {
		t.Fatal("truncated output was treated as complete")
	}
}

func TestCompilerOutputWriterIsBounded(t *testing.T) {
	writer := &boundedCompilerOutput{limit: 4}
	if n, err := writer.Write([]byte("abcdefgh")); err != nil || n != 8 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if string(writer.data) != "abcd" || !writer.truncated {
		t.Fatalf("bounded output = %q, truncated=%v", writer.data, writer.truncated)
	}
}

func TestCompilerDiagnosticBudgetPrioritizesErrors(t *testing.T) {
	uri := protocol.URI("file:///workspace/Many.kt")
	diagnostics := make([]protocol.Diagnostic, maxCompilerDiagnosticsPerFile+2)
	for index := range diagnostics {
		diagnostics[index] = protocol.Diagnostic{Severity: 2, Message: "warning"}
	}
	diagnostics[len(diagnostics)-1] = protocol.Diagnostic{Severity: 1, Message: "important error"}
	values := map[protocol.URI][]protocol.Diagnostic{uri: diagnostics}
	budgetCompilerDiagnostics(values)
	if len(values[uri]) != maxCompilerDiagnosticsPerFile+1 {
		t.Fatalf("budgeted diagnostics = %d", len(values[uri]))
	}
	if values[uri][0].Message != "important error" || values[uri][len(values[uri])-1].Code != "diagnostics-omitted" {
		t.Fatalf("budgeted diagnostics lost priority/marker")
	}
}

func hostProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// The hosted compiler is a long-lived JVM. It must not outlive the index that
// started it, or every editor restart leaks one.
func TestCompilerHostDoesNotOutliveTheIndex(t *testing.T) {
	requireCompilerBackedTest(t)
	compiler, ok := findKotlinCompiler()
	if !ok || !compiler.embedded {
		t.Skip("no embeddable Kotlin compiler")
	}
	idx := New(nil)
	dir := t.TempDir()
	source := filepath.Join(dir, "A.kt")
	if err := os.WriteFile(source, []byte("package demo\n\nfun a() = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := idx.runKotlinCompilerHosted(context.Background(), compiler, []string{source}, filepath.Join(dir, "out"), nil); err != nil {
		t.Skipf("the compiler host is unavailable here: %v", err)
	}
	idx.compilerHosts.mu.Lock()
	host := idx.compilerHosts.host
	idx.compilerHosts.mu.Unlock()
	if host == nil || host.command == nil || host.command.Process == nil {
		t.Fatal("no host process was started")
	}
	pid := host.command.Process.Pid
	if !hostProcessAlive(pid) {
		t.Fatal("the host was not running after a compilation")
	}
	idx.Close()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && hostProcessAlive(pid) {
		time.Sleep(100 * time.Millisecond)
	}
	if hostProcessAlive(pid) {
		t.Fatalf("the compiler host (pid %d) outlived the index", pid)
	}
}

// The host is a performance measure, never a correctness one: whatever it
// answers must match what a one-shot compiler process answers.
func TestHostedCompilerMatchesTheOneShotProcess(t *testing.T) {
	requireCompilerBackedTest(t)
	compiler, ok := findKotlinCompiler()
	if !ok || !compiler.embedded {
		t.Skip("no embeddable Kotlin compiler")
	}
	idx := New(nil)
	defer idx.Close()
	dir := t.TempDir()
	source := filepath.Join(dir, "A.kt")
	if err := os.WriteFile(source, []byte("package demo\n\nfun a(): Int = Missing.value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	direct, _ := runKotlinCompiler(context.Background(), compiler, []string{source}, filepath.Join(dir, "cli"), nil)
	hosted, err := idx.runKotlinCompilerHosted(context.Background(), compiler, []string{source}, filepath.Join(dir, "host"), nil)
	if err != nil {
		t.Skipf("the compiler host is unavailable here: %v", err)
	}
	// The host answers through the structured message renderer and the
	// one-shot process through its text layout; the JVM may also print
	// environment banners (JAVA_TOOL_OPTIONS) on the one-shot's stderr. What
	// must agree is the diagnostic content each transport yields.
	normalise := func(value []byte) map[protocol.URI][]protocol.Diagnostic {
		text := strings.ReplaceAll(string(value), filepath.Join(dir, "cli"), "")
		text = strings.ReplaceAll(text, filepath.Join(dir, "host"), "")
		return parseKotlincDiagnostics(text)
	}
	if directParsed, hostedParsed := normalise(direct), normalise(hosted); !reflect.DeepEqual(directParsed, hostedParsed) {
		t.Fatalf("hosted and one-shot diagnostics differ:\n--- one-shot ---\n%#v\n--- hosted ---\n%#v", directParsed, hostedParsed)
	}
	if len(normalise(hosted)) == 0 {
		t.Fatal("the fixture error was not reported at all, so the comparison proves nothing")
	}
}

// A second compilation must reuse the warm process rather than start another.
func TestCompilerHostIsReused(t *testing.T) {
	requireCompilerBackedTest(t)
	compiler, ok := findKotlinCompiler()
	if !ok || !compiler.embedded {
		t.Skip("no embeddable Kotlin compiler")
	}
	idx := New(nil)
	defer idx.Close()
	dir := t.TempDir()
	source := filepath.Join(dir, "A.kt")
	if err := os.WriteFile(source, []byte("package demo\n\nfun a() = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pids := make([]int, 0, 2)
	for n := 0; n < 2; n++ {
		if _, err := idx.runKotlinCompilerHosted(context.Background(), compiler, []string{source}, filepath.Join(dir, "out"), nil); err != nil {
			t.Skipf("the compiler host is unavailable here: %v", err)
		}
		idx.compilerHosts.mu.Lock()
		pids = append(pids, idx.compilerHosts.host.command.Process.Pid)
		idx.compilerHosts.mu.Unlock()
	}
	if pids[0] != pids[1] {
		t.Fatalf("a second compilation started a new process (%d then %d)", pids[0], pids[1])
	}
}

// javac runs in the same warm JVM through the tool API with the same text
// formatter as the command. The diagnostics that reach the index from either
// have to agree; the JVM's own environment banner (JAVA_TOOL_OPTIONS) on the
// command's stderr is not part of that.
func TestHostedJavacMatchesTheJavacCommand(t *testing.T) {
	requireCompilerBackedTest(t)
	compiler, ok := findKotlinCompiler()
	if !ok || !compiler.embedded {
		t.Skip("no embeddable Kotlin compiler")
	}
	javac := javacExecutableInHome("")
	if javac == "" {
		var err error
		if javac, err = exec.LookPath("javac"); err != nil {
			t.Skip("no javac")
		}
	}
	idx := New(nil)
	defer idx.Close()
	dir := t.TempDir()
	source := filepath.Join(dir, "Broken.java")
	if err := os.WriteFile(source, []byte("public class Broken { int run() { return Missing.VALUE; } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-proc:none", "-Xlint:all", "-Xmaxerrs", "2147483647", "-Xmaxwarns", "2147483647", "-d", filepath.Join(dir, "out")}

	command := exec.Command(javac, append(append([]string(nil), arguments...), source)...)
	fromCommand, _ := command.CombinedOutput()

	fromHost, hosted := idx.compilerHosts.runJavac(context.Background(), compiler, "", append(append([]string(nil), arguments...), source))
	if !hosted {
		t.Skip("the compiler host is unavailable here")
	}
	comparable := func(output []byte) map[protocol.URI][]protocol.Diagnostic {
		return parseJavacDiagnostics(string(output))
	}
	if !reflect.DeepEqual(comparable(fromCommand), comparable(fromHost)) {
		t.Fatalf("hosted javac differs from the command:\n--- command ---\n%#v\n--- hosted ---\n%#v",
			comparable(fromCommand), comparable(fromHost))
	}
	if len(parseJavacDiagnostics(string(fromHost))) == 0 {
		t.Fatal("the fixture error was not reported, so the comparison proves nothing")
	}
}
