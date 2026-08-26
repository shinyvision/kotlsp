package index

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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
	normalise := func(value []byte) string {
		text := strings.ReplaceAll(string(value), filepath.Join(dir, "cli"), "")
		text = strings.ReplaceAll(text, filepath.Join(dir, "host"), "")
		return strings.TrimSpace(text)
	}
	if normalise(direct) != normalise(hosted) {
		t.Fatalf("hosted and one-shot output differ:\n--- one-shot ---\n%s\n--- hosted ---\n%s", normalise(direct), normalise(hosted))
	}
	if len(parseKotlincDiagnostics(normalise(hosted))) == 0 {
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

// javac runs in the same warm JVM through the tool API. Its output has to match
// the javac command exactly, since the same parser reads both.
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
	if strings.TrimSpace(string(fromCommand)) != strings.TrimSpace(string(fromHost)) {
		t.Fatalf("hosted javac differs from the command:\n--- command ---\n%s\n--- hosted ---\n%s",
			strings.TrimSpace(string(fromCommand)), strings.TrimSpace(string(fromHost)))
	}
	if len(parseJavacDiagnostics(string(fromHost))) == 0 {
		t.Fatal("the fixture error was not reported, so the comparison proves nothing")
	}
}
