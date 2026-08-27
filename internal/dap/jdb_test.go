package dap

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// newTestJDB builds a jdbProcess without a real jdb: tests feed `incoming`
// and read results from waitForPrompt.
func newTestJDB() *jdbProcess {
	p := &jdbProcess{
		ctx:      context.Background(),
		incoming: make(chan string),
		chunks:   make(chan string),
		done:     make(chan error, 1),
	}
	go p.relayChunks()
	return p
}

func waitPromptResult(t *testing.T, p *jdbProcess) []string {
	t.Helper()
	type result struct {
		lines []string
		err   error
	}
	outcome := make(chan result, 1)
	go func() {
		lines, err := p.waitForPrompt()
		outcome <- result{lines, err}
	}()
	select {
	case res := <-outcome:
		if res.err != nil {
			t.Fatalf("waitForPrompt: %v", res.err)
		}
		return res.lines
	case <-time.After(2 * time.Second):
		t.Fatal("waitForPrompt hung: prompt was not recognized")
		return nil
	}
}

func TestThreadPromptWithPunctuationNameIsRecognized(t *testing.T) {
	p := newTestJDB()
	p.addThreadName("HikariPool-1:housekeeper")
	go func() {
		p.emit("some command output\n")
		p.emit("HikariPool-1:housekeeper[1] ")
	}()
	lines := waitPromptResult(t, p)
	if len(lines) != 2 {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestArrayRenderingIsNotAPrompt(t *testing.T) {
	p := newTestJDB()
	p.addThreadName("main")
	done := make(chan struct{})
	go func() {
		p.waitForPrompt()
		close(done)
	}()
	// A partial rendering line that ends at a bracketed number, mid-line.
	p.emit("nums = instance of int[3] ")
	select {
	case <-done:
		t.Fatal("array rendering was misdetected as a prompt")
	case <-time.After(300 * time.Millisecond):
	}
	p.emit("(id=453)\n")
	p.emit("main[1] ")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("real prompt was not recognized after a rendering line")
	}
}

func TestPlainMainPromptStillWorks(t *testing.T) {
	p := newTestJDB()
	go func() {
		p.emit("Set breakpoint com.acme.Widget:3\n")
		p.emit("main[1] ")
	}()
	waitPromptResult(t, p)
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

func TestExecuteTimesOutWhenJDBNeverAnswers(t *testing.T) {
	p := newTestJDB()
	p.stdin = nopWriteCloser{}
	p.commandTimeout = 100 * time.Millisecond
	start := time.Now()
	if _, err := p.execute("print user"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("expected a wedged-bridge timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout not enforced promptly: %s", elapsed)
	}
}

func TestEmitTerminatedKillsBridgeAndUnblocksExecute(t *testing.T) {
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	defer s.cancel()
	p := newTestJDB()
	p.stdin = nopWriteCloser{}
	p.commandTimeout = 50 * time.Millisecond
	s.debugMu.Lock()
	s.debug = p
	s.debugMu.Unlock()

	s.emitTerminated()
	waitFor := time.Now().Add(2 * time.Second)
	for s.currentDebugger() != nil && time.Now().Before(waitFor) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.currentDebugger() != nil {
		t.Fatal("bridge still attached after termination")
	}
	start := time.Now()
	if _, err := p.execute("where"); err == nil {
		t.Fatal("execute on a killed bridge must fail, not hang")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("execute on a killed bridge was not released promptly")
	}
}

func TestUnusableThreadFilter(t *testing.T) {
	if !unusableThread("DestroyJavaVM", "running") {
		t.Fatal("DestroyJavaVM must be filtered: jdb hangs on its stack request")
	}
	if !unusableThread("main", "zombie") {
		t.Fatal("zombie threads must be filtered")
	}
	if unusableThread("http-nio-8080-exec-1", "waiting") {
		t.Fatal("ordinary worker thread must stay visible")
	}
}
