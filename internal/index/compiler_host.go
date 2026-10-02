package index

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

// A fresh Kotlin compiler process costs about 2.7 seconds before it reads a
// line of project source: a JVM start, then K2 initialising, then a JIT that
// never repays itself because the process exits. Paying that on every edit is
// most of the latency between typing and seeing a diagnostic.
//
// The official Kotlin daemon solves this, but its service interface extends
// java.rmi.Remote and speaking RMI from Go is not reasonable. So the compiler
// is hosted directly: one long-lived JVM holds K2JVMCompiler and compiles on
// request over a line protocol on its standard input and output. The JVM stays
// warm, its JIT stays warm, and K2's initialisation is paid once.
//
// The host is a few lines of Java compiled with the JDK the server already
// requires for javac diagnostics. Nothing new is vendored, and if any part of
// this is unavailable the caller falls back to the one-shot command line.
//
//go:embed KotlspCompilerHost.java
var compilerHostSource string

// compilerHostRequestTimeout bounds a single compilation. A host that stops
// answering is killed and replaced rather than blocking validation forever.
const compilerHostRequestTimeout = 4 * time.Minute

// Compiler output is diagnostic text, not an arbitrary data channel. A broken
// or compromised helper must not control an unbounded Go allocation.
const compilerHostMaxOutputBytes = 64 << 20

// compilerHostMaxRuns replaces the host periodically. The compiler retains
// per-run caches, and a process that lives forever eventually holds more than
// it needs.
const compilerHostMaxRuns = 200

// A warm compiler is valuable across a burst of edits, but keeping K2's heap
// for the entire editor session permanently removes memory from the interactive
// Go index. Retire it after the burst and pay startup again only when the user
// next requests authoritative diagnostics.
const compilerHostIdleTimeout = 90 * time.Second

type compilerHost struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	// stdoutCloser lets cancellation tear down a blocked ReadString even for
	// test/fake hosts without a live process.
	stdoutCloser  io.Closer
	runs          int
	releaseBudget func()
	closeOnce     sync.Once
	// structured reports whether the host renders Kotlin messages as
	// KOTLSP_DIAGNOSTIC records; transportNote is its own description.
	structured    bool
	transportNote string
}

// compilerHostRetryBackoff grows with consecutive start failures instead of
// retiring the warm compiler for the whole session: a transient failure (a
// busy machine, a JDK being upgraded underneath us) otherwise condemned every
// later pass to the slow one-shot path until the editor was restarted.
const compilerHostRetryBackoff = 30 * time.Second

const compilerHostMaxRetryBackoff = 5 * time.Minute

type compilerHostPool struct {
	mu        sync.Mutex
	host      *compilerHost
	key       string
	disable   bool
	failures  int
	retryAt   time.Time
	idleTimer *time.Timer
	// lastStructured records the transport of the most recent successful
	// run, so the status surface can say what actually answered even after
	// the host has been retired.
	lastStructured bool
	lastTransport  string
}

// structuredTransport reports whether the last hosted run used the structured
// message renderer, with the host's own description of its transport.
func (p *compilerHostPool) structuredTransport() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastStructured, p.lastTransport
}

func compilerHostDirectory(runtimeJars []string) (string, bool) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	// The host source is part of the identity: changing it must rebuild the
	// cached class rather than silently keep running the previous one.
	sum := sha256.Sum256([]byte(strings.Join(runtimeJars, "\x00") + "\x00" + compilerHostSource))
	dir := filepath.Join(cacheRoot, "kotlsp", "compiler-host", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	return dir, true
}

// buildCompilerHost compiles the host class once per compiler version. The
// result is cached on disk, so this is a no-op on every later start.
func buildCompilerHost(ctx context.Context, javaHome string, runtimeJars []string) (string, error) {
	dir, ok := compilerHostDirectory(runtimeJars)
	if !ok {
		return "", errors.New("no cache directory for the compiler host")
	}
	marker := filepath.Join(dir, "KotlspCompilerHost.class")
	if _, err := os.Stat(marker); err == nil {
		return dir, nil
	}
	javac := javacExecutableInHome(javaHome)
	if javac == "" {
		javac, _ = exec.LookPath("javac")
	}
	if javac == "" {
		return "", errors.New("no javac available to build the compiler host")
	}
	source := filepath.Join(dir, "KotlspCompilerHost.java")
	if err := os.WriteFile(source, []byte(compilerHostSource), 0o600); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, javac, "-d", dir, source)
	configureCompilerProcess(command)
	output := &boundedCompilerOutput{limit: 1 << 20}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(string(output.data))
		if output.truncated {
			detail += " [output truncated]"
		}
		return "", fmt.Errorf("building the compiler host: %w: %s", err, detail)
	}
	return dir, nil
}

func startCompilerHost(ctx context.Context, compiler kotlinCompiler, javaHome string) (*compilerHost, error) {
	reserveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	releaseBudget, reserveErr := resourcebudget.Acquire(reserveCtx, "compiler-host", resourcebudget.CompilerHostBytes)
	if reserveErr != nil {
		return nil, reserveErr
	}
	releaseOnFailure := true
	defer func() {
		if releaseOnFailure {
			releaseBudget()
		}
	}()
	dir, err := buildCompilerHost(ctx, javaHome, compiler.runtimeJars)
	if err != nil {
		return nil, err
	}
	classpath := strings.Join(append(append([]string(nil), compiler.runtimeJars...), dir), string(os.PathListSeparator))
	// No tiering limit here: unlike a one-shot process, this one compiles many
	// times and does repay the JIT.
	// Capped: a JVM otherwise claims a quarter of physical memory, and a
	// long-lived one holding compiler caches will grow into it. An OOM ends
	// the host cleanly and the pool restarts or falls back.
	args := []string{"-Xmx768m", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseParallelGC", "-cp", classpath, "KotlspCompilerHost"}
	command := exec.Command(compiler.executable, args...)
	configureCompilerProcess(command)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = nil
	if err := command.Start(); err != nil {
		return nil, err
	}
	host := &compilerHost{command: command, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<16), stdoutCloser: stdout, releaseBudget: releaseBudget}
	type readyResult struct {
		line string
		err  error
	}
	readyDone := make(chan readyResult, 1)
	go func() {
		line, readErr := readCompilerHostLine(host.stdout, 4096)
		readyDone <- readyResult{line: line, err: readErr}
	}()
	startupTimer := time.NewTimer(30 * time.Second)
	defer startupTimer.Stop()
	var ready string
	select {
	case result := <-readyDone:
		ready, err = result.line, result.err
	case <-ctx.Done():
		host.close()
		return nil, ctx.Err()
	case <-startupTimer.C:
		host.close()
		return nil, errors.New("compiler host did not report readiness within 30 seconds")
	}
	if err != nil {
		host.close()
		return nil, fmt.Errorf("compiler host did not start: %w", err)
	}
	ready = strings.TrimSpace(ready)
	if ready != "READY" && !strings.HasPrefix(ready, "READY ") {
		host.close()
		return nil, fmt.Errorf("compiler host reported %q", ready)
	}
	host.structured = strings.HasPrefix(ready, "READY structured")
	host.transportNote = strings.TrimSpace(strings.TrimPrefix(ready, "READY"))
	releaseOnFailure = false
	return host, nil
}

func (h *compilerHost) close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		if h.stdin != nil {
			_ = h.stdin.Close()
		}
		if h.stdoutCloser != nil {
			_ = h.stdoutCloser.Close()
		}
		if h.command != nil && h.command.Process != nil {
			_ = h.command.Process.Kill()
			_ = h.command.Wait()
		}
		if h.releaseBudget != nil {
			h.releaseBudget()
		}
	})
}

func readCompilerHostLine(reader *bufio.Reader, limit int) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", errors.New("compiler host control line exceeds its buffer limit")
	}
	if err != nil {
		return "", err
	}
	if len(line) > limit {
		return "", fmt.Errorf("compiler host control line exceeds its %d-byte safety limit", limit)
	}
	return string(line), nil
}

func (h *compilerHost) compile(arguments []string) ([]byte, error) {
	verb := "ARGS64"
	if len(arguments) > 0 && arguments[0] == "\x00javac" {
		verb, arguments = "JAVAC64", arguments[1:]
	}
	if len(arguments) > 300_000 {
		return nil, errors.New("compiler argument count exceeds its 300000-item safety limit")
	}
	totalBytes := 0
	for _, argument := range arguments {
		totalBytes += len(argument)
		if totalBytes > 32<<20 {
			return nil, errors.New("compiler arguments exceed their 32 MiB safety limit")
		}
	}
	var request strings.Builder
	request.Grow(totalBytes + totalBytes/2)
	request.WriteString(verb + " " + strconv.Itoa(len(arguments)) + "\n")
	for _, argument := range arguments {
		request.WriteString(base64.StdEncoding.EncodeToString([]byte(argument)))
		request.WriteByte('\n')
	}
	if _, err := io.WriteString(h.stdin, request.String()); err != nil {
		return nil, err
	}
	header, err := readCompilerHostLine(h.stdout, 4096)
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "OUTPUT ") {
		return nil, fmt.Errorf("compiler host answered %q", header)
	}
	size, err := strconv.Atoi(strings.TrimPrefix(header, "OUTPUT "))
	if err != nil || size < 0 || size > compilerHostMaxOutputBytes {
		return nil, fmt.Errorf("compiler host sent an unusable length in %q", header)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(h.stdout, payload); err != nil {
		return nil, err
	}
	trailer, err := readCompilerHostLine(h.stdout, 4096)
	if err != nil {
		return nil, err
	}
	trailer = strings.TrimSpace(trailer)
	if !strings.HasPrefix(trailer, "EXIT ") {
		return nil, fmt.Errorf("compiler host sent an unusable trailer %q", trailer)
	}
	exit := strings.TrimSpace(strings.TrimPrefix(trailer, "EXIT "))
	if exit != "OK" && exit != "COMPILATION_ERROR" {
		return nil, fmt.Errorf("compiler host failed with %s", exit)
	}
	h.runs++
	return payload, nil
}

// run compiles through the pooled host, starting or replacing it as needed.
// Any failure disables the host for this session and reports it, so the caller
// can fall back to the one-shot command line rather than lose diagnostics.
func (p *compilerHostPool) run(ctx context.Context, compiler kotlinCompiler, javaHome string, arguments []string) ([]byte, error) {
	if !compiler.embedded {
		return nil, errors.New("the compiler host requires the embeddable compiler")
	}
	p.mu.Lock()
	p.stopIdleTimerLocked()
	defer func() {
		p.scheduleIdleCloseLocked()
		p.mu.Unlock()
	}()
	if p.disable {
		return nil, errors.New("the compiler host is disabled for this session")
	}
	key := strings.Join(compiler.runtimeJars, "\x00") + "\x00" + javaHome
	if p.host != nil && (p.key != key || p.host.runs >= compilerHostMaxRuns) {
		p.host.close()
		p.host = nil
	}
	if p.host == nil {
		if !p.retryAt.IsZero() && time.Now().Before(p.retryAt) {
			return nil, fmt.Errorf("the compiler host is retrying at %s after %d consecutive start failures", p.retryAt.Format(time.TimeOnly), p.failures)
		}
		host, err := startCompilerHost(ctx, compiler, javaHome)
		if err != nil {
			if ctx.Err() == nil {
				p.failures++
				backoff := min(time.Duration(p.failures)*compilerHostRetryBackoff, compilerHostMaxRetryBackoff)
				p.retryAt = time.Now().Add(backoff)
			}
			return nil, err
		}
		p.host, p.key, p.failures, p.retryAt = host, key, 0, time.Time{}
	}

	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	host := p.host
	go func() {
		output, err := host.compile(arguments)
		done <- result{output: output, err: err}
	}()
	timer := time.NewTimer(compilerHostRequestTimeout)
	defer timer.Stop()
	select {
	case answer := <-done:
		if answer.err != nil {
			// The channel is no longer in a known state.
			p.host.close()
			p.host = nil
			return nil, answer.err
		}
		p.lastStructured, p.lastTransport = host.structured, host.transportNote
		return answer.output, nil
	case <-timer.C:
		p.host.close()
		p.host = nil
		return nil, errors.New("the compiler host stopped answering")
	case <-ctx.Done():
		// The compile goroutine owns the shared stdin/stdout stream. Reusing the
		// host before it drains would interleave two requests, so cancellation
		// invalidates the process and the next run starts with a clean stream.
		p.host.close()
		p.host = nil
		return nil, ctx.Err()
	}
}

func (p *compilerHostPool) stopIdleTimerLocked() {
	if p.idleTimer != nil {
		p.idleTimer.Stop()
		p.idleTimer = nil
	}
}

func (p *compilerHostPool) scheduleIdleCloseLocked() {
	if p.host == nil {
		return
	}
	host := p.host
	p.idleTimer = time.AfterFunc(compilerHostIdleTimeout, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.host != host {
			return
		}
		p.host.close()
		p.host = nil
		p.key = ""
		p.idleTimer = nil
	})
}

// runJavac compiles through the warm host. The second result reports whether
// the host answered, so the caller can fall back to the javac command.
func (p *compilerHostPool) runJavac(ctx context.Context, compiler kotlinCompiler, javaHome string, arguments []string) ([]byte, bool) {
	output, err := p.run(ctx, compiler, javaHome, append([]string{"\x00javac"}, arguments...))
	if err != nil {
		return nil, false
	}
	return output, true
}

func (p *compilerHostPool) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopIdleTimerLocked()
	if p.host != nil {
		p.host.close()
		p.host = nil
	}
}
