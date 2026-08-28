package index

import (
	"bufio"
	"context"
	"crypto/sha256"
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
const compilerHostSource = `
import java.io.ByteArrayOutputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Compiles on demand inside one long-lived JVM.
 *
 * Protocol, all UTF-8. Request: a line "ARGS <n>" followed by n lines, one
 * compiler argument each. Response: a line "OUTPUT <byteCount>", that many
 * bytes of compiler output, then a line "EXIT <name>".
 */
public final class KotlspCompilerHost {
    public static void main(String[] commandLine) throws Exception {
        // Bound to the descriptor, so redirecting System.out cannot corrupt it.
        OutputStream channel = new BufferedOutputStream(new FileOutputStream(FileDescriptor.out));
        PrintStream realErr = System.err;
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        Class<?> compilerClass;
        Method exec;
		Method structuredExec = null;
		Class<?> messageRendererClass = null;
		String structuredFailure = "";
        try {
            compilerClass = Class.forName("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler");
            exec = compilerClass.getMethod("exec", PrintStream.class, String[].class);
			// The structured transport: the compiler renders every message
			// through a MessageRenderer, so a renderer that emits one record per
			// message yields path, position, severity, and text without parsing
			// the human-readable layout. exec(PrintStream, MessageRenderer,
			// String[]) is the public CLI entry point that accepts a renderer.
			try {
				messageRendererClass = Class.forName("org.jetbrains.kotlin.cli.common.messages.MessageRenderer");
				structuredExec = compilerClass.getMethod("exec", PrintStream.class, messageRendererClass, String[].class);
			} catch (Throwable missingStructuredAPI) {
				structuredExec = null;
				structuredFailure = String.valueOf(missingStructuredAPI);
			}
        } catch (Throwable failure) {
            writeLine(channel, "FATAL " + failure);
            channel.flush();
            return;
        }
        writeLine(channel, structuredExec != null ? "READY structured" : "READY text " + structuredFailure);
        channel.flush();

        // The host must never outlive the server. Reading EOF on stdin covers
        // an orderly shutdown, but a server killed mid-compilation is not
        // reading anything, and the compiler's own threads would keep the JVM
        // alive. A daemon thread watches the parent process instead.
        // The pid is captured once: when the server dies this process is
        // reparented to init or to a subreaper, so asking for the current
        // parent from then on names a live process that never owned it.
        long parentPid = ProcessHandle.current().parent().map(ProcessHandle::pid).orElse(-1L);
        Thread watchdog = new Thread(() -> {
            while (true) {
                if (parentPid < 0 || !ProcessHandle.of(parentPid).map(ProcessHandle::isAlive).orElse(false)) {
                    Runtime.getRuntime().halt(0);
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException interrupted) {
                    return;
                }
            }
        }, "kotlsp-parent-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();

        String line;
        while ((line = input.readLine()) != null) {
            boolean kotlin = line.startsWith("ARGS64 ");
            boolean javaRequest = line.startsWith("JAVAC64 ");
            if (!kotlin && !javaRequest) {
                continue;
            }
			int count = Integer.parseInt(line.substring(line.indexOf(' ') + 1).trim());
			if (count < 0 || count > 300000) throw new IllegalArgumentException("compiler argument count exceeds limit");
            String[] arguments = new String[count];
            for (int n = 0; n < count; n++) {
                String argument = input.readLine();
                if (argument == null) {
                    return;
                }
				arguments[n] = new String(Base64.getDecoder().decode(argument), StandardCharsets.UTF_8);
            }
			BoundedOutput collected = new BoundedOutput(64 * 1024 * 1024);
            PrintStream capture = new PrintStream(collected, true, "UTF-8");
            PrintStream previousOut = System.out;
            PrintStream previousErr = System.err;
            String exit = "INTERNAL_ERROR";
            // The compiler writes to the ambient streams as well as the one it
            // is handed, so both are captured for the duration of the run.
            System.setOut(capture);
            System.setErr(capture);
            try {
                if (javaRequest) {
                    // javac in this same warm JVM: the tool API skips a second
                    // process start, which was the whole cost of the Java pass.
                    javax.tools.JavaCompiler tool = javax.tools.ToolProvider.getSystemJavaCompiler();
                    if (tool == null) {
                        exit = "NO_JAVA_COMPILER";
                    } else {
                        // javac's own text formatter is used deliberately: the
                        // tool API's DiagnosticListener hands out the basic
                        // formatter's wording (fully qualified class names),
                        // while the text output uses the rich formatter whose
                        // wording the fast Java rules predict and reconcile
                        // against. The text output carries the full staged path
                        // and a caret line, so nothing is lost.
                        int code = tool.run(null, collected, collected, arguments);
                        exit = code == 0 ? "OK" : "COMPILATION_ERROR";
                    }
                } else {
                    Object compiler = compilerClass.getDeclaredConstructor().newInstance();
					Object code;
					if (structuredExec != null && messageRendererClass != null) {
						Object renderer = Proxy.newProxyInstance(messageRendererClass.getClassLoader(), new Class<?>[]{messageRendererClass}, (proxy, method, values) -> {
							String name = method.getName();
							if (name.equals("render") && values != null && values.length >= 3) {
								String severity = String.valueOf(values[0]);
								String message = String.valueOf(values[1]);
								Object location = values[2];
								String path = "";
								int sourceLine = 0, sourceColumn = 0;
								if (location != null) {
									try { path = String.valueOf(location.getClass().getMethod("getPath").invoke(location)); } catch (Throwable noPath) { path = ""; }
									try { sourceLine = ((Number) location.getClass().getMethod("getLine").invoke(location)).intValue(); } catch (Throwable noLine) { sourceLine = 0; }
									try { sourceColumn = ((Number) location.getClass().getMethod("getColumn").invoke(location)).intValue(); } catch (Throwable noColumn) { sourceColumn = 0; }
								}
								boolean isError = severity.contains("ERROR") || severity.contains("EXCEPTION");
								boolean isWarning = severity.contains("WARNING");
								if (!isError && !isWarning) return "";
								if (path.isEmpty() || "null".equals(path)) {
									// A finding with no source is a compiler-level failure
									// (a crash, a missing input); it is rendered as text so
									// the pass is rejected with that evidence rather than
									// published as clean. Sourceless warnings are noise.
									return isError ? "e: " + message : "";
								}
								return "KOTLSP_DIAGNOSTIC\t" + Base64.getEncoder().encodeToString(path.getBytes(StandardCharsets.UTF_8)) + "\t" + sourceLine + "\t" + sourceColumn + "\t" + severity + "\t" + Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
							}
							if (name.equals("getName")) return "KOTLSP";
							if (method.getReturnType() == String.class) return "";
							if (method.getReturnType() == boolean.class) return false;
							if (method.getReturnType() == int.class) return 0;
							return null;
						});
						code = structuredExec.invoke(compiler, capture, renderer, (Object) arguments);
					} else {
						code = exec.invoke(compiler, capture, (Object) arguments);
					}
                    exit = String.valueOf(code);
                }
            } catch (Throwable failure) {
                failure.printStackTrace(capture);
            } finally {
                System.setOut(previousOut);
                System.setErr(previousErr);
                capture.flush();
            }
			if (collected.truncated()) exit = "OUTPUT_LIMIT";
            byte[] payload = collected.toByteArray();
            writeLine(channel, "OUTPUT " + payload.length);
            channel.write(payload);
            writeLine(channel, "EXIT " + exit);
            channel.flush();
            // The compiler holds large caches per run; returning them promptly
            // keeps a long-lived host from growing without bound.
            realErr.flush();
        }
        // Stdin is closed: the server is gone. Compiler threads must not keep
        // the JVM alive.
        Runtime.getRuntime().halt(0);
    }

    private static void writeLine(OutputStream out, String text) throws java.io.IOException {
        out.write((text + "\n").getBytes(StandardCharsets.UTF_8));
    }

	private static final class BoundedOutput extends OutputStream {
		private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
		private final int limit;
		private boolean truncated;
		BoundedOutput(int limit) { this.limit = limit; }
		@Override public void write(int value) {
			if (delegate.size() < limit) delegate.write(value); else truncated = true;
		}
		@Override public void write(byte[] value, int offset, int length) {
			int remaining = limit - delegate.size();
			if (remaining > 0) delegate.write(value, offset, Math.min(remaining, length));
			if (length > remaining) truncated = true;
		}
		byte[] toByteArray() { return delegate.toByteArray(); }
		boolean truncated() { return truncated; }
	}
}
`

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

type compilerHostPool struct {
	mu        sync.Mutex
	host      *compilerHost
	key       string
	disable   bool
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
		host, err := startCompilerHost(ctx, compiler, javaHome)
		if err != nil {
			p.disable = true
			return nil, err
		}
		p.host, p.key = host, key
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
