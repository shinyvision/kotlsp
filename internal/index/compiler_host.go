package index

import (
	"bufio"
	"context"
	"crypto/sha256"
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
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * Compiles on demand inside one long-lived JVM.
 *
 * Protocol, all UTF-8. Request: a line "ARGS <n>" followed by n lines, one
 * compiler argument each. Response: a line "OUTPUT <byteCount>", that many
 * bytes of compiler output, then a line "EXIT <name>".
 */
public final class KotlspCompilerHost {
    public static void main(String[] ignored) throws Exception {
        // Bound to the descriptor, so redirecting System.out cannot corrupt it.
        OutputStream channel = new BufferedOutputStream(new FileOutputStream(FileDescriptor.out));
        PrintStream realErr = System.err;
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

        Class<?> compilerClass;
        Method exec;
        try {
            compilerClass = Class.forName("org.jetbrains.kotlin.cli.jvm.K2JVMCompiler");
            exec = compilerClass.getMethod("exec", PrintStream.class, String[].class);
        } catch (Throwable failure) {
            writeLine(channel, "FATAL " + failure);
            channel.flush();
            return;
        }
        writeLine(channel, "READY");
        channel.flush();

        // The host must never outlive the server. Reading EOF on stdin covers
        // an orderly shutdown, but a server killed mid-compilation is not
        // reading anything, and the compiler's own threads would keep the JVM
        // alive. A daemon thread watches the parent process instead.
        Thread watchdog = new Thread(() -> {
            java.util.Optional<ProcessHandle> parent = ProcessHandle.current().parent();
            while (true) {
                if (!parent.isPresent() || !parent.get().isAlive()) {
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
            boolean kotlin = line.startsWith("ARGS ");
            boolean java = line.startsWith("JAVAC ");
            if (!kotlin && !java) {
                continue;
            }
            int count = Integer.parseInt(line.substring(line.indexOf(' ') + 1).trim());
            String[] arguments = new String[count];
            for (int n = 0; n < count; n++) {
                String argument = input.readLine();
                if (argument == null) {
                    return;
                }
                arguments[n] = argument;
            }
            ByteArrayOutputStream collected = new ByteArrayOutputStream();
            PrintStream capture = new PrintStream(collected, true, "UTF-8");
            PrintStream previousOut = System.out;
            PrintStream previousErr = System.err;
            String exit = "INTERNAL_ERROR";
            // The compiler writes to the ambient streams as well as the one it
            // is handed, so both are captured for the duration of the run.
            System.setOut(capture);
            System.setErr(capture);
            try {
                if (java) {
                    // javac in this same warm JVM: the tool API skips a second
                    // process start, which was the whole cost of the Java pass.
                    javax.tools.JavaCompiler tool = javax.tools.ToolProvider.getSystemJavaCompiler();
                    if (tool == null) {
                        exit = "NO_JAVA_COMPILER";
                    } else {
                        int code = tool.run(null, collected, collected, arguments);
                        exit = code == 0 ? "OK" : "COMPILATION_ERROR";
                    }
                } else {
                    Object compiler = compilerClass.getDeclaredConstructor().newInstance();
                    Object code = exec.invoke(compiler, capture, (Object) arguments);
                    exit = String.valueOf(code);
                }
            } catch (Throwable failure) {
                failure.printStackTrace(capture);
            } finally {
                System.setOut(previousOut);
                System.setErr(previousErr);
                capture.flush();
            }
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
}
`

// compilerHostRequestTimeout bounds a single compilation. A host that stops
// answering is killed and replaced rather than blocking validation forever.
const compilerHostRequestTimeout = 4 * time.Minute

// compilerHostMaxRuns replaces the host periodically. The compiler retains
// per-run caches, and a process that lives forever eventually holds more than
// it needs.
const compilerHostMaxRuns = 200

type compilerHost struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	runs    int
}

type compilerHostPool struct {
	mu      sync.Mutex
	host    *compilerHost
	key     string
	disable bool
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
func buildCompilerHost(javaHome string, runtimeJars []string) (string, error) {
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
	command := exec.Command(javac, "-d", dir, source)
	configureCompilerProcess(command)
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building the compiler host: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return dir, nil
}

func startCompilerHost(compiler kotlinCompiler, javaHome string) (*compilerHost, error) {
	dir, err := buildCompilerHost(javaHome, compiler.runtimeJars)
	if err != nil {
		return nil, err
	}
	classpath := strings.Join(append(append([]string(nil), compiler.runtimeJars...), dir), string(os.PathListSeparator))
	// No tiering limit here: unlike a one-shot process, this one compiles many
	// times and does repay the JIT.
	// Capped: a JVM otherwise claims a quarter of physical memory, and a
	// long-lived one holding compiler caches will grow into it. An OOM ends
	// the host cleanly and the pool restarts or falls back.
	args := []string{"-Xmx2g", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseParallelGC", "-cp", classpath, "KotlspCompilerHost"}
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
	host := &compilerHost{command: command, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<16)}
	ready, err := host.stdout.ReadString('\n')
	if err != nil {
		host.close()
		return nil, fmt.Errorf("compiler host did not start: %w", err)
	}
	if strings.TrimSpace(ready) != "READY" {
		host.close()
		return nil, fmt.Errorf("compiler host reported %q", strings.TrimSpace(ready))
	}
	return host, nil
}

func (h *compilerHost) close() {
	if h == nil {
		return
	}
	if h.stdin != nil {
		_ = h.stdin.Close()
	}
	if h.command != nil && h.command.Process != nil {
		_ = h.command.Process.Kill()
		_ = h.command.Wait()
	}
}

func (h *compilerHost) compile(arguments []string) ([]byte, error) {
	verb := "ARGS"
	if len(arguments) > 0 && arguments[0] == "\x00javac" {
		verb, arguments = "JAVAC", arguments[1:]
	}
	var request strings.Builder
	request.WriteString(verb + " " + strconv.Itoa(len(arguments)) + "\n")
	for _, argument := range arguments {
		if strings.ContainsAny(argument, "\n\r") {
			return nil, errors.New("compiler argument contains a newline")
		}
		request.WriteString(argument)
		request.WriteByte('\n')
	}
	if _, err := io.WriteString(h.stdin, request.String()); err != nil {
		return nil, err
	}
	header, err := h.stdout.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "OUTPUT ") {
		return nil, fmt.Errorf("compiler host answered %q", header)
	}
	size, err := strconv.Atoi(strings.TrimPrefix(header, "OUTPUT "))
	if err != nil || size < 0 {
		return nil, fmt.Errorf("compiler host sent an unusable length in %q", header)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(h.stdout, payload); err != nil {
		return nil, err
	}
	if _, err := h.stdout.ReadString('\n'); err != nil {
		return nil, err
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
	defer p.mu.Unlock()
	if p.disable {
		return nil, errors.New("the compiler host is disabled for this session")
	}
	key := strings.Join(compiler.runtimeJars, "\x00") + "\x00" + javaHome
	if p.host != nil && (p.key != key || p.host.runs >= compilerHostMaxRuns) {
		p.host.close()
		p.host = nil
	}
	if p.host == nil {
		host, err := startCompilerHost(compiler, javaHome)
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
		return answer.output, nil
	case <-timer.C:
		p.host.close()
		p.host = nil
		return nil, errors.New("the compiler host stopped answering")
	case <-ctx.Done():
		// The request is superseded. The host is left running: it finishes the
		// compilation it started, and its warmth is the whole point.
		return nil, ctx.Err()
	}
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
	if p.host != nil {
		p.host.close()
		p.host = nil
	}
}
