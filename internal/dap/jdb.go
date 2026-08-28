package dap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

// The production debugger talks to the JDK's JDI API through a tiny helper
// JVM. The protocol is framed, machine-readable, locale-independent, and has
// one response ID per command; no prompt, command echo, or human jdb output is
// involved. Keeping the helper source embedded makes it use the exact JDK
// available to the server without introducing a separately versioned jar.

const maxBridgeRecordBytes = 16 << 20

type debugThread struct {
	token string
	name  string
	state string
}

type debugFrameInfo struct {
	index      int
	name       string
	sourceName string
	line       int
	className  string
	total      int
}

type debugValue struct {
	name         string
	value        string
	typeName     string
	evaluateName string
	handle       string
	expandable   bool
	indexed      int
}

type lineBreakpointSpec struct {
	Class string
	Line  int
}

type debugEvent struct {
	kind          string
	reason        string
	threadToken   string
	threadName    string
	className     string
	methodName    string
	line          int
	description   string
	protocolError string
}

type bridgeResponse struct {
	rows [][]string
	err  error
}

type jdiProcess struct {
	ctx           context.Context
	cmd           *exec.Cmd
	stdin         *bufio.Writer
	helperDir     string
	onEvent       func(debugEvent)
	events        chan debugEvent
	commandMu     sync.Mutex
	writeMu       sync.Mutex
	pendingMu     sync.Mutex
	pending       map[uint64]chan bridgeResponse
	nextID        atomic.Uint64
	done          chan error
	exited        chan struct{}
	closeOnce     sync.Once
	workers       sync.WaitGroup
	releaseBudget func()
	commandLimit  time.Duration
}

func startJDI(ctx, lifetime context.Context, javaExecutable, host string, port int, directory string, environment []string, onEvent func(debugEvent)) (*jdiProcess, error) {
	if lifetime == nil {
		lifetime = context.Background()
	}
	releaseBudget, reserveErr := resourcebudget.Acquire(ctx, "jdi-helper", resourcebudget.JDIHelperBytes)
	if reserveErr != nil {
		return nil, reserveErr
	}
	keepBudget := false
	defer func() {
		if !keepBudget {
			releaseBudget()
		}
	}()
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid JDWP port")
	}
	if host == "" {
		host = "127.0.0.1"
	}
	java, javac, err := jdiToolchain(javaExecutable)
	if err != nil {
		return nil, err
	}
	helperDir, err := os.MkdirTemp("", "kotlsp-jdi-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(helperDir) }
	sourcePath := filepath.Join(helperDir, "KotLSPJDI.java")
	if err = os.WriteFile(sourcePath, []byte(jdiBridgeSource), 0o600); err != nil {
		cleanup()
		return nil, err
	}
	compileCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	compile := exec.CommandContext(compileCtx, javac, "-J-Xmx256m", "-J-XX:+ExitOnOutOfMemoryError", "--add-modules", "jdk.jdi", "-encoding", "UTF-8", "-d", helperDir, sourcePath)
	compile.Dir = helperDir
	compile.Env = environment
	var compileOutput boundedBridgeBuffer
	compile.Stdout, compile.Stderr = &compileOutput, &compileOutput
	if err = compile.Run(); err != nil {
		cleanup()
		message := strings.TrimSpace(compileOutput.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("compile structured JDI bridge: %s", message)
	}
	// The helper outlives the attach/launch request. Startup cancellation still
	// aborts the PING handshake below, while the session lifetime owns the
	// established process; binding CommandContext to the request would kill a
	// successful debugger as soon as its DAP response was published.
	command := exec.Command(java,
		"-Xmx256m", "-XX:+ExitOnOutOfMemoryError",
		"--add-modules", "jdk.jdi",
		"--add-exports", "jdk.jdi/com.sun.tools.example.debug.expr=ALL-UNNAMED",
		"-cp", helperDir, "KotLSPJDI", host, strconv.Itoa(port))
	command.Dir = directory
	command.Env = environment
	stdin, err := command.StdinPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	if err = command.Start(); err != nil {
		cleanup()
		return nil, err
	}
	process := &jdiProcess{
		ctx: lifetime, cmd: command, stdin: bufio.NewWriter(stdin), helperDir: helperDir,
		onEvent: onEvent, events: make(chan debugEvent, 256), pending: make(map[uint64]chan bridgeResponse), done: make(chan error, 1), exited: make(chan struct{}), commandLimit: 30 * time.Second,
		releaseBudget: releaseBudget,
	}
	keepBudget = true
	process.workers.Add(5)
	go func() {
		defer process.workers.Done()
		process.dispatchEvents()
	}()
	go func() {
		defer process.workers.Done()
		process.read(stdout)
	}()
	go func() {
		defer process.workers.Done()
		process.readErrors(stderr)
	}()
	go func() {
		defer process.workers.Done()
		select {
		case <-lifetime.Done():
			process.kill()
		case <-process.exited:
		}
	}()
	go func() {
		defer process.workers.Done()
		waitErr := command.Wait()
		process.failPending(waitErr)
		process.done <- waitErr
		close(process.done)
		close(process.exited)
		process.releaseResourceBudget()
	}()
	readyCtx, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	if _, err = process.requestContext(readyCtx, "PING"); err != nil {
		process.close()
		return nil, fmt.Errorf("structured JDI bridge did not attach: %w", err)
	}
	return process, nil
}

type boundedBridgeBuffer struct {
	data      []byte
	truncated bool
}

func (b *boundedBridgeBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := (1 << 20) - len(b.data)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		b.data = append(b.data, value[:remaining]...)
	}
	if remaining < len(value) {
		b.truncated = true
	}
	return written, nil
}

func (b *boundedBridgeBuffer) String() string {
	if b.truncated {
		return string(b.data) + " [output truncated]"
	}
	return string(b.data)
}

func jdiToolchain(javaExecutable string) (string, string, error) {
	java := javaExecutable
	if java == "" {
		java = "java"
	}
	resolved, err := exec.LookPath(java)
	if err != nil {
		return "", "", fmt.Errorf("Java executable was not found: %w", err)
	}
	java = resolved
	javacName := "javac"
	if strings.HasSuffix(strings.ToLower(filepath.Base(java)), ".exe") {
		javacName += ".exe"
	}
	javac := filepath.Join(filepath.Dir(java), javacName)
	if info, statErr := os.Stat(javac); statErr != nil || info.IsDir() {
		javac, err = exec.LookPath(javacName)
		if err != nil {
			return "", "", errors.New("the selected Java runtime has no javac; a JDK is required for debugging")
		}
		// The preferred executable may be a JRE. Compile and run the bridge
		// with the JDK that owns javac so its class version and jdk.jdi module
		// necessarily match; JDWP remains compatible with the separate target.
		helperJava := filepath.Join(filepath.Dir(javac), filepath.Base(java))
		if info, statErr = os.Stat(helperJava); statErr != nil || info.IsDir() {
			return "", "", errors.New("the javac installation has no matching Java runtime")
		}
		java = helperJava
	}
	return java, javac, nil
}

func (p *jdiProcess) read(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxBridgeRecordBytes)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 4)
		if len(parts) < 2 {
			p.protocolFailure("malformed bridge record")
			continue
		}
		switch parts[0] {
		case "R":
			p.readResponse(parts)
		case "E":
			p.readEvent(parts)
		default:
			p.protocolFailure("unknown bridge record kind")
		}
	}
	if err := scanner.Err(); err != nil {
		p.failPending(err)
	}
}

func (p *jdiProcess) readResponse(parts []string) {
	if len(parts) < 4 {
		p.protocolFailure("short bridge response")
		return
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		p.protocolFailure("invalid bridge response id")
		return
	}
	payload, decodeErr := base64.StdEncoding.DecodeString(parts[3])
	response := bridgeResponse{}
	if decodeErr != nil {
		response.err = decodeErr
	} else if parts[2] != "OK" {
		response.err = errors.New(string(payload))
	} else {
		response.rows = decodeBridgeRows(string(payload))
	}
	p.pendingMu.Lock()
	answer := p.pending[id]
	delete(p.pending, id)
	p.pendingMu.Unlock()
	if answer != nil {
		answer <- response
	}
}

func decodeBridgeRows(payload string) [][]string {
	if payload == "" {
		return nil
	}
	rowValues := strings.SplitN(payload, "\x1e", 8193)
	if len(rowValues) > 8192 {
		return nil
	}
	rows := make([][]string, 0, len(rowValues))
	for _, row := range rowValues {
		fields := strings.SplitN(row, "\x1f", 17)
		if len(fields) > 16 {
			return nil
		}
		rows = append(rows, fields)
	}
	return rows
}

func (p *jdiProcess) readEvent(parts []string) {
	if len(parts) < 3 || p.onEvent == nil {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		p.protocolFailure("invalid bridge event payload")
		return
	}
	rows := decodeBridgeRows(string(payload))
	if len(rows) == 0 {
		return
	}
	row := rows[0]
	event := debugEvent{kind: parts[1]}
	if event.kind == "STOP" && len(row) >= 7 {
		event.reason, event.threadToken, event.threadName = row[0], row[1], row[2]
		event.className, event.methodName = row[3], row[4]
		event.line, _ = strconv.Atoi(row[5])
		event.description = row[6]
	} else if event.kind == "ERROR" && len(row) > 0 {
		event.protocolError = row[0]
	}
	p.emitEvent(event)
}

func (p *jdiProcess) readErrors(reader io.Reader) {
	buffered := bufio.NewReaderSize(reader, 32<<10)
	var consumed int
	for consumed < 1<<20 {
		chunk, err := buffered.ReadSlice('\n')
		consumed += len(chunk)
		if len(chunk) > 0 && p.onEvent != nil {
			p.emitEvent(debugEvent{kind: "ERROR", protocolError: strings.TrimSpace(string(chunk))})
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return
		}
	}
}

func (p *jdiProcess) protocolFailure(message string) {
	p.emitEvent(debugEvent{kind: "ERROR", protocolError: message})
}

func (p *jdiProcess) emitEvent(event debugEvent) {
	if p.onEvent == nil {
		return
	}
	select {
	case p.events <- event:
	default:
		// Stop/termination events must never be dropped. A consumer which
		// cannot keep up has lost debugger state, so terminate explicitly.
		p.kill()
	}
}

func (p *jdiProcess) dispatchEvents() {
	for {
		select {
		case event := <-p.events:
			p.onEvent(event)
		case <-p.ctx.Done():
			return
		case <-p.exited:
			return
		}
	}
}

func (p *jdiProcess) failPending(cause error) {
	if cause == nil {
		cause = errors.New("structured JDI bridge exited")
	}
	p.pendingMu.Lock()
	pending := p.pending
	p.pending = make(map[uint64]chan bridgeResponse)
	p.pendingMu.Unlock()
	for _, answer := range pending {
		answer <- bridgeResponse{err: cause}
	}
}

func (p *jdiProcess) request(operation string, arguments ...string) ([][]string, error) {
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if p.commandLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.commandLimit)
		defer cancel()
	}
	return p.requestContext(ctx, operation, arguments...)
}

func (p *jdiProcess) requestFor(contexts []context.Context, operation string, arguments ...string) ([][]string, error) {
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if len(contexts) > 0 && contexts[0] != nil {
		ctx = contexts[0]
	}
	if p.commandLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.commandLimit)
		defer cancel()
	}
	return p.requestContext(ctx, operation, arguments...)
}

func (p *jdiProcess) requestContext(ctx context.Context, operation string, arguments ...string) ([][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.commandMu.Lock()
	defer p.commandMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.requestUnlockedRows(ctx, operation, arguments...)
}

func (p *jdiProcess) requestUnlockedRows(ctx context.Context, operation string, arguments ...string) ([][]string, error) {
	if len(arguments) > 100_000 {
		return nil, errors.New("debugger command exceeds its 100000-argument safety limit")
	}
	totalArgumentBytes := 0
	for _, argument := range arguments {
		totalArgumentBytes += len(argument)
		if totalArgumentBytes > 8<<20 {
			return nil, errors.New("debugger command exceeds its 8 MiB argument safety limit")
		}
	}
	id := p.nextID.Add(1)
	answer := make(chan bridgeResponse, 1)
	p.pendingMu.Lock()
	if len(p.pending) >= 128 {
		p.pendingMu.Unlock()
		return nil, errors.New("too many pending debugger commands")
	}
	p.pending[id] = answer
	p.pendingMu.Unlock()
	var record bytes.Buffer
	_, _ = fmt.Fprintf(&record, "%d\t%s", id, operation)
	for _, argument := range arguments {
		record.WriteByte('\t')
		record.WriteString(base64.StdEncoding.EncodeToString([]byte(argument)))
	}
	record.WriteByte('\n')
	if record.Len() > maxBridgeRecordBytes {
		p.pendingMu.Lock()
		delete(p.pending, id)
		p.pendingMu.Unlock()
		return nil, errors.New("encoded debugger command exceeds its protocol record limit")
	}
	p.writeMu.Lock()
	_, err := p.stdin.Write(record.Bytes())
	if err == nil {
		err = p.stdin.Flush()
	}
	p.writeMu.Unlock()
	if err != nil {
		p.pendingMu.Lock()
		delete(p.pending, id)
		p.pendingMu.Unlock()
		return nil, err
	}
	select {
	case response := <-answer:
		return response.rows, response.err
	case <-ctx.Done():
		p.pendingMu.Lock()
		delete(p.pending, id)
		p.pendingMu.Unlock()
		return nil, ctx.Err()
	}
}

func (p *jdiProcess) threads(contexts ...context.Context) ([]debugThread, error) {
	rows, err := p.requestFor(contexts, "THREADS")
	if err != nil {
		return nil, err
	}
	values := make([]debugThread, 0, len(rows))
	for _, row := range rows {
		if len(row) >= 3 {
			values = append(values, debugThread{token: row[0], name: row[1], state: row[2]})
		}
	}
	return values, nil
}

func (p *jdiProcess) stack(token string, start, levels int, contexts ...context.Context) ([]debugFrameInfo, error) {
	rows, err := p.requestFor(contexts, "FRAMES", token, strconv.Itoa(start), strconv.Itoa(levels))
	if err != nil {
		return nil, err
	}
	values := make([]debugFrameInfo, 0, len(rows))
	for _, row := range rows {
		if len(row) < 6 {
			continue
		}
		index, _ := strconv.Atoi(row[0])
		line, _ := strconv.Atoi(row[3])
		total, _ := strconv.Atoi(row[5])
		values = append(values, debugFrameInfo{index: index, name: row[1], sourceName: row[2], line: line, className: row[4], total: total})
	}
	return values, nil
}

func (p *jdiProcess) selectFrame(token string, index int, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "SELECT", token, strconv.Itoa(index))
	return err
}

func decodeDebugValues(rows [][]string) []debugValue {
	values := make([]debugValue, 0, len(rows))
	for _, row := range rows {
		if len(row) < 6 {
			continue
		}
		indexed, _ := strconv.Atoi(row[5])
		value := debugValue{name: row[0], value: row[1], typeName: row[2], evaluateName: row[3], expandable: row[4] == "true", indexed: indexed}
		if len(row) >= 7 {
			value.handle = row[6]
		}
		values = append(values, value)
	}
	return values
}

func (p *jdiProcess) locals(contexts ...context.Context) ([]debugValue, error) {
	rows, err := p.requestFor(contexts, "LOCALS")
	return decodeDebugValues(rows), err
}

func (p *jdiProcess) evaluate(expression string, contexts ...context.Context) (debugValue, error) {
	rows, err := p.requestFor(contexts, "EVAL", expression)
	if err != nil {
		return debugValue{}, err
	}
	values := decodeDebugValues(rows)
	if len(values) == 0 {
		return debugValue{}, errors.New("expression produced no value")
	}
	return values[0], nil
}

func (p *jdiProcess) children(handle string, start, count int, filter string, contexts ...context.Context) ([]debugValue, error) {
	rows, err := p.requestFor(contexts, "CHILDREN", handle, strconv.Itoa(start), strconv.Itoa(count), filter)
	return decodeDebugValues(rows), err
}

func (p *jdiProcess) assign(expression, value string, contexts ...context.Context) (debugValue, error) {
	rows, err := p.requestFor(contexts, "SET", expression, value)
	if err != nil {
		return debugValue{}, err
	}
	values := decodeDebugValues(rows)
	if len(values) == 0 {
		return debugValue{}, errors.New("assignment produced no value")
	}
	return values[0], nil
}

func (p *jdiProcess) setLineBreakpoint(className string, line int, contexts ...context.Context) (bool, string, error) {
	rows, err := p.requestFor(contexts, "BREAK_LINE", className, strconv.Itoa(line))
	if err != nil || len(rows) == 0 || len(rows[0]) < 2 {
		return false, "", err
	}
	return rows[0][0] == "true", rows[0][1], nil
}

func (p *jdiProcess) clearLineBreakpoint(className string, line int, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "CLEAR_LINE", className, strconv.Itoa(line))
	return err
}

// replaceLineBreakpoints is one bridge command: the helper validates every
// new location before changing the VM and restores the prior set if JDI still
// rejects an installation. Go-side condition/log metadata is committed only
// after this command succeeds.
func (p *jdiProcess) replaceLineBreakpoints(old, replacement []lineBreakpointSpec, contexts ...context.Context) error {
	arguments := make([]string, 0, 2+2*len(old)+2*len(replacement))
	arguments = append(arguments, strconv.Itoa(len(old)))
	for _, breakpoint := range old {
		arguments = append(arguments, breakpoint.Class, strconv.Itoa(breakpoint.Line))
	}
	arguments = append(arguments, strconv.Itoa(len(replacement)))
	for _, breakpoint := range replacement {
		arguments = append(arguments, breakpoint.Class, strconv.Itoa(breakpoint.Line))
	}
	_, err := p.requestFor(contexts, "REPLACE_LINES", arguments...)
	return err
}

func (p *jdiProcess) setFunctionBreakpoint(name string, contexts ...context.Context) (bool, string, error) {
	rows, err := p.requestFor(contexts, "BREAK_FUNCTION", name)
	if err != nil || len(rows) == 0 || len(rows[0]) < 2 {
		return false, "", err
	}
	return rows[0][0] == "true", rows[0][1], nil
}

func (p *jdiProcess) replaceFunctionBreakpoints(old, replacement []string, contexts ...context.Context) (map[string][]string, error) {
	arguments := make([]string, 0, 2+len(old)+len(replacement))
	arguments = append(arguments, strconv.Itoa(len(old)))
	arguments = append(arguments, old...)
	arguments = append(arguments, strconv.Itoa(len(replacement)))
	arguments = append(arguments, replacement...)
	rows, err := p.requestFor(contexts, "REPLACE_FUNCTIONS", arguments...)
	if err != nil {
		return nil, err
	}
	status := make(map[string][]string, len(rows))
	for _, row := range rows {
		if len(row) >= 3 {
			status[row[0]] = row[1:3]
		}
	}
	return status, nil
}

func (p *jdiProcess) configureExceptions(caught, uncaught bool, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "EXCEPTIONS", strconv.FormatBool(caught), strconv.FormatBool(uncaught))
	return err
}

func (p *jdiProcess) resume(mode, token string, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "RESUME", mode, token)
	return err
}

func (p *jdiProcess) pause(token string, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "PAUSE", token)
	return err
}

func (p *jdiProcess) restartFrame(contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "RESTART_FRAME")
	return err
}

type jdiTransaction struct{ process *jdiProcess }

func (p *jdiProcess) transaction(action func(*jdiTransaction)) {
	p.commandMu.Lock()
	defer p.commandMu.Unlock()
	action(&jdiTransaction{process: p})
}

func (t *jdiTransaction) evaluate(expression string) (debugValue, error) {
	ctx, cancel := context.WithTimeout(t.process.ctx, t.process.commandLimit)
	defer cancel()
	rows, err := t.process.requestUnlockedRows(ctx, "EVAL", expression)
	if err != nil {
		return debugValue{}, err
	}
	values := decodeDebugValues(rows)
	if len(values) == 0 {
		return debugValue{}, errors.New("expression produced no value")
	}
	return values[0], nil
}

func (t *jdiTransaction) resume() error {
	ctx, cancel := context.WithTimeout(t.process.ctx, t.process.commandLimit)
	defer cancel()
	_, err := t.process.requestUnlockedRows(ctx, "RESUME", "continue", "")
	return err
}

func (p *jdiProcess) kill() {
	p.closeOnce.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		_ = os.RemoveAll(p.helperDir)
	})
}

func (p *jdiProcess) close() {
	p.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		_, _ = p.requestContext(ctx, "DETACH")
		cancel()
		if p.cmd != nil && p.cmd.Process != nil {
			select {
			case <-p.exited:
			case <-time.After(250 * time.Millisecond):
				_ = p.cmd.Process.Kill()
			}
		}
		_ = os.RemoveAll(p.helperDir)
	})
	// Killing is asynchronous at the OS boundary. Do not return ownership to a
	// closed DAP connection until Wait has reaped the helper and both pipe
	// readers, the event dispatcher, and the lifetime watcher have exited.
	if p.cmd != nil && p.cmd.Process != nil {
		select {
		case <-p.exited:
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exited
		}
	}
	p.workers.Wait()
}

func (p *jdiProcess) releaseResourceBudget() {
	if p.releaseBudget != nil {
		p.releaseBudget()
	}
}

const jdiBridgeSource = `
import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class KotLSPJDI {
  private final VirtualMachine vm;
  private final BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
  private final PrintWriter output = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
  private final Object outputLock = new Object();
  private final List<String[]> pendingLines = Collections.synchronizedList(new ArrayList<>());
  private final List<String> pendingFunctions = Collections.synchronizedList(new ArrayList<>());
  private final Map<String, Value> values = new HashMap<>();
  private long nextValue = 1;
  private volatile ThreadReference selectedThread;
  private volatile int selectedFrame;

  private KotLSPJDI(String host, String port) throws Exception {
    AttachingConnector socket = null;
    for (AttachingConnector connector : Bootstrap.virtualMachineManager().attachingConnectors()) {
      if (connector.name().endsWith("SocketAttach")) { socket = connector; break; }
    }
    if (socket == null) throw new IllegalStateException("JDI SocketAttach connector is unavailable");
    Map<String, Connector.Argument> arguments = socket.defaultArguments();
    arguments.get("hostname").setValue(host);
    arguments.get("port").setValue(port);
    vm = socket.attach(arguments);
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 2) throw new IllegalArgumentException("host and port are required");
    KotLSPJDI bridge = new KotLSPJDI(args[0], args[1]);
    Thread events = new Thread(bridge::events, "kotlsp-jdi-events");
    events.setDaemon(true);
    events.start();
    bridge.commands();
  }

  private static String decode(String value) {
    return new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
  }

  private static String encode(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String rows(List<List<String>> values) {
    StringBuilder out = new StringBuilder();
    for (int r = 0; r < values.size(); r++) {
      if (r > 0) out.append('\u001e');
      List<String> row = values.get(r);
      for (int c = 0; c < row.size(); c++) {
        if (c > 0) out.append('\u001f');
		String field = bounded(row.get(c), 4096);
		if (out.length() + field.length() > 8 * 1024 * 1024) throw new IllegalArgumentException("debugger response exceeds its 8 MiB safety limit");
		out.append(field);
      }
    }
    return out.toString();
  }

  private static String bounded(String value, int limit) {
	if (value == null) return "";
	if (value.length() <= limit) return value;
	return value.substring(0, limit) + " [truncated]";
  }

  private void respond(String id, List<List<String>> values) {
    synchronized (outputLock) { output.println("R\t" + id + "\tOK\t" + encode(rows(values))); }
  }

  private void fail(String id, Throwable failure) {
    Throwable cause = failure;
    if (failure instanceof InvocationTargetException && ((InvocationTargetException)failure).getCause() != null) {
      cause = ((InvocationTargetException)failure).getCause();
    }
    String message = cause.getMessage();
    if (message == null || message.isBlank()) message = cause.toString();
    synchronized (outputLock) { output.println("R\t" + id + "\tERR\t" + encode(message)); }
  }

  private void event(String kind, List<String> value) {
    synchronized (outputLock) { output.println("E\t" + kind + "\t" + encode(rows(List.of(value)))); }
  }

  private void commands() {
    try {
      String line;
      while ((line = input.readLine()) != null) {
        String[] wire = line.split("\\t", -1);
        if (wire.length < 2) continue;
        String id = wire[0], operation = wire[1];
        List<String> args = new ArrayList<>();
        for (int i = 2; i < wire.length; i++) args.add(decode(wire[i]));
        try {
          List<List<String>> result = command(operation, args);
          respond(id, result == null ? List.of() : result);
          if (operation.equals("DETACH")) return;
        } catch (Throwable failure) {
          fail(id, failure);
        }
      }
    } catch (Throwable failure) {
      event("ERROR", List.of(failure.toString()));
    }
  }

  private List<List<String>> command(String op, List<String> args) throws Exception {
    switch (op) {
      case "PING": return List.of(List.of("ready"));
      case "THREADS": return threads();
      case "FRAMES": return frames(args.get(0), integer(args, 1, 0), integer(args, 2, 0));
      case "SELECT": select(args.get(0), integer(args, 1, 1)); return List.of();
      case "LOCALS": return locals();
      case "EVAL": return List.of(valueRow("", evaluate(args.get(0)), args.get(0)));
      case "CHILDREN": return children(args.get(0), integer(args, 1, 0), integer(args, 2, 200), args.size() > 3 ? args.get(3) : "");
      case "SET": return List.of(valueRow("", evaluate(args.get(0) + " = " + args.get(1)), args.get(0)));
      case "BREAK_LINE": return List.of(setLine(args.get(0), integer(args, 1, 0)));
      case "CLEAR_LINE": clearLine(args.get(0), integer(args, 1, 0)); return List.of();
      case "REPLACE_LINES": replaceLines(args); return List.of();
      case "BREAK_FUNCTION": return List.of(setFunction(args.get(0)));
	  case "REPLACE_FUNCTIONS": return replaceFunctions(args);
      case "EXCEPTIONS": exceptions(Boolean.parseBoolean(args.get(0)), Boolean.parseBoolean(args.get(1))); return List.of();
      case "RESUME": resume(args.get(0), args.size() > 1 ? args.get(1) : ""); return List.of();
      case "PAUSE": pause(args.size() > 0 ? args.get(0) : ""); return List.of();
      case "RESTART_FRAME": restartFrame(); return List.of();
      case "DETACH": vm.dispose(); return List.of();
      default: throw new IllegalArgumentException("unknown debugger operation: " + op);
    }
  }

  private static int integer(List<String> args, int index, int fallback) {
    if (index >= args.size()) return fallback;
    try { return Integer.parseInt(args.get(index)); } catch (NumberFormatException ignored) { return fallback; }
  }

  private ThreadReference thread(String token) {
    if (token != null && !token.isBlank()) {
      try {
        long id = Long.parseLong(token);
        for (ThreadReference thread : vm.allThreads()) if (thread.uniqueID() == id) return thread;
      } catch (NumberFormatException ignored) {}
    }
    return selectedThread;
  }

  private List<List<String>> threads() {
	List<ThreadReference> snapshot = vm.allThreads();
	if (snapshot.size() > 4096) throw new IllegalStateException("thread snapshot exceeds its 4096-item safety limit");
    List<List<String>> rows = new ArrayList<>();
	for (ThreadReference thread : snapshot) {
      rows.add(List.of(Long.toString(thread.uniqueID()), thread.name(), Integer.toString(thread.status())));
    }
    return rows;
  }

  private List<List<String>> frames(String token, int start, int levels) throws Exception {
    ThreadReference thread = thread(token);
    if (thread == null) throw new IllegalStateException("unknown thread");
    int from = Math.max(0, start);
	int total = thread.frameCount();
	int maximum = levels <= 0 ? 200 : Math.min(levels, 200);
	int count = Math.max(0, Math.min(maximum, total - from));
	List<StackFrame> frames = count == 0 ? List.of() : thread.frames(from, count);
    List<List<String>> rows = new ArrayList<>();
	for (int offset = 0; offset < frames.size(); offset++) {
	  int i = from + offset;
	  Location location = frames.get(offset).location();
      String source;
      try { source = location.sourceName(); }
      catch (AbsentInformationException missing) { source = location.declaringType().name().replace('.', '/') + ".java"; }
      String name = location.declaringType().name() + "." + location.method().name();
	  rows.add(List.of(Integer.toString(i + 1), name, source, Integer.toString(Math.max(0, location.lineNumber())), location.declaringType().name(), Integer.toString(total)));
    }
    return rows;
  }

  private void select(String token, int index) throws Exception {
    ThreadReference thread = thread(token);
    if (thread == null) throw new IllegalStateException("unknown thread");
    int frame = Math.max(0, index - 1);
    if (frame >= thread.frameCount()) throw new IllegalArgumentException("unknown stack frame");
    selectedThread = thread;
    selectedFrame = frame;
  }

  private StackFrame frame() throws Exception {
    ThreadReference thread = selectedThread;
    if (thread == null) throw new IllegalStateException("no selected thread");
    return thread.frame(selectedFrame);
  }

  private List<List<String>> locals() throws Exception {
    StackFrame frame = frame();
    List<List<String>> rows = new ArrayList<>();
    for (LocalVariable variable : frame.visibleVariables()) {
	  if (rows.size() >= 4096) break;
      rows.add(valueRow(variable.name(), frame.getValue(variable), variable.name()));
    }
    return rows;
  }

  private Value evaluate(String expression) throws Exception {
    Class<?> parser = Class.forName("com.sun.tools.example.debug.expr.ExpressionParser");
    java.lang.reflect.Method target = null;
    for (java.lang.reflect.Method method : parser.getDeclaredMethods()) {
      if (method.getName().equals("evaluate") && method.getParameterCount() == 3 && method.getParameterTypes()[0] == String.class) {
        target = method; break;
      }
    }
    if (target == null) throw new IllegalStateException("JDK expression evaluator is unavailable");
    Class<?> getterType = target.getParameterTypes()[2];
    Object getter = Proxy.newProxyInstance(getterType.getClassLoader(), new Class<?>[]{getterType}, (proxy, method, args) -> frame());
    target.setAccessible(true);
    return (Value)target.invoke(null, expression, vm, getter);
  }

	private static String quoted(String value) {
	value = bounded(value, 4096);
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\': out.append("\\\\"); break;
        case '"': out.append("\\\""); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default: out.append(c);
      }
    }
    return out.append('"').toString();
  }

  private static String render(Value value) {
    if (value == null) return "null";
    if (value instanceof StringReference) return quoted(((StringReference)value).value());
    if (value instanceof ArrayReference) {
      ArrayReference array = (ArrayReference)value;
      return "instance of " + array.referenceType().name() + " (length=" + array.length() + ", id=" + array.uniqueID() + ")";
    }
    if (value instanceof ObjectReference) {
      ObjectReference object = (ObjectReference)value;
      return "instance of " + object.referenceType().name() + " (id=" + object.uniqueID() + ")";
    }
    return value.toString();
  }

  private String valueHandle(Value value) {
    if (!(value instanceof ObjectReference) || value instanceof StringReference) return "";
	if (values.size() >= 100000) return "";
    String handle = Long.toString(nextValue++);
    values.put(handle, value);
    return handle;
  }

  private List<String> valueRow(String name, Value value, String expression) {
    String type = value == null || value.type() == null ? "" : value.type().name();
	String handle = valueHandle(value);
	boolean expandable = !handle.isEmpty();
    int indexed = value instanceof ArrayReference ? ((ArrayReference)value).length() : 0;
	return List.of(name, render(value), type, expression == null ? "" : expression, Boolean.toString(expandable), Integer.toString(indexed), handle);
  }

  private List<List<String>> children(String handle, int start, int count, String filter) throws Exception {
    Value value = values.get(handle);
    if (value == null) throw new IllegalArgumentException("unknown or expired value handle");
    int from = Math.max(0, start), maximum = count <= 0 ? 200 : Math.min(count, 200);
    List<List<String>> rows = new ArrayList<>();
    if (value instanceof ArrayReference) {
      if (filter.equals("named")) return rows;
      ArrayReference array = (ArrayReference)value;
      int to = Math.min(array.length(), from + maximum);
      List<Value> values = array.getValues(from, Math.max(0, to - from));
      for (int i = 0; i < values.size(); i++) {
        String name = "[" + (from + i) + "]";
        rows.add(valueRow(name, values.get(i), ""));
      }
      return rows;
    }
    if (!(value instanceof ObjectReference) || filter.equals("indexed")) return rows;
    ObjectReference object = (ObjectReference)value;
    List<Field> fields = object.referenceType().allFields();
    int to = Math.min(fields.size(), from + maximum);
    for (int i = from; i < to; i++) {
      Field field = fields.get(i);
      Value child = field.isStatic() ? field.declaringType().getValue(field) : object.getValue(field);
      rows.add(valueRow(field.name(), child, ""));
    }
    return rows;
  }

  private List<String> setLine(String className, int line) throws Exception {
    boolean installed = installLine(className, line);
    if (installed) return List.of("true", "breakpoint installed");
    if (vm.classesByName(className).isEmpty()) {
      String[] pending = new String[]{className, Integer.toString(line)};
      if (!containsLine(pending)) pendingLines.add(pending);
      ClassPrepareRequest request = vm.eventRequestManager().createClassPrepareRequest();
      request.addClassFilter(className);
	  request.putProperty("line-class", className);
	  request.putProperty("line", line);
      // Class preparation must stop the VM until the event worker installs the
      // real breakpoint. With SUSPEND_NONE a short-lived method can execute
      // past the requested line before prepared() gets CPU time.
      request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
      request.enable();
      return List.of("true", "breakpoint deferred until class preparation");
    }
    return List.of("false", "no executable location at requested line");
  }

  private boolean containsLine(String[] wanted) {
    synchronized (pendingLines) {
      for (String[] value : pendingLines) if (value[0].equals(wanted[0]) && value[1].equals(wanted[1])) return true;
    }
    return false;
  }

  private boolean installLine(String className, int line) throws Exception {
    boolean installed = false;
    for (ReferenceType type : vm.classesByName(className)) {
      for (Location location : type.locationsOfLine(line)) {
        BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
        request.putProperty("class", className);
        request.putProperty("line", line);
        request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        request.enable();
        installed = true;
      }
    }
    return installed;
  }

  private void clearLine(String className, int line) {
    List<BreakpointRequest> remove = new ArrayList<>();
    for (BreakpointRequest request : vm.eventRequestManager().breakpointRequests()) {
      if (className.equals(request.getProperty("class")) && Integer.valueOf(line).equals(request.getProperty("line"))) remove.add(request);
    }
    vm.eventRequestManager().deleteEventRequests(remove);
	List<ClassPrepareRequest> prepares = new ArrayList<>();
	for (ClassPrepareRequest request : vm.eventRequestManager().classPrepareRequests()) {
	  if (className.equals(request.getProperty("line-class")) && Integer.valueOf(line).equals(request.getProperty("line"))) prepares.add(request);
	}
	vm.eventRequestManager().deleteEventRequests(prepares);
    synchronized (pendingLines) { pendingLines.removeIf(value -> value[0].equals(className) && value[1].equals(Integer.toString(line))); }
  }

  private void restoreLines(List<String[]> oldLines) throws Exception {
    // First remove any survivors from a partially failed bulk deletion. This
    // makes restoration idempotent and prevents duplicate stop events.
    for (String[] value : oldLines) clearLine(value[0], Integer.parseInt(value[1]));
    for (String[] value : oldLines) {
      List<String> status = setLine(value[0], Integer.parseInt(value[1]));
      if (!status.get(0).equals("true")) throw new IllegalStateException("could not restore " + value[0] + ":" + value[1] + ": " + status.get(1));
    }
  }

  private void replaceLines(List<String> args) throws Exception {
	int index = 0;
	int oldCount = integer(args, index++, 0);
	List<String[]> oldLines = new ArrayList<>();
	for (int i = 0; i < oldCount; i++) oldLines.add(new String[]{args.get(index++), args.get(index++)});
	int newCount = integer(args, index++, 0);
	List<String[]> newLines = new ArrayList<>();
	for (int i = 0; i < newCount; i++) newLines.add(new String[]{args.get(index++), args.get(index++)});
	// Stage every replacement request while the old requests remain enabled.
	// Class preparation takes the same pendingLines monitor, so it cannot
	// observe a half-published deferred set. If validation, creation, or enable
	// fails, only staged request objects are deleted and the old set is intact.
	List<EventRequest> staged = new ArrayList<>(), oldRequests = new ArrayList<>();
	List<String[]> deferred = new ArrayList<>();
	boolean oldDeletionStarted = false;
	synchronized (pendingLines) {
	  try {
		for (String[] value : newLines) {
		  String className = value[0];
		  int line = Integer.parseInt(value[1]);
		  List<ReferenceType> types = vm.classesByName(className);
		  if (types.isEmpty()) {
			ClassPrepareRequest request = vm.eventRequestManager().createClassPrepareRequest();
			request.addClassFilter(className);
			request.putProperty("line-class", className);
			request.putProperty("line", line);
			request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
			staged.add(request);
			deferred.add(new String[]{className, Integer.toString(line)});
			continue;
		  }
		  boolean executable = false;
		  for (ReferenceType type : types) {
			for (Location location : type.locationsOfLine(line)) {
			  BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
			  request.putProperty("class", className);
			  request.putProperty("line", line);
			  request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
			  staged.add(request);
			  executable = true;
			}
		  }
		  if (!executable) throw new IllegalArgumentException("no executable location at " + className + ":" + line);
		}
		Set<EventRequest> stagedIdentity = Collections.newSetFromMap(new IdentityHashMap<>());
		stagedIdentity.addAll(staged);
		for (BreakpointRequest request : vm.eventRequestManager().breakpointRequests()) {
		  if (!stagedIdentity.contains(request) && containsLine(oldLines, request.getProperty("class"), request.getProperty("line"))) oldRequests.add(request);
		}
		for (ClassPrepareRequest request : vm.eventRequestManager().classPrepareRequests()) {
		  if (!stagedIdentity.contains(request) && containsLine(oldLines, request.getProperty("line-class"), request.getProperty("line"))) oldRequests.add(request);
		}
		for (EventRequest request : staged) request.enable();
		oldDeletionStarted = true;
		vm.eventRequestManager().deleteEventRequests(oldRequests);
		pendingLines.removeIf(value -> containsLine(oldLines, value[0], value[1]));
		for (String[] value : deferred) if (!containsLine(value)) pendingLines.add(value);
	  } catch (Throwable failure) {
		Throwable rollbackFailure = null;
		try { vm.eventRequestManager().deleteEventRequests(staged); } catch (Throwable rollback) { rollbackFailure = rollback; }
		if (oldDeletionStarted) {
		  try { restoreLines(oldLines); } catch (Throwable rollback) { rollbackFailure = rollback; }
		}
		if (rollbackFailure != null) {
		  failure.addSuppressed(rollbackFailure);
		  // Continuing with Go metadata for the old set and an unknowable VM set
		  // is worse than ending this debug session explicitly.
		  try { vm.dispose(); } catch (Throwable ignored) {}
		}
		throw failure;
	  }
	}
  }

  private boolean containsLine(List<String[]> lines, Object className, Object line) {
	if (className == null || line == null) return false;
	for (String[] value : lines) {
	  if (value[0].equals(className.toString()) && value[1].equals(line.toString())) return true;
	}
	return false;
  }

  private List<String> setFunction(String qualified) throws Exception {
    int dot = qualified.lastIndexOf('.');
    if (dot <= 0 || dot + 1 >= qualified.length()) return List.of("false", "function breakpoint requires Class.method");
    String className = qualified.substring(0, dot), methodName = qualified.substring(dot + 1);
    boolean installed = installFunction(className, methodName);
    if (installed) return List.of("true", "breakpoint installed");
    if (vm.classesByName(className).isEmpty()) {
      if (!pendingFunctions.contains(qualified)) pendingFunctions.add(qualified);
      ClassPrepareRequest request = vm.eventRequestManager().createClassPrepareRequest();
      request.addClassFilter(className);
      request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
      request.enable();
      return List.of("true", "breakpoint deferred until class preparation");
    }
    return List.of("false", "method was not found");
  }

  private void clearFunction(String qualified) {
    List<EventRequest> remove = new ArrayList<>();
    for (BreakpointRequest request : vm.eventRequestManager().breakpointRequests()) {
      Object function = request.getProperty("function");
      if (function != null && qualified.equals(function.toString())) remove.add(request);
    }
    for (ClassPrepareRequest request : vm.eventRequestManager().classPrepareRequests()) {
      Object function = request.getProperty("function");
      if (function != null && qualified.equals(function.toString())) remove.add(request);
    }
    vm.eventRequestManager().deleteEventRequests(remove);
    synchronized (pendingFunctions) { pendingFunctions.remove(qualified); }
  }

  private void restoreFunctions(List<String> oldFunctions) throws Exception {
    for (String qualified : oldFunctions) clearFunction(qualified);
    for (String qualified : oldFunctions) {
      List<String> status = setFunction(qualified);
      if (!status.get(0).equals("true")) throw new IllegalStateException("could not restore " + qualified + ": " + status.get(1));
    }
  }

  private List<List<String>> replaceFunctions(List<String> args) throws Exception {
	int index = 0;
	int oldCount = integer(args, index++, 0);
	List<String> oldFunctions = new ArrayList<>();
	for (int i = 0; i < oldCount; i++) oldFunctions.add(args.get(index++));
	int newCount = integer(args, index++, 0);
	List<String> newFunctions = new ArrayList<>();
	for (int i = 0; i < newCount; i++) newFunctions.add(args.get(index++));
	List<EventRequest> staged = new ArrayList<>(), oldRequests = new ArrayList<>();
	List<String> deferred = new ArrayList<>();
	List<List<String>> statuses = new ArrayList<>();
	boolean oldDeletionStarted = false;
	synchronized (pendingFunctions) {
	  try {
		for (String qualified : newFunctions) {
		  int dot = qualified.lastIndexOf('.');
		  if (dot <= 0 || dot + 1 >= qualified.length()) {
			statuses.add(List.of(qualified, "false", "function breakpoint requires Class.method"));
			continue;
		  }
		  String className = qualified.substring(0, dot), methodName = qualified.substring(dot + 1);
		  List<ReferenceType> types = vm.classesByName(className);
		  if (types.isEmpty()) {
			ClassPrepareRequest request = vm.eventRequestManager().createClassPrepareRequest();
			request.addClassFilter(className);
			request.putProperty("function", qualified);
			request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
			staged.add(request);
			deferred.add(qualified);
			statuses.add(List.of(qualified, "true", "breakpoint deferred until class preparation"));
			continue;
		  }
		  boolean installed = false;
		  for (ReferenceType type : types) {
			for (com.sun.jdi.Method method : type.methodsByName(methodName)) {
			  Location location = method.location();
			  if (location == null) continue;
			  BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
			  request.putProperty("function", qualified);
			  request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
			  staged.add(request);
			  installed = true;
			}
		  }
		  statuses.add(List.of(qualified, Boolean.toString(installed), installed ? "breakpoint installed" : "method was not found"));
		}
		Set<EventRequest> stagedIdentity = Collections.newSetFromMap(new IdentityHashMap<>());
		stagedIdentity.addAll(staged);
		for (BreakpointRequest request : vm.eventRequestManager().breakpointRequests()) {
		  Object function = request.getProperty("function");
		  if (!stagedIdentity.contains(request) && function != null && oldFunctions.contains(function.toString())) oldRequests.add(request);
		}
		for (ClassPrepareRequest request : vm.eventRequestManager().classPrepareRequests()) {
		  Object function = request.getProperty("function");
		  if (!stagedIdentity.contains(request) && function != null && oldFunctions.contains(function.toString())) oldRequests.add(request);
		}
		for (EventRequest request : staged) request.enable();
		oldDeletionStarted = true;
		vm.eventRequestManager().deleteEventRequests(oldRequests);
		pendingFunctions.removeIf(oldFunctions::contains);
		for (String qualified : deferred) if (!pendingFunctions.contains(qualified)) pendingFunctions.add(qualified);
	  } catch (Throwable failure) {
		Throwable rollbackFailure = null;
		try { vm.eventRequestManager().deleteEventRequests(staged); } catch (Throwable rollback) { rollbackFailure = rollback; }
		if (oldDeletionStarted) {
		  try { restoreFunctions(oldFunctions); } catch (Throwable rollback) { rollbackFailure = rollback; }
		}
		if (rollbackFailure != null) {
		  failure.addSuppressed(rollbackFailure);
		  try { vm.dispose(); } catch (Throwable ignored) {}
		}
		throw failure;
	  }
	}
	return statuses;
  }

  private boolean installFunction(String className, String methodName) throws Exception {
    boolean installed = false;
    for (ReferenceType type : vm.classesByName(className)) {
      for (com.sun.jdi.Method method : type.methodsByName(methodName)) {
        Location location = method.location();
        if (location == null) continue;
        BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
        request.putProperty("function", className + "." + methodName);
        request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        request.enable();
        installed = true;
      }
    }
    return installed;
  }

  private void exceptions(boolean caught, boolean uncaught) {
    EventRequestManager manager = vm.eventRequestManager();
    manager.deleteEventRequests(new ArrayList<>(manager.exceptionRequests()));
    if (caught || uncaught) {
      ExceptionRequest request = manager.createExceptionRequest(null, caught, uncaught);
      request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
      request.enable();
    }
  }

  private void resume(String mode, String token) throws Exception {
	values.clear();
    EventRequestManager manager = vm.eventRequestManager();
    manager.deleteEventRequests(new ArrayList<>(manager.stepRequests()));
    if (!mode.equals("continue")) {
      ThreadReference thread = thread(token);
      if (thread == null) throw new IllegalStateException("unknown thread for step");
      int depth = mode.equals("stepIn") ? StepRequest.STEP_INTO : mode.equals("stepOut") ? StepRequest.STEP_OUT : StepRequest.STEP_OVER;
      StepRequest request = manager.createStepRequest(thread, StepRequest.STEP_LINE, depth);
      request.addCountFilter(1);
      request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
      request.enable();
    }
    vm.resume();
  }

  private void pause(String token) {
    ThreadReference thread = thread(token);
    if (thread == null || token == null || token.isBlank()) vm.suspend();
    else thread.suspend();
  }

  private void restartFrame() throws Exception {
    ThreadReference thread = selectedThread;
    if (thread == null) throw new IllegalStateException("no selected thread");
    thread.popFrames(thread.frame(selectedFrame));
    selectedFrame = 0;
	values.clear();
  }

  private void events() {
    try {
      while (true) {
        EventSet set = vm.eventQueue().remove();
        boolean resume = true;
        for (Event raw : set) {
          if (raw instanceof VMStartEvent) {
            // A debuggee launched with suspend=y must remain stopped until the
            // DAP client has installed breakpoints and sends configurationDone.
            resume = false;
          } else if (raw instanceof ClassPrepareEvent) {
            prepared(((ClassPrepareEvent)raw).referenceType());
          } else if (raw instanceof BreakpointEvent) {
            stopped("breakpoint", (LocatableEvent)raw, "Breakpoint hit");
            resume = false;
          } else if (raw instanceof StepEvent) {
            stopped("step", (LocatableEvent)raw, "Step completed");
            resume = false;
          } else if (raw instanceof ExceptionEvent) {
            ExceptionEvent event = (ExceptionEvent)raw;
            String type = event.exception().referenceType().name();
            if (type.equals("org.springframework.boot.devtools.restart.SilentExitExceptionHandler$SilentExitException")) continue;
            stopped("exception", event, type);
            resume = false;
          } else if (raw instanceof VMDeathEvent || raw instanceof VMDisconnectEvent) {
            event("TERMINATED", List.of("terminated"));
            return;
          }
        }
        if (resume) set.resume();
      }
    } catch (VMDisconnectedException disconnected) {
      event("TERMINATED", List.of("disconnected"));
    } catch (Throwable failure) {
      event("ERROR", List.of(failure.toString()));
    }
  }

  private void prepared(ReferenceType type) throws Exception {
    synchronized (pendingLines) {
      Iterator<String[]> iterator = pendingLines.iterator();
      while (iterator.hasNext()) {
        String[] value = iterator.next();
        if (value[0].equals(type.name())) { installLine(value[0], Integer.parseInt(value[1])); iterator.remove(); }
      }
    }
    synchronized (pendingFunctions) {
      Iterator<String> iterator = pendingFunctions.iterator();
      while (iterator.hasNext()) {
        String value = iterator.next();
        int dot = value.lastIndexOf('.');
        if (value.substring(0, dot).equals(type.name())) { installFunction(type.name(), value.substring(dot + 1)); iterator.remove(); }
      }
    }
  }

  private void stopped(String reason, LocatableEvent event, String description) {
	values.clear();
    ThreadReference thread = event.thread();
    selectedThread = thread;
    selectedFrame = 0;
    Location location = event.location();
    event("STOP", List.of(reason, Long.toString(thread.uniqueID()), thread.name(), location.declaringType().name(), location.method().name(), Integer.toString(Math.max(0, location.lineNumber())), description));
  }
}
`
