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
	} else if (event.kind == "ERROR" || event.kind == "SKIPPED") && len(row) > 0 {
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

type debugMember struct {
	name, kind, detail string
}

// members lists the fields and methods of expression's type, or of the
// selected frame's own class for an empty expression.
func (p *jdiProcess) members(expression string, contexts ...context.Context) ([]debugMember, error) {
	rows, err := p.requestFor(contexts, "MEMBERS", expression)
	members := make([]debugMember, 0, len(rows))
	for _, row := range rows {
		if len(row) >= 3 {
			members = append(members, debugMember{name: row[0], kind: row[1], detail: row[2]})
		}
	}
	return members, err
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

// replaceLineBreakpoints is one bridge command: the helper validates every
// new location before changing the VM and restores the prior set if JDI still
// rejects an installation. Go-side condition/log metadata is committed only
// after this command succeeds.
// The answer says, per new spec, whether it was installed, deferred until
// its class loads, or has no code in its (loaded) class.
func (p *jdiProcess) replaceLineBreakpoints(old, replacement []lineBreakpointSpec, contexts ...context.Context) (map[lineBreakpointSpec]string, error) {
	arguments := make([]string, 0, 2+2*len(old)+2*len(replacement))
	arguments = append(arguments, strconv.Itoa(len(old)))
	for _, breakpoint := range old {
		arguments = append(arguments, breakpoint.Class, strconv.Itoa(breakpoint.Line))
	}
	arguments = append(arguments, strconv.Itoa(len(replacement)))
	for _, breakpoint := range replacement {
		arguments = append(arguments, breakpoint.Class, strconv.Itoa(breakpoint.Line))
	}
	rows, err := p.requestFor(contexts, "REPLACE_LINES", arguments...)
	if err != nil {
		return nil, err
	}
	statuses := make(map[lineBreakpointSpec]string, len(rows))
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		line, _ := strconv.Atoi(row[1])
		statuses[lineBreakpointSpec{Class: row[0], Line: line}] = row[2]
	}
	return statuses, nil
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

// resumeWith resumes with a mode's extra arguments: a step-in target's
// class, method and signature.
func (p *jdiProcess) resumeWith(mode, token string, extra []string, contexts ...context.Context) error {
	_, err := p.requestFor(contexts, "RESUME", append([]string{mode, token}, extra...)...)
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
  // Set while an expression runs in the debuggee. The JDK evaluator invokes
  // methods with every thread resumed; a breakpoint the call (or another
  // thread) reaches meanwhile would suspend the VM under the invocation and
  // never let it return. Such events are skipped, as IDEs do.
  private volatile boolean evaluating;
  // The exception the VM last stopped for, for exceptionInfo.
  private volatile ObjectReference lastException;
  private volatile ThreadReference lastExceptionThread;
  private volatile boolean lastExceptionUncaught;
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
      case "MEMBERS": return members(args.get(0));
      case "EXCEPTION": return exceptionDetails();
      case "CHILDREN": return children(args.get(0), integer(args, 1, 0), integer(args, 2, 200), args.size() > 3 ? args.get(3) : "");
      case "SET": return List.of(valueRow("", evaluate(args.get(0) + " = " + args.get(1)), args.get(0)));
      case "BREAK_LINE": return List.of(setLine(args.get(0), integer(args, 1, 0)));
      case "CLEAR_LINE": clearLine(args.get(0), integer(args, 1, 0)); return List.of();
      case "REPLACE_LINES": return replaceLines(args);
      case "BREAK_FUNCTION": return List.of(setFunction(args.get(0)));
	  case "REPLACE_FUNCTIONS": return replaceFunctions(args);
      case "EXCEPTIONS": exceptions(Boolean.parseBoolean(args.get(0)), Boolean.parseBoolean(args.get(1))); return List.of();
      case "RESUME": resume(args.get(0), args.size() > 1 ? args.get(1) : "", args.size() > 4 ? args.subList(2, 5) : List.of()); return List.of();
      case "STEP_TARGETS": return stepTargets();
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
    // An instance method's receiver: its fields are what a Variables view
    // most often needs, and nothing else reaches them.
    ObjectReference self = frame.thisObject();
    if (self != null) rows.add(valueRow("this", self, "this"));
    for (LocalVariable variable : frame.visibleVariables()) {
	  if (rows.size() >= 4096) break;
      String name = variable.name();
      // Kotlin's compiler-made locals: inline markers ($i$f$map, $i$a$-let-...)
      // and the variables of an inlined library body (destination$iv$iv) are
      // not the program's. An extension receiver ($this$doubled) is "this", a
      // captured value ($total) its own name; both still evaluate by the
      // name the JVM knows.
      if (name.startsWith("$i$") || name.contains("$iv")) continue;
      String shown = name;
      if (name.startsWith("$this$")) shown = self == null ? "this" : "this@" + name.substring(6);
      else if (name.startsWith("$") && name.length() > 1 && Character.isJavaIdentifierStart(name.charAt(1))) shown = name.substring(1);
      rows.add(valueRow(shown, frame.getValue(variable), name));
    }
    return rows;
  }

  // evaluate adds to the JDK evaluator what it lacks and conditions need:
  // && and ||, with Java's short-circuit, and names of the frame's own
  // class used unqualified from a static context (square(4)).
  private Value evaluate(String expression) throws Exception {
    String trimmed = stripParentheses(expression.trim());
    if (topLevel(trimmed, "?") < 0) {
      for (String operator : new String[]{"||", "&&"}) {
        int at = topLevel(trimmed, operator);
        if (at < 0) continue;
        boolean left = truth(evaluate(trimmed.substring(0, at)), trimmed.substring(0, at));
        if (operator.equals("||") ? left : !left) return vm.mirrorOf(left);
        return vm.mirrorOf(truth(evaluate(trimmed.substring(at + 2)), trimmed.substring(at + 2)));
      }
    }
    try {
      return evaluateWithParser(trimmed);
    } catch (Exception failure) {
      Throwable cause = failure instanceof InvocationTargetException && failure.getCause() != null ? failure.getCause() : failure;
      String message = String.valueOf(cause.getMessage());
      if (message.startsWith("Name unknown: ") && !trimmed.isEmpty() && Character.isJavaIdentifierStart(trimmed.charAt(0))) {
        try {
          return evaluateWithParser(frame().location().declaringType().name() + "." + trimmed);
        } catch (Exception ignored) {
          // The original error names what is unknown.
        }
      }
      throw failure;
    }
  }

  private static boolean truth(Value value, String expression) {
    if (value instanceof BooleanValue) return ((BooleanValue)value).value();
    throw new IllegalArgumentException("not a boolean: " + expression.trim());
  }

  // topLevel finds operator outside strings, characters and brackets.
  private static int topLevel(String text, String operator) {
    int depth = 0;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c == '"' || c == '\'') {
        for (i++; i < text.length() && text.charAt(i) != c; i++) {
          if (text.charAt(i) == '\\') i++;
        }
        continue;
      }
      if (c == '(' || c == '[' || c == '{') depth++;
      else if (c == ')' || c == ']' || c == '}') depth--;
      else if (depth == 0 && text.startsWith(operator, i)) return i;
    }
    return -1;
  }

  private static String stripParentheses(String text) {
    while (text.startsWith("(") && text.endsWith(")")) {
      int depth = 0, close = -1;
      for (int i = 0; i < text.length(); i++) {
        char c = text.charAt(i);
        if (c == '(') depth++;
        else if (c == ')' && --depth == 0) { close = i; break; }
      }
      if (close != text.length() - 1) break;
      text = text.substring(1, text.length() - 1).trim();
    }
    return text;
  }

  // exceptionDetails describes the exception of the last exception stop:
  // its class, its message (read from Throwable's field, without calling
  // getMessage), whether anything catches it, and the stopped thread's stack.
  private List<List<String>> exceptionDetails() throws Exception {
    ObjectReference exception = lastException;
    if (exception == null) return List.of();
    String message = "";
    Value detail = field(exception, "detailMessage");
    if (detail instanceof StringReference) message = ((StringReference)detail).value();
    StringBuilder stack = new StringBuilder();
    ThreadReference thread = lastExceptionThread;
    if (thread != null && thread.isSuspended()) {
      int count = Math.min(thread.frameCount(), 64);
      for (StackFrame frame : thread.frames(0, count)) {
        Location location = frame.location();
        String source;
        try { source = location.sourceName(); } catch (AbsentInformationException absent) { source = "Unknown Source"; }
        stack.append("\tat ").append(location.declaringType().name()).append('.').append(location.method().name())
            .append('(').append(source).append(location.lineNumber() > 0 ? ":" + location.lineNumber() : "").append(")\n");
      }
    }
    return List.of(List.of(exception.referenceType().name(), message, Boolean.toString(lastExceptionUncaught), stack.toString()));
  }

  // stepTargets lists the calls the selected frame's line has yet to make,
  // read from the method's bytecode: [label, class, name, signature].
  private List<List<String>> stepTargets() throws Exception {
    StackFrame frame = frame();
    Location here = frame.location();
    Method method = here.method();
    if (!vm.canGetBytecodes()) return List.of();
    byte[] code = method.bytecodes();
    long end = code.length;
    String file = sourceOf(here);
    int line = lineOf(here);
    try {
      for (Location entry : method.allLineLocations()) {
        if (entry.codeIndex() > here.codeIndex() && entry.codeIndex() < end && sourceOf(entry).equals(file) && lineOf(entry) != line) end = entry.codeIndex();
      }
    } catch (AbsentInformationException absent) {
      return List.of();
    }
    ConstantPool pool = new ConstantPool(method.declaringType());
    List<List<String>> rows = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    for (int pc = 0; pc < end && pc < code.length; ) {
      int opcode = code[pc] & 0xff;
      int length = instructionLength(code, pc);
      if (length <= 0) break;
      if (pc >= here.codeIndex() && opcode >= 0xb6 && opcode <= 0xb9) {
        String[] target = pool.member(((code[pc + 1] & 0xff) << 8) | (code[pc + 2] & 0xff));
        if (target != null && seen.add(target[0] + target[1] + target[2])) {
          String simple = target[0].substring(target[0].lastIndexOf('.') + 1);
          String label = target[1].equals("<init>") ? "new " + simple : simple + "." + target[1];
          rows.add(List.of(label, target[0], target[1], target[2]));
        }
      }
      pc += length;
    }
    return rows;
  }

  private static int instructionLength(byte[] code, int pc) {
    int opcode = code[pc] & 0xff;
    if (opcode == 0xaa || opcode == 0xab) {
      int at = pc + 1 + ((4 - (pc + 1) % 4) % 4);
      if (at + 12 > code.length) return -1;
      if (opcode == 0xaa) {
        int low = readInt(code, at + 4), high = readInt(code, at + 8);
        return at + 12 + (high - low + 1) * 4 - pc;
      }
      return at + 8 + readInt(code, at + 4) * 8 - pc;
    }
    if (opcode == 0xc4) return pc + 1 < code.length && (code[pc + 1] & 0xff) == 0x84 ? 6 : 4;
    if (opcode == 0x10 || opcode == 0x12 || opcode >= 0x15 && opcode <= 0x19 || opcode >= 0x36 && opcode <= 0x3a || opcode == 0xa9 || opcode == 0xbc) return 2;
    if (opcode == 0x11 || opcode == 0x13 || opcode == 0x14 || opcode == 0x84 || opcode >= 0x99 && opcode <= 0xa8 || opcode >= 0xb2 && opcode <= 0xb8 || opcode == 0xbb || opcode == 0xbd || opcode == 0xc0 || opcode == 0xc1 || opcode == 0xc6 || opcode == 0xc7) return 3;
    if (opcode == 0xc5) return 4;
    if (opcode == 0xb9 || opcode == 0xba || opcode == 0xc8 || opcode == 0xc9) return 5;
    return 1;
  }

  private static int readInt(byte[] code, int at) {
    return ((code[at] & 0xff) << 24) | ((code[at + 1] & 0xff) << 16) | ((code[at + 2] & 0xff) << 8) | (code[at + 3] & 0xff);
  }

  // ConstantPool resolves the method references a call instruction names.
  private static final class ConstantPool {
    private final int[] tags, first, second;
    private final String[] text;

    ConstantPool(ReferenceType type) {
      int count = type.constantPoolCount();
      tags = new int[count]; first = new int[count]; second = new int[count]; text = new String[count];
      byte[] bytes = type.constantPool();
      int at = 0;
      for (int index = 1; index < count && at < bytes.length; index++) {
        int tag = bytes[at++] & 0xff;
        tags[index] = tag;
        switch (tag) {
          case 1: {
            int length = ((bytes[at] & 0xff) << 8) | (bytes[at + 1] & 0xff);
            text[index] = new String(bytes, at + 2, length, StandardCharsets.UTF_8);
            at += 2 + length;
            break;
          }
          case 3: case 4: at += 4; break;
          case 5: case 6: at += 8; index++; break;
          case 7: case 8: case 16: case 19: case 20: first[index] = u2(bytes, at); at += 2; break;
          case 9: case 10: case 11: case 12: case 17: case 18: first[index] = u2(bytes, at); second[index] = u2(bytes, at + 2); at += 4; break;
          case 15: first[index] = bytes[at] & 0xff; second[index] = u2(bytes, at + 1); at += 3; break;
          default: return;
        }
      }
    }

    private static int u2(byte[] bytes, int at) { return ((bytes[at] & 0xff) << 8) | (bytes[at + 1] & 0xff); }

    private boolean valid(int index, int... wanted) {
      if (index <= 0 || index >= tags.length) return false;
      for (int tag : wanted) if (tags[index] == tag) return true;
      return false;
    }

    // member returns [class, name, descriptor] for a Methodref or
    // InterfaceMethodref, or null.
    String[] member(int index) {
      if (!valid(index, 10, 11)) return null;
      int owner = first[index], nameAndType = second[index];
      if (!valid(owner, 7) || !valid(nameAndType, 12) || !valid(first[owner], 1) || !valid(first[nameAndType], 1) || !valid(second[nameAndType], 1)) return null;
      return new String[]{text[first[owner]].replace('/', '.'), text[first[nameAndType]], text[second[nameAndType]]};
    }
  }

  // members lists the fields and methods completion can offer after
  // "expression.", or, for an empty expression, in the frame's own scope.
  private List<List<String>> members(String expression) throws Exception {
    ReferenceType type = null;
    boolean statics = false;
    if (expression.isBlank()) {
      StackFrame frame = frame();
      ObjectReference self = frame.thisObject();
      type = self != null ? self.referenceType() : frame.location().declaringType();
      statics = self == null;
    } else {
      Value value = null;
      try { value = evaluate(expression); } catch (Exception ignored) {}
      if (value instanceof ObjectReference) {
        type = ((ObjectReference)value).referenceType();
      } else if (value == null) {
        List<ReferenceType> named = vm.classesByName(expression.trim());
        if (!named.isEmpty()) { type = named.get(0); statics = true; }
      }
    }
    List<List<String>> rows = new ArrayList<>();
    if (type == null) return rows;
    Set<String> seen = new HashSet<>();
    for (Field field : type.allFields()) {
      if (rows.size() >= 2048) break;
      if (field.isSynthetic() || statics && !field.isStatic() || !seen.add("f" + field.name())) continue;
      rows.add(List.of(field.name(), "field", field.typeName()));
    }
    for (Method method : type.allMethods()) {
      if (rows.size() >= 2048) break;
      if (method.isSynthetic() || method.isConstructor() || method.isStaticInitializer() || statics && !method.isStatic() || method.name().contains("$")) continue;
      if (!seen.add("m" + method.name() + method.signature())) continue;
      rows.add(List.of(method.name(), "method", method.returnTypeName() + " " + method.name() + "(" + String.join(", ", method.argumentTypeNames()) + ")"));
    }
    return rows;
  }

  private Value evaluateWithParser(String expression) throws Exception {
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
    evaluating = true;
    try {
      return (Value)target.invoke(null, expression, vm, getter);
    } finally {
      evaluating = false;
    }
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

  private static final Set<String> boxedTypes = Set.of("java.lang.Integer", "java.lang.Long", "java.lang.Short", "java.lang.Byte", "java.lang.Character", "java.lang.Boolean", "java.lang.Double", "java.lang.Float");

  private static String boxedPreview(ObjectReference object) {
    ReferenceType type = object.referenceType();
    if (boxedTypes.contains(type.name())) {
      Value inner = field(object, "value");
      if (inner instanceof CharValue) return "'" + ((CharValue)inner).value() + "'";
      if (inner != null) return inner.toString();
    }
    if (type instanceof ClassType && (((ClassType)type).isEnum() || ((ClassType)type).superclass() != null && ((ClassType)type).superclass().isEnum())) {
      Value name = field(object, "name");
      if (name instanceof StringReference) return type.name().substring(type.name().lastIndexOf('.') + 1) + "." + ((StringReference)name).value();
    }
    return null;
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
      // A boxed primitive reads as its value and an enum constant as its
      // name; the identity says nothing about either.
      String boxed = boxedPreview(object);
      if (boxed != null) return boxed;
      return "instance of " + object.referenceType().name() + " (id=" + object.uniqueID() + ")";
    }
    return value.toString();
  }

  private String valueHandle(Value value) {
    if (!(value instanceof ObjectReference) || value instanceof StringReference) return "";
    if (boxedTypes.contains(((ObjectReference)value).referenceType().name())) return "";
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
    String rendered = render(value);
    if (value instanceof ObjectReference && !(value instanceof ArrayReference) && !(value instanceof StringReference)) {
      try {
        int size = logicalSize((ObjectReference)value, 0);
        if (size >= 0) {
          indexed = size;
          rendered = rendered + " size=" + size;
        }
      } catch (Exception ignored) {
        // A structure that cannot be read logically is still shown raw.
      } finally {
        keyOf.clear();
      }
    }
	return List.of(name, rendered, type, expression == null ? "" : expression, Boolean.toString(expandable), Integer.toString(indexed), handle);
  }

  // Element is one entry of a collection's logical view. expression is
  // appended to the collection's own expression ("[0]" for arrays,
  // ".get(0)" for lists) or empty when no expression reaches it.
  private static final class Element {
    final String name, expression;
    final Value value;
    Element(String name, Value value, String expression) { this.name = name; this.value = value; this.expression = expression; }
  }

  private static final int maxLogicalElements = 10_000;

  // logical reads the elements of the JDK's common collections from their
  // fields -- never by calling a method in the target, which could change
  // it or deadlock -- or returns null for anything else.
  private List<Element> logical(ObjectReference object, int depth) throws Exception {
    if (depth > 4) return null;
    for (ReferenceType type = object.referenceType(); type != null; type = type instanceof ClassType ? ((ClassType)type).superclass() : null) {
      switch (type.name()) {
        case "java.util.ArrayList": return listFromArray(object, field(object, "elementData"), intField(object, "size"));
        case "java.util.Vector": return listFromArray(object, field(object, "elementData"), intField(object, "elementCount"));
        case "java.util.Arrays$ArrayList": {
          Value array = field(object, "a");
          return listFromArray(object, array, array instanceof ArrayReference ? ((ArrayReference)array).length() : 0);
        }
        case "java.util.LinkedList": {
          List<Element> out = new ArrayList<>();
          Value node = field(object, "first");
          while (node instanceof ObjectReference && out.size() < maxLogicalElements) {
            int index = out.size();
            out.add(new Element("[" + index + "]", field((ObjectReference)node, "item"), ".get(" + index + ")"));
            node = field((ObjectReference)node, "next");
          }
          return out;
        }
        case "java.util.ArrayDeque": {
          Value array = field(object, "elements");
          if (!(array instanceof ArrayReference)) return null;
          ArrayReference elements = (ArrayReference)array;
          int head = intField(object, "head"), tail = intField(object, "tail"), length = elements.length();
          List<Element> out = new ArrayList<>();
          for (int i = head; i != tail && length > 0 && out.size() < maxLogicalElements; i = (i + 1) % length) {
            out.add(new Element("[" + out.size() + "]", elements.getValue(i), ""));
          }
          return out;
        }
        case "java.util.ImmutableCollections$ListN": return listFromArray(object, field(object, "elements"), -1);
        case "java.util.ImmutableCollections$List12":
        case "java.util.ImmutableCollections$Set12": {
          boolean list = type.name().endsWith("List12");
          List<Element> out = new ArrayList<>();
          for (String name : new String[]{"e0", "e1"}) {
            Value element = field(object, name);
            if (element == null || isEmptySentinel(element)) continue;
            out.add(new Element("[" + out.size() + "]", element, list ? ".get(" + out.size() + ")" : ""));
          }
          return out;
        }
        case "java.util.ImmutableCollections$SetN": {
          Value array = field(object, "elements");
          List<Element> out = new ArrayList<>();
          if (array instanceof ArrayReference) {
            for (Value element : ((ArrayReference)array).getValues()) {
              if (element != null && out.size() < maxLogicalElements) out.add(new Element("[" + out.size() + "]", element, ""));
            }
          }
          return out;
        }
        case "java.util.ImmutableCollections$Map1": {
          List<Element> out = new ArrayList<>();
          out.add(entry(field(object, "k0"), field(object, "v0")));
          return out;
        }
        case "java.util.ImmutableCollections$MapN": {
          Value array = field(object, "table");
          List<Element> out = new ArrayList<>();
          if (array instanceof ArrayReference) {
            List<Value> table = ((ArrayReference)array).getValues();
            for (int i = 0; i + 1 < table.size() && out.size() < maxLogicalElements; i += 2) {
              if (table.get(i) != null) out.add(entry(table.get(i), table.get(i + 1)));
            }
          }
          return out;
        }
        case "java.util.LinkedHashMap": {
          List<Element> out = new ArrayList<>();
          Value node = field(object, "head");
          while (node instanceof ObjectReference && out.size() < maxLogicalElements) {
            out.add(entry(field((ObjectReference)node, "key"), field((ObjectReference)node, "value")));
            node = field((ObjectReference)node, "after");
          }
          return out;
        }
        case "java.util.HashMap": return hashEntries(object, "value");
        case "java.util.concurrent.ConcurrentHashMap": return hashEntries(object, "val");
        case "java.util.TreeMap": {
          List<Element> out = new ArrayList<>();
          treeEntries(field(object, "root"), out, 0);
          return out;
        }
        case "java.util.HashSet":
        case "java.util.LinkedHashSet": return keys(field(object, "map"), depth);
        case "java.util.TreeSet": return keys(field(object, "m"), depth);
        case "java.util.Collections$UnmodifiableCollection":
        case "java.util.Collections$SynchronizedCollection": return delegate(field(object, "c"), depth);
        case "java.util.Collections$UnmodifiableMap":
        case "java.util.Collections$SynchronizedMap": return delegate(field(object, "m"), depth);
        case "java.util.Collections$EmptyList":
        case "java.util.Collections$EmptySet":
        case "java.util.Collections$EmptyMap":
        case "kotlin.collections.EmptyList":
        case "kotlin.collections.EmptySet":
        case "kotlin.collections.EmptyMap": return new ArrayList<>();
        case "java.util.Collections$SingletonList":
        case "java.util.Collections$SingletonSet": {
          List<Element> out = new ArrayList<>();
          out.add(new Element("[0]", field(object, "element"), type.name().endsWith("List") ? ".get(0)" : ""));
          return out;
        }
        default:
      }
    }
    return null;
  }

  // logicalSize is a collection's element count, or -1 for a value with no
  // logical view. It reads the collection's own count where it keeps one, so
  // a list of maps does not walk every map to label it.
  private int logicalSize(ObjectReference object, int depth) throws Exception {
    if (depth > 4) return -1;
    for (ReferenceType type = object.referenceType(); type != null; type = type instanceof ClassType ? ((ClassType)type).superclass() : null) {
      switch (type.name()) {
        case "java.util.ArrayList": case "java.util.LinkedList": case "java.util.HashMap": case "java.util.TreeMap":
          return Math.min(intField(object, "size"), maxLogicalElements);
        case "java.util.Vector": return Math.min(intField(object, "elementCount"), maxLogicalElements);
        case "java.util.HashSet": case "java.util.LinkedHashSet": {
          Value map = field(object, "map");
          return map instanceof ObjectReference ? logicalSize((ObjectReference)map, depth + 1) : -1;
        }
        case "java.util.TreeSet": {
          Value map = field(object, "m");
          return map instanceof ObjectReference ? logicalSize((ObjectReference)map, depth + 1) : -1;
        }
        default:
      }
    }
    List<Element> elements = logical(object, depth);
    return elements == null ? -1 : elements.size();
  }

  private List<Element> listFromArray(ObjectReference owner, Value array, int size) {
    List<Element> out = new ArrayList<>();
    if (!(array instanceof ArrayReference)) return out;
    ArrayReference elements = (ArrayReference)array;
    int count = Math.min(size < 0 ? elements.length() : size, Math.min(elements.length(), maxLogicalElements));
    List<Value> values = count == 0 ? List.of() : elements.getValues(0, count);
    for (int i = 0; i < values.size(); i++) out.add(new Element("[" + i + "]", values.get(i), ".get(" + i + ")"));
    return out;
  }

  private List<Element> hashEntries(ObjectReference map, String valueField) {
    List<Element> out = new ArrayList<>();
    Value array = field(map, "table");
    if (!(array instanceof ArrayReference)) return out;
    for (Value bucket : ((ArrayReference)array).getValues()) {
      for (Value node = bucket; node instanceof ObjectReference && out.size() < maxLogicalElements; node = field((ObjectReference)node, "next")) {
        out.add(entry(field((ObjectReference)node, "key"), field((ObjectReference)node, valueField)));
      }
    }
    return out;
  }

  private void treeEntries(Value node, List<Element> out, int depth) {
    if (!(node instanceof ObjectReference) || depth > 64 || out.size() >= maxLogicalElements) return;
    ObjectReference entry = (ObjectReference)node;
    treeEntries(field(entry, "left"), out, depth + 1);
    if (out.size() < maxLogicalElements) out.add(entry(field(entry, "key"), field(entry, "value")));
    treeEntries(field(entry, "right"), out, depth + 1);
  }

  private List<Element> keys(Value map, int depth) throws Exception {
    if (!(map instanceof ObjectReference)) return null;
    List<Element> entries = logical((ObjectReference)map, depth + 1);
    if (entries == null) return null;
    List<Element> out = new ArrayList<>();
    for (Element entry : entries) out.add(new Element("[" + out.size() + "]", keyOf.get(entry), ""));
    return out;
  }

  private List<Element> delegate(Value inner, int depth) throws Exception {
    return inner instanceof ObjectReference ? logical((ObjectReference)inner, depth + 1) : null;
  }

  // The key behind each map entry, for sets built on maps.
  private final Map<Element, Value> keyOf = new IdentityHashMap<>();

  private Element entry(Value key, Value value) {
    String preview = keyPreview(key);
    String expression = key instanceof StringReference || key instanceof PrimitiveValue ? ".get(" + preview + ")" : "";
    Element element = new Element(preview, value, expression);
    keyOf.put(element, key);
    return element;
  }

  private String keyPreview(Value key) {
    if (key == null) return "null";
    if (key instanceof StringReference) return quoted(((StringReference)key).value());
    if (key instanceof PrimitiveValue) return key.toString();
    if (key instanceof ObjectReference) {
      ObjectReference object = (ObjectReference)key;
      String type = object.referenceType().name();
      if (type.startsWith("java.lang.") && object.referenceType().fieldByName("value") != null) {
        Value boxed = field(object, "value");
        if (boxed instanceof PrimitiveValue) return boxed.toString();
      }
      if (object.referenceType() instanceof ClassType && ((ClassType)object.referenceType()).isEnum()) {
        Value name = field(object, "name");
        if (name instanceof StringReference) return ((StringReference)name).value();
      }
      return type.substring(type.lastIndexOf('.') + 1) + "@" + object.uniqueID();
    }
    return String.valueOf(key);
  }

  private boolean isEmptySentinel(Value value) {
    if (!(value instanceof ObjectReference)) return false;
    List<ReferenceType> owners = vm.classesByName("java.util.ImmutableCollections");
    if (owners.isEmpty()) return false;
    Field empty = owners.get(0).fieldByName("EMPTY");
    return empty != null && value.equals(owners.get(0).getValue(empty));
  }

  private static Value field(ObjectReference object, String name) {
    Field field = object.referenceType().fieldByName(name);
    return field == null ? null : object.getValue(field);
  }

  private static int intField(ObjectReference object, String name) {
    Value value = field(object, name);
    return value instanceof PrimitiveValue ? ((PrimitiveValue)value).intValue() : 0;
  }

  private List<List<String>> children(String handle, int start, int count, String filter) throws Exception {
    boolean raw = handle.startsWith("raw:");
    Value value = values.get(raw ? handle.substring(4) : handle);
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
        rows.add(valueRow(name, values.get(i), name));
      }
      return rows;
    }
    if (!(value instanceof ObjectReference)) return rows;
    ObjectReference object = (ObjectReference)value;
    // A collection shows its elements, paged as indexed children, and one
    // named child, [raw], with the fields behind them.
    List<Element> logical = raw ? null : logical(object, 0);
    if (logical != null) {
      if (!filter.equals("named")) {
        int to = Math.min(logical.size(), from + maximum);
        for (int i = from; i < to; i++) rows.add(valueRow(logical.get(i).name, logical.get(i).value, logical.get(i).expression));
      }
      if (!filter.equals("indexed") && (filter.equals("named") || from + maximum >= logical.size())) {
        rows.add(List.of("[raw]", "", object.referenceType().name(), "", "true", "0", "raw:" + valueHandle(object)));
      }
      keyOf.clear();
      return rows;
    }
    if (filter.equals("indexed")) return rows;
    // Instance fields only: a class's constants (serialVersionUID and the
    // like) are not part of the value.
    List<Field> fields = new ArrayList<>();
    for (Field field : object.referenceType().allFields()) {
      if (!field.isStatic()) fields.add(field);
    }
    int to = Math.min(fields.size(), from + maximum);
    for (int i = from; i < to; i++) {
      Field field = fields.get(i);
      rows.add(valueRow(field.name(), object.getValue(field), "." + field.name()));
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
      for (Location location : lineVisits(type, line)) {
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

  // lineVisits is where a breakpoint on line goes: each place execution
  // arrives at the line, not each line-table entry for it. Kotlin restates a
  // line after code inlined from another file -- "Store(mutableListOf())" is
  // line 16 at offsets 0 and 14 -- and a request on both stopped twice per
  // call. A later entry is a new visit only when another line of the same
  // file runs in between, as in a Java for loop's header.
  private static List<Location> lineVisits(ReferenceType type, int line) throws AbsentInformationException {
    List<Location> candidates = type.locationsOfLine(line);
    Map<Method, List<Location>> byMethod = new LinkedHashMap<>();
    for (Location location : candidates) byMethod.computeIfAbsent(location.method(), ignored -> new ArrayList<>()).add(location);
    List<Location> kept = new ArrayList<>();
    for (Map.Entry<Method, List<Location>> group : byMethod.entrySet()) {
      List<Location> locations = group.getValue();
      locations.sort(Comparator.comparingLong(Location::codeIndex));
      List<Location> table;
      try { table = group.getKey().allLineLocations(); } catch (AbsentInformationException absent) { table = List.of(); }
      String file = sourceOf(locations.get(0));
      Location previous = null;
      for (Location candidate : locations) {
        boolean visit = previous == null;
        for (Location entry : table) {
          if (visit) break;
          if (entry.codeIndex() <= previous.codeIndex() || entry.codeIndex() >= candidate.codeIndex()) continue;
          if (sourceOf(entry).equals(file) && lineOf(entry) != line) visit = true;
        }
        if (visit) kept.add(candidate);
        previous = candidate;
      }
    }
    return kept;
  }

  // Kotlin's source map tells inlined code's own file and line apart from the
  // caller's; for other classes the default stratum is the source.
  private static String sourceOf(Location location) {
    try { return location.sourceName("Kotlin"); } catch (AbsentInformationException absent) {
      try { return location.sourceName(); } catch (AbsentInformationException none) { return ""; }
    }
  }

  private static int lineOf(Location location) {
    int line = location.lineNumber("Kotlin");
    return line > 0 ? line : location.lineNumber();
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

  // replaceLines answers, per new (class, line), "installed", "deferred" or
  // "none". A source line names every class its file declares; that one of
  // them -- App$Inner for a line of App -- has no code there is expected, and
  // used to fail the whole request once the classes were loaded.
  private List<List<String>> replaceLines(List<String> args) throws Exception {
	List<List<String>> statuses = new ArrayList<>();
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
			statuses.add(List.of(className, Integer.toString(line), "deferred"));
			continue;
		  }
		  boolean executable = false;
		  for (ReferenceType type : types) {
			for (Location location : lineVisits(type, line)) {
			  BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
			  request.putProperty("class", className);
			  request.putProperty("line", line);
			  request.setSuspendPolicy(EventRequest.SUSPEND_ALL);
			  staged.add(request);
			  executable = true;
			}
		  }
		  statuses.add(List.of(className, Integer.toString(line), executable ? "installed" : "none"));
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
	return statuses;
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

  private void resume(String mode, String token, List<String> target) throws Exception {
	values.clear();
    EventRequestManager manager = vm.eventRequestManager();
    manager.deleteEventRequests(new ArrayList<>(manager.stepRequests()));
    manager.deleteEventRequests(new ArrayList<>(manager.methodEntryRequests()));
    if (!mode.equals("continue")) {
      ThreadReference thread = thread(token);
      if (thread == null) throw new IllegalStateException("unknown thread for step");
      if (mode.equals("target")) {
        // Step into one call of the line: stop on entering that method, or at
        // the next line if the line finishes without calling it.
        MethodEntryRequest entry = manager.createMethodEntryRequest();
        entry.addThreadFilter(thread);
        List<ReferenceType> owners = vm.classesByName(target.get(0));
        if (owners.isEmpty()) entry.addClassFilter(target.get(0)); else entry.addClassFilter(owners.get(0));
        entry.putProperty("target", target.get(1) + target.get(2));
        entry.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        entry.enable();
        mode = "next";
      }
      int depth = mode.equals("stepIn") ? StepRequest.STEP_INTO : mode.equals("stepOut") ? StepRequest.STEP_OUT : StepRequest.STEP_OVER;
      StepRequest request = manager.createStepRequest(thread, StepRequest.STEP_LINE, depth);
      // Step filters: stepping into the JDK's or the Kotlin runtime's
      // internals (string concatenation, lambda bootstrap, null checks) lands
      // in code without sources. The step continues to the next frame that is
      // the program's own, as other Java debuggers do by default.
      for (String excluded : new String[]{"java.*", "javax.*", "jdk.*", "sun.*", "com.sun.*", "kotlin.jvm.internal.*", "kotlin.coroutines.jvm.internal.*"}) {
        request.addClassExclusionFilter(excluded);
      }
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
        if (evaluating) {
          for (Event raw : set) {
            if (raw instanceof LocatableEvent && !(raw instanceof ClassPrepareEvent)) {
              Location location = ((LocatableEvent)raw).location();
              event("SKIPPED", List.of(location.declaringType().name() + "." + location.method().name() + ":" + Math.max(0, location.lineNumber())));
            } else if (raw instanceof ClassPrepareEvent) {
              prepared(((ClassPrepareEvent)raw).referenceType());
            }
          }
          set.resume();
          continue;
        }
        // A step that ends on a breakpoint's line arrives with that breakpoint
        // in one set. Reported as two stops, the breakpoint's false condition
        // resumed the thread the step had just stopped.
        boolean stepped = false;
        for (Event raw : set) {
          if (raw instanceof StepEvent) stepped = true;
        }
        boolean reported = false;
        for (Event raw : set) {
          if (raw instanceof VMStartEvent) {
            // A debuggee launched with suspend=y must remain stopped until the
            // DAP client has installed breakpoints and sends configurationDone.
            resume = false;
          } else if (raw instanceof ClassPrepareEvent) {
            prepared(((ClassPrepareEvent)raw).referenceType());
          } else if (raw instanceof BreakpointEvent) {
            if (!reported) stopped(stepped ? "breakpoint+step" : "breakpoint", (LocatableEvent)raw, "Breakpoint hit");
            reported = true;
            resume = false;
          } else if (raw instanceof MethodEntryEvent) {
            MethodEntryEvent entered = (MethodEntryEvent)raw;
            Object wanted = entered.request().getProperty("target");
            if (wanted != null && wanted.equals(entered.method().name() + entered.method().signature())) {
              EventRequestManager manager = vm.eventRequestManager();
              manager.deleteEventRequests(new ArrayList<>(manager.methodEntryRequests()));
              manager.deleteEventRequests(new ArrayList<>(manager.stepRequests()));
              if (!reported) stopped("step", entered, "Stepped into " + entered.method().name());
              reported = true;
              resume = false;
            }
          } else if (raw instanceof StepEvent) {
            vm.eventRequestManager().deleteEventRequests(new ArrayList<>(vm.eventRequestManager().methodEntryRequests()));
            if (!reported) {
              boolean breakpointToo = false;
              for (Event other : set) {
                if (other instanceof BreakpointEvent) breakpointToo = true;
              }
              if (!breakpointToo) stopped("step", (LocatableEvent)raw, "Step completed");
            }
            resume = false;
          } else if (raw instanceof ExceptionEvent) {
            ExceptionEvent event = (ExceptionEvent)raw;
            String type = event.exception().referenceType().name();
            if (type.equals("org.springframework.boot.devtools.restart.SilentExitExceptionHandler$SilentExitException")) continue;
            lastException = event.exception();
            lastExceptionThread = event.thread();
            lastExceptionUncaught = event.catchLocation() == null;
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
