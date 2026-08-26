package dap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// jdbProcess is a small, clean-room bridge over the JDK's supported debugger
// command-line frontend. It keeps all command serialization here so the DAP
// layer can expose a normal asynchronous protocol while JDWP remains owned by
// the JDK that matches the debuggee.
type jdbProcess struct {
	ctx       context.Context
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	incoming  chan string
	chunks    chan string
	done      chan error
	onOutput  func(string)
	commandMu sync.Mutex
	closeOnce sync.Once
}

func startJDB(ctx context.Context, executable string, args []string, directory string, environment []string, onOutput func(string)) (*jdbProcess, error) {
	if executable == "" {
		executable = "jdb"
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	if directory != "" {
		cmd.Dir = directory
	}
	if environment != nil {
		cmd.Env = environment
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err = cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	process := &jdbProcess{ctx: ctx, cmd: cmd, stdin: stdin, incoming: make(chan string), chunks: make(chan string), done: make(chan error, 1), onOutput: onOutput}
	go process.relayChunks()
	go process.readOutput(reader)
	go func() {
		err := cmd.Wait()
		_ = writer.Close()
		process.done <- err
		close(process.done)
	}()
	initial, err := process.waitForPrompt()
	if err != nil {
		process.close()
		return nil, fmt.Errorf("jdb did not become ready: %w", err)
	}
	// The attaching connector first prints a bare prompt, then reports the VM
	// start and emits the real thread prompt. Consuming that second prompt here
	// prevents it from being mistaken for the response to the first DAP command.
	if len(initial) > 0 && !isThreadJDBPrompt(initial[len(initial)-1]) {
		if _, err = process.waitForPrompt(); err != nil {
			process.close()
			return nil, fmt.Errorf("jdb did not report the attached VM prompt: %w", err)
		}
	}
	return process, nil
}

func (p *jdbProcess) readOutput(reader *io.PipeReader) {
	defer reader.Close()
	defer close(p.incoming)
	buffered := bufio.NewReader(reader)
	var value strings.Builder
	for {
		b, err := buffered.ReadByte()
		if err != nil {
			if value.Len() > 0 {
				p.emit(value.String())
			}
			return
		}
		value.WriteByte(b)
		text := value.String()
		if b == '\n' || b == ' ' && isJDBPrompt(text) {
			p.emit(text)
			value.Reset()
		}
	}
}

func (p *jdbProcess) emit(value string) {
	if p.onOutput != nil {
		p.onOutput(value)
	}
	p.incoming <- value
}

// relayChunks is an elastic FIFO. JDB output can legitimately contain more
// than any fixed channel capacity before its prompt; dropping one of those
// chunks can corrupt evaluate/stack results or lose the prompt entirely.
func (p *jdbProcess) relayChunks() {
	defer close(p.chunks)
	input := p.incoming
	queue := make([]string, 0, 64)
	for input != nil || len(queue) > 0 {
		var output chan string
		var next string
		if len(queue) > 0 {
			output, next = p.chunks, queue[0]
		}
		select {
		case value, ok := <-input:
			if !ok {
				input = nil
			} else {
				queue = append(queue, value)
			}
		case output <- next:
			queue[0] = ""
			queue = queue[1:]
		}
	}
}

func isJDBPrompt(value string) bool {
	trimmed := strings.TrimRight(value, "\r\n")
	if strings.HasSuffix(trimmed, "> ") {
		return true
	}
	return isThreadJDBPrompt(value)
}

func isThreadJDBPrompt(value string) bool {
	trimmed := strings.TrimRight(value, "\r\n")
	trimmed = strings.TrimSuffix(trimmed, " ")
	open := strings.LastIndexByte(trimmed, '[')
	if open < 0 || !strings.HasSuffix(trimmed, "]") {
		return false
	}
	if strings.TrimSpace(trimmed[:open]) == "" {
		return false
	}
	for _, r := range trimmed[open+1 : len(trimmed)-1] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return open+1 < len(trimmed)-1
}

func (p *jdbProcess) waitForPrompt() ([]string, error) {
	lines := make([]string, 0, 16)
	for {
		select {
		case chunk, ok := <-p.chunks:
			if !ok {
				return lines, errors.New("jdb output closed")
			}
			lines = append(lines, chunk)
			if isJDBPrompt(chunk) {
				return lines, nil
			}
			if isAsyncJDBNotification(chunk) {
				// Already delivered through onOutput as a DAP event. It belongs
				// to the preceding run/step, not the synchronous query which may
				// have been issued immediately afterward.
				continue
			}
		case err, ok := <-p.done:
			if !ok || err == nil {
				return lines, errors.New("jdb exited")
			}
			return lines, err
		case <-p.ctx.Done():
			return lines, p.ctx.Err()
		}
	}
}

func isAsyncJDBNotification(value string) bool {
	for _, marker := range []string{"Breakpoint hit:", "Step completed:", "Exception occurred:", "Interrupted:", "The application exited", "VM disconnected"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func (p *jdbProcess) execute(command string) ([]string, error) {
	p.commandMu.Lock()
	defer p.commandMu.Unlock()
	quiet := time.NewTimer(5 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case <-p.chunks:
			if !quiet.Stop() {
				select {
				case <-quiet.C:
				default:
				}
			}
			quiet.Reset(5 * time.Millisecond)
		case <-quiet.C:
			goto drained
		}
	}
drained:
	if _, err := io.WriteString(p.stdin, command+"\n"); err != nil {
		return nil, err
	}
	return p.waitForCommandPrompt(command)
}

func (p *jdbProcess) waitForCommandPrompt(command string) ([]string, error) {
	requireOutput := false
	for _, prefix := range []string{"threads", "where", "print ", "eval ", "dump ", "locals", "methods ", "fields ", "class ", "list", "classpath"} {
		if command == prefix || strings.HasPrefix(command, prefix) {
			requireOutput = true
			break
		}
	}
	lines := make([]string, 0, 16)
	sawOutput := false
	for {
		select {
		case chunk, ok := <-p.chunks:
			if !ok {
				return lines, errors.New("jdb output closed")
			}
			if isJDBPrompt(chunk) {
				if requireOutput && !sawOutput {
					// An asynchronous stop emits its prompt just after the stop
					// notification. If a client immediately sends a query, that
					// stale boundary can arrive after the pre-command drain.
					continue
				}
				lines = append(lines, chunk)
				return lines, nil
			}
			if strings.TrimSpace(chunk) != "" {
				sawOutput = true
			}
			lines = append(lines, chunk)
		case err, ok := <-p.done:
			if !ok || err == nil {
				return lines, errors.New("jdb exited")
			}
			return lines, err
		case <-p.ctx.Done():
			return lines, p.ctx.Err()
		}
	}
}

func (p *jdbProcess) send(command string) error {
	p.commandMu.Lock()
	defer p.commandMu.Unlock()
	_, err := io.WriteString(p.stdin, command+"\n")
	return err
}

func (p *jdbProcess) close() {
	p.closeOnce.Do(func() {
		_ = p.send("exit")
		_ = p.stdin.Close()
		if p.cmd.Process != nil {
			select {
			case <-p.done:
			case <-time.After(250 * time.Millisecond):
				_ = p.cmd.Process.Kill()
			}
		}
	})
}
