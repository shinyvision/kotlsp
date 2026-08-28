// Package dap provides the TCP endpoint created by the IntelliJ-compatible
// start_debug_server command. The adapter deliberately owns its listener for
// the lifetime of the language server so repeated commands return the same
// ready port instead of racing multiple listeners.
package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Server struct {
	listener    net.Listener
	port        int
	cancel      context.CancelFunc
	once        sync.Once
	sources     SourceResolver
	lifetime    sync.Mutex
	closing     bool
	workers     sync.WaitGroup
	connections map[net.Conn]struct{}
}

// SourceResolver connects debugger frames to the language index's exact
// source attachment instead of rediscovering artifacts by filename.
type SourceResolver func(ctx context.Context, classPaths []string, className, sourceName string) (string, bool)

func Start(parent context.Context, sourceResolvers ...SourceResolver) (*Server, error) {
	if parent == nil {
		parent = context.Background()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	server := &Server{listener: listener, port: listener.Addr().(*net.TCPAddr).Port, cancel: cancel, connections: make(map[net.Conn]struct{})}
	if len(sourceResolvers) > 0 {
		server.sources = sourceResolvers[0]
	}
	server.workers.Add(2)
	go func() {
		defer server.workers.Done()
		server.serve(ctx)
	}()
	go func() {
		defer server.workers.Done()
		<-ctx.Done()
		_ = server.listener.Close()
	}()
	return server, nil
}

func (s *Server) Port() int { return s.port }

func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		s.lifetime.Lock()
		s.closing = true
		s.cancel()
		err = s.listener.Close()
		for connection := range s.connections {
			_ = connection.Close()
		}
		s.lifetime.Unlock()
		s.workers.Wait()
	})
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) serve(ctx context.Context) {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.lifetime.Lock()
		if s.closing || ctx.Err() != nil {
			s.lifetime.Unlock()
			_ = connection.Close()
			return
		}
		s.workers.Add(1)
		s.connections[connection] = struct{}{}
		s.lifetime.Unlock()
		go func(connection net.Conn) {
			defer s.workers.Done()
			defer func() {
				s.lifetime.Lock()
				delete(s.connections, connection)
				s.lifetime.Unlock()
			}()
			serveConnection(ctx, connection, s.sources)
		}(connection)
	}
}

type message struct {
	Seq       int             `json:"seq"`
	Type      string          `json:"type"`
	Command   string          `json:"command,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func serveConnection(ctx context.Context, connection net.Conn, sources SourceResolver) {
	const maxInFlightRequestBytes = 128 << 20
	connectionCtx, cancel := context.WithCancel(ctx)
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	session := newSession(connectionCtx, writer)
	session.sourceResolver = sources
	jobs := make(chan message, 64)
	controls := make(chan message, 8)
	var admissionMu sync.Mutex
	admittedBytes := 0
	reserve := func(bytes int) bool {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		if bytes > maxInFlightRequestBytes-admittedBytes {
			return false
		}
		admittedBytes += bytes
		return true
	}
	release := func(bytes int) {
		admissionMu.Lock()
		admittedBytes -= bytes
		admissionMu.Unlock()
	}
	var workers sync.WaitGroup
	defer func() {
		// Cancel request contexts and tear down the VM bridge before waiting for
		// workers: a worker may be inside a debugger query whose only release is
		// cancellation/process shutdown.
		cancel()
		session.close()
		_ = connection.Close()
		close(jobs)
		close(controls)
		workers.Wait()
	}()
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for request := range jobs {
				session.handleRequest(request)
				release(dapMessageBytes(request))
				if request.Command == "disconnect" {
					cancel()
					_ = connection.Close()
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for request := range controls {
			session.handleRequest(request)
			release(dapMessageBytes(request))
			cancel()
			_ = connection.Close()
		}
	}()
	// Parent/server cancellation must interrupt a connection blocked in a
	// partial frame read. Count the watcher with the request workers so the
	// server's Close barrier also waits for this final socket owner.
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-connectionCtx.Done()
		_ = connection.Close()
	}()
	for {
		payload, err := readMessage(reader)
		if err != nil {
			return
		}
		var request message
		if json.Unmarshal(payload, &request) != nil || request.Type != "request" || request.Seq <= 0 || request.Command == "" || len(request.Command) > 256 {
			continue
		}
		if request.Command == "cancel" {
			var args struct {
				RequestID int `json:"requestId"`
			}
			if decodeDAPArguments(request.Arguments, &args) != nil || args.RequestID <= 0 {
				if err := session.respond(request, nil, false, "cancel requires a valid requestId"); err != nil {
					return
				}
				continue
			}
			session.cancelRequest(args.RequestID)
			if err := session.respond(request, map[string]any{}, true, ""); err != nil {
				return
			}
			continue
		}
		requestBytes := dapMessageBytes(request)
		if !reserve(requestBytes) {
			_ = session.respond(request, nil, false, "debug adapter request byte budget is full")
			continue
		}
		if !session.registerRequest(request) {
			release(requestBytes)
			_ = session.respond(request, nil, false, "duplicate in-flight request sequence")
			continue
		}
		if request.Command == "disconnect" || request.Command == "terminate" {
			// Lifecycle requests supersede queued inspection work. Canceling the
			// request contexts releases the serialized JDI command lane before
			// the dedicated control worker detaches or terminates the target.
			session.cancelOutstandingRequests(request.Seq)
			select {
			case controls <- request:
			default:
				release(requestBytes)
				session.rejectQueuedRequest(request, "debug adapter control queue is full")
			}
			continue
		}
		select {
		case jobs <- request:
		default:
			release(requestBytes)
			session.rejectQueuedRequest(request, "debug adapter request queue is full")
		}
		select {
		case <-connectionCtx.Done():
			return
		default:
		}
	}
}

func dapMessageBytes(request message) int {
	return len(request.Type) + len(request.Command) + len(request.Arguments) + 128
}

func readMessage(reader *bufio.Reader) ([]byte, error) {
	const maxHeaderBytes = 32 << 10
	length := -1
	headerBytes := 0
	for {
		lineBytes, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		headerBytes += len(lineBytes)
		if headerBytes > maxHeaderBytes {
			return nil, fmt.Errorf("DAP headers exceed their %d-byte safety limit", maxHeaderBytes)
		}
		line := string(lineBytes)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			if length >= 0 {
				return nil, fmt.Errorf("duplicate Content-Length")
			}
			length, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || length < 0 || length > 16<<20 {
				return nil, fmt.Errorf("invalid Content-Length")
			}
		}
	}
	if length < 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func writeMessage(writer *bufio.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > 64<<20 {
		return fmt.Errorf("outgoing DAP message exceeds its 64 MiB safety limit")
	}
	if _, err = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	if _, err = writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}
