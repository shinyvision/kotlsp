// Package dap provides the TCP endpoint created by the IntelliJ-compatible
// start_debug_server command. The adapter deliberately owns its listener for
// the lifetime of the language server so repeated commands return the same
// ready port instead of racing multiple listeners.
package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Server struct {
	listener net.Listener
	port     int
	cancel   context.CancelFunc
	once     sync.Once
}

func Start(parent context.Context) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	server := &Server{listener: listener, port: listener.Addr().(*net.TCPAddr).Port, cancel: cancel}
	go server.serve(ctx)
	return server, nil
}

func (s *Server) Port() int { return s.port }

func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		err = s.listener.Close()
	})
	return err
}

func (s *Server) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		go serveConnection(ctx, connection)
	}
}

type message struct {
	Seq       int             `json:"seq"`
	Type      string          `json:"type"`
	Command   string          `json:"command,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	session := newSession(ctx, writer)
	defer session.close()
	for {
		payload, err := readMessage(reader)
		if err != nil {
			return
		}
		var request message
		if json.Unmarshal(payload, &request) != nil || request.Type != "request" {
			continue
		}
		body, success, responseText := session.dispatch(request.Command, request.Arguments)
		if session.respond(request, body, success, responseText) != nil {
			return
		}
		if request.Command == "initialize" {
			if session.event("initialized", nil) != nil {
				return
			}
		}
		if request.Command == "disconnect" {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func readMessage(reader *bufio.Reader) ([]byte, error) {
	length := -1
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
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
	if _, err = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	if _, err = writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}
