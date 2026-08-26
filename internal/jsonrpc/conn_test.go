package jsonrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type echoHandler struct{}

func (echoHandler) Request(_ context.Context, method string, params json.RawMessage) (any, *ResponseError) {
	return map[string]any{"method": method, "params": json.RawMessage(params)}, nil
}

type pendingClientRequestHandler struct {
	conn    *Conn
	started chan struct{}
	once    sync.Once
}

func (h *pendingClientRequestHandler) Request(ctx context.Context, _ string, _ json.RawMessage) (any, *ResponseError) {
	h.once.Do(func() { close(h.started) })
	err := h.conn.Request(ctx, "workspace/applyEdit", map[string]any{"edit": map[string]any{}}, nil)
	if err == nil {
		return nil, &ResponseError{Code: InternalError, Message: "client request unexpectedly completed"}
	}
	return nil, nil
}
func (*pendingClientRequestHandler) Notify(context.Context, string, json.RawMessage) {}

func TestStopCancelsInboundHandlerWaitingOnClientRequest(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":7,"method":"block","params":{}}`
	input := bytes.NewBufferString("Content-Length: " + itoa(len(request)) + "\r\n\r\n" + request)
	var output bytes.Buffer
	handler := &pendingClientRequestHandler{started: make(chan struct{})}
	conn := NewConn(input, &output, handler)
	handler.conn = conn
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background()) }()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	conn.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not release a handler waiting on a client response")
	}
}
func (echoHandler) Notify(context.Context, string, json.RawMessage) {}

func TestConnectionFramesRequestAndResponse(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":7,"method":"echo","params":{"ok":true}}`
	input := bytes.NewBufferString("Content-Length: " + itoa(len(request)) + "\r\n\r\n" + request)
	var output bytes.Buffer
	conn := NewConn(input, &output, echoHandler{})
	if err := conn.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&output)
	header, _ := reader.ReadString('\n')
	if !strings.HasPrefix(header, "Content-Length: ") {
		t.Fatalf("bad response header %q", header)
	}
	_, _ = reader.ReadString('\n')
	body, _ := io.ReadAll(reader)
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response["id"] != float64(7) || response["result"] == nil {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	n := len(digits)
	for value > 0 {
		n--
		digits[n] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[n:])
}
