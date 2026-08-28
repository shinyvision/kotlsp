package jsonrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type echoHandler struct{}

func (echoHandler) Request(_ context.Context, method string, params json.RawMessage) (any, *ResponseError) {
	return map[string]any{"method": method, "params": json.RawMessage(params)}, nil
}

type blockingNotificationHandler struct {
	started        chan struct{}
	release        chan struct{}
	requestStarted chan struct{}
}

func (h *blockingNotificationHandler) Request(_ context.Context, method string, _ json.RawMessage) (any, *ResponseError) {
	if h.requestStarted != nil {
		close(h.requestStarted)
	}
	return map[string]any{"method": method}, nil
}

func (h *blockingNotificationHandler) Notify(context.Context, string, json.RawMessage) {
	close(h.started)
	<-h.release
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

func TestEOFCancelsInboundHandlerWaitingOnClientRequest(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":8,"method":"block","params":{}}`
	input := bytes.NewBufferString("Content-Length: " + itoa(len(request)) + "\r\n\r\n" + request)
	var output bytes.Buffer
	handler := &pendingClientRequestHandler{started: make(chan struct{})}
	conn := NewConn(input, &output, handler)
	handler.conn = conn
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF did not release a handler waiting on a client response")
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

func TestReadRejectsOversizedFrameBeforeAllocatingBody(t *testing.T) {
	input := bytes.NewBufferString("Content-Length: " + itoa(maxMessageBytes+1) + "\r\n\r\n")
	conn := NewConn(input, io.Discard, echoHandler{})
	if _, err := conn.read(); err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("oversized frame error = %v", err)
	}
}

func TestReadRejectsOversizedHeaderLine(t *testing.T) {
	input := bytes.NewBufferString("X-Fill: " + strings.Repeat("x", maxHeaderLineBytes) + "\r\n\r\n")
	conn := NewConn(input, io.Discard, echoHandler{})
	if _, err := conn.read(); err == nil || !strings.Contains(err.Error(), "header line") {
		t.Fatalf("oversized header error = %v", err)
	}
}

func TestReadDistinguishesInvalidMessageShapeFromInvalidJSON(t *testing.T) {
	for _, fixture := range []struct {
		label string
		body  string
	}{
		{"scalar params", `{"jsonrpc":"2.0","id":1,"method":"echo","params":7}`},
		{"scalar error object", `{"jsonrpc":"2.0","id":1,"error":"failure"}`},
	} {
		input := bytes.NewBufferString("Content-Length: " + itoa(len(fixture.body)) + "\r\n\r\n" + fixture.body)
		_, err := NewConn(input, io.Discard, echoHandler{}).read()
		var recoverable *recoverableReadError
		if !errors.As(err, &recoverable) || recoverable.code != InvalidRequest {
			t.Fatalf("%s: error = %#v, want invalid request", fixture.label, err)
		}
	}
}

func TestMalformedJSONGetsParseErrorAndConnectionContinues(t *testing.T) {
	malformed := `{"jsonrpc":"2.0",`
	valid := `{"jsonrpc":"2.0","id":12,"method":"echo","params":{}}`
	frame := func(body string) string { return "Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body }
	var output bytes.Buffer
	conn := NewConn(bytes.NewBufferString(frame(malformed)+frame(valid)), &output, echoHandler{})
	if err := conn.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	bodies := readFramedBodies(t, output.Bytes())
	if len(bodies) != 2 {
		t.Fatalf("responses = %d, want parse error plus valid response", len(bodies))
	}
	var first, second map[string]any
	if json.Unmarshal(bodies[0], &first) != nil || json.Unmarshal(bodies[1], &second) != nil {
		t.Fatalf("invalid response JSON: %q %q", bodies[0], bodies[1])
	}
	errorObject, _ := first["error"].(map[string]any)
	if errorObject["code"] != float64(ParseError) || second["id"] != float64(12) {
		t.Fatalf("responses = %#v %#v", first, second)
	}
}

func readFramedBodies(t *testing.T, data []byte) [][]byte {
	t.Helper()
	reader := bufio.NewReader(bytes.NewReader(data))
	var bodies [][]byte
	for {
		header, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			return bodies
		}
		if err != nil {
			t.Fatal(err)
		}
		length, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "Content-Length: ")))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
}

func TestSlowNotificationDoesNotBlockReadingLaterCancellation(t *testing.T) {
	notification := "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/didChange\",\"params\":{}}"
	request := "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"hover\",\"params\":{}}"
	cancelRequest := "{\"jsonrpc\":\"2.0\",\"method\":\"$/cancelRequest\",\"params\":{\"id\":9}}"
	frame := func(body string) string {
		return "Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	}
	inputReader, inputWriter := io.Pipe()
	outputReader, outputWriter := io.Pipe()
	defer outputReader.Close()
	handler := &blockingNotificationHandler{started: make(chan struct{}), release: make(chan struct{})}
	conn := NewConn(inputReader, outputWriter, handler)
	done := make(chan error, 1)
	go func() {
		done <- conn.Run(context.Background())
		_ = outputWriter.Close()
	}()
	go func() {
		_, _ = io.WriteString(inputWriter, frame(notification)+frame(request)+frame(cancelRequest))
	}()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("notification did not start")
	}
	response := make(chan []byte, 1)
	responseErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(outputReader)
		header, err := reader.ReadString('\n')
		if err == nil && !strings.HasPrefix(header, "Content-Length: ") {
			err = errors.New("missing response Content-Length")
		}
		length := 0
		if err == nil {
			length, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "Content-Length: ")))
		}
		if err == nil {
			_, err = reader.ReadString('\n')
		}
		if err == nil {
			body := make([]byte, length)
			_, err = io.ReadFull(reader, body)
			if err == nil {
				response <- body
				return
			}
		}
		responseErr <- err
	}()
	select {
	case body := <-response:
		var decoded struct {
			Error *ResponseError `json:"error"`
		}
		if json.Unmarshal(body, &decoded) != nil || decoded.Error == nil || decoded.Error.Code != RequestCanceled {
			t.Fatalf("cancel response = %s", body)
		}
	case err := <-responseErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("cancellation remained unread behind slow notification")
	}
	close(handler.release)
	_ = inputWriter.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection did not finish after notification release")
	}
}

func TestRequestWaitsForEarlierStateNotification(t *testing.T) {
	notification := "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/didChange\",\"params\":{}}"
	request := "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"hover\",\"params\":{}}"
	frame := func(body string) string {
		return "Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	}
	inputReader, inputWriter := io.Pipe()
	var output bytes.Buffer
	handler := &blockingNotificationHandler{started: make(chan struct{}), release: make(chan struct{}), requestStarted: make(chan struct{})}
	conn := NewConn(inputReader, &output, handler)
	done := make(chan error, 1)
	go func() { done <- conn.Run(context.Background()) }()
	go func() { _, _ = io.WriteString(inputWriter, frame(notification)+frame(request)) }()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("notification did not start")
	}
	select {
	case <-handler.requestStarted:
		t.Fatal("request overtook the preceding document notification")
	case <-time.After(20 * time.Millisecond):
	}
	close(handler.release)
	select {
	case <-handler.requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not start after the preceding notification completed")
	}
	_ = inputWriter.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection did not finish")
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
