package jsonrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ParseError      = -32700
	InvalidRequest  = -32600
	MethodNotFound  = -32601
	InvalidParams   = -32602
	InternalError   = -32603
	RequestCanceled = -32800
	// ServerNotInitialized is defined by LSP rather than base JSON-RPC.
	ServerNotInitialized = -32002
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *ResponseError) Error() string { return e.Message }

type Handler interface {
	Request(context.Context, string, json.RawMessage) (any, *ResponseError)
	Notify(context.Context, string, json.RawMessage)
}

type Conn struct {
	r         *bufio.Reader
	reader    io.Reader
	w         io.Writer
	mu        sync.Mutex
	cancelMu  sync.Mutex
	cancels   map[string]context.CancelFunc
	handler   Handler
	nextID    atomic.Int64
	pendingMu sync.Mutex
	pending   map[string]chan Message
	stop      chan struct{}
	stopOnce  sync.Once
}

func NewConn(r io.Reader, w io.Writer, handler Handler) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 64<<10), reader: r, w: w, handler: handler, cancels: make(map[string]context.CancelFunc), pending: make(map[string]chan Message), stop: make(chan struct{})}
}

// Stop terminates Run even when the peer keeps the input stream open after an
// LSP `exit` notification.
func (c *Conn) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		// Inbound handlers may be waiting on server-to-client requests. Cancel
		// every request context before Run waits for those goroutines, otherwise
		// an LSP exit can deadlock forever on an unanswered client response.
		c.cancelMu.Lock()
		for _, cancel := range c.cancels {
			cancel()
		}
		c.cancelMu.Unlock()
		if closer, ok := c.reader.(io.Closer); ok {
			_ = closer.Close()
		}
	})
}

func (c *Conn) Run(ctx context.Context) error {
	var requests sync.WaitGroup
	for {
		msg, err := c.read()
		if err != nil {
			select {
			case <-c.stop:
				requests.Wait()
				return nil
			default:
			}
			if errors.Is(err, io.EOF) {
				requests.Wait()
				return nil
			}
			return err
		}
		if msg.Method == "$/cancelRequest" {
			var p struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(msg.Params, &p) == nil {
				c.cancel(string(p.ID))
			}
			continue
		}
		if msg.Method == "" && len(msg.ID) != 0 {
			c.pendingMu.Lock()
			waiting := c.pending[string(msg.ID)]
			c.pendingMu.Unlock()
			if waiting != nil {
				select {
				case waiting <- msg:
				default:
				}
			}
			continue
		}
		if len(msg.ID) == 0 {
			c.handler.Notify(ctx, msg.Method, msg.Params)
			select {
			case <-c.stop:
				requests.Wait()
				return nil
			default:
			}
			continue
		}
		requestCtx, cancel := context.WithCancel(ctx)
		key := string(msg.ID)
		c.cancelMu.Lock()
		c.cancels[key] = cancel
		c.cancelMu.Unlock()
		requests.Add(1)
		go func(m Message) {
			defer requests.Done()
			defer func() {
				cancel()
				c.cancelMu.Lock()
				delete(c.cancels, key)
				c.cancelMu.Unlock()
			}()
			result, responseErr := c.handler.Request(requestCtx, m.Method, m.Params)
			if requestCtx.Err() != nil && responseErr == nil {
				responseErr = &ResponseError{Code: RequestCanceled, Message: "request cancelled"}
			}
			_ = c.respond(m.ID, result, responseErr)
		}(msg)
	}
}

func (c *Conn) Notify(method string, params any) error {
	return c.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// Request sends a server-to-client JSON-RPC request while Run continues
// reading the shared stream. Context cancellation removes the pending entry so
// late client replies are safely ignored.
func (c *Conn) Request(ctx context.Context, method string, params any, result any) error {
	id := c.nextID.Add(1)
	rawID := strconv.FormatInt(id, 10)
	waiting := make(chan Message, 1)
	c.pendingMu.Lock()
	c.pending[rawID] = waiting
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, rawID)
		c.pendingMu.Unlock()
	}()
	if err := c.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stop:
		return context.Canceled
	case response := <-waiting:
		if response.Error != nil {
			return response.Error
		}
		if result != nil && len(response.Result) != 0 && string(response.Result) != "null" {
			if err := json.Unmarshal(response.Result, result); err != nil {
				return fmt.Errorf("decode client response: %w", err)
			}
		}
		return nil
	}
}

func (c *Conn) respond(id json.RawMessage, result any, responseErr *ResponseError) error {
	response := map[string]any{"jsonrpc": "2.0", "id": id}
	if responseErr != nil {
		response["error"] = responseErr
	} else {
		response["result"] = result
	}
	return c.write(response)
}

func (c *Conn) write(v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err = fmt.Fprintf(c.w, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err = c.w.Write(body)
	return err
}

func (c *Conn) read() (Message, error) {
	contentLength := -1
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return Message{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			contentLength, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || contentLength < 0 {
				return Message{}, errors.New("invalid Content-Length")
			}
		}
	}
	if contentLength < 0 {
		return Message{}, errors.New("missing Content-Length")
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return Message{}, fmt.Errorf("decode JSON-RPC: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return Message{}, errors.New("unsupported JSON-RPC version")
	}
	return msg, nil
}

func (c *Conn) cancel(id string) {
	c.cancelMu.Lock()
	cancel := c.cancels[id]
	c.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}
