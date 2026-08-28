package jsonrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
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

	// LSP messages are editor control traffic, not a bulk-transfer channel.
	// Bound frames before allocation; DAP applies the same ceiling.
	maxMessageBytes    = 16 << 20
	maxHeaderLineBytes = 8 << 10

	maxConcurrentInboundRequests = 16
	maxQueuedInboundRequests     = 256
	maxQueuedNotifications       = 1024
	maxQueuedNotificationBytes   = 64 << 20
	maxInboundRequestBytes       = 128 << 20
	maxOutgoingMessageBytes      = 64 << 20
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

type recoverableReadError struct {
	code    int
	message string
}

func (e *recoverableReadError) Error() string { return e.message }

func (e *ResponseError) Error() string { return e.Message }

type Handler interface {
	Request(context.Context, string, json.RawMessage) (any, *ResponseError)
	Notify(context.Context, string, json.RawMessage)
}

type inboundRequest struct {
	message            Message
	ctx                context.Context
	cancel             context.CancelFunc
	key                string
	afterNotifications <-chan struct{}
}

type queuedNotification struct {
	message Message
	done    chan struct{}
}

// notificationQueue preserves LSP notification ordering without executing
// didOpen/didChange on the frame-reader goroutine. It is bounded so a peer
// cannot trade the old head-of-line stall for unbounded queued memory.
type notificationQueue struct {
	mu       sync.Mutex
	ready    *sync.Cond
	messages []queuedNotification
	bytes    int
	closed   bool
}

func newNotificationQueue() *notificationQueue {
	queue := &notificationQueue{}
	queue.ready = sync.NewCond(&queue.mu)
	return queue
}

func (q *notificationQueue) push(message Message) (<-chan struct{}, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cost := messageMemoryBytes(message)
	if q.closed || len(q.messages) >= maxQueuedNotifications || cost > maxQueuedNotificationBytes-q.bytes {
		return nil, false
	}
	done := make(chan struct{})
	q.messages = append(q.messages, queuedNotification{message: message, done: done})
	q.bytes += cost
	q.ready.Signal()
	return done, true
}

func (q *notificationQueue) pop() (queuedNotification, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.messages) == 0 && !q.closed {
		q.ready.Wait()
	}
	if len(q.messages) == 0 {
		return queuedNotification{}, false
	}
	notification := q.messages[0]
	q.messages[0] = queuedNotification{}
	q.messages = q.messages[1:]
	q.bytes -= messageMemoryBytes(notification.message)
	return notification, true
}

func (q *notificationQueue) close(drop bool) {
	q.mu.Lock()
	q.closed = true
	if drop {
		for _, notification := range q.messages {
			close(notification.done)
		}
		q.messages = nil
		q.bytes = 0
	}
	q.ready.Broadcast()
	q.mu.Unlock()
}

func messageMemoryBytes(message Message) int {
	return len(message.JSONRPC) + len(message.ID) + len(message.Method) + len(message.Params) + len(message.Result) + 128
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
	peerGone  chan struct{}
	peerOnce  sync.Once
}

func NewConn(r io.Reader, w io.Writer, handler Handler) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, maxHeaderLineBytes+1), reader: r, w: w, handler: handler, cancels: make(map[string]context.CancelFunc), pending: make(map[string]chan Message), stop: make(chan struct{}), peerGone: make(chan struct{})}
}

func (c *Conn) markPeerGone() { c.peerOnce.Do(func() { close(c.peerGone) }) }

// Stop terminates Run even when the peer keeps the input stream open after an
// LSP `exit` notification.
func (c *Conn) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.markPeerGone()
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
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	notifications := newNotificationQueue()
	var notificationWorker sync.WaitGroup
	notificationWorker.Add(1)
	go func() {
		defer notificationWorker.Done()
		for {
			notification, ok := notifications.pop()
			if !ok {
				return
			}
			if runCtx.Err() != nil {
				close(notification.done)
				return
			}
			invokeNotification(c.handler, runCtx, notification.message.Method, notification.message.Params)
			close(notification.done)
		}
	}()
	initialNotificationBarrier := make(chan struct{})
	close(initialNotificationBarrier)
	var notificationBarrier <-chan struct{} = initialNotificationBarrier

	requestJobs := make(chan inboundRequest, maxQueuedInboundRequests)
	var inboundBytesMu sync.Mutex
	inboundBytes := 0
	reserveInbound := func(bytes int) bool {
		inboundBytesMu.Lock()
		defer inboundBytesMu.Unlock()
		if bytes > maxInboundRequestBytes-inboundBytes {
			return false
		}
		inboundBytes += bytes
		return true
	}
	releaseInbound := func(bytes int) {
		inboundBytesMu.Lock()
		inboundBytes -= bytes
		inboundBytesMu.Unlock()
	}
	var requestWorkers sync.WaitGroup
	requestWorkers.Add(maxConcurrentInboundRequests)
	for range maxConcurrentInboundRequests {
		go func() {
			defer requestWorkers.Done()
			for request := range requestJobs {
				requestBytes := messageMemoryBytes(request.message)
				var result any
				var responseErr *ResponseError
				select {
				case <-request.afterNotifications:
					if request.ctx.Err() == nil {
						result, responseErr = invokeRequest(c.handler, request.ctx, request.message.Method, request.message.Params)
					}
				case <-request.ctx.Done():
				}
				if request.ctx.Err() != nil && responseErr == nil {
					responseErr = &ResponseError{Code: RequestCanceled, Message: "request cancelled"}
				}
				_ = c.respond(request.message.ID, result, responseErr)
				request.cancel()
				c.cancelMu.Lock()
				delete(c.cancels, request.key)
				c.cancelMu.Unlock()
				releaseInbound(requestBytes)
			}
		}()
	}

	finish := func(dropNotifications bool) {
		if dropNotifications {
			cancelRun()
		}
		notifications.close(dropNotifications)
		close(requestJobs)
		notificationWorker.Wait()
		requestWorkers.Wait()
		cancelRun()
	}
	for {
		msg, err := c.read()
		if err != nil {
			var recoverable *recoverableReadError
			if errors.As(err, &recoverable) {
				_ = c.respond(nil, nil, &ResponseError{Code: recoverable.code, Message: recoverable.message})
				continue
			}
			select {
			case <-c.stop:
				finish(true)
				return nil
			default:
			}
			if errors.Is(err, io.EOF) {
				// No new frames can arrive, but every already accepted inbound
				// request still deserves its response. Mark the peer unavailable so
				// a handler attempting a server-to-client request is released, then
				// drain accepted notifications/requests without canceling ordinary
				// handler contexts.
				c.markPeerGone()
				finish(false)
				return nil
			}
			finish(true)
			return err
		}
		if msg.Method == "$/cancelRequest" && len(msg.ID) == 0 {
			var p struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(msg.Params, &p) == nil {
				if key, valid := requestIDKey(p.ID); valid {
					c.cancel(key)
				}
			}
			continue
		}
		if msg.Method == "" && len(msg.ID) != 0 {
			key, valid := requestIDKey(msg.ID)
			if !valid {
				continue
			}
			c.pendingMu.Lock()
			waiting := c.pending[key]
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
			barrier, accepted := notifications.push(msg)
			if !accepted {
				finish(true)
				return errors.New("JSON-RPC notification queue is full")
			}
			notificationBarrier = barrier
			if msg.Method == "exit" {
				// The handler stops the connection while processing exit. Wait for
				// that instead of reading again: a blocking stdin read cannot be
				// interrupted, and the peer may keep the stream open.
				<-barrier
				finish(true)
				return nil
			}
			continue
		}
		requestCtx, cancel := context.WithCancel(runCtx)
		key, valid := requestIDKey(msg.ID)
		if !valid {
			cancel()
			_ = c.respond(nil, nil, &ResponseError{Code: InvalidRequest, Message: "request id must be a bounded string or integer"})
			continue
		}
		c.cancelMu.Lock()
		if _, duplicate := c.cancels[key]; duplicate {
			c.cancelMu.Unlock()
			cancel()
			_ = c.respond(msg.ID, nil, &ResponseError{Code: InvalidRequest, Message: "duplicate in-flight request id"})
			continue
		}
		c.cancels[key] = cancel
		c.cancelMu.Unlock()
		request := inboundRequest{message: msg, ctx: requestCtx, cancel: cancel, key: key, afterNotifications: notificationBarrier}
		requestBytes := messageMemoryBytes(msg)
		if !reserveInbound(requestBytes) {
			cancel()
			c.cancelMu.Lock()
			delete(c.cancels, key)
			c.cancelMu.Unlock()
			_ = c.respond(msg.ID, nil, &ResponseError{Code: InternalError, Message: "server request byte budget is full"})
			continue
		}
		select {
		case requestJobs <- request:
		default:
			releaseInbound(requestBytes)
			cancel()
			c.cancelMu.Lock()
			delete(c.cancels, key)
			c.cancelMu.Unlock()
			_ = c.respond(msg.ID, nil, &ResponseError{Code: InternalError, Message: "server request queue is full"})
		}
	}
}

func invokeRequest(handler Handler, ctx context.Context, method string, params json.RawMessage) (result any, responseErr *ResponseError) {
	defer func() {
		if recover() != nil {
			result = nil
			responseErr = &ResponseError{Code: InternalError, Message: "request handler panicked"}
		}
	}()
	return handler.Request(ctx, method, params)
}

func invokeNotification(handler Handler, ctx context.Context, method string, params json.RawMessage) {
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintf(os.Stderr, "kotlsp jsonrpc: notification handler %s panicked: %v\n", method, failure)
		}
	}()
	handler.Notify(ctx, method, params)
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
	requestKey := "n:" + rawID
	waiting := make(chan Message, 1)
	c.pendingMu.Lock()
	if len(c.pending) >= 128 {
		c.pendingMu.Unlock()
		return errors.New("too many pending server-to-client requests")
	}
	c.pending[requestKey] = waiting
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, requestKey)
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
	case <-c.peerGone:
		return io.EOF
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
	if len(body) > maxOutgoingMessageBytes {
		return fmt.Errorf("outgoing JSON-RPC message exceeds its %d-byte safety limit", maxOutgoingMessageBytes)
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
	headerBytes := 0
	for {
		lineBytes, err := c.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || len(lineBytes) > maxHeaderLineBytes {
			return Message{}, errors.New("JSON-RPC header line exceeds size limit")
		}
		if err != nil {
			return Message{}, err
		}
		headerBytes += len(lineBytes)
		if headerBytes > 32<<10 {
			return Message{}, errors.New("JSON-RPC headers exceed aggregate size limit")
		}
		line := string(lineBytes)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			if contentLength >= 0 {
				return Message{}, errors.New("duplicate Content-Length")
			}
			contentLength, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || contentLength < 0 || contentLength > maxMessageBytes {
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
	if !json.Valid(body) {
		return Message{}, &recoverableReadError{code: ParseError, message: "invalid JSON-RPC JSON"}
	}
	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return Message{}, &recoverableReadError{code: InvalidRequest, message: "invalid JSON-RPC message shape"}
	}
	if msg.JSONRPC != "2.0" {
		return Message{}, &recoverableReadError{code: InvalidRequest, message: "unsupported JSON-RPC version"}
	}
	if msg.Method != "" {
		if len(msg.Method) > 4096 || strings.IndexByte(msg.Method, 0) >= 0 {
			return Message{}, &recoverableReadError{code: InvalidRequest, message: "JSON-RPC method exceeds its size or NUL-safety limit"}
		}
		if len(msg.Result) != 0 || msg.Error != nil {
			return Message{}, &recoverableReadError{code: InvalidRequest, message: "JSON-RPC request contains response fields"}
		}
		if !validParamsShape(msg.Params) {
			return Message{}, &recoverableReadError{code: InvalidRequest, message: "JSON-RPC params must be an object or array"}
		}
	} else if len(msg.ID) != 0 {
		if len(msg.Result) == 0 && msg.Error == nil || len(msg.Result) != 0 && msg.Error != nil {
			return Message{}, &recoverableReadError{code: InvalidRequest, message: "JSON-RPC response must contain exactly one result or error"}
		}
	}
	if msg.Method == "" && len(msg.ID) == 0 {
		return Message{}, &recoverableReadError{code: InvalidRequest, message: "JSON-RPC message has neither method nor response id"}
	}
	return msg, nil
}

func validParamsShape(params json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(params))
	return trimmed == "" || trimmed[0] == '{' || trimmed[0] == '['
}

func validRequestID(id json.RawMessage) bool {
	_, valid := requestIDKey(id)
	return valid
}

func requestIDKey(id json.RawMessage) (string, bool) {
	if len(id) == 0 || len(id) > 256 {
		return "", false
	}
	decoder := json.NewDecoder(strings.NewReader(string(id)))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return "", false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		if len(typed) > 256 || strings.IndexByte(typed, 0) >= 0 {
			return "", false
		}
		return "s:" + typed, true
	case json.Number:
		integer, ok := new(big.Int).SetString(string(typed), 10)
		if !ok {
			// Fractional and exponent IDs have ambiguous equality across JSON
			// implementations. JSON-RPC discourages them, so reject them at the
			// boundary instead of letting 1 and 1.0 become concurrent requests.
			return "", false
		}
		return "n:" + integer.String(), true
	default:
		return "", false
	}
}

func (c *Conn) cancel(id string) {
	c.cancelMu.Lock()
	cancel := c.cancels[id]
	c.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}
