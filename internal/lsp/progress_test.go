package lsp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
)

func waitFor(condition func() bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// recordingConn captures the notifications the server would put on the wire.
type recordingConn struct {
	mu       sync.Mutex
	notified []map[string]any
}

func (r *recordingConn) record(method string, params any) {
	encoded, err := json.Marshal(params)
	if err != nil {
		return
	}
	var decoded map[string]any
	if json.Unmarshal(encoded, &decoded) != nil {
		return
	}
	decoded["__method"] = method
	r.mu.Lock()
	r.notified = append(r.notified, decoded)
	r.mu.Unlock()
}

func (r *recordingConn) snapshot() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.notified...)
}

// A client that never sees the warm-up cannot tell an indexing server from a
// broken one, so the stream must be created and then closed exactly once.
func TestIndexingProgressIsCreatedThenEnded(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	recorder := &recordingConn{}
	created := make(chan string, 1)
	s.clientCall = func(_ context.Context, method string, params, _ any) error {
		if method == "window/workDoneProgress/create" {
			encoded, _ := json.Marshal(params)
			var payload struct {
				Token string `json:"token"`
			}
			_ = json.Unmarshal(encoded, &payload)
			select {
			case created <- payload.Token:
			default:
			}
		}
		return nil
	}
	s.notify = recorder.record
	s.rootMu.Lock()
	s.clientCaps = map[string]any{"window": map[string]any{"workDoneProgress": true}}
	s.rootMu.Unlock()

	var ready atomic.Bool
	s.progressSource = func() index.Progress {
		return index.Progress{FilesParsed: 40, FilesTotal: 100, LibrariesParsed: 10, LibrariesTotal: 100, Ready: ready.Load()}
	}

	s.reportIndexingProgress()
	var token string
	select {
	case token = <-created:
	case <-time.After(5 * time.Second):
		t.Fatal("server never asked the client to create a progress token")
	}
	if token == "" {
		t.Fatal("progress token is empty")
	}

	// The warm-up must be visible while it lasts...
	if !waitFor(func() bool {
		kinds := progressKinds(recorder.snapshot(), token)
		return len(kinds) >= 2 && kinds[0] == "begin" && kinds[1] == "report"
	}) {
		t.Fatalf("progress stream did not begin and report: %v", progressKinds(recorder.snapshot(), token))
	}
	// ...and must get out of the way once the index is ready.
	ready.Store(true)
	if !waitFor(func() bool {
		kinds := progressKinds(recorder.snapshot(), token)
		return len(kinds) > 0 && kinds[len(kinds)-1] == "end"
	}) {
		t.Fatalf("progress stream never ended: %v", progressKinds(recorder.snapshot(), token))
	}
	settled := progressKinds(recorder.snapshot(), token)
	time.Sleep(3 * progressInterval)
	if final := progressKinds(recorder.snapshot(), token); len(final) != len(settled) {
		t.Fatalf("stream kept reporting after it ended: %v", final)
	}
}

// Without client support the server must stay silent rather than report against
// a token the client never created.
func TestIndexingProgressIsSkippedWithoutClientSupport(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	recorder := &recordingConn{}
	calls := 0
	s.clientCall = func(context.Context, string, any, any) error { calls++; return nil }
	s.notify = recorder.record
	s.reportIndexingProgress()
	time.Sleep(300 * time.Millisecond)
	if calls != 0 || len(recorder.snapshot()) != 0 {
		t.Fatalf("server reported progress to a client that never advertised support: %d calls, %d notifications", calls, len(recorder.snapshot()))
	}
}

func progressKinds(notifications []map[string]any, token string) []string {
	kinds := make([]string, 0, len(notifications))
	for _, notification := range notifications {
		if notification["__method"] != "$/progress" || notification["token"] != token {
			continue
		}
		value, ok := notification["value"].(map[string]any)
		if !ok {
			continue
		}
		kind, _ := value["kind"].(string)
		kinds = append(kinds, kind)
	}
	return kinds
}
