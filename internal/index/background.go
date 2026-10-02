package index

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
)

// SetLogger directs the index's own reports (recovered panics, mostly) to the
// server log. Without one they go only to the health ring.
func (i *Index) SetLogger(logf func(format string, args ...any)) {
	i.logf.Store(&logf)
}

func (i *Index) logPrintf(format string, args ...any) {
	if logf := i.logf.Load(); logf != nil && *logf != nil {
		(*logf)(format, args...)
	}
}

// lifecycleContext is cancelled when the index closes. Background work that no
// request bounds derives its context from it.
func (i *Index) lifecycleContext() context.Context {
	if i.lifecycleCtx == nil {
		return context.Background()
	}
	return i.lifecycleCtx
}

// recoverBackground is deferred at the top of every goroutine the index
// starts. A panic in background work used to end the process -- the editor
// saw the server vanish mid-keystroke. Now it is logged with its stack and
// recorded as a health issue, and only that unit of work is lost.
func (i *Index) recoverBackground(task string) {
	recovered := recover()
	if recovered == nil {
		return
	}
	stack := string(debug.Stack())
	i.logPrintf("panic in background %s: %v\n%s", task, recovered, stack)
	frames := strings.Split(stack, "\n")
	where := ""
	for n, frame := range frames {
		if strings.Contains(frame, "panic(") && n+3 < len(frames) {
			where = strings.TrimSpace(frames[n+3])
			break
		}
	}
	i.recordHealth("panic", task, fmt.Sprintf("%v at %s", recovered, where))
}

// indexLockGuard tracks whether a function still holds i.mu, so a deferred
// release can undo a lock that a panic left behind. A request handler
// recovers panics; without this, a panic between a manual RLock and its
// RUnlock left a reader registered forever, the next edit's writer blocked
// on it, and every request after that blocked behind the writer.
type indexLockGuard struct {
	i          *Index
	read, held bool
}

func (i *Index) lockGuard() *indexLockGuard { return &indexLockGuard{i: i} }

func (g *indexLockGuard) RLock() {
	g.i.mu.RLock()
	g.read, g.held = true, true
}

func (g *indexLockGuard) RUnlock() {
	g.held = false
	g.i.mu.RUnlock()
}

func (g *indexLockGuard) Lock() {
	g.i.mu.Lock()
	g.read, g.held = false, true
}

func (g *indexLockGuard) Unlock() {
	g.held = false
	g.i.mu.Unlock()
}

func (g *indexLockGuard) release() {
	if !g.held {
		return
	}
	g.held = false
	if g.read {
		g.i.mu.RUnlock()
	} else {
		g.i.mu.Unlock()
	}
}
