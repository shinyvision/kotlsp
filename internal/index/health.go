package index

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const maxHealthIssues = 128

// HealthIssue is a bounded, aggregate record of a degraded operation. The
// index deliberately keeps serving partial results, but partial must never
// mean invisible: callers can distinguish an empty project from an unreadable
// project and see which fallback produced the current model.
type HealthIssue struct {
	Subsystem   string
	Scope       string
	Message     string
	Occurrences uint64
	LastSeen    time.Time
}

type healthTracker struct {
	mu     sync.RWMutex
	issues map[string]*HealthIssue
}

func (t *healthTracker) record(subsystem, scope, message string) {
	subsystem = boundedStatusText(subsystem, 256)
	scope = boundedStatusText(scope, 4096)
	message = boundedStatusText(message, 4096)
	if subsystem == "" || message == "" {
		return
	}
	key := subsystem + "\x00" + scope + "\x00" + message
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.issues == nil {
		t.issues = make(map[string]*HealthIssue)
	}
	if issue := t.issues[key]; issue != nil {
		issue.Occurrences++
		issue.LastSeen = time.Now()
		return
	}
	if len(t.issues) >= maxHealthIssues {
		oldestKey := ""
		oldest := time.Time{}
		for candidate, issue := range t.issues {
			if oldestKey == "" || issue.LastSeen.Before(oldest) {
				oldestKey, oldest = candidate, issue.LastSeen
			}
		}
		delete(t.issues, oldestKey)
	}
	t.issues[key] = &HealthIssue{
		Subsystem: subsystem, Scope: scope, Message: message,
		Occurrences: 1, LastSeen: time.Now(),
	}
}

func boundedStatusText(value string, limit int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for len(value) > 0 && strings.ToValidUTF8(value, "") != value {
		value = value[:len(value)-1]
	}
	return value + "…"
}

func (t *healthTracker) snapshot() []HealthIssue {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]HealthIssue, 0, len(t.issues))
	for _, issue := range t.issues {
		out = append(out, *issue)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].LastSeen.Equal(out[b].LastSeen) {
			if out[a].Subsystem == out[b].Subsystem {
				return out[a].Scope < out[b].Scope
			}
			return out[a].Subsystem < out[b].Subsystem
		}
		return out[a].LastSeen.After(out[b].LastSeen)
	})
	return out
}

func (i *Index) recordHealth(subsystem, scope, message string) {
	i.health.record(subsystem, scope, message)
}

// Health returns recent degraded operations in newest-first order.
func (i *Index) Health() []HealthIssue { return i.health.snapshot() }
