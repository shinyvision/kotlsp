package resourcebudget

import (
	"context"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
)

const (
	ProcessTreeSoftLimitBytes int64 = 3 << 30
	GoSoftLimitBytes          int64 = 2 << 30
	GoMinimumLimitBytes       int64 = 768 << 20
	// Leave native/metaspace/thread-stack headroom beyond child -Xmx values.
	// Admitting a full two GiB of Java heaps inside a three-GiB process-tree
	// envelope made the arithmetic look safe while real RSS could exceed it.
	ToolProcessLimitBytes int64 = 1792 << 20
	CompilerHostBytes     int64 = 768 << 20
	CompilerOneShotBytes  int64 = 768 << 20
	BuildToolBytes        int64 = 512 << 20
	JDIHelperBytes        int64 = 256 << 20
)

type Component struct {
	Name    string
	Current int64
	Peak    int64
}

type Snapshot struct {
	ProcessTreeSoftLimit int64
	GoSoftLimit          int64
	EffectiveGoSoftLimit int64
	ToolProcessLimit     int64
	ToolCurrent          int64
	ToolPeak             int64
	Components           []Component
}

type componentUsage struct{ current, peak int64 }

var memory = struct {
	sync.Mutex
	changed    chan struct{}
	current    int64
	peak       int64
	components map[string]*componentUsage
}{changed: make(chan struct{}), components: make(map[string]*componentUsage)}

// Acquire reserves a configured child-JVM heap ceiling. Call sites install the
// matching -Xmx limit; this coordinator prevents those hard per-child maxima
// from being admitted concurrently beyond the envelope and lowers Go's real
// runtime memory limit while the reservation is live. It is not an RSS meter,
// and an independently configured debug target is intentionally outside it.
func Acquire(ctx context.Context, component string, bytes int64) (func(), error) {
	if bytes <= 0 {
		return func() {}, nil
	}
	if bytes > ToolProcessLimitBytes {
		return nil, fmt.Errorf("resource reservation %d exceeds the %d-byte tool-process envelope", bytes, ToolProcessLimitBytes)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		memory.Lock()
		if memory.current+bytes <= ToolProcessLimitBytes {
			memory.current += bytes
			applyGoLimitLocked()
			if memory.current > memory.peak {
				memory.peak = memory.current
			}
			usage := memory.components[component]
			if usage == nil {
				usage = &componentUsage{}
				memory.components[component] = usage
			}
			usage.current += bytes
			if usage.current > usage.peak {
				usage.peak = usage.current
			}
			memory.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					memory.Lock()
					memory.current -= bytes
					usage.current -= bytes
					applyGoLimitLocked()
					close(memory.changed)
					memory.changed = make(chan struct{})
					memory.Unlock()
				})
			}, nil
		}
		changed := memory.changed
		memory.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func Current() Snapshot {
	memory.Lock()
	defer memory.Unlock()
	snapshot := Snapshot{
		ProcessTreeSoftLimit: ProcessTreeSoftLimitBytes,
		GoSoftLimit:          GoSoftLimitBytes, EffectiveGoSoftLimit: effectiveGoLimitLocked(),
		ToolProcessLimit: ToolProcessLimitBytes, ToolCurrent: memory.current, ToolPeak: memory.peak,
	}
	for name, usage := range memory.components {
		snapshot.Components = append(snapshot.Components, Component{Name: name, Current: usage.current, Peak: usage.peak})
	}
	sort.Slice(snapshot.Components, func(left, right int) bool { return snapshot.Components[left].Name < snapshot.Components[right].Name })
	return snapshot
}

func effectiveGoLimitLocked() int64 {
	limit := ProcessTreeSoftLimitBytes - memory.current
	if limit > GoSoftLimitBytes {
		limit = GoSoftLimitBytes
	}
	if limit < GoMinimumLimitBytes {
		limit = GoMinimumLimitBytes
	}
	return limit
}

func applyGoLimitLocked() {
	debug.SetMemoryLimit(effectiveGoLimitLocked())
}
