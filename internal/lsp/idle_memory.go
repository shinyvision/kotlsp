package lsp

import (
	"runtime"
	"runtime/debug"
	"time"
)

// A burst of work (a first references query, a build touching hundreds of
// files) leaves the Go runtime holding far more memory than the index needs:
// freed pages are returned to the OS lazily, so the process sat at several
// gigabytes long after the work was done. Once the server has been idle for a
// while, hand them back.
const (
	minimumReleasableBytes = 256 << 20
	idleReleaseAfter       = 30 * time.Second
	idleReleaseCheck       = 10 * time.Second
)

func (s *Server) noteActivity() {
	s.lastActivity.Store(time.Now().UnixNano())
	s.memoryReleased.Store(false)
}

func (s *Server) releaseMemoryWhenIdle() {
	ticker := time.NewTicker(idleReleaseCheck)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		last := s.lastActivity.Load()
		if last == 0 || s.memoryReleased.Load() || time.Since(time.Unix(0, last)) < idleReleaseAfter {
			continue
		}
		// While indexing, the heap is growing on purpose.
		if !s.index.Progress().Ready {
			continue
		}
		// Returning pages forces a full collection and makes the next burst of
		// work fault them back in, so only do it when there is a meaningful amount
		// of heap that is free but still held.
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		if stats.HeapIdle-stats.HeapReleased >= minimumReleasableBytes {
			debug.FreeOSMemory()
		}
		s.memoryReleased.Store(true)
	}
}
