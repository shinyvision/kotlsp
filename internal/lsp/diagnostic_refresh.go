package lsp

import (
	"context"
	"time"
)

// Diagnostics computed while the workspace was still being indexed describe an
// index that did not yet contain the Kotlin standard library or any dependency.
// Every name that resolves through one of those was reported unresolved, and
// nothing recomputed it once indexing finished: a pulled report is only
// recomputed when the client asks again, and a pushed one is a snapshot of the
// parse that produced it.
//
// Once the index is ready the stale answers are therefore withdrawn: pull
// clients are asked to re-request, and push clients are sent a recomputed set
// for every document they have open.
const diagnosticRefreshPoll = 250 * time.Millisecond

func (s *Server) refreshDiagnosticsWhenIndexed() {
	if !s.diagnosticIndexWait.CompareAndSwap(false, true) {
		return
	}
	if !s.launchBackground(func() {
		defer s.diagnosticIndexWait.Store(false)
		ticker := time.NewTicker(diagnosticRefreshPoll)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if s.shutdown.Load() {
					return
				}
				if !s.indexProgressNow().Ready {
					continue
				}
				s.queueDiagnosticRefresh()
				return
			}
		}
	}) {
		s.diagnosticIndexWait.Store(false)
	}
}

// queueDiagnosticRefresh coalesces compiler/index changes and keeps a client
// which never answers workspace/diagnostic/refresh from retaining one goroutine
// per validation pass. A change arriving during an active refresh sets pending
// and causes exactly one further refresh after the current bounded call.
func (s *Server) queueDiagnosticRefresh() {
	s.diagnosticRefreshPending.Store(true)
	if !s.diagnosticRefreshActive.CompareAndSwap(false, true) {
		return
	}
	if !s.launchBackground(func() {
		for {
			s.diagnosticRefreshPending.Store(false)
			s.refreshDiagnostics()
			if s.diagnosticRefreshPending.Load() {
				continue
			}
			s.diagnosticRefreshActive.Store(false)
			// Close the race between observing no pending work and making the
			// runner inactive. A concurrent producer either owns a new runner or
			// leaves pending set for this one to reclaim.
			if !s.diagnosticRefreshPending.Load() || !s.diagnosticRefreshActive.CompareAndSwap(false, true) {
				return
			}
		}
	}) {
		s.diagnosticRefreshActive.Store(false)
	}
}

func (s *Server) refreshDiagnostics() {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	s.refreshDiagnosticsContext(ctx)
}

func (s *Server) refreshDiagnosticsContext(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if s.clientCapabilityBool("workspace", "diagnostics", "refreshSupport") {
		if err := s.callClient(ctx, "workspace/diagnostic/refresh", nil, nil); err != nil && ctx.Err() == nil {
			s.log.Printf("diagnostic refresh: %v", err)
		}
	}
	// A pull client has just been told to re-request, and never receives pushed
	// diagnostics anyway.
	if s.clientCapabilityPresent("textDocument", "diagnostic") {
		return
	}
	for _, uri := range s.index.OpenDocuments() {
		if ctx.Err() != nil {
			return
		}
		s.publishDiagnostics(uri, s.index.Diagnostics(uri))
	}
}
