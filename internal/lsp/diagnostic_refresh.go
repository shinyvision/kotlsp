package lsp

import (
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
	if !s.diagnosticRefreshActive.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.diagnosticRefreshActive.Store(false)
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
				s.refreshDiagnostics()
				return
			}
		}
	}()
}

func (s *Server) refreshDiagnostics() {
	if s.clientCapabilityBool("workspace", "diagnostics", "refreshSupport") {
		if err := s.callClient(s.ctx, "workspace/diagnostic/refresh", nil, nil); err != nil && s.ctx.Err() == nil {
			s.log.Printf("diagnostic refresh: %v", err)
		}
	}
	// A pull client has just been told to re-request, and never receives pushed
	// diagnostics anyway.
	if s.clientCapabilityPresent("textDocument", "diagnostic") {
		return
	}
	for _, uri := range s.index.OpenDocuments() {
		s.publishDiagnostics(uri, s.index.Diagnostics(uri))
	}
}
