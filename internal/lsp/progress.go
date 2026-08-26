package lsp

import (
	"strconv"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
)

type indexProgress = index.Progress

// Everything the server answers reads an immutable snapshot, so a request made
// before the workspace and its dependencies are indexed returns an honest but
// empty result. Without progress reporting that is indistinguishable from a
// broken server. Work-done progress makes the warm-up visible for as long as it
// lasts and then gets out of the way.
const (
	progressToken    = "kotlsp/indexing"
	progressInterval = 200 * time.Millisecond
	// A generation cancelled mid-scan never reaches the ready state, so the
	// stream is bounded rather than reporting against a token forever.
	progressCeiling = 10 * time.Minute
)

// reportIndexingProgress publishes the background index warm-up as one
// work-done progress stream. It is a no-op when the client did not advertise
// support, when indexing is already finished, or when a stream is already live.
func (s *Server) reportIndexingProgress() {
	if s.conn == nil && s.clientCall == nil && s.notify == nil {
		return
	}
	if !s.clientCapabilityBool("window", "workDoneProgress") {
		return
	}
	if !s.progressActive.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.progressActive.Store(false)
		s.streamIndexingProgress()
	}()
}

// indexProgressNow reads the warm-up state the stream reports on.
func (s *Server) indexProgressNow() indexProgress {
	if s.progressSource != nil {
		return s.progressSource()
	}
	return s.index.Progress()
}

func (s *Server) streamIndexingProgress() {
	if s.indexProgressNow().Ready {
		return
	}
	token := progressToken + "/" + strconv.FormatInt(s.progressSequence.Add(1), 36)
	if err := s.callClient(s.ctx, "window/workDoneProgress/create", map[string]any{"token": token}, nil); err != nil {
		// A client that refuses the token cannot render the stream, and
		// reporting against an uncreated token is a protocol violation.
		s.log.Printf("work done progress create: %v", err)
		return
	}
	s.notifyProgress(token, map[string]any{"kind": "begin", "title": "Indexing", "message": "scanning workspace", "cancellable": false, "percentage": 0})
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	ceiling := time.NewTimer(progressCeiling)
	defer ceiling.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.notifyProgress(token, map[string]any{"kind": "end"})
			return
		case <-ceiling.C:
			s.notifyProgress(token, map[string]any{"kind": "end", "message": indexingSummary(s.indexProgressNow())})
			return
		case <-ticker.C:
			progress := s.indexProgressNow()
			if progress.Ready || s.shutdown.Load() {
				s.notifyProgress(token, map[string]any{"kind": "end", "message": indexingSummary(progress)})
				return
			}
			s.notifyProgress(token, map[string]any{"kind": "report", "message": indexingSummary(progress), "percentage": indexingPercentage(progress)})
		}
	}
}

func (s *Server) notifyProgress(token string, value map[string]any) {
	params := map[string]any{"token": token, "value": value}
	if s.notify != nil {
		s.notify("$/progress", params)
		return
	}
	if s.conn == nil {
		return
	}
	_ = s.conn.Notify("$/progress", params)
}

func indexingSummary(progress indexProgress) string {
	sources := strconv.FormatInt(progress.FilesParsed, 10)
	if progress.FilesTotal > 0 {
		sources += "/" + strconv.FormatInt(progress.FilesTotal, 10)
	}
	libraries := strconv.FormatInt(progress.LibrariesParsed, 10)
	if progress.LibrariesTotal > 0 {
		libraries += "/" + strconv.FormatInt(progress.LibrariesTotal, 10)
	}
	return sources + " sources, " + libraries + " library files"
}

// indexingPercentage keeps the reported fraction monotonic in the common case
// by weighting both queues together. Totals grow while dependencies are still
// being discovered, so a per-queue percentage would visibly run backwards.
func indexingPercentage(progress indexProgress) uint32 {
	total := progress.FilesTotal + progress.LibrariesTotal
	if total <= 0 {
		return 0
	}
	done := progress.FilesParsed + progress.LibrariesParsed
	if done >= total {
		return 99
	}
	percent := done * 100 / total
	if percent > 99 {
		percent = 99
	}
	return uint32(percent)
}
