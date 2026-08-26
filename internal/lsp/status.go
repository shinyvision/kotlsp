package lsp

import (
	"time"

	"github.com/shinyvision/kotlsp/internal/jsonrpc"

	"github.com/shinyvision/kotlsp/internal/index"
)

// serverStatus answers kotlsp/status: what indexing and background validation
// are doing right now, and how long the last pass took. A validation pass is
// measured in seconds even when warm, so an editor needs a way to say whether
// the server is busy or idle rather than leaving the author guessing.
func (s *Server) serverStatus() (any, *jsonrpc.ResponseError) {
	progress := s.indexProgressNow()
	passes := make([]map[string]any, 0, 2)
	for _, status := range s.index.CompilerStatus() {
		entry := map[string]any{
			"language": status.Language,
			"passes":   status.Passes,
			"running":  status.Running,
			"hosted":   status.Hosted,
		}
		if status.LastDuration > 0 {
			entry["lastDurationMs"] = status.LastDuration.Milliseconds()
		}
		if !status.LastFinished.IsZero() {
			entry["finishedSecondsAgo"] = int64(time.Since(status.LastFinished).Seconds())
		}
		passes = append(passes, entry)
	}
	return map[string]any{
		"indexing": map[string]any{
			"ready":           progress.Ready,
			"filesParsed":     progress.FilesParsed,
			"filesTotal":      progress.FilesTotal,
			"librariesParsed": progress.LibrariesParsed,
			"librariesTotal":  progress.LibrariesTotal,
		},
		"validation":         passes,
		"diagnosticsTrigger": s.diagnosticsTriggerName(),
	}, nil
}

func (s *Server) diagnosticsTriggerName() string {
	if s.index.CompilerTrigger() == index.CompilerOnSave {
		return "save"
	}
	return "change"
}
