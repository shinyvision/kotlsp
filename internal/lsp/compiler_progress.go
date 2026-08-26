package lsp

import (
	"strconv"
	"strings"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
)

// A validation pass takes long enough to notice. Reporting it turns a silent
// wait into a visible one, which is the difference between a server that looks
// slow and a server that looks broken.
const (
	compilerProgressToken = "kotlsp/validating"
	compilerProgressPoll  = 150 * time.Millisecond
	// A pass shorter than this finishes before a reader could register it, and
	// announcing it would only make the status line flicker.
	compilerProgressFloor = 400 * time.Millisecond
)

// watchCompilerProgress reports background validation for as long as it runs.
func (s *Server) watchCompilerProgress() {
	if !s.clientCapabilityBool("window", "workDoneProgress") {
		return
	}
	if !s.compilerProgressActive.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.compilerProgressActive.Store(false)
		ticker := time.NewTicker(compilerProgressPoll)
		defer ticker.Stop()
		token := ""
		since := time.Time{}
		for {
			select {
			case <-s.ctx.Done():
				s.endCompilerProgress(&token)
				return
			case <-ticker.C:
				if s.shutdown.Load() {
					s.endCompilerProgress(&token)
					return
				}
				running := runningCompilerLanguages(s.compilerStatusNow())
				switch {
				case len(running) == 0:
					s.endCompilerProgress(&token)
					since = time.Time{}
				case token == "":
					if since.IsZero() {
						since = time.Now()
						continue
					}
					if time.Since(since) < compilerProgressFloor {
						continue
					}
					token = compilerProgressToken + "/" + strconv.FormatInt(s.progressSequence.Add(1), 36)
					if err := s.callClient(s.ctx, "window/workDoneProgress/create", map[string]any{"token": token}, nil); err != nil {
						token = ""
						continue
					}
					s.notifyProgress(token, map[string]any{
						"kind": "begin", "title": "Validating", "message": strings.Join(running, " and "), "cancellable": false,
					})
				default:
					s.notifyProgress(token, map[string]any{"kind": "report", "message": strings.Join(running, " and ")})
				}
			}
		}
	}()
}

func (s *Server) compilerStatusNow() []index.CompilerPassStatus {
	if s.compilerStatusSource != nil {
		return s.compilerStatusSource()
	}
	return s.index.CompilerStatus()
}

func (s *Server) endCompilerProgress(token *string) {
	if *token == "" {
		return
	}
	s.notifyProgress(*token, map[string]any{"kind": "end"})
	*token = ""
}

func runningCompilerLanguages(statuses []index.CompilerPassStatus) []string {
	running := make([]string, 0, len(statuses))
	for _, status := range statuses {
		if status.Running {
			running = append(running, status.Language)
		}
	}
	// Stable ordering, so the message does not shuffle between reports.
	if len(running) == 2 && running[0] > running[1] {
		running[0], running[1] = running[1], running[0]
	}
	return running
}
