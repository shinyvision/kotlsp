package lsp

import (
	"fmt"

	"github.com/shinyvision/kotlsp/internal/dap"
)

func (s *Server) startDAP() (int, error) {
	s.rootMu.Lock()
	defer s.rootMu.Unlock()
	if s.dap != nil {
		return s.dap.Port(), nil
	}
	server, err := dap.Start(s.ctx, s.index.DebugSourcePath)
	if err != nil {
		return 0, err
	}
	if server.Port() <= 0 {
		_ = server.Close()
		return 0, fmt.Errorf("listener did not provide a port")
	}
	s.dap = server
	return server.Port(), nil
}

func (s *Server) closeDAP() {
	s.rootMu.Lock()
	defer s.rootMu.Unlock()
	if s.dap != nil {
		_ = s.dap.Close()
		s.dap = nil
	}
}
