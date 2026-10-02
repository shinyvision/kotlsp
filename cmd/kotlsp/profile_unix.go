//go:build unix

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/shinyvision/kotlsp/internal/lsp"
)

// installProfileSignals enables on-demand profiling for a long-running
// session, driven by KOTLSP_PROFILE_DIR. It costs nothing when unset.
//
//	SIGUSR1  write mutex, block, goroutine and heap profiles into the directory
//	SIGUSR2  start a CPU profile; a second SIGUSR2 stops and writes it
//
// Mutex and block sampling are switched on only when the directory is set, as
// they are not free. The point is to answer "what is this server doing right
// now" for a session that has already misbehaved, without restarting it.
func installProfileSignals() {
	dir := os.Getenv("KOTLSP_PROFILE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	runtime.SetMutexProfileFraction(5)
	runtime.SetBlockProfileRate(1_000_000) // one sample per millisecond blocked
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		var cpuFile *os.File
		for sig := range signals {
			stamp := time.Now().Format("150405")
			switch sig {
			case syscall.SIGUSR1:
				if file, err := os.Create(filepath.Join(dir, fmt.Sprintf("requests-%s.txt", stamp))); err == nil {
					methods, counts := lsp.RequestCounts()
					for _, method := range methods {
						fmt.Fprintf(file, "%8d %s\n", counts[method], method)
					}
					_ = file.Close()
				}
				for _, name := range []string{"mutex", "block", "goroutine", "heap"} {
					if profile := pprof.Lookup(name); profile != nil {
						if file, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s-%s.prof", name, stamp))); err == nil {
							_ = profile.WriteTo(file, 0)
							_ = file.Close()
						}
					}
				}
			case syscall.SIGUSR2:
				if cpuFile != nil {
					pprof.StopCPUProfile()
					_ = cpuFile.Close()
					cpuFile = nil
					continue
				}
				if file, err := os.Create(filepath.Join(dir, fmt.Sprintf("cpu-%s.prof", stamp))); err == nil {
					if pprof.StartCPUProfile(file) == nil {
						cpuFile = file
					} else {
						_ = file.Close()
					}
				}
			}
		}
	}()
}
