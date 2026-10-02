package index

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A work directory whose owning process has exited is removed at the next
// sweep; one owned by a live process, or this one, stays.
func TestSweepRemovesWorkOfExitedProcesses(t *testing.T) {
	root := t.TempDir()
	mine := filepath.Join(root, "kotlsp-kotlinc-"+strconv.Itoa(os.Getpid())+"-1")
	gone := filepath.Join(root, "kotlsp-kotlinc-999999999-1")
	legacy := filepath.Join(root, "kotlsp-javac-12345")
	for _, directory := range []string{mine, gone, legacy} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	compilerWorkSweep.Store(0)
	sweepStaleCompilerWork(root)
	if _, err := os.Stat(mine); err != nil {
		t.Error("the live process's directory was removed")
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Error("an exited process's directory was kept")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Error("a fresh unnamed directory was removed before a day passed")
	}
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(legacy, old, old)
	compilerWorkSweep.Store(0)
	sweepStaleCompilerWork(root)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Error("a day-old unnamed directory was kept")
	}
}
