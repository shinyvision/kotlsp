//go:build linux

package lsp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processTreeRSSBytes samples the server and all descendants visible through
// procfs. The walk is bounded so a benchmark cannot hang on a pathological
// process tree; disappeared children are simply omitted from that sample.
func processTreeRSSBytes() uint64 {
	const maxProcesses = 512
	queue := []int{os.Getpid()}
	seen := make(map[int]bool)
	var total uint64
	for len(queue) > 0 && len(seen) < maxProcesses {
		pid := queue[0]
		queue = queue[1:]
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		if status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status")); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if !strings.HasPrefix(line, "VmRSS:") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kilobytes, _ := strconv.ParseUint(fields[1], 10, 64)
					total += kilobytes << 10
				}
				break
			}
		}
		childrenPath := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children")
		if children, err := os.ReadFile(childrenPath); err == nil {
			for _, child := range strings.Fields(string(children)) {
				childPID, parseErr := strconv.Atoi(child)
				if parseErr == nil && !seen[childPID] {
					queue = append(queue, childPID)
				}
			}
		}
	}
	return total
}
