//go:build !race && !latency

package analysis

import "time"

// Correctness suites run packages concurrently and use a generous watchdog.
// The dedicated `latency` tag runs the actual 100ms wall-clock gate serially.
const testTimingBudget = 30 * time.Second
