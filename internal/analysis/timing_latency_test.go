//go:build latency && !race

package analysis

import "time"

const testTimingBudget = 100 * time.Millisecond
