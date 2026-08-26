//go:build latency && !race

package index

import "time"

const testTimingBudget = 100 * time.Millisecond
