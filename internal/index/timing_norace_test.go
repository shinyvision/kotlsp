//go:build !race && !latency

package index

import "time"

const testTimingBudget = 2 * time.Second
