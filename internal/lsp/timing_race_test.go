//go:build race

package lsp

import "time"

const testLatencyLimit = 5 * time.Second
