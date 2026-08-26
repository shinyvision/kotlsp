//go:build !race && !latency

package lsp

const testLatencyLimit = 2 * latencyLimit * 10
