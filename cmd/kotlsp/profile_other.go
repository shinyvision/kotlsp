//go:build !unix

package main

// installProfileSignals is a no-op where there are no SIGUSR1/SIGUSR2
// (Windows): on-demand profiles are driven by those signals. The startup
// profiles (KOTLSP_CPU_PROFILE, KOTLSP_HEAP_PROFILE) work everywhere.
func installProfileSignals() {}
