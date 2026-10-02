//go:build windows

package index

// processAlive cannot ask cheaply on Windows; ownership-named directories are
// then left to the age-based sweep.
func processAlive(int) bool { return true }
