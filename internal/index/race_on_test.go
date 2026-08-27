//go:build race

package index

// raceDetector reports whether the test binary was built with -race. Wall-clock
// budget tests cannot hold under race instrumentation, so they consult this.
const raceDetector = true
