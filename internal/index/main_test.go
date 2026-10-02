package index

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain gives every test an empty home, Gradle home and cache directory,
// so no test can pass or fail because of what happens to be in the
// developer's ~/.gradle, ~/.m2 or caches. A test that needs a library builds
// it, or reads it from testdata.
func TestMain(m *testing.M) {
	os.Exit(runIsolated(m))
}

func runIsolated(m *testing.M) int {
	home, err := os.MkdirTemp("", "kotlsp-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(home)
	for name, value := range map[string]string{
		"HOME":             home,
		"GRADLE_USER_HOME": filepath.Join(home, ".gradle"),
		"XDG_CACHE_HOME":   filepath.Join(home, ".cache"),
		"XDG_CONFIG_HOME":  filepath.Join(home, ".config"),
		"MAVEN_OPTS":       "-Dmaven.repo.local=" + filepath.Join(home, ".m2", "repository"),
	} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return m.Run()
}
