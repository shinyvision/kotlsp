package index

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// An annotation processor produces declarations that exist in no source file.
// The index does read the conventional output directories, so a project that
// has been built once is modelled correctly. A project that declares a
// processor but has never produced its output is not: every reference to a
// generated declaration would look undefined, and a rule that reported it would
// be confidently wrong about correct code.
//
// Fast diagnostics therefore abstain entirely for such a workspace. Validation
// still runs; only the predictions are withheld.
var annotationProcessorMarkers = []string{
	"kotlin(\"kapt\")", "id(\"kotlin-kapt\")", "kotlin-kapt", "apply plugin: 'kotlin-kapt'",
	"com.google.devtools.ksp", "id(\"com.google.devtools.ksp\")",
	"annotationProcessor", "kapt(", "ksp(",
	"<annotationProcessorPaths>",
}

var generatedSourceDirectories = []string{
	filepath.Join("build", "generated"),
	filepath.Join("target", "generated-sources"),
}

type generatedSourceState struct {
	unmodelled atomic.Bool
}

// computeGeneratedSourceState decides, once per scan, whether predictions may
// run. It walks build output on disk, so it belongs in the background scan
// that already owns the modules, never on the foreground diagnostic path. The
// previous form took the index read lock from inside a caller that already
// held it: a nested read lock deadlocks the moment a writer is waiting between
// the two, and the compiler pass storing its results is exactly such a writer.
func (i *Index) computeGeneratedSourceState() {
	i.mu.RLock()
	modules := append([]ModuleInfo(nil), i.modules...)
	i.mu.RUnlock()
	i.generatedSources.unmodelled.Store(anyModuleAwaitsGeneratedSources(modules))
}

// hasUnmodelledGeneratedSources reports whether any module declares an
// annotation processor whose generated output is absent from disk. Safe to
// call with any lock held: it reads a value the scan computed.
func (i *Index) hasUnmodelledGeneratedSources() bool {
	return i.generatedSources.unmodelled.Load()
}

func anyModuleAwaitsGeneratedSources(modules []ModuleInfo) bool {
	for _, module := range modules {
		if module.Dir == "" || !moduleDeclaresAnnotationProcessor(module.Dir) {
			continue
		}
		if !moduleHasGeneratedOutput(module.Dir) {
			return true
		}
	}
	return false
}

func moduleDeclaresAnnotationProcessor(directory string) bool {
	for _, name := range []string{"build.gradle.kts", "build.gradle", "pom.xml"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			continue
		}
		text := string(data)
		for _, marker := range annotationProcessorMarkers {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func moduleHasGeneratedOutput(directory string) bool {
	for _, relative := range generatedSourceDirectories {
		root := filepath.Join(directory, relative)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		found := false
		_ = filepath.Walk(root, func(path string, entry os.FileInfo, err error) error {
			if err != nil || entry.IsDir() || found {
				return nil
			}
			if isJavaOrKotlinSource(path) {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}
