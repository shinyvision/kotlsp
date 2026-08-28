package index

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// An annotation processor produces declarations that exist in no source file.
// The index does read the conventional output directories, so a project that
// has been built once is modelled correctly. A project that declares a
// processor but has never produced its output is not: every reference to a
// generated declaration would look undefined, and a rule that reported it would
// be confidently wrong about correct code.
//
// Fast diagnostics therefore abstain only in the owning source set and source
// sets whose module can read it. Validation still runs; only predictions whose
// file can depend on the missing generated declarations are withheld.
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
	mu             sync.RWMutex
	complete       bool
	unmodelledDirs map[string]bool
	affectedSets   map[string]bool
}

// computeGeneratedSourceState decides, once per scan, which modules may run
// predictions. It walks build output on disk, so it belongs in the background scan
// that already owns the modules, never on the foreground diagnostic path. The
// previous form took the index read lock from inside a caller that already
// held it: a nested read lock deadlocks the moment a writer is waiting between
// the two, and the compiler pass storing its results is exactly such a writer.
func (i *Index) computeGeneratedSourceState() {
	_ = i.computeGeneratedSourceStateContext(context.Background())
}

func (i *Index) computeGeneratedSourceStateContext(ctx context.Context) error {
	i.mu.RLock()
	modules := make([]ModuleInfo, len(i.modules))
	for moduleIndex, module := range i.modules {
		modules[moduleIndex] = cloneModuleInfo(module)
	}
	i.mu.RUnlock()
	unmodelled := make(map[string]bool)
	for moduleIndex, module := range modules {
		if moduleIndex&31 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		generated, complete := moduleHasGeneratedOutputContext(ctx, module.Dir)
		if !complete {
			return fmt.Errorf("generated-source inventory for %s was incomplete", module.Dir)
		}
		if module.Dir == "" || !moduleDeclaresAnnotationProcessor(module.Dir) || generated {
			continue
		}
		unmodelled[filepath.Clean(module.Dir)] = true
	}
	affected := make(map[string]bool)
	var unmodelledTargets []*ModuleInfo
	byName := make(map[string][]*ModuleInfo, len(modules))
	for moduleIndex := range modules {
		module := &modules[moduleIndex]
		byName[module.Root+"\x00"+module.Name] = append(byName[module.Root+"\x00"+module.Name], module)
		if unmodelled[filepath.Clean(module.Dir)] {
			unmodelledTargets = append(unmodelledTargets, module)
		}
	}
	totalStates, totalSourceSets := 0, 0
	for fromIndex := range modules {
		from := &modules[fromIndex]
		sets := map[string]bool{"main": true}
		for set := range from.SourceSets {
			sets[set] = true
		}
		for set := range from.DependenciesBySourceSet {
			sets[set] = true
		}
		for set := range sets {
			totalSourceSets++
			if totalSourceSets > 100_000 {
				return fmt.Errorf("generated-source analysis exceeds its 100000-source-set safety limit")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			accessible, complete := moduleAccessSet(from, set, byName)
			if !complete {
				return fmt.Errorf("generated-source dependency closure for %s/%s exceeded its safety limit", from.Name, set)
			}
			totalStates += len(accessible)
			if totalStates > 1_000_000 {
				return fmt.Errorf("generated-source dependency closures exceed their 1000000-membership safety limit")
			}
			for _, target := range unmodelledTargets {
				if filepath.Clean(from.Dir) == filepath.Clean(target.Dir) || accessible[moduleAccessIdentity(target)] {
					affected[libraryAccessKey(from.Dir, set)] = true
					break
				}
			}
		}
	}
	i.generatedSources.mu.Lock()
	i.generatedSources.complete = true
	i.generatedSources.unmodelledDirs = unmodelled
	i.generatedSources.affectedSets = affected
	i.generatedSources.mu.Unlock()
	i.diagnosticStateVersion.Add(1)
	return nil
}

// hasUnmodelledGeneratedSourcesFor reports uncertainty only for the file's
// owning source set and the module dependencies that source set can read. It
// is called with the index read lock held; the generated-source state has its
// own lock because background scans replace it wholesale.
func (i *Index) hasUnmodelledGeneratedSourcesFor(file *analysis.ParsedFile) bool {
	if file == nil {
		return false
	}
	// An index populated directly through Open has no build-model scan and no
	// generated-source inventory to be incomplete. This is the in-memory/editor
	// fragment mode used before Start (and by embedders); treating its absent
	// module graph as uncertainty disables every workspace-backed operation.
	if i.generation.Load() == 0 {
		i.generatedSources.mu.RLock()
		complete := i.generatedSources.complete
		i.generatedSources.mu.RUnlock()
		if !complete {
			return false
		}
	}
	module, unique := moduleForURIInModules(file.URI, i.modules)
	if !unique || module.Dir == "" {
		return true
	}
	sourceSet, unique := sourceSetForURIInModule(file.URI, module)
	if !unique {
		return true
	}
	i.generatedSources.mu.RLock()
	defer i.generatedSources.mu.RUnlock()
	if !i.generatedSources.complete {
		return true
	}
	return i.generatedSources.affectedSets[libraryAccessKey(module.Dir, sourceSet)]
}

func moduleDeclaresAnnotationProcessor(directory string) bool {
	for _, name := range []string{"build.gradle.kts", "build.gradle", "pom.xml"} {
		data, err := readFileBounded(filepath.Join(directory, name), 8<<20, "build manifest")
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
	found, _ := moduleHasGeneratedOutputContext(context.Background(), directory)
	return found
}

func moduleHasGeneratedOutputContext(ctx context.Context, directory string) (bool, bool) {
	if directory == "" {
		return false, true
	}
	for _, relative := range generatedSourceDirectories {
		root := filepath.Join(directory, relative)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		found, visited, complete := false, 0, true
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if ctx.Err() != nil {
				complete = false
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			visited++
			if visited > 100_000 {
				complete = false
				return filepath.SkipAll
			}
			if entry.IsDir() || found {
				return nil
			}
			if isJavaOrKotlinSource(path) {
				found = true
				return filepath.SkipAll
			}
			return nil
		})
		if found {
			return true, true
		}
		if !complete {
			return false, false
		}
	}
	return false, true
}
