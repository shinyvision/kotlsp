package index

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func TestGeneratedSourceUncertaintyFollowsOnlyModuleDependencies(t *testing.T) {
	root := t.TempDir()
	producerDir := filepath.Join(root, "producer")
	consumerDir := filepath.Join(root, "consumer")
	unrelatedDir := filepath.Join(root, "unrelated")
	for _, directory := range []string{producerDir, consumerDir, unrelatedDir} {
		if err := os.MkdirAll(filepath.Join(directory, "src", "main", "kotlin"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(producerDir, "build.gradle"), []byte("dependencies { annotationProcessor 'sample:generator:1' }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	defer idx.Close()
	idx.modules = []ModuleInfo{
		{Name: ":producer", Root: root, Dir: producerDir, SourceSets: map[string][]string{"main": {filepath.Join(producerDir, "src", "main", "kotlin")}}, DependenciesBySourceSet: map[string][]string{}},
		{Name: ":consumer", Root: root, Dir: consumerDir, SourceSets: map[string][]string{"main": {filepath.Join(consumerDir, "src", "main", "kotlin")}}, DependenciesBySourceSet: map[string][]string{"main": {":producer"}}},
		{Name: ":unrelated", Root: root, Dir: unrelatedDir, SourceSets: map[string][]string{"main": {filepath.Join(unrelatedDir, "src", "main", "kotlin")}}, DependenciesBySourceSet: map[string][]string{}},
	}
	idx.computeGeneratedSourceState()
	consumer := &analysis.ParsedFile{URI: uriutil.File(filepath.Join(consumerDir, "src", "main", "kotlin", "Use.kt"))}
	unrelated := &analysis.ParsedFile{URI: uriutil.File(filepath.Join(unrelatedDir, "src", "main", "kotlin", "Other.kt"))}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	if !idx.hasUnmodelledGeneratedSourcesFor(consumer) {
		t.Fatal("dependent module was allowed to prove absence of generated declarations")
	}
	if idx.hasUnmodelledGeneratedSourcesFor(unrelated) {
		t.Fatal("unrelated module inherited generated-source uncertainty")
	}
}
