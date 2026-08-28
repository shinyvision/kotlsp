package index

import (
	"path/filepath"
	"testing"
)

func TestTargetedRefreshClearsOnlyAffectedLibraryAccess(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	first := filepath.Clean("/workspace/first")
	second := filepath.Clean("/workspace/second")
	archive := filepath.Clean("/cache/dependency.jar")
	idx.libraryAccess[archive] = map[string]bool{
		libraryAccessKey(first, "main"):  true,
		libraryAccessKey(first, "test"):  true,
		libraryAccessKey(second, "main"): true,
	}
	modules := []ModuleInfo{{Dir: first}, {Dir: second}}
	idx.clearLibraryAccessForRoots(modules, map[string]bool{first: true})
	access := idx.libraryAccess[archive]
	if access[libraryAccessKey(first, "main")] || access[libraryAccessKey(first, "test")] {
		t.Fatalf("affected access survived refresh: %#v", access)
	}
	if !access[libraryAccessKey(second, "main")] {
		t.Fatalf("unaffected access was removed: %#v", access)
	}
}
