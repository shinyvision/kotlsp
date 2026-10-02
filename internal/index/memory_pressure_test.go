package index

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A pressure sweep may only drop caches that rebuild themselves. This asserts
// both halves: the coldest entries go first, and a dropped document is served
// again from its archive on the next request.
func TestColdLibraryCachesEvictAndReload(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "library.jar")
	writeLibraryJar(t, archive, map[string]string{
		"lib/Cold.java": "package lib;\npublic class Cold {}\n",
		"lib/Warm.java": "package lib;\npublic class Warm {}\n",
	})

	idx := New(nil)
	defer idx.Close()
	cold := protocol.URI("jar://" + archive + "!/lib/Cold.java")
	warm := protocol.URI("jar://" + archive + "!/lib/Warm.java")
	idx.mu.Lock()
	idx.librarySources[cold] = LibrarySource{Archive: archive, Entry: "lib/Cold.java", LanguageID: "java"}
	idx.librarySources[warm] = LibrarySource{Archive: archive, Entry: "lib/Warm.java", LanguageID: "java"}
	idx.mu.Unlock()

	// Populate both caches, then touch only the warm one.
	if _, ok := idx.DocumentContext(context.Background(), cold); !ok {
		t.Fatal("cold entry did not load")
	}
	if _, ok := idx.DocumentContext(context.Background(), warm); !ok {
		t.Fatal("warm entry did not load")
	}
	if _, ok := idx.DocumentContext(context.Background(), warm); !ok {
		t.Fatal("warm entry did not re-read")
	}
	idx.mu.RLock()
	resident := len(idx.libraryDocs)
	idx.mu.RUnlock()
	if resident != 2 {
		t.Fatalf("resident library documents = %d, want 2", resident)
	}

	if dropped := idx.evictColdLibraryCaches(1); dropped != 1 {
		t.Fatalf("evicted %d entries, want 1", dropped)
	}
	idx.mu.RLock()
	_, coldResident := idx.libraryDocs[cold]
	_, warmResident := idx.libraryDocs[warm]
	idx.mu.RUnlock()
	if coldResident {
		t.Fatal("the least recently used entry survived the sweep")
	}
	if !warmResident {
		t.Fatal("the most recently used entry was evicted first")
	}

	// The evicted entry must come back on demand, or navigation into it would
	// silently answer nothing until an unrelated rescan.
	document, ok := idx.DocumentContext(context.Background(), cold)
	if !ok || document == nil {
		t.Fatal("an evicted library document did not reload from its archive")
	}
	if want := "public class Cold {}"; !strings.Contains(document.Text, want) {
		t.Fatalf("reloaded document did not contain %q", want)
	}
}

func TestEvictionBudgetIsRespected(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	if dropped := idx.evictColdLibraryCaches(0); dropped != 0 {
		t.Fatalf("a zero budget evicted %d entries", dropped)
	}
	if dropped := idx.evictColdLibraryCaches(4); dropped != 0 {
		t.Fatalf("an empty cache evicted %d entries", dropped)
	}
}

func writeLibraryJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, body := range entries {
		member, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := member.Write([]byte(body)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
