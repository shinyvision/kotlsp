package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Assigning to a val is an error under every reading of the program, so the
// index can say so without waiting for a compiler.
func TestValReassignmentIsPredicted(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)
	uri := fixtureFile(root, "src/main/kotlin/fixture/Errors.kt")
	found := fastFindings(idx, uri, "VAL_REASSIGNMENT")
	if len(found) < 2 {
		t.Fatalf("expected the local and the member reassignment, got %d: %#v", len(found), found)
	}
	// Nothing may be reported in sources that only read their vals.
	for _, clean := range []string{
		"src/main/kotlin/fixture/Clean.kt",
		"src/main/kotlin/fixture/Imported.kt",
	} {
		if reported := fastFindings(idx, fixtureFile(root, clean), "VAL_REASSIGNMENT"); len(reported) != 0 {
			t.Fatalf("%s: reported %#v", clean, reported)
		}
	}
}

// A var is assignable, and a declaration's own initialiser is not a
// reassignment. Neither may be reported.
func TestVarAssignmentAndInitialisersAreNotReported(t *testing.T) {
	idx, root := startedFixtureIndex(t)
	path := filepath.Join(root, "src", "main", "kotlin", "fixture", "Vars.kt")
	source := "package fixture\n\nclass Vars {\n    var counter: Int = 0\n\n    fun bump(): Int {\n        counter = counter + 1\n        var local = 1\n        local = 2\n        val fixed = 3\n        return counter + local + fixed\n    }\n}\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	uri := fixtureFile(root, "src/main/kotlin/fixture/Vars.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	if reported := fastFindings(idx, uri, "VAL_REASSIGNMENT"); len(reported) != 0 {
		t.Fatalf("assignable declarations were reported: %#v", reported)
	}
}
