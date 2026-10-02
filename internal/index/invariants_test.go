package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Typing a stray name at the top of an annotated interface changes the
// interface's identity (the error detaches its annotation) while its members
// keep theirs. The members were left filed under the old container, and the
// next edit that removed them left those entries pointing at nothing:
// completion dereferenced one and panicked.
func TestEditsKeepContainerBucketsConsistent(t *testing.T) {
	ctx := context.Background()
	const uri = protocol.URI("file:///workspace/app/Repo.kt")
	clean := "package app\n\n@Suppress(\"TooManyFunctions\")\ninterface Repo {\n    suspend fun first(id: Int): Int?\n\n    suspend fun second(id: Int): Int\n}\n"
	idx := scopeIndex(t, map[string]string{"app/Repo.kt": clean})
	at := strings.Index(clean, "{\n") + 2
	version := 1
	for _, typed := range []string{"i", "it", "it.", ""} {
		version++
		text := clean
		if typed != "" {
			text = clean[:at] + "    " + typed + "\n" + clean[at:]
		}
		if _, err := idx.Change(ctx, protocol.DidChangeTextDocumentParams{TextDocument: protocol.VersionedTextDocumentIdentifier{URI: uri, Version: version}, ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}}}); err != nil {
			t.Fatal(err)
		}
		idx.mu.RLock()
		problems := idx.checkInvariantsLocked()
		idx.mu.RUnlock()
		if len(problems) > 0 {
			t.Fatalf("after typing %q:\n%s", typed, strings.Join(problems, "\n"))
		}
	}
}
