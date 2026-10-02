package index

import (
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A half-typed name at the top of a class body parses as a call whose
// trailing lambda is the rest of the body, so resolving it needs the receiver
// of its own lambda, which needs it resolved. That cycle overflowed the stack,
// which kills the process: the server died while the author typed.
func TestHalfTypedNameInsideItsOwnLambdaTerminates(t *testing.T) {
	const uri = protocol.URI("file:///workspace/record/Record.kt")
	clean := "package record\n\nimport java.util.UUID\n\ndata class Record(\n    val id: UUID,\n    val sortOrder: Int,\n) {\n    companion object {\n        fun create(\n            id: UUID?,\n            sortOrder: Int?,\n        ): Record = Record(\n            requireNotNull(id) { \"Record id is null\" },\n            requireNotNull(sortOrder) { \"Record sortOrder is null\" },\n        )\n    }\n}\n"
	at := strings.Index(clean, "companion object {\n") + len("companion object {\n")
	for _, typed := range []string{"l", "le", "let", "it.", "tr", "this.", "listOf(1).ma"} {
		text := clean[:at] + "    " + typed + "\n" + clean[at:]
		idx := scopeIndex(t, map[string]string{
			"lib/Preconditions.kt": "package kotlin\nfun <T : Any> requireNotNull(value: T?, lazyMessage: () -> Any): T = value!!\nfun <T, R> T.let(block: (T) -> R): R = block(this)\nfun <T> listOf(vararg elements: T): List<T> = TODO()\n",
			"java/util/UUID.java":  "package java.util;\npublic final class UUID {}\n",
			"record/Record.kt":     text,
		})
		_ = idx.Diagnostics(uri)
		doc := textdoc.NewDocument(uri, "kotlin", 1, text)
		_ = idx.Completion(uri, doc.Position(at+4+len(typed)), 200)
		_ = idx.Definitions(uri, doc.Position(at+4))
	}
}
