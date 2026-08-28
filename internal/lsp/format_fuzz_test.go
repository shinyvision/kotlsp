package lsp

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func FuzzFormatter(f *testing.F) {
	f.Add("fun main(){println(\"ok\")}", true)
	f.Add("class Main{/* nested /* comment */ end */}", true)
	f.Add("class Main { String text = \"}\\\"\"; }", false)
	f.Fuzz(func(t *testing.T, source string, kotlin bool) {
		if len(source) > 1<<20 {
			t.Skip()
		}
		formatted, completed := formatSourceContext(context.Background(), source, protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}, kotlin)
		if completed {
			second, secondCompleted := formatSourceContext(context.Background(), formatted, protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}, kotlin)
			if secondCompleted && second != formatted {
				t.Fatalf("formatter is not idempotent")
			}
		}
	})
}
