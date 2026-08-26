package index

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func BenchmarkOpenLargeKotlinMethods(b *testing.B) {
	for _, count := range []int{4_000, 12_000} {
		for _, fixture := range []struct {
			name        string
			diagnostics bool
			background  bool
		}{
			{name: "without-diagnostics"},
			{name: "with-diagnostics", diagnostics: true},
			{name: "during-library-index", diagnostics: true, background: true},
		} {
			name := fmt.Sprintf("methods-%d/%s", count, fixture.name)
			var parsedCallback func(protocol.URI, []protocol.Diagnostic)
			if fixture.diagnostics {
				parsedCallback = func(protocol.URI, []protocol.Diagnostic) {}
			}
			b.Run(name, func(b *testing.B) {
				var source strings.Builder
				source.WriteString("class Huge {\n")
				for method := 0; method < count; method++ {
					fmt.Fprintf(&source, "fun method%d(value:Int):Int{if(value>0){return value+%d}else{return %d}}\n", method, method, method)
				}
				source.WriteString("}\n")
				item := protocol.TextDocumentItem{URI: "file:///benchmark/Huge.kt", LanguageID: "kotlin", Version: 1, Text: source.String()}
				b.ReportAllocs()
				b.SetBytes(int64(len(item.Text)))
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					idx := New(parsedCallback)
					if fixture.background {
						idx.Start(context.Background(), []protocol.URI{"file:///tmp/kotlsp-cancel-audit"})
					}
					idx.Open(context.Background(), item)
					idx.Close()
				}
			})
		}
	}
}
