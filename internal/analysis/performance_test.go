package analysis

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// BenchmarkParseLargeKotlinMethods guards the flat-declaration workload used
// by the end-to-end cancellation/performance audit. Keep the source shape in
// sync with /tmp/kotlsp-cancel-probe.py so CPU and allocation profiles are
// directly comparable with transport measurements.
func BenchmarkParseLargeKotlinMethods(b *testing.B) {
	for _, count := range []int{1_000, 4_000, 12_000} {
		b.Run(fmt.Sprintf("methods-%d", count), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("class Huge {\n")
			for method := 0; method < count; method++ {
				fmt.Fprintf(&source, "fun method%d(value:Int):Int{if(value>0){return value+%d}else{return %d}}\n", method, method, method)
			}
			source.WriteString("}\n")
			doc := textdoc.NewDocument(protocol.URI("file:///benchmark/Huge.kt"), "kotlin", 1, source.String())
			b.ReportAllocs()
			b.SetBytes(int64(len(source.String())))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				Parse(context.Background(), doc)
			}
		})
	}
}
