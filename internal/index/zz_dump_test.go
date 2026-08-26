package index

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// Temporary: dumps what the hosted compilers report for probe sources.
func TestZZDumpCompilerMessages(t *testing.T) {
	requireCompilerBackedTest(t)
	src := os.Getenv("KOTLSP_DUMP_SRC")
	if src == "" {
		t.Skip("KOTLSP_DUMP_SRC unset")
	}
	root := t.TempDir()
	var uris []protocol.URI
	for _, spec := range []struct{ from, to string }{
		{"kprobe/Probe.kt", "src/main/kotlin/probe/Probe.kt"},
		{"jprobe/probe/Pr.java", "src/main/java/probe/Pr.java"},
		{"jprobe/probe/Flow.java", "src/main/java/probe/Flow.java"},
	} {
		data, err := os.ReadFile(filepath.Join(src, spec.from))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(spec.to))
		os.MkdirAll(filepath.Dir(target), 0o700)
		os.WriteFile(target, data, 0o600)
		uris = append(uris, uriutil.File(target))
	}
	idx := New(nil)
	t.Cleanup(idx.Close)
	idx.Start(context.Background(), []protocol.URI{uriutil.File(root)})
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(20 * time.Millisecond)
	}
	for _, uri := range uris {
		p, _ := uriutil.Path(uri)
		data, _ := os.ReadFile(p)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: map[bool]string{true: "kotlin", false: "java"}[filepath.Ext(string(uri)) == ".kt"], Version: 1, Text: string(data)})
	}
	time.Sleep(2 * time.Second)
	deadline = time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if idx.CompilerPasses("kotlin") > 0 && idx.CompilerPasses("java") > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	for _, uri := range uris {
		idx.mu.RLock()
		raw := append([]protocol.Diagnostic(nil), idx.compilerDiagnostics[uri]...)
		idx.mu.RUnlock()
		sort.SliceStable(raw, func(a, b int) bool {
			return raw[a].Range.Start.Line < raw[b].Range.Start.Line || raw[a].Range.Start.Line == raw[b].Range.Start.Line && raw[a].Range.Start.Character < raw[b].Range.Start.Character
		})
		fmt.Printf("=== %s (%d)\n", filepath.Base(string(uri)), len(raw))
		for _, d := range raw {
			fmt.Printf("L%d:%d [%s] %v %s :: %q\n", d.Range.Start.Line+1, d.Range.Start.Character+1, d.Source, d.Code, d.Message, d.Message)
		}
	}
}
