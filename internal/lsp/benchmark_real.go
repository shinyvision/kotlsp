package lsp

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// benchmarkRealWorkspace measures the requests an editor sends while someone
// reads and writes the workspace's own code: definition, hover and member
// completion at real qualified references (`repository.findById`,
// `TABLE.FIELD`, `it.name`) in the workspace's own Kotlin sources. The
// synthetic fixture measures one tiny file; this measures what using the
// server on the project costs.
func benchmarkRealWorkspace(ctx context.Context, s *Server, files, perFile int, out io.Writer) error {
	inventory, _ := s.index.WorkspaceFilesContext(ctx, 250000)
	var sources []*analysis.ParsedFile
	for _, file := range inventory {
		path, ok := uriutil.Path(file.URI)
		if ok && file.Language == analysis.LanguageKotlin && strings.HasSuffix(path, ".kt") && !strings.Contains(path, "/generated/") && !strings.Contains(path, "/build/") {
			sources = append(sources, file)
		}
	}
	sort.Slice(sources, func(left, right int) bool { return sources[left].URI < sources[right].URI })
	if len(sources) == 0 {
		return fmt.Errorf("the workspace has no Kotlin sources to measure")
	}
	// An even spread over the workspace rather than its first directory.
	step := max(1, len(sources)/files)
	durations := map[string][]time.Duration{}
	measured := 0
	for index := 0; index < len(sources) && measured < files; index += step {
		file := sources[index]
		path, _ := uriutil.Path(file.URI)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(data)
		s.index.Open(ctx, protocol.TextDocumentItem{URI: file.URI, LanguageID: "kotlin", Version: 1, Text: text})
		parsed, ok := s.index.Parsed(file.URI)
		if !ok {
			continue
		}
		doc := textdoc.NewDocument(file.URI, "kotlin", 1, text)
		taken := 0
		for _, reference := range parsed.References {
			if taken >= perFile {
				break
			}
			if reference.Qualifier == "" || reference.Synthetic || reference.EndByte > len(text) || text[reference.StartByte:reference.EndByte] != reference.Name {
				continue
			}
			taken++
			at := doc.Position(reference.StartByte)
			params := mustJSON(map[string]any{"textDocument": map[string]any{"uri": file.URI}, "position": at})
			for _, method := range []string{"textDocument/definition", "textDocument/hover"} {
				begin := time.Now()
				_, _ = s.Request(ctx, method, params)
				durations[method] = append(durations[method], time.Since(begin))
			}
			// Member completion right after the dot, as the editor asks it.
			completion := mustJSON(map[string]any{"textDocument": map[string]any{"uri": file.URI}, "position": at})
			begin := time.Now()
			_, _ = s.Request(ctx, "textDocument/completion", completion)
			durations["textDocument/completion (member)"] = append(durations["textDocument/completion (member)"], time.Since(begin))
		}
		s.Notify(ctx, "textDocument/didClose", mustJSON(map[string]any{"textDocument": map[string]any{"uri": file.URI}}))
		measured++
	}
	methods := make([]string, 0, len(durations))
	for method := range durations {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	fmt.Fprintf(out, "real workspace: %d files, up to %d qualified references each\n", measured, perFile)
	fmt.Fprintf(out, "%-40s %8s %10s %10s %10s %10s\n", "METHOD", "COUNT", "P50", "P95", "P99", "WORST")
	failed := false
	for _, method := range methods {
		values := durations[method]
		sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
		worst := values[len(values)-1]
		status := ""
		if worst >= latencyLimit {
			status, failed = " FAIL", true
		}
		fmt.Fprintf(out, "%-40s %8d %10s %10s %10s %10s%s\n", method, len(values), benchmarkPercentile(values, 50).Round(time.Microsecond), benchmarkPercentile(values, 95).Round(time.Microsecond), benchmarkPercentile(values, 99).Round(time.Microsecond), worst.Round(time.Microsecond), status)
	}
	if failed {
		return fmt.Errorf("latency gate failed: one or more real-workspace requests reached %s", latencyLimit)
	}
	return nil
}
