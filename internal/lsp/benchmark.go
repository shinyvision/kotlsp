package lsp

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/jsonrpc"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

type benchmarkResult struct {
	Method string
	First  time.Duration
	Min    time.Duration
	P50    time.Duration
	P95    time.Duration
	P99    time.Duration
	Worst  time.Duration
	Alloc  uint64
	Heap   uint64
	RSS    uint64
	// Informational results document unavoidable/background lower bounds but
	// are not complete JSON-RPC response latency gates.
	Informational bool
}

type benchmarkFixture struct {
	URI           protocol.URI
	Symbol        analysis.Symbol
	Position      protocol.Position
	ExtractRange  protocol.Range
	LibraryURI    protocol.URI
	ExportDir     string
	WatermarkPath string
	Source        string
}

func RunBenchmarkCLI(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(out)
	workspace := fs.String("workspace", ".", "Kotlin/Java workspace to index")
	iterations := fs.Int("iterations", 100, "iterations per LSP request")
	wait := fs.Duration("index-timeout", 2*time.Minute, "maximum wait for background source indexing")
	requireCompiler := fs.Bool("require-compiler-pass", true, "require every source language present in the workspace to complete an authoritative compiler pass")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iterations < 1 {
		return fmt.Errorf("iterations must be positive")
	}
	root := uriutil.File(*workspace)
	s := NewServer(ctx, log.New(io.Discard, "", 0))
	defer s.Close()
	var appliedEdits atomic.Int64
	s.clientCall = func(_ context.Context, method string, params, result any) error {
		if method != "workspace/applyEdit" {
			return nil
		}
		payload, ok := params.(map[string]any)
		if !ok || payload["label"] == "" || payload["edit"] == nil {
			return fmt.Errorf("benchmark received malformed workspace/applyEdit params")
		}
		response, ok := result.(*struct {
			Applied       bool   `json:"applied"`
			FailureReason string `json:"failureReason"`
		})
		if !ok {
			return fmt.Errorf("workspace/applyEdit response has unexpected type %T", result)
		}
		response.Applied = true
		appliedEdits.Add(1)
		return nil
	}
	initParams := map[string]any{"rootUri": root, "workspaceFolders": []any{map[string]any{"uri": root, "name": "benchmark"}}, "capabilities": map[string]any{}}
	initRaw := mustJSON(initParams)
	started := time.Now()
	if _, err := s.Request(ctx, "initialize", initRaw); err != nil {
		return err
	}
	initDuration := time.Since(started)
	s.Notify(ctx, "initialized", nil)
	indexWaitStarted := time.Now()
	deadline := indexWaitStarted.Add(*wait)
	for !s.index.Progress().Ready && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !s.index.Progress().Ready {
		return fmt.Errorf("source index did not become ready in %s", *wait)
	}
	indexReadyDuration := time.Since(indexWaitStarted)
	if *requireCompiler {
		if err := waitForBenchmarkCompilerPass(ctx, s, time.Now().Add(*wait)); err != nil {
			return err
		}
	}
	fixture, cleanup, err := makeBenchmarkFixture(ctx, s, *workspace)
	if err != nil {
		return err
	}
	defer cleanup()
	uri, sym, pos := fixture.URI, fixture.Symbol, fixture.Position
	item := s.hierarchyItem(sym)
	requests := map[string]json.RawMessage{
		"textDocument/completion":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"completionItem/resolve":         mustJSON(protocol.CompletionItem{Label: sym.Name, Data: map[string]string{"symbolId": sym.ID}}),
		"textDocument/hover":             mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/definition":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/declaration":       mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/typeDefinition":    mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/implementation":    mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/references":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos, "context": map[string]bool{"includeDeclaration": true}}),
		"textDocument/documentHighlight": mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/documentSymbol":    mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"workspace/symbol":               mustJSON(map[string]any{"query": sym.Name}),
		"workspace/symbol broad":         mustJSON(map[string]any{"query": ""}),
		"textDocument/formatting":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "options": map[string]any{"tabSize": 4, "insertSpaces": true}}),
		"textDocument/rangeFormatting":   mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": sym.Range, "options": map[string]any{"tabSize": 4, "insertSpaces": true}}),
		// A declaration name with no diagnostics and no imports correctly has
		// no actions; the extractable literal is the range that must yield some.
		"textDocument/codeAction":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": fixture.ExtractRange, "context": map[string]any{"diagnostics": []any{}}}),
		"textDocument/diagnostic":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"textDocument/codeLens":             mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"textDocument/foldingRange":         mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"textDocument/semanticTokens/full":  mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"textDocument/semanticTokens/range": mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": sym.Range}),
		"textDocument/inlayHint":            mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": sym.Range}),
		"inlayHint/resolve":                 mustJSON(protocol.InlayHint{Position: pos, Label: ": Any"}),
		"textDocument/signatureHelp":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/prepareCallHierarchy": mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"callHierarchy/incomingCalls":       mustJSON(map[string]any{"item": item}),
		"callHierarchy/outgoingCalls":       mustJSON(map[string]any{"item": item}),
		"textDocument/prepareTypeHierarchy": mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"typeHierarchy/supertypes":          mustJSON(map[string]any{"item": item}),
		"typeHierarchy/subtypes":            mustJSON(map[string]any{"item": item}),
		"textDocument/prepareRename":        mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/rename":               mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos, "newName": sym.Name + "Bench"}),
		"workspace/willRenameFiles":         mustJSON(map[string]any{"files": []any{map[string]any{"oldUri": uri, "newUri": uriutil.File(filepath.Join(*workspace, "LatencyFixtureBench.kt"))}}}),
	}
	for _, command := range supportedCommands() {
		requests["workspace/executeCommand:"+command] = mustJSON(map[string]any{"command": command, "arguments": benchmarkCommandArgs(command, fixture)})
	}
	results := make([]benchmarkResult, 0, len(requests)+1)
	results = append(results, benchmarkResult{Method: "initialize", First: initDuration, Min: initDuration, P50: initDuration, P95: initDuration, P99: initDuration, Worst: initDuration})
	results = append(results, benchmarkResult{Method: "workspace/indexReady (cold background lower bound)", First: indexReadyDuration, Min: indexReadyDuration, P50: indexReadyDuration, P95: indexReadyDuration, P99: indexReadyDuration, Worst: indexReadyDuration, Informational: true})
	methods := make([]string, 0, len(requests))
	for method := range requests {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, label := range methods {
		method := label
		if at := indexColon(label); at >= 0 {
			method = "workspace/executeCommand"
		} else if strings.HasPrefix(label, "workspace/symbol ") {
			method = "workspace/symbol"
		}
		raw := requests[label]
		durations := make([]time.Duration, *iterations)
		allocations := make([]uint64, *iterations)
		var heapPeak uint64
		var rssPeak uint64
		for n := 0; n < *iterations; n++ {
			iterationRaw := raw
			if label == "workspace/executeCommand:jetbrains.kotlin.completion.apply" {
				// Application IDs are intentionally one-shot. Provision a fresh
				// visible completion session before every measured command and keep
				// that preparation outside the command duration.
				liveArgs, err := benchmarkKotlinCompletionArgs(s, requests["textDocument/completion"])
				if err != nil {
					return err
				}
				iterationRaw = mustJSON(map[string]any{"command": "jetbrains.kotlin.completion.apply", "arguments": liveArgs})
			}
			if label == "workspace/executeCommand:chooseModCommandAction" {
				s.modMu.Lock()
				s.modSessions[1] = []map[string]any{{"type": "Nothing"}}
				s.modSessionCreated[1] = time.Now()
				s.modMu.Unlock()
			}
			var memoryBefore, memoryAfter runtime.MemStats
			runtime.ReadMemStats(&memoryBefore)
			begin := time.Now()
			result, responseErr := s.Request(ctx, method, iterationRaw)
			durations[n] = time.Since(begin)
			runtime.ReadMemStats(&memoryAfter)
			allocations[n] = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
			if memoryAfter.HeapAlloc > heapPeak {
				heapPeak = memoryAfter.HeapAlloc
			}
			if rss := processTreeRSSBytes(); rss > rssPeak {
				rssPeak = rss
			}
			if responseErr != nil && !(label == "workspace/symbol broad" && responseErr.Code == jsonrpc.RequestCanceled) {
				// An unqualified query over a real workspace exceeds the symbol
				// candidate bound; the server answers with its defined bounded
				// refusal, which is the latency being measured here.
				return fmt.Errorf("%s iteration %d returned JSON-RPC error %d: %s", label, n+1, responseErr.Code, responseErr.Message)
			}
			if err := validateBenchmarkResult(label, result); err != nil {
				return fmt.Errorf("%s iteration %d: %w", label, n+1, err)
			}
		}
		first := durations[0]
		warm := append([]time.Duration(nil), durations...)
		if len(warm) > 1 {
			warm = warm[1:]
		}
		sort.Slice(warm, func(a, b int) bool { return warm[a] < warm[b] })
		var allocationTotal uint64
		for _, allocation := range allocations {
			allocationTotal += allocation
		}
		results = append(results, benchmarkResult{Method: label, First: first, Min: warm[0], P50: benchmarkPercentile(warm, 50), P95: benchmarkPercentile(warm, 95), P99: benchmarkPercentile(warm, 99), Worst: warm[len(warm)-1], Alloc: allocationTotal / uint64(len(allocations)), Heap: heapPeak, RSS: rssPeak})
	}
	mixed, err := benchmarkMixedTypingAndQueries(ctx, s, fixture, *iterations, requests["textDocument/completion"])
	if err != nil {
		return err
	}
	results = append(results, mixed)
	incremental, err := benchmarkIncrementalTypingAndQueries(ctx, s, fixture, *iterations, requests["textDocument/completion"])
	if err != nil {
		return err
	}
	results = append(results, incremental)
	fmt.Fprintf(out, "%-58s %10s %10s %10s %10s %10s %10s %11s %11s %11s\n", "METHOD", "FIRST", "MIN", "P50", "P95", "P99", "WORST", "ALLOC/OP", "HEAP PEAK", "TREE RSS")
	failed := false
	for _, r := range results {
		status := ""
		if r.Informational {
			status = " INFO"
		} else if r.First >= latencyLimit || r.Worst >= latencyLimit {
			status = " FAIL"
			failed = true
		}
		fmt.Fprintf(out, "%-58s %10s %10s %10s %10s %10s %10s %11s %11s %11s%s\n", r.Method, r.First.Round(time.Microsecond), r.Min.Round(time.Microsecond), r.P50.Round(time.Microsecond), r.P95.Round(time.Microsecond), r.P99.Round(time.Microsecond), r.Worst.Round(time.Microsecond), benchmarkBytes(r.Alloc), benchmarkBytes(r.Heap), benchmarkBytes(r.RSS), status)
	}
	if failed {
		return fmt.Errorf("latency gate failed: one or more operations reached 100ms")
	}
	if appliedEdits.Load() < 4 {
		return fmt.Errorf("server-initiated edit validation failed: observed %d workspace/applyEdit requests, want at least four extraction edits", appliedEdits.Load())
	}
	progress := s.index.Progress()
	fmt.Fprintf(out, "PASS: all %d request/command paths completed below 100ms (%d iterations each); corpus indexed %d source files and %d libraries\n", len(results), *iterations, progress.FilesParsed, progress.LibrariesParsed)
	return nil
}

func waitForBenchmarkCompilerPass(ctx context.Context, s *Server, deadline time.Time) error {
	files, truncated := s.index.WorkspaceFilesContext(ctx, 250000)
	if truncated {
		return fmt.Errorf("compiler benchmark corpus exceeds the 250000-file inspection limit")
	}
	required := make(map[string]bool)
	for _, file := range files {
		lower := strings.ToLower(string(file.URI))
		if strings.HasSuffix(lower, ".java") {
			required["java"] = true
		} else if strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts") {
			required["kotlin"] = true
		}
	}
	for len(required) > 0 && time.Now().Before(deadline) {
		for _, status := range s.index.CompilerStatus() {
			if !required[status.Language] || status.Passes == 0 {
				continue
			}
			if status.LastOutcome != "succeeded" {
				return fmt.Errorf("%s compiler benchmark pass %s: %s", status.Language, status.LastOutcome, status.LastError)
			}
			delete(required, status.Language)
		}
		if len(required) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if len(required) > 0 {
		languages := make([]string, 0, len(required))
		for language := range required {
			languages = append(languages, language)
		}
		sort.Strings(languages)
		return fmt.Errorf("compiler benchmark pass did not succeed for %s before timeout", strings.Join(languages, ", "))
	}
	return nil
}

func benchmarkMixedTypingAndQueries(ctx context.Context, s *Server, fixture benchmarkFixture, iterations int, completion json.RawMessage) (benchmarkResult, error) {
	durations := make([]time.Duration, iterations)
	allocations := make([]uint64, iterations)
	current := fixture.Source
	version := 1
	var heapPeak uint64
	var rssPeak uint64
	for iteration := 0; iteration < iterations; iteration++ {
		next := current
		if strings.HasSuffix(current, "// benchmark edit\n") {
			next = strings.TrimSuffix(current, "// benchmark edit\n")
		} else {
			next += "// benchmark edit\n"
		}
		version++
		params := protocol.DidChangeTextDocumentParams{TextDocument: protocol.VersionedTextDocumentIdentifier{URI: fixture.URI, Version: version}, ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: next}}}
		var memoryBefore, memoryAfter runtime.MemStats
		runtime.ReadMemStats(&memoryBefore)
		begin := time.Now()
		var wait sync.WaitGroup
		wait.Add(1)
		var changeErr error
		go func() {
			defer wait.Done()
			_, changeErr = s.index.Change(ctx, params)
		}()
		result, responseErr := s.Request(ctx, "textDocument/completion", completion)
		wait.Wait()
		durations[iteration] = time.Since(begin)
		runtime.ReadMemStats(&memoryAfter)
		allocations[iteration] = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
		if memoryAfter.HeapAlloc > heapPeak {
			heapPeak = memoryAfter.HeapAlloc
		}
		if rss := processTreeRSSBytes(); rss > rssPeak {
			rssPeak = rss
		}
		if changeErr != nil {
			return benchmarkResult{}, fmt.Errorf("mixed workload edit %d: %w", iteration+1, changeErr)
		}
		if responseErr != nil {
			return benchmarkResult{}, fmt.Errorf("mixed workload completion %d: %s", iteration+1, responseErr.Message)
		}
		if err := validateBenchmarkResult("textDocument/completion", result); err != nil {
			return benchmarkResult{}, fmt.Errorf("mixed workload completion %d: %w", iteration+1, err)
		}
		current = next
	}
	first := durations[0]
	warm := append([]time.Duration(nil), durations...)
	if len(warm) > 1 {
		warm = warm[1:]
	}
	sort.Slice(warm, func(left, right int) bool { return warm[left] < warm[right] })
	var allocationTotal uint64
	for _, allocation := range allocations {
		allocationTotal += allocation
	}
	return benchmarkResult{Method: "mixed: concurrent full-text edit + completion", First: first, Min: warm[0], P50: benchmarkPercentile(warm, 50), P95: benchmarkPercentile(warm, 95), P99: benchmarkPercentile(warm, 99), Worst: warm[len(warm)-1], Alloc: allocationTotal / uint64(len(allocations)), Heap: heapPeak, RSS: rssPeak}, nil
}

func benchmarkIncrementalTypingAndQueries(ctx context.Context, s *Server, fixture benchmarkFixture, iterations int, completion json.RawMessage) (benchmarkResult, error) {
	const marker = "// incremental benchmark edit\n"
	durations := make([]time.Duration, iterations)
	allocations := make([]uint64, iterations)
	var heapPeak uint64
	var rssPeak uint64
	document, ok := s.index.Document(fixture.URI)
	if !ok {
		return benchmarkResult{}, fmt.Errorf("incremental workload fixture disappeared")
	}
	version := document.Version
	for iteration := 0; iteration < iterations; iteration++ {
		document, ok = s.index.Document(fixture.URI)
		if !ok {
			return benchmarkResult{}, fmt.Errorf("incremental workload fixture disappeared at iteration %d", iteration+1)
		}
		start, end, replacement := len(document.Text), len(document.Text), marker
		if strings.HasSuffix(document.Text, marker) {
			start, replacement = len(document.Text)-len(marker), ""
		}
		version++
		change := protocol.TextDocumentContentChangeEvent{Range: &protocol.Range{Start: document.Position(start), End: document.Position(end)}, Text: replacement}
		params := protocol.DidChangeTextDocumentParams{TextDocument: protocol.VersionedTextDocumentIdentifier{URI: fixture.URI, Version: version}, ContentChanges: []protocol.TextDocumentContentChangeEvent{change}}
		var memoryBefore, memoryAfter runtime.MemStats
		runtime.ReadMemStats(&memoryBefore)
		begin := time.Now()
		var wait sync.WaitGroup
		wait.Add(1)
		var changeErr error
		go func() {
			defer wait.Done()
			_, changeErr = s.index.Change(ctx, params)
		}()
		result, responseErr := s.Request(ctx, "textDocument/completion", completion)
		wait.Wait()
		durations[iteration] = time.Since(begin)
		runtime.ReadMemStats(&memoryAfter)
		allocations[iteration] = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
		if memoryAfter.HeapAlloc > heapPeak {
			heapPeak = memoryAfter.HeapAlloc
		}
		if rss := processTreeRSSBytes(); rss > rssPeak {
			rssPeak = rss
		}
		if changeErr != nil {
			return benchmarkResult{}, fmt.Errorf("incremental workload edit %d: %w", iteration+1, changeErr)
		}
		if responseErr != nil {
			return benchmarkResult{}, fmt.Errorf("incremental workload completion %d: %s", iteration+1, responseErr.Message)
		}
		if validateErr := validateBenchmarkResult("textDocument/completion", result); validateErr != nil {
			return benchmarkResult{}, fmt.Errorf("incremental workload completion %d: %w", iteration+1, validateErr)
		}
	}
	first := durations[0]
	warm := append([]time.Duration(nil), durations...)
	if len(warm) > 1 {
		warm = warm[1:]
	}
	sort.Slice(warm, func(left, right int) bool { return warm[left] < warm[right] })
	var allocationTotal uint64
	for _, allocation := range allocations {
		allocationTotal += allocation
	}
	return benchmarkResult{Method: "mixed: incremental edit + concurrent completion", First: first, Min: warm[0], P50: benchmarkPercentile(warm, 50), P95: benchmarkPercentile(warm, 95), P99: benchmarkPercentile(warm, 99), Worst: warm[len(warm)-1], Alloc: allocationTotal / uint64(len(allocations)), Heap: heapPeak, RSS: rssPeak}, nil
}

func benchmarkPercentile(sorted []time.Duration, percentile int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted) - 1) * percentile / 100
	return sorted[index]
}

func benchmarkBytes(value uint64) string {
	if value == 0 {
		return "-"
	}
	if value >= 1<<30 {
		return fmt.Sprintf("%.1fGiB", float64(value)/float64(1<<30))
	}
	if value >= 1<<20 {
		return fmt.Sprintf("%.1fMiB", float64(value)/float64(1<<20))
	}
	if value >= 1<<10 {
		return fmt.Sprintf("%.1fKiB", float64(value)/float64(1<<10))
	}
	return fmt.Sprintf("%dB", value)
}

func benchmarkKotlinCompletionArgs(s *Server, completionParams json.RawMessage) ([]any, error) {
	result, responseErr := s.Request(context.Background(), "textDocument/completion", completionParams)
	if responseErr != nil {
		return nil, fmt.Errorf("prepare Kotlin completion application: %s", responseErr.Message)
	}
	completion, ok := result.(protocol.CompletionList)
	if !ok {
		return nil, fmt.Errorf("prepare Kotlin completion application: result has type %T", result)
	}
	for _, item := range completion.Items {
		if item.Command != nil && item.Command.Command == "jetbrains.kotlin.completion.apply" && len(item.Command.Arguments) == 1 {
			return item.Command.Arguments, nil
		}
	}
	return nil, fmt.Errorf("prepare Kotlin completion application: no applicable completion item")
}

func benchmarkSymbol(s *Server) (protocol.URI, analysis.Symbol, bool) {
	for _, uri := range s.index.AllFiles() {
		symbols := s.index.SymbolsInFile(uri)
		for _, sym := range symbols {
			if !sym.Library && analysis.IsTypeKind(sym.Kind) {
				return uri, sym, true
			}
		}
	}
	return "", analysis.Symbol{}, false
}
func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
func benchmarkCommandArgs(command string, fixture benchmarkFixture) []any {
	switch command {
	case "decompile":
		return []any{fixture.LibraryURI}
	case "applyModCommand":
		return []any{map[string]any{"type": "ChooseAction", "sessionId": 1, "title": "Benchmark", "entries": []any{map[string]any{"index": 0, "name": "Nothing"}}, "actions": []any{map[string]any{"type": "Nothing"}}}}
	case "chooseModCommandAction":
		return []any{1, 0}
	case "interpolateFileTemplate":
		return []any{fixture.URI, "package $PACKAGE_NAME\nclass $NAME"}
	case "set-highwatermark-file":
		return []any{fixture.WatermarkPath}
	case "wait-for-highwatermark":
		return []any{int64(0)}
	case "intellij.java.resolveClassDocument":
		return []any{map[string]any{"fqn": fixture.Symbol.FQN}}
	case "intellij.java.resolveWorkingDirectory":
		return []any{map[string]any{"uri": fixture.URI}}
	case "intellij.java.resolveClasspath", "intellij.java.resolveJavaExecutable":
		return []any{map[string]any{"uri": fixture.URI}}
	case "jetbrains.java.completion.apply":
		return []any{map[string]any{"type": "Nothing"}}
	case "jetbrains.kotlin.completion.apply":
		// Replaced with an ID captured from a live completion session by the
		// benchmark loop. This placeholder is never sent.
		return []any{int64(0)}
	case "java.organize.imports", "kotlin.organize.imports":
		return []any{fixture.URI}
	case "refactor.extract.variable", "refactor.extract.function", "refactor.extract.field", "refactor.extract.constant":
		title := map[string]string{"refactor.extract.variable": "Extract variable", "refactor.extract.function": "Extract function", "refactor.extract.field": "Extract field", "refactor.extract.constant": "Extract constant"}[command]
		return []any{fixture.URI, map[string]any{"type": "Data", "selection": fixture.ExtractRange, "choice": title}}
	case "exportWorkspace":
		return []any{fixture.ExportDir}
	default:
		return []any{}
	}
}

func makeBenchmarkFixture(ctx context.Context, s *Server, workspace string) (benchmarkFixture, func(), error) {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return benchmarkFixture{}, func() {}, fmt.Errorf("resolve benchmark workspace: %w", err)
	}
	exportDir, err := os.MkdirTemp("", "kotlsp-benchmark-")
	if err != nil {
		return benchmarkFixture{}, func() {}, fmt.Errorf("create benchmark directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(exportDir) }
	source := "package kotlsp.benchmark\n\nclass LatencyFixture {\n    fun compute(input: String): Int {\n        val answer = 1 + 2\n        return answer\n    }\n}\n"
	uri := uriutil.File(filepath.Join(root, "LatencyFixture.kt"))
	s.index.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	typeOffset := strings.Index(source, "LatencyFixture")
	extractOffset := strings.Index(source, "1 + 2") + len("1 + ")
	symbol, _, ok := s.index.SymbolAt(uri, doc.Position(typeOffset))
	if !ok || !analysis.IsTypeKind(symbol.Kind) {
		cleanup()
		return benchmarkFixture{}, func() {}, fmt.Errorf("could not create benchmark type fixture")
	}
	libraryURI := protocol.URI("")
	for _, candidate := range s.index.AllFiles() {
		if strings.HasPrefix(string(candidate), "jar:") || strings.HasPrefix(string(candidate), "jrt:") {
			libraryURI = candidate
			break
		}
	}
	if libraryURI == "" {
		cleanup()
		return benchmarkFixture{}, func() {}, fmt.Errorf("library navigation/decompilation fixture is unavailable")
	}
	return benchmarkFixture{
		URI: uri, Symbol: symbol, Position: doc.Position(typeOffset),
		ExtractRange: doc.Range(extractOffset, extractOffset+1), LibraryURI: libraryURI,
		ExportDir: exportDir, WatermarkPath: filepath.Join(exportDir, "watermark"),
		Source: source,
	}, cleanup, nil
}

func validateBenchmarkResult(label string, result any) error {
	requireNonNil := map[string]bool{
		"textDocument/completion": true, "completionItem/resolve": true,
		"textDocument/hover": true, "textDocument/definition": true,
		"textDocument/declaration": true, "textDocument/references": true,
		"textDocument/documentHighlight": true,
		"textDocument/documentSymbol":    true, "workspace/symbol": true,
		"textDocument/codeAction": true, "textDocument/diagnostic": true,
		"textDocument/prepareCallHierarchy": true, "textDocument/prepareTypeHierarchy": true,
		"textDocument/prepareRename": true, "textDocument/rename": true,
		"workspace/willRenameFiles": true,
	}
	if requireNonNil[label] && result == nil {
		return fmt.Errorf("returned a null result for a resolvable fixture")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("result is not JSON serializable: %w", err)
	}
	if requireNonNil[label] && (string(payload) == "null" || string(payload) == "[]" || string(payload) == "{}") {
		return fmt.Errorf("returned an empty result for a resolvable fixture")
	}
	if strings.HasPrefix(label, "workspace/executeCommand:refactor.extract.") && string(payload) != "true" {
		return fmt.Errorf("refactoring command did not report successful application")
	}
	for _, command := range []string{"decompile", "intellij.java.resolveClassDocument", "intellij.java.resolveJavaExecutable", "intellij.java.resolveWorkingDirectory", "intellij.java.resolveClasspath"} {
		if label == "workspace/executeCommand:"+command && (result == nil || string(payload) == "{}") {
			return fmt.Errorf("command returned no resolution data")
		}
	}
	return nil
}
func indexColon(s string) int {
	for n, c := range s {
		if c == ':' {
			return n
		}
	}
	return -1
}
