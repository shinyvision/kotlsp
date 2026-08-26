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
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

type benchmarkResult struct {
	Method string
	Min    time.Duration
	P50    time.Duration
	P95    time.Duration
	Worst  time.Duration
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
}

func RunBenchmarkCLI(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(out)
	workspace := fs.String("workspace", ".", "Kotlin/Java workspace to index")
	iterations := fs.Int("iterations", 100, "iterations per LSP request")
	wait := fs.Duration("index-timeout", 2*time.Minute, "maximum wait for background source indexing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iterations < 1 {
		return fmt.Errorf("iterations must be positive")
	}
	root := uriutil.File(*workspace)
	s := NewServer(ctx, log.New(io.Discard, "", 0))
	defer s.index.Close()
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
	fixture, cleanup, err := makeBenchmarkFixture(ctx, s, *workspace)
	if err != nil {
		return err
	}
	defer cleanup()
	uri, sym, pos := fixture.URI, fixture.Symbol, fixture.Position
	item := s.hierarchyItem(sym)
	requests := map[string]json.RawMessage{
		"textDocument/completion":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"completionItem/resolve":            mustJSON(protocol.CompletionItem{Label: sym.Name, Data: map[string]string{"symbolId": sym.ID}}),
		"textDocument/hover":                mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/definition":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/declaration":          mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/typeDefinition":       mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/implementation":       mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/references":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos, "context": map[string]bool{"includeDeclaration": true}}),
		"textDocument/documentHighlight":    mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": pos}),
		"textDocument/documentSymbol":       mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}),
		"workspace/symbol":                  mustJSON(map[string]any{"query": sym.Name}),
		"textDocument/formatting":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "options": map[string]any{"tabSize": 4, "insertSpaces": true}}),
		"textDocument/rangeFormatting":      mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": sym.Range, "options": map[string]any{"tabSize": 4, "insertSpaces": true}}),
		"textDocument/codeAction":           mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": sym.SelectionRange, "context": map[string]any{"diagnostics": []any{}}}),
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
	results = append(results, benchmarkResult{Method: "initialize", Min: initDuration, P50: initDuration, P95: initDuration, Worst: initDuration})
	results = append(results, benchmarkResult{Method: "workspace/indexReady (background lower bound)", Min: indexReadyDuration, P50: indexReadyDuration, P95: indexReadyDuration, Worst: indexReadyDuration, Informational: true})
	methods := make([]string, 0, len(requests))
	for method := range requests {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, label := range methods {
		method := label
		if at := indexColon(label); at >= 0 {
			method = "workspace/executeCommand"
		}
		raw := requests[label]
		durations := make([]time.Duration, *iterations)
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
			begin := time.Now()
			result, responseErr := s.Request(ctx, method, iterationRaw)
			durations[n] = time.Since(begin)
			if responseErr != nil {
				return fmt.Errorf("%s iteration %d returned JSON-RPC error %d: %s", label, n+1, responseErr.Code, responseErr.Message)
			}
			if err := validateBenchmarkResult(label, result); err != nil {
				return fmt.Errorf("%s iteration %d: %w", label, n+1, err)
			}
		}
		sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
		results = append(results, benchmarkResult{Method: label, Min: durations[0], P50: durations[len(durations)/2], P95: durations[(len(durations)-1)*95/100], Worst: durations[len(durations)-1]})
	}
	fmt.Fprintf(out, "%-58s %10s %10s %10s %10s\n", "METHOD", "MIN", "P50", "P95", "WORST")
	failed := false
	for _, r := range results {
		status := ""
		if r.Informational {
			status = " INFO"
		} else if r.Worst >= latencyLimit {
			status = " FAIL"
			failed = true
		}
		fmt.Fprintf(out, "%-58s %10s %10s %10s %10s%s\n", r.Method, r.Min.Round(time.Microsecond), r.P50.Round(time.Microsecond), r.P95.Round(time.Microsecond), r.Worst.Round(time.Microsecond), status)
	}
	if failed {
		return fmt.Errorf("latency gate failed: one or more operations reached 100ms")
	}
	if appliedEdits.Load() < 4 {
		return fmt.Errorf("server-initiated edit validation failed: observed %d workspace/applyEdit requests, want at least four extraction edits", appliedEdits.Load())
	}
	fmt.Fprintf(out, "PASS: all %d request/command paths completed below 100ms (%d iterations each)\n", len(results), *iterations)
	return nil
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
