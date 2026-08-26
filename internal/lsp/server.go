package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/dap"
	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/jsonrpc"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

const latencyLimit = 100 * time.Millisecond

type Server struct {
	ctx                     context.Context
	conn                    *jsonrpc.Conn
	index                   *index.Index
	log                     *log.Logger
	initializeReceived      atomic.Bool
	initialized             atomic.Bool
	shutdown                atomic.Bool
	runMainCodeLens         atomic.Bool
	rootMu                  sync.RWMutex
	roots                   []protocol.URI
	clientCaps              map[string]any
	latencyMu               sync.Mutex
	latency                 map[string]time.Duration
	dap                     *dap.Server
	watermark               atomic.Int64
	watermarkPath           string
	defaultJavaHome         string
	modMu                   sync.Mutex
	modSequence             atomic.Int64
	modSessions             map[int64][]map[string]any
	modSessionCreated       map[int64]time.Time
	completionMu            sync.Mutex
	completionSequence      atomic.Int64
	completionGeneration    atomic.Int64
	completionSessions      map[int64]completionApplication
	progressActive          atomic.Bool
	progressSequence        atomic.Int64
	diagnosticRefreshActive atomic.Bool
	compilerProgressActive  atomic.Bool
	// clientCall is injected by the benchmark and focused unit tests. Production
	// traffic always uses conn; keeping the same request/response contract means
	// server-initiated requests can never be silently treated as successful.
	clientCall func(context.Context, string, any, any) error
	// notify is injected by focused unit tests to observe server-initiated
	// notifications. Production traffic always uses conn.
	notify func(string, any)
	// progressSource is injected by focused unit tests so the progress stream
	// can be driven without waiting on a real workspace scan. Production
	// traffic always reads the index.
	progressSource func() index.Progress
	// compilerStatusSource is injected the same way, so validation reporting
	// can be exercised without a compiler installed.
	compilerStatusSource func() []index.CompilerPassStatus
}

type completionApplication struct {
	Edit       *protocol.WorkspaceEdit
	URI        protocol.URI
	Version    int
	Generation int64
	Created    time.Time
}

const transientSessionTTL = 10 * time.Minute

// completionCandidateLimit bounds one completion response. It is far larger
// than any editor renders at once and small enough that building the items
// stays inside the interaction budget on a full dependency graph.
const completionCandidateLimit = 512

func Serve(ctx context.Context, in io.Reader, out io.Writer, logPath string) error {
	logger := log.New(io.Discard, "", log.LstdFlags|log.Lmicroseconds)
	var closer io.Closer
	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open log: %w", err)
		}
		logger = log.New(f, "kotlsp ", log.LstdFlags|log.Lmicroseconds)
		closer = f
	}
	if closer != nil {
		defer closer.Close()
	}
	s := NewServer(ctx, logger)
	conn := jsonrpc.NewConn(in, out, s)
	s.conn = conn
	defer s.index.Close()
	defer s.closeDAP()
	return conn.Run(ctx)
}

func NewServer(ctx context.Context, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{ctx: ctx, log: logger, latency: make(map[string]time.Duration), modSessions: make(map[int64][]map[string]any), modSessionCreated: make(map[int64]time.Time), completionSessions: make(map[int64]completionApplication)}
	s.watermark.Store(time.Now().UnixMilli())
	s.index = index.New(func(uri protocol.URI, diagnostics []protocol.Diagnostic) {
		if s.conn != nil {
			s.publishDiagnostics(uri, diagnostics)
		}
	})
	// Compiler validation finishes long after the edit that triggered it. A
	// client that pulls diagnostics has to be told to ask again, or the
	// recomputed set is never seen.
	s.index.SetDiagnosticsListener(s.refreshDiagnostics)
	return s
}

func (s *Server) Request(ctx context.Context, method string, params json.RawMessage) (result any, responseErr *jsonrpc.ResponseError) {
	start := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			responseErr = &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: fmt.Sprintf("internal error: %v", recovered)}
			s.log.Printf("panic in %s: %v", method, recovered)
		}
		d := time.Since(start)
		s.latencyMu.Lock()
		if d > s.latency[method] {
			s.latency[method] = d
		}
		s.latencyMu.Unlock()
		if d >= latencyLimit {
			s.log.Printf("LATENCY VIOLATION method=%s elapsed=%s", method, d)
		}
	}()
	if s.shutdown.Load() && method != "exit" {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidRequest, Message: "server has shut down"}
	}
	if method == "initialize" {
		if !s.initializeReceived.CompareAndSwap(false, true) {
			return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidRequest, Message: "initialize may only be requested once"}
		}
		return s.initialize(ctx, params)
	}
	if !s.initialized.Load() {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.ServerNotInitialized, Message: "server has not received the initialized notification"}
	}
	params = s.internalParams(params)
	switch method {
	case "shutdown":
		s.shutdown.Store(true)
		return nil, nil
	case "textDocument/completion":
		return s.completion(params)
	case "completionItem/resolve":
		return s.resolveCompletion(params)
	case "textDocument/hover":
		return s.hover(params)
	case "textDocument/definition":
		return s.definition(params, false)
	case "textDocument/declaration":
		return s.definition(params, false)
	case "textDocument/typeDefinition":
		return s.definition(params, true)
	case "textDocument/implementation":
		return s.implementation(params)
	case "textDocument/references":
		return s.references(params)
	case "textDocument/documentHighlight":
		return s.documentHighlight(params)
	case "textDocument/documentSymbol":
		return s.documentSymbols(params)
	case "workspace/symbol":
		return s.workspaceSymbols(params)
	case "textDocument/formatting":
		return s.formatting(ctx, params)
	case "textDocument/rangeFormatting":
		return s.rangeFormatting(ctx, params)
	case "textDocument/codeAction":
		return s.codeActions(params)
	case "textDocument/diagnostic":
		return s.diagnostic(params)
	case "textDocument/codeLens":
		return s.codeLens(params)
	case "textDocument/foldingRange":
		return s.foldingRanges(params)
	case "textDocument/semanticTokens/full":
		return s.semanticTokens(params, nil)
	case "textDocument/semanticTokens/range":
		return s.semanticTokensRange(params)
	case "textDocument/inlayHint":
		return s.inlayHints(params)
	case "inlayHint/resolve":
		return s.resolveInlayHint(params)
	case "textDocument/signatureHelp":
		return s.signatureHelp(params)
	case "textDocument/prepareCallHierarchy":
		return s.prepareHierarchy(params, false)
	case "callHierarchy/incomingCalls":
		return s.incomingCalls(params)
	case "callHierarchy/outgoingCalls":
		return s.outgoingCalls(params)
	case "textDocument/prepareTypeHierarchy":
		return s.prepareHierarchy(params, true)
	case "typeHierarchy/supertypes":
		return s.typeHierarchy(params, true)
	case "typeHierarchy/subtypes":
		return s.typeHierarchy(params, false)
	case "textDocument/rename":
		return s.rename(params)
	case "textDocument/prepareRename":
		return s.prepareRename(params)
	case "workspace/willRenameFiles":
		return s.willRenameFiles(params)
	case "workspace/executeCommand":
		return s.executeCommand(ctx, params)
	case "kotlsp/status":
		return s.serverStatus()
	default:
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.MethodNotFound, Message: "method not found: " + method}
	}
}

func (s *Server) Notify(ctx context.Context, method string, params json.RawMessage) {
	if method == "exit" {
		s.index.Close()
		if s.conn != nil {
			s.conn.Stop()
		}
		return
	}
	if method == "initialized" {
		if s.initializeReceived.Load() && !s.shutdown.Load() {
			s.initialized.Store(true)
			if s.clientCapabilityBool("workspace", "didChangeWatchedFiles", "dynamicRegistration") {
				go s.registerWatchedFiles()
			}
			s.reportIndexingProgress()
			s.refreshDiagnosticsWhenIndexed()
			s.watchCompilerProgress()
		}
		return
	}
	// LSP notifications sent before the initialized handshake, or after
	// shutdown, are ignored. They must not mutate documents or workspace state.
	if !s.initialized.Load() || s.shutdown.Load() {
		return
	}
	// Mirrored library files are read-only archive views. Their lifecycle
	// notifications are dropped rather than mapped: entering an archive entry
	// into the workspace document set would parse it as project source.
	if s.mirrorsLibraryFile(params) {
		return
	}
	params = s.internalParams(params)
	switch method {
	case "textDocument/didOpen":
		var p protocol.DidOpenTextDocumentParams
		if decode(params, &p) == nil {
			s.index.Open(ctx, p.TextDocument)
			s.markWatermark()
		}
	case "textDocument/didChange":
		var p protocol.DidChangeTextDocumentParams
		if decode(params, &p) == nil {
			if _, err := s.index.Change(ctx, p); err != nil {
				s.log.Printf("didChange: %v", err)
			} else {
				s.markWatermark()
			}
		}
	case "textDocument/didClose":
		var p protocol.DidCloseTextDocumentParams
		if decode(params, &p) == nil {
			s.completionMu.Lock()
			for id, application := range s.completionSessions {
				if application.URI == p.TextDocument.URI {
					delete(s.completionSessions, id)
				}
			}
			s.completionMu.Unlock()
			s.index.CloseDocument(ctx, p.TextDocument.URI)
			s.publishDiagnostics(p.TextDocument.URI, []protocol.Diagnostic{})
		}
	case "textDocument/didSave":
		var p protocol.DidSaveTextDocumentParams
		if decode(params, &p) == nil {
			s.index.Save(ctx, p.TextDocument.URI)
			s.markWatermark()
		}
	case "workspace/didChangeWorkspaceFolders":
		s.changeWorkspaceFolders(params)
	case "workspace/didChangeWatchedFiles":
		s.changedWatchedFiles(params)
	case "$/setTrace":
	}
}

func (s *Server) registerWatchedFiles() {
	watchers := make([]map[string]any, 0, 14)
	for _, pattern := range []string{"**/*.kt", "**/*.kts", "**/*.java", "**/*.jar", "**/build.gradle", "**/build.gradle.kts", "**/settings.gradle", "**/settings.gradle.kts", "**/gradle.properties", "**/pom.xml", "**/MODULE.bazel", "**/WORKSPACE", "**/WORKSPACE.bazel", "**/BUILD", "**/BUILD.bazel", "**/*.bzl"} {
		watchers = append(watchers, map[string]any{"globPattern": pattern, "kind": 7})
	}
	err := s.callClient(s.ctx, "client/registerCapability", map[string]any{"registrations": []any{map[string]any{
		"id": "kotlsp-watch-files", "method": "workspace/didChangeWatchedFiles",
		"registerOptions": map[string]any{"watchers": watchers},
	}}}, nil)
	if err != nil && s.ctx.Err() == nil {
		s.log.Printf("register watched files: %v", err)
	}
}

func (s *Server) markWatermark() {
	s.rootMu.RLock()
	configured := s.watermarkPath != ""
	s.rootMu.RUnlock()
	if configured {
		s.refreshWatermarkFile()
		return
	}
	s.watermark.Store(time.Now().UnixMilli())
}

func (s *Server) refreshWatermarkFile() {
	s.rootMu.RLock()
	path := s.watermarkPath
	s.rootMu.RUnlock()
	if path == "" {
		return
	}
	value := int64(0)
	if info, err := os.Stat(path); err == nil {
		value = info.ModTime().UnixMilli()
	}
	if data, err := os.ReadFile(path); err == nil {
		if parsed, parseErr := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); parseErr == nil && parsed > value {
			value = parsed
		}
	}
	for {
		current := s.watermark.Load()
		if value <= current || s.watermark.CompareAndSwap(current, value) {
			return
		}
	}
}

func (s *Server) initialize(ctx context.Context, raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		RootURI               protocol.URI    `json:"rootUri"`
		RootPath              string          `json:"rootPath"`
		Capabilities          map[string]any  `json:"capabilities"`
		InitializationOptions json.RawMessage `json:"initializationOptions"`
		WorkspaceFolders      []struct {
			URI protocol.URI `json:"uri"`
		} `json:"workspaceFolders"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	roots := make([]protocol.URI, 0, len(p.WorkspaceFolders))
	for _, f := range p.WorkspaceFolders {
		roots = append(roots, f.URI)
	}
	if len(roots) == 0 && p.RootURI != "" {
		roots = append(roots, p.RootURI)
	}
	if len(roots) == 0 && p.RootPath != "" {
		roots = append(roots, uriutil.File(p.RootPath))
	}
	defaultJavaHome := ""
	if len(p.InitializationOptions) > 0 && string(p.InitializationOptions) != "null" {
		var options struct {
			RunMainCodeLens bool   `json:"runMainCodeLens"`
			DefaultSDK      string `json:"defaultSdk"`
			// DiagnosticsTrigger is "change" (default) or "save".
			DiagnosticsTrigger string `json:"diagnosticsTrigger"`
		}
		if json.Unmarshal(p.InitializationOptions, &options) == nil {
			s.runMainCodeLens.Store(options.RunMainCodeLens)
			if strings.EqualFold(options.DiagnosticsTrigger, "save") {
				s.index.SetCompilerTrigger(index.CompilerOnSave)
			}
			if options.DefaultSDK != "" {
				home, err := filepath.Abs(options.DefaultSDK)
				if err != nil {
					return nil, invalidParams(fmt.Errorf("invalid defaultSdk: %w", err))
				}
				if info, statErr := os.Stat(home); statErr != nil || !info.IsDir() {
					return nil, invalidParams(fmt.Errorf("configured Java home does not exist or is not a directory: %s", home))
				}
				defaultJavaHome = filepath.Clean(home)
			}
		}
	}
	s.index.SetDefaultJavaHome(defaultJavaHome)
	s.rootMu.Lock()
	s.roots = roots
	s.clientCaps = p.Capabilities
	s.defaultJavaHome = defaultJavaHome
	s.rootMu.Unlock()
	// Indexing must outlive the initialize request. The JSON-RPC transport
	// cancels each request context as soon as its response is written.
	s.index.Start(s.ctx, roots)
	return map[string]any{"capabilities": serverCapabilities(), "serverInfo": map[string]string{"name": "kotlsp", "version": "0.1.0"}}, nil
}

func serverCapabilities() map[string]any {
	return map[string]any{
		"textDocumentSync":   map[string]any{"openClose": true, "change": 2, "save": map[string]bool{"includeText": false}},
		"completionProvider": map[string]any{"resolveProvider": true, "triggerCharacters": []string{"."}},
		"hoverProvider":      true, "definitionProvider": true, "declarationProvider": true, "typeDefinitionProvider": true, "implementationProvider": true, "referencesProvider": true,
		"documentHighlightProvider": true,
		"documentSymbolProvider":    true, "workspaceSymbolProvider": map[string]any{"resolveProvider": false, "workDoneProgress": true},
		"documentFormattingProvider": true, "documentRangeFormattingProvider": true,
		"codeActionProvider": map[string]any{"codeActionKinds": []string{"quickfix", "refactor", "source.organizeImports", "refactor.extract.variable", "refactor.extract.function", "refactor.extract.field", "refactor.extract.constant", "refactor.inline.variable"}, "resolveProvider": false, "workDoneProgress": false},
		"diagnosticProvider": map[string]any{"interFileDependencies": true, "workspaceDiagnostics": false, "workDoneProgress": false},
		"codeLensProvider":   map[string]any{"resolveProvider": false, "workDoneProgress": false}, "foldingRangeProvider": true,
		"semanticTokensProvider": map[string]any{"legend": map[string]any{"tokenTypes": []string{"namespace", "class", "enum", "interface", "struct", "typeParameter", "type", "parameter", "variable", "property", "enumMember", "event", "function", "method", "macro", "keyword", "modifier", "comment", "string", "number", "regexp", "operator", "decorator"}, "tokenModifiers": []string{"declaration", "definition", "readonly", "static", "deprecated", "abstract", "async", "modification", "documentation", "defaultLibrary"}}, "range": true, "full": true},
		"inlayHintProvider":      map[string]bool{"resolveProvider": true}, "signatureHelpProvider": map[string]any{"triggerCharacters": []string{"(", ","}, "retriggerCharacters": []string{","}, "workDoneProgress": false},
		"callHierarchyProvider": true, "typeHierarchyProvider": true, "renameProvider": map[string]bool{"prepareProvider": true},
		"workspace":              map[string]any{"workspaceFolders": map[string]bool{"supported": true, "changeNotifications": true}, "fileOperations": map[string]any{"willRename": map[string]any{"filters": []any{map[string]any{"pattern": map[string]string{"glob": "**/*"}}}}}},
		"executeCommandProvider": map[string]any{"commands": supportedCommands()},
	}
}

func supportedCommands() []string {
	return []string{"decompile", "applyModCommand", "chooseModCommandAction", "interpolateFileTemplate", "set-highwatermark-file", "wait-for-highwatermark", "start_debug_server", "intellij.java.resolveClassDocument", "intellij.java.resolveClasspath", "intellij.java.resolveJavaExecutable", "intellij.java.resolveWorkingDirectory", "jetbrains.java.completion.apply", "java.organize.imports", "refactor.extract.variable", "refactor.extract.function", "refactor.extract.field", "refactor.extract.constant", "kotlin.organize.imports", "jetbrains.kotlin.completion.apply", "exportWorkspace"}
}

func (s *Server) completion(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	// An unbounded query is proportional to the whole index: on a workspace
	// with a full JVM dependency graph an empty prefix matches tens of
	// thousands of declarations, and formatting them all misses the interaction
	// budget by an order of magnitude. The candidate set is therefore bounded.
	//
	// This loses nothing. The index collects candidates in scope-proximity
	// order and applies the prefix filter before the bound, so the retained
	// candidates are the nearest ones that actually match, and the list is
	// returned as incomplete so the client re-queries as the prefix narrows --
	// which is exactly what `isIncomplete` is for.
	symbols := s.index.Completion(p.TextDocument.URI, p.Position, completionCandidateLimit)
	truncated := len(symbols) >= completionCandidateLimit
	items := make([]protocol.CompletionItem, 0, len(symbols)+40)
	file, _ := s.index.Parsed(p.TextDocument.URI)
	doc, hasDocument := s.index.Document(p.TextDocument.URI)
	annotationOwner := ""
	if hasDocument {
		annotationOwner = index.AnnotationAttributeOwner(doc.Text, doc.Offset(p.Position))
	}
	kotlin := file != nil && file.Language == analysis.LanguageKotlin
	generation := s.completionGeneration.Add(1)
	now := time.Now()
	s.completionMu.Lock()
	for id, application := range s.completionSessions {
		expired := !application.Created.IsZero() && now.Sub(application.Created) > transientSessionTTL
		oldGeneration := application.URI == p.TextDocument.URI && application.Generation < generation-3
		changedVersion := hasDocument && application.URI == p.TextDocument.URI && application.Version != doc.Version
		if expired || oldGeneration || changedVersion {
			delete(s.completionSessions, id)
		}
	}
	snippets := s.clientCapabilityBool("textDocument", "completion", "completionItem", "snippetSupport")
	labelDetails := s.clientCapabilityBool("textDocument", "completion", "completionItem", "labelDetailsSupport")
	javaCanResolveImportEdits := s.clientCompletionResolveProperty("additionalTextEdits")
	for n, sym := range symbols {
		insertName := sym.Name
		if kotlin {
			insertName = kotlinIdentifierInsertion(insertName)
		}
		item := protocol.CompletionItem{Label: sym.Name, Kind: sym.Kind.Completion(), Detail: sym.DisplaySignature(), Documentation: documentation(sym), SortText: fmt.Sprintf("%04d_%s", n, sym.Name), InsertText: insertName, Data: map[string]any{"symbolId": sym.ID, "uri": string(p.TextDocument.URI)}}
		// Two declarations reached by completion routinely share a simple name,
		// and accepting one writes an import. Without the qualified name the
		// list offers no way to tell them apart or to see what will be
		// imported, so it is shown beside the label.
		importEdit, needsImport := s.completionImportIn(p.TextDocument.URI, file, doc, sym)
		if qualified := sym.FQN; qualified != "" && qualified != sym.Name {
			if labelDetails {
				item.LabelDetails = map[string]any{"description": qualified}
			} else if needsImport {
				item.Detail = qualified + " · " + item.Detail
			}
		}
		if snippets && analysis.IsCallableKind(sym.Kind) {
			insertSymbol := sym
			insertSymbol.Name = insertName
			item.InsertText = completionSnippet(insertSymbol)
			item.InsertTextFormat = 2
		}
		ownerName := annotationOwner
		if dot := strings.LastIndexByte(ownerName, '.'); dot >= 0 {
			ownerName = ownerName[dot+1:]
		}
		if annotationOwner != "" && sym.ContainerName == ownerName && analysis.IsCallableKind(sym.Kind) {
			item.InsertText = insertName + " = "
			item.InsertTextFormat = 1
		}
		if sym.Deprecated {
			item.Tags = []int{1}
		}
		if kotlin {
			id := s.completionSequence.Add(1)
			application := completionApplication{URI: p.TextDocument.URI, Generation: generation, Created: now}
			if hasDocument {
				application.Version = doc.Version
			}
			if needsImport {
				workspaceEdit := protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{p.TextDocument.URI: {importEdit}}}
				application.Edit = &workspaceEdit
			}
			s.completionSessions[id] = application
			item.Command = &protocol.Command{Title: "Apply Kotlin completion", Command: "jetbrains.kotlin.completion.apply", Arguments: []any{id}}
			item.Data.(map[string]any)["completionItemId"] = id
		} else {
			item.Command = &protocol.Command{Title: "Apply Java completion", Command: "jetbrains.java.completion.apply", Arguments: []any{map[string]any{"type": "com.jetbrains.ls.kotlinLsp.requests.core.ModCommandData.Nothing"}}}
			if !javaCanResolveImportEdits && needsImport {
				item.AdditionalTextEdits = append(item.AdditionalTextEdits, importEdit)
			}
		}
		items = append(items, item)
	}
	keywords := keywordCompletions(p.TextDocument.URI)
	if hasDocument {
		prefix, qualified := completionKeywordContext(doc.Text, doc.Offset(p.Position))
		filtered := keywords[:0]
		if !qualified {
			for _, keyword := range keywords {
				if prefix == "" || strings.HasPrefix(strings.ToLower(keyword.Label), strings.ToLower(prefix)) {
					filtered = append(filtered, keyword)
				}
			}
		}
		keywords = filtered
	}
	if kotlin {
		for index := range keywords {
			id := s.completionSequence.Add(1)
			application := completionApplication{URI: p.TextDocument.URI, Generation: generation, Created: now}
			if hasDocument {
				application.Version = doc.Version
			}
			s.completionSessions[id] = application
			keywords[index].Command = &protocol.Command{Title: "Apply Kotlin completion", Command: "jetbrains.kotlin.completion.apply", Arguments: []any{id}}
		}
	}
	s.completionMu.Unlock()
	if !kotlin {
		if doc, ok := s.index.Document(p.TextDocument.URI); ok {
			items = append(items, javaTemplateCompletions(doc, p.Position, snippets)...)
			items = append(items, s.javaReferenceCompletions(doc, p.Position)...)
		}
	}
	items = append(items, keywords...)
	return protocol.CompletionList{IsIncomplete: truncated || !s.index.Progress().Ready, Items: items}, nil
}

func completionKeywordContext(source string, offset int) (prefix string, qualified bool) {
	if offset < 0 || offset > len(source) {
		return "", false
	}
	start := offset
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(source[:start])
		if r != utf8.RuneError || size != 1 {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '_' || r == '$' || r == '`' {
				start -= size
				continue
			}
		}
		break
	}
	prefix = source[start:offset]
	index := start - 1
	for index >= 0 && (source[index] == ' ' || source[index] == '\t') {
		index--
	}
	if index >= 0 && source[index] == '.' {
		return prefix, true
	}
	if index >= 1 && source[index] == ':' && source[index-1] == ':' {
		return prefix, true
	}
	return prefix, false
}

func kotlinIdentifierInsertion(name string) string {
	valid := name != "" && !kotlinKeywords[name]
	for index, r := range name {
		if index == 0 {
			valid = valid && (unicode.IsLetter(r) || r == '_')
		} else {
			valid = valid && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '_')
		}
	}
	if valid {
		return name
	}
	return "`" + strings.ReplaceAll(name, "`", "") + "`"
}

var javaLabelPattern = regexp.MustCompile(`(?m)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:for|while|do|switch|\{|try)\b`)

func (s *Server) javaReferenceCompletions(doc *textdoc.Document, position protocol.Position) []protocol.CompletionItem {
	offset := doc.Offset(position)
	start := offset
	for start > 0 {
		value := doc.Text[start-1]
		if value != '_' && value != '$' && value != '.' && (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') && (value < '0' || value > '9') {
			break
		}
		start--
	}
	prefix := doc.Text[start:offset]
	beforePrefix := strings.TrimSpace(doc.Text[:max(0, offset-len(prefix))])
	lastWord := beforePrefix
	if space := strings.LastIndexAny(lastWord, " \t\r\n;{}()"); space >= 0 {
		lastWord = lastWord[space+1:]
	}
	var items []protocol.CompletionItem
	if lastWord == "break" || lastWord == "continue" {
		seen := map[string]bool{}
		for _, match := range javaLabelPattern.FindAllStringSubmatchIndex(doc.Text[:offset], -1) {
			if len(match) < 4 || offset > javaLabeledStatementEnd(doc.Text, match[1]) {
				continue
			}
			name := doc.Text[match[2]:match[3]]
			if !seen[name] && strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				seen[name] = true
				items = append(items, protocol.CompletionItem{Label: name, Kind: protocol.CompletionReference, InsertText: name, SortText: "0000_" + name})
			}
		}
	}
	if lastWord == "requires" {
		for _, name := range s.index.ModuleNames() {
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				items = append(items, protocol.CompletionItem{Label: name, Kind: protocol.CompletionModule, InsertText: name, SortText: "0000_" + name})
			}
		}
	}
	return items
}

func javaLabeledStatementEnd(source string, afterLabel int) int {
	open, semicolon := -1, -1
	for index := afterLabel; index < len(source); index++ {
		switch source[index] {
		case '{':
			open = index
			index = len(source)
		case ';':
			semicolon = index
			index = len(source)
		}
	}
	if open < 0 {
		if semicolon >= 0 {
			return semicolon + 1
		}
		return afterLabel
	}
	depth := 0
	quote := byte(0)
	escaped, lineComment, blockComment := false, false, false
	for index := open; index < len(source); index++ {
		value := source[index]
		if lineComment {
			if value == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if value == '*' && index+1 < len(source) && source[index+1] == '/' {
				blockComment = false
				index++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				quote = 0
			}
			continue
		}
		if value == '/' && index+1 < len(source) && source[index+1] == '/' {
			lineComment = true
			index++
			continue
		}
		if value == '/' && index+1 < len(source) && source[index+1] == '*' {
			blockComment = true
			index++
			continue
		}
		if value == '"' || value == '\'' {
			quote = value
			continue
		}
		if value == '{' {
			depth++
		} else if value == '}' {
			depth--
			if depth == 0 {
				return index + 1
			}
		}
	}
	return len(source)
}

func (s *Server) resolveCompletion(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var item protocol.CompletionItem
	if err := decode(raw, &item); err != nil {
		return nil, invalidParams(err)
	}
	if data, ok := item.Data.(map[string]any); ok {
		if id, ok := data["symbolId"].(string); ok {
			if sym, ok := s.index.Symbol(id); ok {
				item.Detail = sym.DisplaySignature()
				item.Documentation = documentation(sym)
				_, kotlinCommandOwnsImport := data["completionItemId"]
				if sourceURI, ok := data["uri"].(string); ok && !kotlinCommandOwnsImport {
					if edit, needed := s.completionImport(protocol.URI(sourceURI), sym); needed {
						item.AdditionalTextEdits = appendUniqueTextEdit(item.AdditionalTextEdits, edit)
					}
				}
			}
		}
	}
	return item, nil
}

func appendUniqueTextEdit(edits []protocol.TextEdit, edit protocol.TextEdit) []protocol.TextEdit {
	for _, existing := range edits {
		if existing.NewText == edit.NewText && existing.Range == edit.Range {
			return edits
		}
	}
	return append(edits, edit)
}

func (s *Server) completionImport(uri protocol.URI, symbol analysis.Symbol) (protocol.TextEdit, bool) {
	file, ok := s.index.Parsed(uri)
	if !ok {
		return protocol.TextEdit{}, false
	}
	doc, ok := s.index.Document(uri)
	if !ok {
		return protocol.TextEdit{}, false
	}
	return s.completionImportIn(uri, file, doc, symbol)
}

// completionImportIn is the per-candidate form. One completion response asks
// this for every item it returns, so the file and its document are resolved
// once by the caller rather than re-cloned for each candidate.
func (s *Server) completionImportIn(uri protocol.URI, file *analysis.ParsedFile, doc *textdoc.Document, symbol analysis.Symbol) (protocol.TextEdit, bool) {
	if file == nil || doc == nil {
		return protocol.TextEdit{}, false
	}
	if symbol.FQN == "" || symbol.Package == "" || symbol.URI == uri || symbol.ContainerID != "" && !analysis.IsTypeKind(symbol.Kind) {
		return protocol.TextEdit{}, false
	}
	if file.Package == symbol.Package || strings.HasPrefix(symbol.FQN, "java.lang.") || strings.HasPrefix(symbol.FQN, "kotlin.") {
		return protocol.TextEdit{}, false
	}
	for _, imported := range file.Imports {
		if imported.Path == symbol.FQN || imported.Wildcard && imported.Path == symbol.Package {
			return protocol.TextEdit{}, false
		}
	}
	return addImportEdit(doc.Text, uri, symbol.FQN)
}

func (s *Server) hover(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	sym, reference, ok := s.index.SymbolAt(p.TextDocument.URI, p.Position)
	if !ok {
		return nil, nil
	}
	lang := sym.Language.String()
	value := "```" + lang + "\n" + sym.DisplaySignature() + "\n```"
	if sym.Documentation != "" {
		value += "\n\n" + sym.Documentation
	}
	hoverRange := sym.SelectionRange
	if reference != nil {
		hoverRange = reference.Range
	}
	return protocol.Hover{Contents: protocol.MarkupContent{Kind: "markdown", Value: value}, Range: &hoverRange}, nil
}

func (s *Server) definition(raw json.RawMessage, typeDefinition bool) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	var symbols []analysis.Symbol
	if typeDefinition {
		symbols = s.index.TypeDefinitions(p.TextDocument.URI, p.Position)
	} else {
		symbols = s.index.Definitions(p.TextDocument.URI, p.Position)
	}
	result := locations(symbols)
	if !typeDefinition {
		result = append(result, s.index.PackageDefinitions(p.TextDocument.URI, p.Position)...)
	}
	return s.externalLocations(result), nil
}

func (s *Server) implementation(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	return s.externalLocations(locations(s.index.Implementations(p.TextDocument.URI, p.Position))), nil
}

func (s *Server) references(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		protocol.TextDocumentPositionParams
		Context struct {
			IncludeDeclaration bool `json:"includeDeclaration"`
		} `json:"context"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	return s.externalLocations(s.index.References(p.TextDocument.URI, p.Position, p.Context.IncludeDeclaration)), nil
}

func (s *Server) documentHighlight(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	return s.index.DocumentHighlights(p.TextDocument.URI, p.Position), nil
}

func (s *Server) documentSymbols(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	symbols := s.index.SymbolsInFile(p.TextDocument.URI)
	return hierarchicalSymbols(symbols), nil
}

func (s *Server) workspaceSymbols(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		Query string `json:"query"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	// workspace/symbol has no incomplete flag in the negotiated protocol.
	// Return every match rather than presenting a capped list as complete.
	symbols := s.index.WorkspaceSymbols(p.Query, 0)
	out := make([]protocol.SymbolInformation, 0, len(symbols))
	for _, sym := range symbols {
		out = append(out, protocol.SymbolInformation{Name: sym.Name, Kind: sym.Kind.LSP(), Tags: deprecatedTags(sym), Location: s.externalLocation(sym.Location()), ContainerName: sym.ContainerName})
	}
	return out, nil
}

func (s *Server) diagnostic(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument     protocol.TextDocumentIdentifier `json:"textDocument"`
		PreviousResultID string                          `json:"previousResultId"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	file, ok := s.index.Parsed(p.TextDocument.URI)
	if !ok {
		return protocol.FullDocumentDiagnosticReport{Kind: "full", Items: []protocol.Diagnostic{}}, nil
	}
	progress := s.index.Progress()
	resultID := fmt.Sprintf("%x:%d:%d", file.TextHash, progress.FilesParsed+progress.LibrariesParsed, s.index.DiagnosticsVersion())
	if p.PreviousResultID == resultID {
		return map[string]any{"kind": "unchanged", "resultId": resultID}, nil
	}
	items := s.index.Diagnostics(p.TextDocument.URI)
	if items == nil {
		items = []protocol.Diagnostic{}
	}
	return protocol.FullDocumentDiagnosticReport{Kind: "full", ResultID: resultID, Items: items}, nil
}

func (s *Server) foldingRanges(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	file, ok := s.index.Parsed(p.TextDocument.URI)
	if !ok {
		return []protocol.FoldingRange{}, nil
	}
	return file.Folds, nil
}

func (s *Server) semanticTokens(raw json.RawMessage, filter *protocol.Range) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	tokens, textHash, ok := s.index.SemanticTokens(p.TextDocument.URI)
	if !ok {
		return protocol.SemanticTokens{Data: []uint32{}}, nil
	}
	data := encodeSemanticTokens(tokens, filter)
	return protocol.SemanticTokens{ResultID: fmt.Sprintf("%x", textHash), Data: data}, nil
}

func (s *Server) semanticTokensRange(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
		Range        protocol.Range                  `json:"range"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	forward, _ := json.Marshal(struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}{p.TextDocument})
	return s.semanticTokens(forward, &p.Range)
}

func (s *Server) prepareRename(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p protocol.TextDocumentPositionParams
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	sym, ref, ok := s.index.SymbolAt(p.TextDocument.URI, p.Position)
	if !ok || sym.Library || !s.index.Renameable(p.TextDocument.URI, p.Position) {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidRequest, Message: "symbol cannot be renamed"}
	}
	r := sym.SelectionRange
	if ref != nil {
		r = ref.Range
	}
	return map[string]any{"range": r, "placeholder": sym.Name}, nil
}

func (s *Server) rename(raw json.RawMessage) (any, *jsonrpc.ResponseError) {
	var p struct {
		protocol.TextDocumentPositionParams
		NewName string `json:"newName"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, invalidParams(err)
	}
	symbol, _, found := s.index.SymbolAt(p.TextDocument.URI, p.Position)
	if !found || symbol.Library {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidRequest, Message: "symbol cannot be renamed"}
	}
	file, _ := s.index.Parsed(p.TextDocument.URI)
	language := analysis.LanguageJava
	if file != nil {
		language = file.Language
	}
	if !validIdentifierForLanguage(p.NewName, language) {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InvalidParams, Message: "newName is not a valid identifier"}
	}
	edit := s.index.Rename(p.TextDocument.URI, p.Position, p.NewName)
	if symbol.Language == analysis.LanguageKotlin && hasModifier(symbol, "operator") && !kotlinConventionOperatorName(strings.Trim(p.NewName, "`")) {
		if doc, ok := s.index.Document(symbol.URI); ok && symbol.StartByte >= 0 && symbol.NameStartByte <= len(doc.Text) && symbol.StartByte < symbol.NameStartByte {
			prefix := doc.Text[symbol.StartByte:symbol.NameStartByte]
			if relative := strings.Index(prefix, "operator"); relative >= 0 {
				start := symbol.StartByte + relative
				end := start + len("operator")
				for end < symbol.NameStartByte && (doc.Text[end] == ' ' || doc.Text[end] == '\t') {
					end++
				}
				edit.Changes[symbol.URI] = append(edit.Changes[symbol.URI], protocol.TextEdit{Range: doc.Range(start, end), NewText: ""})
			}
		}
	}
	if len(edit.Changes) > 0 {
		uris := make([]string, 0, len(edit.Changes))
		for uri := range edit.Changes {
			uris = append(uris, string(uri))
		}
		sort.Strings(uris)
		for _, rawURI := range uris {
			uri := protocol.URI(rawURI)
			edits := edit.Changes[uri]
			sort.SliceStable(edits, func(left, right int) bool {
				if edits[left].Range.Start.Line != edits[right].Range.Start.Line {
					return edits[left].Range.Start.Line < edits[right].Range.Start.Line
				}
				return edits[left].Range.Start.Character < edits[right].Range.Start.Character
			})
			identifier := protocol.OptionalVersionedTextDocumentIdentifier{URI: uri}
			if doc, ok := s.index.Document(uri); ok {
				version := doc.Version
				identifier.Version = &version
			}
			edit.DocumentChanges = append(edit.DocumentChanges, protocol.TextDocumentEdit{TextDocument: identifier, Edits: edits})
		}
		edit.Changes = nil
	}
	if analysis.IsTypeKind(symbol.Kind) {
		oldName := strings.TrimSuffix(uriutil.Base(symbol.URI), filepath.Ext(uriutil.Base(symbol.URI)))
		newFileName := strings.Trim(p.NewName, "`")
		if oldName == symbol.Name && newFileName != oldName {
			if oldPath, fileURI := uriutil.Path(symbol.URI); fileURI {
				newURI := uriutil.File(filepath.Join(filepath.Dir(oldPath), newFileName+filepath.Ext(oldPath)))
				if s.clientSupportsResourceOperation("rename") {
					edit.DocumentChanges = append(edit.DocumentChanges, protocol.RenameFile{Kind: "rename", OldURI: symbol.URI, NewURI: newURI})
				}
			}
		}
	}
	return edit, nil
}

func kotlinConventionOperatorName(name string) bool {
	switch name {
	case "unaryPlus", "unaryMinus", "not", "inc", "dec",
		"plus", "minus", "times", "div", "rem", "mod", "rangeTo", "rangeUntil",
		"contains", "get", "set", "invoke", "iterator", "hasNext", "next",
		"getValue", "setValue", "provideDelegate", "compareTo", "equals",
		"plusAssign", "minusAssign", "timesAssign", "divAssign", "remAssign",
		"component1", "component2", "component3", "component4", "component5":
		return true
	default:
		return strings.HasPrefix(name, "component") && len(name) > len("component")
	}
}

func (s *Server) clientCapabilityBool(path ...string) bool {
	s.rootMu.RLock()
	var current any = s.clientCaps
	s.rootMu.RUnlock()
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[key]
		if !ok {
			return false
		}
	}
	value, _ := current.(bool)
	return value
}

// clientCapabilityPresent reports whether the client advertised a capability at
// all, for capabilities whose presence is the signal and whose value is an
// object rather than a flag.
func (s *Server) clientCapabilityPresent(path ...string) bool {
	s.rootMu.RLock()
	var current any = s.clientCaps
	s.rootMu.RUnlock()
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[key]
		if !ok || current == nil {
			return false
		}
	}
	return true
}

func (s *Server) clientSupportsResourceOperation(operation string) bool {
	s.rootMu.RLock()
	var current any = s.clientCaps
	s.rootMu.RUnlock()
	for _, key := range []string{"workspace", "workspaceEdit", "resourceOperations"} {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[key]
		if !ok {
			return false
		}
	}
	values, ok := current.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == operation {
			return true
		}
	}
	return false
}

func (s *Server) clientCompletionResolveProperty(property string) bool {
	s.rootMu.RLock()
	var current any = s.clientCaps
	s.rootMu.RUnlock()
	for _, key := range []string{"textDocument", "completion", "completionItem", "resolveSupport", "properties"} {
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = object[key]
		if !ok {
			return false
		}
	}
	values, ok := current.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if text, ok := value.(string); ok && text == property {
			return true
		}
	}
	return false
}

func (s *Server) publishDiagnostics(uri protocol.URI, diagnostics []protocol.Diagnostic) {
	// A client that pulls diagnostics also receiving pushed ones records both,
	// in separate namespaces, and reports every problem twice. The pushed copy
	// is additionally a snapshot of whatever the index knew when the document
	// was parsed, so it keeps reporting names that later became resolvable.
	if s.clientCapabilityPresent("textDocument", "diagnostic") {
		return
	}
	if diagnostics == nil {
		diagnostics = []protocol.Diagnostic{}
	}
	params := map[string]any{"uri": uri, "diagnostics": diagnostics}
	if s.notify != nil {
		s.notify("textDocument/publishDiagnostics", params)
		return
	}
	if s.conn != nil {
		_ = s.conn.Notify("textDocument/publishDiagnostics", params)
	}
}

func (s *Server) changeWorkspaceFolders(raw json.RawMessage) {
	var p struct {
		Event struct {
			Added []struct {
				URI protocol.URI `json:"uri"`
			} `json:"added"`
			Removed []struct {
				URI protocol.URI `json:"uri"`
			} `json:"removed"`
		} `json:"event"`
	}
	if decode(raw, &p) != nil {
		return
	}
	s.rootMu.Lock()
	roots := append([]protocol.URI(nil), s.roots...)
	for _, r := range p.Event.Removed {
		for n := 0; n < len(roots); n++ {
			if roots[n] == r.URI {
				roots = append(roots[:n], roots[n+1:]...)
				n--
			}
		}
	}
	for _, a := range p.Event.Added {
		roots = append(roots, a.URI)
	}
	s.roots = roots
	s.rootMu.Unlock()
	s.index.Start(s.ctx, roots)
	s.reportIndexingProgress()
}

func (s *Server) changedWatchedFiles(raw json.RawMessage) {
	var p struct {
		Changes []struct {
			URI  protocol.URI `json:"uri"`
			Type int          `json:"type"`
		} `json:"changes"`
	}
	if decode(raw, &p) != nil {
		return
	}
	reindex := false
	for _, change := range p.Changes {
		if watchedBuildModelOrLibrary(change.URI) {
			reindex = true
			break
		}
	}
	if reindex {
		s.rootMu.RLock()
		roots := append([]protocol.URI(nil), s.roots...)
		s.rootMu.RUnlock()
		s.index.Start(s.ctx, roots)
		s.markWatermark()
		return
	}
	var pending []<-chan struct{}
	for _, c := range p.Changes {
		if c.Type == 3 {
			if s.index.RemoveClosed(c.URI) {
				s.publishDiagnostics(c.URI, []protocol.Diagnostic{})
			}
		} else {
			pending = append(pending, s.index.Reload(s.ctx, c.URI))
		}
	}
	if len(pending) == 0 {
		s.index.ScheduleCompilerDiagnostics(s.ctx)
		s.markWatermark()
		return
	}
	go func() {
		for _, done := range pending {
			<-done
		}
		s.index.ScheduleCompilerDiagnostics(s.ctx)
		s.markWatermark()
	}()
}

func watchedBuildModelOrLibrary(uri protocol.URI) bool {
	lower := strings.ToLower(filepath.Base(string(uri)))
	if strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".bzl") {
		return true
	}
	switch lower {
	case "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.properties", "pom.xml", "module.bazel", "workspace", "workspace.bazel", "build", "build.bazel":
		return true
	default:
		return false
	}
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	return json.Unmarshal(raw, v)
}
func invalidParams(err error) *jsonrpc.ResponseError {
	return &jsonrpc.ResponseError{Code: jsonrpc.InvalidParams, Message: err.Error()}
}
func locations(symbols []analysis.Symbol) []protocol.Location {
	out := make([]protocol.Location, 0, len(symbols))
	for _, s := range symbols {
		out = append(out, s.Location())
	}
	return out
}
func documentation(sym analysis.Symbol) any {
	if sym.Documentation == "" {
		return nil
	}
	return protocol.MarkupContent{Kind: "markdown", Value: sym.Documentation}
}
func deprecatedTags(sym analysis.Symbol) []int {
	if sym.Deprecated {
		return []int{1}
	}
	return nil
}
func completionSnippet(sym analysis.Symbol) string {
	if len(sym.Parameters) == 0 {
		return sym.Name + "()"
	}
	var b strings.Builder
	b.WriteString(sym.Name)
	b.WriteByte('(')
	for n, p := range sym.Parameters {
		if n > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "${%d:%s}", n+1, p.Name)
	}
	b.WriteString(")$0")
	return b.String()
}
func keywordCompletions(uri protocol.URI) []protocol.CompletionItem {
	words := []string{"class", "interface", "fun", "val", "var", "object", "when", "if", "else", "for", "while", "return", "import", "package", "private", "public", "protected", "internal", "override", "suspend", "data", "sealed", "enum", "typealias", "this", "super", "null", "true", "false"}
	if strings.HasSuffix(strings.ToLower(string(uri)), ".java") {
		words = []string{"class", "interface", "enum", "record", "public", "private", "protected", "static", "final", "abstract", "void", "new", "return", "if", "else", "for", "while", "switch", "try", "catch", "throw", "throws", "extends", "implements", "this", "super", "null", "true", "false"}
	}
	out := make([]protocol.CompletionItem, len(words))
	for n, w := range words {
		out[n] = protocol.CompletionItem{Label: w, Kind: protocol.CompletionKeyword, InsertText: w, SortText: "zz_" + w}
	}
	return out
}
func hierarchicalSymbols(symbols []analysis.Symbol) []protocol.DocumentSymbol {
	children := map[string][]analysis.Symbol{}
	for _, s := range symbols {
		if s.Kind == analysis.KindParameter || s.Kind == analysis.KindVariable || s.Kind == analysis.KindTypeParameter {
			continue
		}
		children[s.ContainerID] = append(children[s.ContainerID], s)
	}
	var build func(string) []protocol.DocumentSymbol
	build = func(parent string) []protocol.DocumentSymbol {
		xs := children[parent]
		sort.SliceStable(xs, func(a, b int) bool { return xs[a].StartByte < xs[b].StartByte })
		out := make([]protocol.DocumentSymbol, 0, len(xs))
		for _, s := range xs {
			out = append(out, protocol.DocumentSymbol{Name: s.Name, Detail: s.Type, Kind: s.Kind.LSP(), Tags: deprecatedTags(s), Range: s.Range, SelectionRange: s.SelectionRange, Children: build(s.ID)})
		}
		return out
	}
	return build("")
}
func encodeSemanticTokens(tokens []analysis.Token, filter *protocol.Range) []uint32 {
	out := make([]uint32, 0, len(tokens)*5)
	prevLine, prevChar := 0, 0
	first := true
	for _, t := range tokens {
		if t.Range.Start.Line != t.Range.End.Line {
			continue
		}
		if filter != nil && (before(t.Range.End, filter.Start) || before(filter.End, t.Range.Start)) {
			continue
		}
		line, char := t.Range.Start.Line, t.Range.Start.Character
		dl, dc := line-prevLine, char
		if !first && dl == 0 {
			dc = char - prevChar
		}
		length := t.Range.End.Character - char
		if length <= 0 {
			continue
		}
		out = append(out, uint32(dl), uint32(dc), uint32(length), t.Type, t.Modifiers)
		prevLine, prevChar = line, char
		first = false
	}
	return out
}
func before(a, b protocol.Position) bool {
	return a.Line < b.Line || (a.Line == b.Line && a.Character < b.Character)
}
func validIdentifierForLanguage(s string, language analysis.Language) bool {
	if s == "" {
		return false
	}
	if language == analysis.LanguageKotlin && strings.HasPrefix(s, "`") && strings.HasSuffix(s, "`") {
		inner := strings.TrimSuffix(strings.TrimPrefix(s, "`"), "`")
		return inner != "" && !strings.ContainsAny(inner, "`\r\n")
	}
	for n, r := range s {
		if !(r == '_' || language == analysis.LanguageJava && r == '$' || unicode.IsLetter(r) || n > 0 && unicode.IsDigit(r)) {
			return false
		}
	}
	if language == analysis.LanguageKotlin {
		return !kotlinKeywords[s]
	}
	return !javaKeywords[s]
}

var kotlinKeywords = map[string]bool{"as": true, "break": true, "class": true, "continue": true, "do": true, "else": true, "false": true, "for": true, "fun": true, "if": true, "in": true, "interface": true, "is": true, "null": true, "object": true, "package": true, "return": true, "super": true, "this": true, "throw": true, "true": true, "try": true, "typealias": true, "typeof": true, "val": true, "var": true, "when": true, "while": true}
var javaKeywords = map[string]bool{"abstract": true, "assert": true, "boolean": true, "break": true, "byte": true, "case": true, "catch": true, "char": true, "class": true, "const": true, "continue": true, "default": true, "do": true, "double": true, "else": true, "enum": true, "extends": true, "final": true, "finally": true, "float": true, "for": true, "goto": true, "if": true, "implements": true, "import": true, "instanceof": true, "int": true, "interface": true, "long": true, "native": true, "new": true, "package": true, "private": true, "protected": true, "public": true, "return": true, "short": true, "static": true, "strictfp": true, "super": true, "switch": true, "synchronized": true, "this": true, "throw": true, "throws": true, "transient": true, "try": true, "void": true, "volatile": true, "while": true, "true": true, "false": true, "null": true, "record": true, "sealed": true, "permits": true, "var": true, "yield": true}

func (s *Server) rootPath() string {
	s.rootMu.RLock()
	defer s.rootMu.RUnlock()
	if len(s.roots) > 0 {
		if p, ok := uriutil.Path(s.roots[0]); ok {
			return p
		}
	}
	p, _ := os.Getwd()
	return p
}
func javaExecutable() string {
	name := "java"
	if runtime.GOOS == "windows" {
		name = "java.exe"
	}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		if p := javaExecutableInHome(home); p != "" {
			return p
		}
	}
	if p, err := os.Executable(); err == nil && strings.Contains(p, "jbr") {
		if executable := javaExecutableInHome(filepath.Dir(filepath.Dir(p))); executable != "" {
			return executable
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
			return resolved
		}
		if absolute, absoluteErr := filepath.Abs(path); absoluteErr == nil {
			return absolute
		}
	}
	return ""
}

func (s *Server) configuredJavaExecutable() string {
	s.rootMu.RLock()
	home := s.defaultJavaHome
	s.rootMu.RUnlock()
	if home != "" {
		return javaExecutableInHome(home)
	}
	return ""
}

func javaExecutableInHome(home string) string {
	name := "java"
	if runtime.GOOS == "windows" {
		name = "java.exe"
	}
	path := filepath.Join(home, "bin", name)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if resolved, resolveErr := filepath.EvalSymlinks(path); resolveErr == nil {
			return resolved
		}
		return path
	}
	return ""
}
