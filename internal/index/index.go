package index

import (
	"context"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

type Progress struct {
	FilesParsed     int64
	FilesTotal      int64
	LibrariesParsed int64
	LibrariesTotal  int64
	Ready           bool
}

type LibrarySource struct {
	Archive    string
	Entry      string
	LanguageID string
	Binary     bool
}

type LibraryFile struct {
	Source  LibrarySource
	Parsed  analysis.ParsedFile
	Content string
}

type Index struct {
	mu                    sync.RWMutex
	backgroundMu          sync.RWMutex
	interactiveOnce       sync.Once
	interactiveStarted    chan struct{}
	files                 map[protocol.URI]*analysis.ParsedFile
	fileSymbolsByName     map[protocol.URI]map[string][]*analysis.Symbol
	fileSmartCastsByName  map[protocol.URI]map[string][]analysis.SmartCast
	fileAnonymousByName   map[protocol.URI]map[string][]*analysis.Symbol
	docs                  map[protocol.URI]*textdoc.Document
	indexedDocs           map[protocol.URI]*textdoc.Document
	libraryDocs           map[protocol.URI]*textdoc.Document
	librarySources        map[protocol.URI]LibrarySource
	libraryAccess         map[string]map[string]bool
	libraryStringMu       sync.Mutex
	libraryStrings        map[string]string
	librarySymbolSeq      atomic.Uint64
	symbols               map[string]*analysis.Symbol
	byName                map[string][]string
	byFQN                 map[string][]string
	bySuper               map[string][]string
	byContainerName       map[string][]string
	byContainerMember     map[string][]string
	byReceiver            map[string][]string
	byReceiverMember      map[string][]string
	byOrigin              map[string][]string
	byPackage             map[string][]string
	packageChildren       map[string][]string
	packageCounts         map[string]int
	workspaceByName       map[string][]string
	workspaceKnown        map[string]bool
	workspaceNames        []string
	workspaceByChar       map[byte][]string
	workspaceByInitial    map[byte][]string
	workspaceByPrefix     map[string][]string
	completionByName      map[string][]string
	completionKnown       map[string]bool
	completionNames       []string
	completionByInitial   map[byte][]string
	completionByPrefix    map[string][]string
	refsByName            map[string][]analysis.Reference
	packages              map[string][]protocol.URI
	importersByPrefix     map[string][]protocol.URI
	compilerDiagnostics   map[protocol.URI][]protocol.Diagnostic
	roots                 []string
	classpath             []string
	modules               []ModuleInfo
	defaultJavaHome       string
	progress              atomic.Pointer[Progress]
	generation            atomic.Uint64
	compilerRun           atomic.Uint64
	diagnosticsVersion    atomic.Uint64
	documentRevision      map[protocol.URI]uint64
	sourceMirror          librarySourceMirror
	libraryReferenceOrder []protocol.URI
	nextDocumentRevision  uint64
	compilerMu            sync.Mutex
	compilerCancelMu      sync.Mutex
	compilerCancel        context.CancelFunc
	cancel                context.CancelFunc
	onParsed              func(protocol.URI, []protocol.Diagnostic)
}

func (i *Index) DiagnosticsVersion() uint64 { return i.diagnosticsVersion.Load() }

func New(onParsed func(protocol.URI, []protocol.Diagnostic)) *Index {
	i := &Index{files: make(map[protocol.URI]*analysis.ParsedFile), fileSymbolsByName: make(map[protocol.URI]map[string][]*analysis.Symbol), fileSmartCastsByName: make(map[protocol.URI]map[string][]analysis.SmartCast), fileAnonymousByName: make(map[protocol.URI]map[string][]*analysis.Symbol), interactiveStarted: make(chan struct{}), docs: make(map[protocol.URI]*textdoc.Document), indexedDocs: make(map[protocol.URI]*textdoc.Document), libraryDocs: make(map[protocol.URI]*textdoc.Document), librarySources: make(map[protocol.URI]LibrarySource), libraryAccess: make(map[string]map[string]bool), libraryStrings: make(map[string]string), symbols: make(map[string]*analysis.Symbol), byName: make(map[string][]string), byFQN: make(map[string][]string), bySuper: make(map[string][]string), byContainerName: make(map[string][]string), byContainerMember: make(map[string][]string), byReceiver: make(map[string][]string), byReceiverMember: make(map[string][]string), byOrigin: make(map[string][]string), byPackage: make(map[string][]string), packageChildren: make(map[string][]string), packageCounts: make(map[string]int), workspaceByName: make(map[string][]string), workspaceKnown: make(map[string]bool), workspaceByChar: make(map[byte][]string), workspaceByInitial: make(map[byte][]string), workspaceByPrefix: make(map[string][]string), completionByName: make(map[string][]string), completionKnown: make(map[string]bool), completionByInitial: make(map[byte][]string), completionByPrefix: make(map[string][]string), refsByName: make(map[string][]analysis.Reference), packages: make(map[string][]protocol.URI), importersByPrefix: make(map[string][]protocol.URI), compilerDiagnostics: make(map[protocol.URI][]protocol.Diagnostic), documentRevision: make(map[protocol.URI]uint64), onParsed: onParsed}
	i.progress.Store(&Progress{})
	return i
}

func (i *Index) Close() {
	i.cancelCompilerDiagnostics()
	if i.cancel != nil {
		i.cancel()
	}
}

// SetDefaultJavaHome configures the initializationOptions.defaultSdk fallback.
// Build-model-specific toolchains still win for their own modules.
func (i *Index) SetDefaultJavaHome(home string) {
	i.mu.Lock()
	i.defaultJavaHome = filepath.Clean(home)
	if home == "" {
		i.defaultJavaHome = ""
	}
	i.mu.Unlock()
}

func (i *Index) DefaultJavaHome() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.defaultJavaHome
}

func (i *Index) Start(ctx context.Context, roots []protocol.URI) {
	if i.cancel != nil {
		i.cancel()
	}
	generation := i.generation.Add(1)
	i.compilerRun.Add(1)
	scanCtx, cancel := context.WithCancel(ctx)
	i.cancel = cancel
	paths := make([]string, 0, len(roots))
	for _, root := range roots {
		if p, ok := uriutil.Path(root); ok {
			paths = append(paths, p)
		}
	}
	i.mu.Lock()
	openFiles := make([]*analysis.ParsedFile, 0, len(i.docs))
	for uri := range i.docs {
		if parsed := i.files[uri]; parsed != nil {
			openFiles = append(openFiles, parsed)
		}
	}
	i.clearIndexLocked()
	i.roots = paths
	i.classpath = nil
	i.modules = nil
	for _, parsed := range openFiles {
		i.replaceLocked(parsed)
	}
	i.mu.Unlock()
	go i.scan(scanCtx, paths, generation)
}

func (i *Index) clearIndexLocked() {
	i.files = make(map[protocol.URI]*analysis.ParsedFile)
	i.fileSymbolsByName = make(map[protocol.URI]map[string][]*analysis.Symbol)
	i.fileSmartCastsByName = make(map[protocol.URI]map[string][]analysis.SmartCast)
	i.fileAnonymousByName = make(map[protocol.URI]map[string][]*analysis.Symbol)
	i.indexedDocs = make(map[protocol.URI]*textdoc.Document)
	i.libraryDocs = make(map[protocol.URI]*textdoc.Document)
	i.librarySources = make(map[protocol.URI]LibrarySource)
	i.libraryAccess = make(map[string]map[string]bool)
	i.libraryStringMu.Lock()
	i.libraryStrings = make(map[string]string)
	i.libraryStringMu.Unlock()
	i.librarySymbolSeq.Store(0)
	i.symbols = make(map[string]*analysis.Symbol)
	i.byName = make(map[string][]string)
	i.byFQN = make(map[string][]string)
	i.bySuper = make(map[string][]string)
	i.byContainerName = make(map[string][]string)
	i.byContainerMember = make(map[string][]string)
	i.byReceiver = make(map[string][]string)
	i.byReceiverMember = make(map[string][]string)
	i.byOrigin = make(map[string][]string)
	i.byPackage = make(map[string][]string)
	i.packageChildren = make(map[string][]string)
	i.packageCounts = make(map[string]int)
	i.workspaceByName = make(map[string][]string)
	i.workspaceKnown = make(map[string]bool)
	i.workspaceNames = nil
	i.workspaceByChar = make(map[byte][]string)
	i.workspaceByInitial = make(map[byte][]string)
	i.workspaceByPrefix = make(map[string][]string)
	i.completionByName = make(map[string][]string)
	i.completionKnown = make(map[string]bool)
	i.completionNames = nil
	i.completionByInitial = make(map[byte][]string)
	i.completionByPrefix = make(map[string][]string)
	i.refsByName = make(map[string][]analysis.Reference)
	i.packages = make(map[string][]protocol.URI)
	i.importersByPrefix = make(map[string][]protocol.URI)
	i.compilerDiagnostics = make(map[protocol.URI][]protocol.Diagnostic)
}

func (i *Index) Progress() Progress {
	p := i.progress.Load()
	if p == nil {
		return Progress{}
	}
	return *p
}

func (i *Index) Open(ctx context.Context, item protocol.TextDocumentItem) *analysis.ParsedFile {
	i.interactiveOnce.Do(func() { close(i.interactiveStarted) })
	i.backgroundMu.Lock()
	defer i.backgroundMu.Unlock()
	i.cancelCompilerDiagnostics()
	doc := textdoc.NewDocument(item.URI, item.LanguageID, item.Version, item.Text)
	parsed := analysis.Parse(ctx, doc)
	i.mu.Lock()
	_, libraryDocument := i.librarySources[item.URI]
	parsed = recoverDeclarations(parsed, i.files[item.URI], doc.Text)
	if libraryDocument {
		for symbol := range parsed.Symbols {
			parsed.Symbols[symbol].Library = true
		}
	}
	i.docs[item.URI] = doc
	i.nextDocumentRevision++
	i.documentRevision[item.URI] = i.nextDocumentRevision
	delete(i.indexedDocs, item.URI)
	i.replaceLocked(parsed)
	i.mu.Unlock()
	if i.onParsed != nil {
		i.onParsed(item.URI, i.Diagnostics(item.URI))
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed
}

func (i *Index) Change(ctx context.Context, params protocol.DidChangeTextDocumentParams) (*analysis.ParsedFile, error) {
	i.interactiveOnce.Do(func() { close(i.interactiveStarted) })
	i.backgroundMu.Lock()
	defer i.backgroundMu.Unlock()
	i.cancelCompilerDiagnostics()
	i.mu.RLock()
	old := i.docs[params.TextDocument.URI]
	previousParsed := i.files[params.TextDocument.URI]
	if old != nil {
		old = old.Clone()
	}
	i.mu.RUnlock()
	if old == nil {
		return nil, errors.New("document is not open")
	}
	previousText := old.Text
	if err := old.Apply(params.TextDocument.Version, params.ContentChanges); err != nil {
		return nil, err
	}
	if old.Text == previousText && previousParsed != nil {
		updated := *previousParsed
		updated.Version = params.TextDocument.Version
		i.mu.Lock()
		i.docs[old.URI] = old
		i.files[old.URI] = &updated
		i.mu.Unlock()
		if i.onParsed != nil {
			i.onParsed(old.URI, i.Diagnostics(old.URI))
		}
		return &updated, nil
	}
	parsed := analysis.Parse(ctx, old)
	parsed = recoverDeclarations(parsed, previousParsed, old.Text)
	i.mu.Lock()
	i.docs[old.URI] = old
	i.replaceLocked(parsed)
	i.mu.Unlock()
	if i.onParsed != nil {
		i.onParsed(old.URI, i.Diagnostics(old.URI))
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed, nil
}

// recoverDeclarations retains declarations from the last valid snapshot when
// a transient edit (most commonly a trailing '.') makes the grammar collapse
// an enclosing subtree. A declaration is reused only if its exact name still
// occupies the same bytes, preventing stale names from leaking after edits.
func recoverDeclarations(current, previous *analysis.ParsedFile, source string) *analysis.ParsedFile {
	if current == nil || previous == nil || len(current.Diagnostics) == 0 || len(current.Symbols) >= len(previous.Symbols) {
		return current
	}
	seen := make(map[string]bool, len(current.Symbols))
	for _, symbol := range current.Symbols {
		seen[symbol.ID] = true
	}
	for _, symbol := range previous.Symbols {
		if seen[symbol.ID] || symbol.NameStartByte < 0 || symbol.NameEndByte > len(source) || symbol.NameStartByte >= symbol.NameEndByte {
			continue
		}
		if strings.Trim(source[symbol.NameStartByte:symbol.NameEndByte], "`") != symbol.Name {
			continue
		}
		current.Symbols = append(current.Symbols, symbol)
	}
	sort.SliceStable(current.Symbols, func(a, b int) bool { return current.Symbols[a].StartByte < current.Symbols[b].StartByte })
	return current
}

func (i *Index) CloseDocument(ctx context.Context, uri protocol.URI) {
	// Invalidate any compiler run which captured the discarded unsaved buffer.
	i.compilerRun.Add(1)
	i.mu.Lock()
	delete(i.docs, uri)
	revision := i.documentRevision[uri]
	i.mu.Unlock()
	path, ok := uriutil.Path(uri)
	if !ok {
		return
	}
	go func() {
		data, err := os.ReadFile(path)
		if err != nil {
			i.removeClosedRevision(uri, revision)
			if i.onParsed != nil {
				i.onParsed(uri, nil)
			}
			i.ScheduleCompilerDiagnostics(ctx)
			return
		}
		doc := textdoc.NewDocument(uri, uriutil.LanguageID(path), 0, string(data))
		parsed := analysis.Parse(ctx, doc)
		i.mu.Lock()
		if i.docs[uri] != nil || i.documentRevision[uri] != revision {
			i.mu.Unlock()
			return
		}
		i.indexedDocs[uri] = doc
		i.replaceLocked(parsed)
		i.mu.Unlock()
		if i.onParsed != nil {
			i.onParsed(uri, i.Diagnostics(uri))
		}
		i.ScheduleCompilerDiagnostics(ctx)
	}()
}

// Reload refreshes a closed workspace document after a file-watcher event.
// Open buffers remain authoritative until didClose. The returned channel is
// closed only after the replacement index is observable, allowing protocol
// high-watermarks to describe completed work rather than queued work.
func (i *Index) Reload(ctx context.Context, uri protocol.URI) <-chan struct{} {
	done := make(chan struct{})
	i.mu.RLock()
	_, open := i.docs[uri]
	revision := i.documentRevision[uri]
	i.mu.RUnlock()
	if open {
		close(done)
		return done
	}
	path, ok := uriutil.Path(uri)
	if !ok || !isSource(path) {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		data, err := os.ReadFile(path)
		if err != nil {
			i.removeClosedRevision(uri, revision)
			return
		}
		doc := textdoc.NewDocument(uri, uriutil.LanguageID(path), 0, string(data))
		parsed := analysis.Parse(ctx, doc)
		i.mu.Lock()
		if i.docs[uri] != nil || i.documentRevision[uri] != revision {
			i.mu.Unlock()
			return
		}
		i.indexedDocs[uri] = doc
		i.replaceLocked(parsed)
		i.mu.Unlock()
		if i.onParsed != nil {
			i.onParsed(uri, i.Diagnostics(uri))
		}
	}()
	return done
}

// Remove evicts every declaration and reference belonging to a deleted file.
func (i *Index) Remove(uri protocol.URI) {
	i.mu.Lock()
	i.removeLocked(uri)
	i.mu.Unlock()
}

// RemoveClosed applies a filesystem deletion only when no editor buffer owns
// the URI. A watched delete can race didOpen and must not discard unsaved text.
func (i *Index) RemoveClosed(uri protocol.URI) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.docs[uri] != nil {
		return false
	}
	i.removeLocked(uri)
	return true
}

func (i *Index) removeClosedRevision(uri protocol.URI, revision uint64) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.docs[uri] != nil || i.documentRevision[uri] != revision {
		return false
	}
	i.removeLocked(uri)
	return true
}

func (i *Index) removeLocked(uri protocol.URI) {
	if old := i.files[uri]; old != nil {
		i.removeFileContentsLocked(old)
	}
	delete(i.files, uri)
	delete(i.docs, uri)
	delete(i.indexedDocs, uri)
	delete(i.libraryDocs, uri)
	delete(i.librarySources, uri)
}

func (i *Index) Save(ctx context.Context, uri protocol.URI) {
	i.mu.RLock()
	_, open := i.docs[uri]
	i.mu.RUnlock()
	if !open {
		return
	}
	// didOpen/didChange already synchronously publish an indexed snapshot. A
	// save does not alter that authoritative text, so reparsing it would create
	// an avoidable race where the save watermark preceded replacement.
	i.ScheduleCompilerDiagnostics(ctx)
}

func (i *Index) Document(uri protocol.URI) (*textdoc.Document, bool) {
	i.mu.RLock()
	if d := i.docs[uri]; d != nil {
		clone := d.Clone()
		i.mu.RUnlock()
		return clone, true
	}
	if d := i.libraryDocs[uri]; d != nil {
		clone := d.Clone()
		i.mu.RUnlock()
		return clone, true
	}
	if d := i.indexedDocs[uri]; d != nil {
		clone := d.Clone()
		i.mu.RUnlock()
		return clone, true
	}
	source, library := i.librarySources[uri]
	i.mu.RUnlock()
	if library {
		document, err := loadLibraryDocument(uri, source)
		if err == nil {
			i.mu.Lock()
			if current, exists := i.librarySources[uri]; exists && current == source {
				i.libraryDocs[uri] = document
			}
			clone := document.Clone()
			i.mu.Unlock()
			return clone, true
		}
	}
	return nil, false
}

func (i *Index) Parsed(uri protocol.URI) (*analysis.ParsedFile, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	p, ok := i.files[uri]
	return p, ok
}

func (i *Index) Symbol(id string) (analysis.Symbol, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	s, ok := i.symbols[id]
	if !ok {
		return analysis.Symbol{}, false
	}
	return *s, true
}

// SymbolsByFQN returns declarations whose fully-qualified name exactly matches
// fqn. The returned slice is detached from the index and safe for callers to
// retain while background indexing continues.
func (i *Index) SymbolsByFQN(fqn string) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.symbolsForIDsLocked(i.byFQN[fqn], nil)
}

// Classpath returns the binary compile classpath discovered from the workspace
// build. Source archives used for navigation are intentionally not included.
func (i *Index) Classpath() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return append([]string(nil), i.classpath...)
}

func (i *Index) ModuleNames() []string {
	i.mu.RLock()
	seen := make(map[string]bool)
	for uri, document := range i.docs {
		if strings.HasSuffix(strings.ToLower(string(uri)), "module-info.java") {
			if name := declaredJavaModuleName(document.Text); name != "" {
				seen[name] = true
			}
		}
	}
	for uri, document := range i.indexedDocs {
		if strings.HasSuffix(strings.ToLower(string(uri)), "module-info.java") {
			if name := declaredJavaModuleName(document.Text); name != "" {
				seen[name] = true
			}
		}
	}
	i.mu.RUnlock()
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func declaredJavaModuleName(source string) string {
	for at := 0; at < len(source); {
		relative := strings.Index(source[at:], "module")
		if relative < 0 {
			return ""
		}
		start := at + relative
		if start > 0 && isIdentRune(rune(source[start-1])) || start+len("module") < len(source) && isIdentRune(rune(source[start+len("module")])) {
			at = start + len("module")
			continue
		}
		nameStart := start + len("module")
		for nameStart < len(source) && unicode.IsSpace(rune(source[nameStart])) {
			nameStart++
		}
		nameEnd := nameStart
		for nameEnd < len(source) && (isIdentRune(rune(source[nameEnd])) || source[nameEnd] == '.') {
			nameEnd++
		}
		return strings.Trim(source[nameStart:nameEnd], ".")
	}
	return ""
}

func (i *Index) SymbolAt(uri protocol.URI, pos protocol.Position) (analysis.Symbol, *analysis.Reference, bool) {
	doc, ok := i.Document(uri)
	if !ok {
		return analysis.Symbol{}, nil, false
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return analysis.Symbol{}, nil, false
	}
	for _, s := range file.Symbols {
		if offset >= s.NameStartByte && offset < s.NameEndByte {
			return s, nil, true
		}
	}
	for n := range file.References {
		r := &file.References[n]
		if offset >= r.StartByte && offset < r.EndByte {
			resolved := i.resolveLocked(file, *r)
			if len(resolved) > 0 {
				return resolved[0], r, true
			}
		}
	}
	// Editors commonly place the cursor immediately after an identifier. Keep
	// that convenience only as a fallback, after testing the end-exclusive LSP
	// ranges so adjacent punctuation conventions such as box[0] win.
	for _, s := range file.Symbols {
		if offset == s.NameEndByte && offset >= s.NameStartByte {
			return s, nil, true
		}
	}
	for n := range file.References {
		r := &file.References[n]
		if offset == r.EndByte && offset >= r.StartByte {
			resolved := i.resolveLocked(file, *r)
			if len(resolved) > 0 {
				return resolved[0], r, true
			}
		}
	}
	return analysis.Symbol{}, nil, false
}

func (i *Index) Definitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	if resolved, handled := i.springDataDefinitionLocked(file, offset); handled {
		return resolved
	}
	for _, s := range file.Symbols {
		if offset >= s.NameStartByte && offset < s.NameEndByte {
			return []analysis.Symbol{s}
		}
	}
	for _, r := range file.References {
		if offset >= r.StartByte && offset < r.EndByte {
			if resolved := i.resolveLocked(file, r); len(resolved) > 0 {
				return resolved
			}
		}
	}
	for _, s := range file.Symbols {
		if offset == s.NameEndByte && offset >= s.NameStartByte {
			return []analysis.Symbol{s}
		}
	}
	for _, r := range file.References {
		if offset == r.EndByte && offset >= r.StartByte {
			if resolved := i.resolveLocked(file, r); len(resolved) > 0 {
				return resolved
			}
		}
	}
	return nil
}

// CallSignatures returns the complete overload family and the best active
// signature at a call site. Constructor navigation intentionally targets the
// class, while signature help exposes all constructors and selects one.
func (i *Index) CallSignatures(uri protocol.URI, pos protocol.Position) ([]analysis.Symbol, int) {
	doc, ok := i.Document(uri)
	if !ok {
		return nil, 0
	}
	i.ensureLibraryReferences(uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil, 0
	}
	var reference *analysis.Reference
	for index := range file.References {
		candidate := &file.References[index]
		if candidate.Role == analysis.RoleCall && (candidate.StartByte <= offset && offset <= candidate.EndByte) {
			reference = candidate
			break
		}
	}
	if reference == nil {
		return nil, 0
	}
	resolved := i.resolveLocked(file, *reference)
	candidates := make([]analysis.Symbol, 0, len(resolved)+2)
	seen := make(map[string]bool)
	appendCandidate := func(symbol *analysis.Symbol) {
		if symbol != nil && analysis.IsCallableKind(symbol.Kind) && i.accessibleLocked(file, *symbol, reference.StartByte) && !seen[symbol.ID] {
			seen[symbol.ID] = true
			candidates = append(candidates, *symbol)
		}
	}
	for _, symbol := range resolved {
		if analysis.IsTypeKind(symbol.Kind) {
			for _, id := range i.byContainerMember[memberKey(symbol.Name, symbol.Name)] {
				constructor := i.symbols[id]
				if constructor != nil && constructor.Kind == analysis.KindConstructor && constructor.ContainerID == symbol.ID {
					appendCandidate(constructor)
				}
			}
			continue
		}
		if !analysis.IsCallableKind(symbol.Kind) {
			continue
		}
		if symbol.ContainerID != "" {
			for _, id := range i.byContainerMember[memberKey(symbol.ContainerName, symbol.Name)] {
				candidate := i.symbols[id]
				if candidate != nil && candidate.ContainerID == symbol.ContainerID && candidate.Kind == symbol.Kind {
					appendCandidate(candidate)
				}
			}
		} else if symbol.FQN != "" {
			for _, id := range i.byFQN[symbol.FQN] {
				appendCandidate(i.symbols[id])
			}
		} else {
			appendCandidate(i.symbols[symbol.ID])
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}
	sortSymbols(candidates)
	active := 0
	if len(candidates) == 1 {
		return candidates, active
	}
	scores := make([]int, len(candidates))
	best, typed := -1<<30, false
	for index, candidate := range candidates {
		score, hasTypes := i.callCompatibilityLocked(file, *reference, candidate)
		scores[index] = score
		if hasTypes {
			if !typed || score > best {
				typed = true
				best = score
				active = index
			}
		}
	}
	if !typed {
		best = scores[0]
		for index := 1; index < len(scores); index++ {
			if scores[index] > best {
				best, active = scores[index], index
			}
		}
	}
	return candidates, active
}

// PackageDefinitions mirrors IntelliJ's Java/Kotlin package providers: a
// package reference navigates to each workspace directory containing files in
// that exact package. Library packages are deliberately excluded.
func (i *Index) PackageDefinitions(uri protocol.URI, pos protocol.Position) []protocol.Location {
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	offset := doc.Offset(pos)
	start := strings.LastIndexByte(doc.Text[:offset], '\n') + 1
	end := len(doc.Text)
	if newline := strings.IndexByte(doc.Text[offset:], '\n'); newline >= 0 {
		end = offset + newline
	}
	line := doc.Text[start:end]
	trimmed := strings.TrimLeft(line, " \t")
	indent := len(line) - len(trimmed)
	keyword := ""
	switch {
	case strings.HasPrefix(trimmed, "package "):
		keyword = "package"
	case strings.HasPrefix(trimmed, "import "):
		keyword = "import"
	default:
		return nil
	}
	qualifiedStart := indent + len(keyword)
	for qualifiedStart < len(line) && (line[qualifiedStart] == ' ' || line[qualifiedStart] == '\t') {
		qualifiedStart++
	}
	if keyword == "import" && strings.HasPrefix(line[qualifiedStart:], "static ") {
		qualifiedStart += len("static ")
	}
	relative := offset - start
	if relative < qualifiedStart || relative > len(line) {
		return nil
	}
	if relative == len(line) || relative > qualifiedStart && !isIdentRune(rune(line[relative])) {
		relative--
	}
	if relative < qualifiedStart || !isIdentRune(rune(line[relative])) {
		return nil
	}
	tokenEnd := relative + 1
	for tokenEnd < len(line) && isIdentRune(rune(line[tokenEnd])) {
		tokenEnd++
	}
	qualified := strings.ReplaceAll(strings.Trim(line[qualifiedStart:tokenEnd], "."), "`", "")
	i.mu.RLock()
	directories := append([]protocol.URI(nil), i.packages[qualified]...)
	i.mu.RUnlock()
	locations := make([]protocol.Location, 0, len(directories))
	for _, directory := range directories {
		locations = append(locations, protocol.Location{URI: directory, Range: protocol.Range{}})
	}
	return locations
}

func (i *Index) TypeDefinitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	s, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	if analysis.IsTypeKind(s.Kind) {
		return []analysis.Symbol{s}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[s.URI]
	if file == nil {
		return nil
	}
	typ := s.Type
	if typ == "" || typ == "var" || typ == "val" {
		typ = i.inferExpressionTypeLocked(file, s.Initializer, s.StartByte)
	}
	if typ == "" {
		return nil
	}
	return i.resolveTypeSymbolsLocked(file, typ)
}

func (i *Index) Implementations(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []analysis.Symbol
	if containsString(target.Modifiers, "expect") || i.containerHasKotlinModifierLocked(target, "expect") {
		for _, counterpart := range i.expectActualFamilyLocked(target) {
			if counterpart.ID != target.ID && (containsString(counterpart.Modifiers, "actual") || i.containerHasKotlinModifierLocked(counterpart, "actual")) {
				out = append(out, counterpart)
			}
		}
	}
	if analysis.IsTypeKind(target.Kind) {
		queue := []analysis.Symbol{target}
		seen := map[string]bool{}
		for len(queue) > 0 {
			parent := queue[0]
			queue = queue[1:]
			ids := append([]string(nil), i.bySuper[parent.Name]...)
			ids = append(ids, i.bySuper[parent.FQN]...)
			for _, id := range ids {
				if seen[id] {
					continue
				}
				if candidate, ok := i.symbols[id]; ok {
					if !i.directSupertypeMatchesLocked(*candidate, parent.ID) {
						continue
					}
					seen[id] = true
					out = append(out, *candidate)
					queue = append(queue, *candidate)
				}
			}
		}
	}
	if analysis.IsCallableKind(target.Kind) {
		for _, id := range i.byName[target.Name] {
			candidate, ok := i.symbols[id]
			if ok && analysis.IsCallableKind(candidate.Kind) && sameCallableShape(*candidate, target) && candidate.ContainerID != target.ContainerID && i.containerInheritsLocked(candidate.ContainerID, target.ContainerID) {
				out = append(out, *candidate)
			}
		}
	}
	sortSymbols(out)
	return out
}

func (i *Index) References(uri protocol.URI, pos protocol.Position, includeDeclaration bool) []protocol.Location {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	family := i.referenceFamilyLocked(target)
	out := make([]protocol.Location, 0)
	if includeDeclaration {
		for _, member := range family {
			out = append(out, member.Location())
		}
	}
	for _, member := range family {
		for _, r := range i.refsByName[member.Name] {
			if r.ResolvedID != "" {
				if r.ResolvedID == member.ID {
					out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
				}
				continue
			}
			file := i.files[r.URI]
			if file == nil {
				continue
			}
			resolved := i.resolveLocked(file, r)
			for _, s := range resolved {
				if s.ID == member.ID {
					out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
					break
				}
			}
		}
	}
	return uniqueLocations(out)
}

func (i *Index) referenceFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	origin := target
	if target.OriginID != "" {
		if value, ok := i.symbols[target.OriginID]; ok {
			origin = *value
		}
	}
	family := []analysis.Symbol{origin}
	for _, id := range i.byOrigin[origin.ID] {
		if symbol, ok := i.symbols[id]; ok {
			family = append(family, *symbol)
		}
	}
	for _, counterpart := range i.expectActualFamilyLocked(origin) {
		if counterpart.ID != origin.ID {
			family = append(family, counterpart)
			for _, id := range i.byOrigin[counterpart.ID] {
				if symbol, ok := i.symbols[id]; ok {
					family = append(family, *symbol)
				}
			}
		}
	}
	if analysis.IsCallableKind(origin.Kind) && origin.ContainerID != "" {
		for _, id := range i.byName[origin.Name] {
			candidate, ok := i.symbols[id]
			if !ok || candidate.ID == origin.ID || candidate.ContainerID == "" || !analysis.IsCallableKind(candidate.Kind) || !sameCallableShape(*candidate, origin) {
				continue
			}
			if i.containerInheritsLocked(candidate.ContainerID, origin.ContainerID) || i.containerInheritsLocked(origin.ContainerID, candidate.ContainerID) {
				family = append(family, *candidate)
			}
		}
	}
	property, bean := beanPropertyName(origin.Name)
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		property, bean = origin.Name, true
	}
	if bean && origin.ContainerID != "" {
		stem := property
		if stem != "" && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		for _, name := range []string{property, "get" + stem, "is" + stem, "set" + stem} {
			for _, id := range i.byContainerMember[memberKey(origin.ContainerName, name)] {
				candidate := i.symbols[id]
				if candidate.ContainerID == origin.ContainerID {
					family = append(family, *candidate)
				}
			}
		}
	}
	return uniqueSymbols(family)
}

func (i *Index) expectActualFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	if target.Language != analysis.LanguageKotlin || target.FQN == "" {
		return nil
	}
	targetMarked := containsString(target.Modifiers, "expect") || containsString(target.Modifiers, "actual")
	if !targetMarked && target.ContainerID != "" {
		targetMarked = i.containerHasKotlinModifierLocked(target, "expect") || i.containerHasKotlinModifierLocked(target, "actual")
	}
	if !targetMarked {
		return nil
	}
	targetModule := i.moduleForURILocked(target.URI)
	result := []analysis.Symbol{target}
	for _, id := range i.byFQN[target.FQN] {
		candidate, ok := i.symbols[id]
		if !ok || candidate.ID == target.ID || candidate.Language != analysis.LanguageKotlin || candidate.Kind != target.Kind {
			continue
		}
		if analysis.IsCallableKind(target.Kind) && !sameCallableShape(*candidate, target) {
			continue
		}
		candidateMarked := containsString(candidate.Modifiers, "expect") || containsString(candidate.Modifiers, "actual") || i.containerHasKotlinModifierLocked(*candidate, "expect") || i.containerHasKotlinModifierLocked(*candidate, "actual")
		if !candidateMarked {
			continue
		}
		candidateModule := i.moduleForURILocked(candidate.URI)
		if targetModule != nil && candidateModule != nil && (targetModule.Name != candidateModule.Name || targetModule.Dir != candidateModule.Dir) {
			continue
		}
		result = append(result, *candidate)
	}
	return uniqueSymbols(result)
}

func (i *Index) containerHasKotlinModifierLocked(symbol analysis.Symbol, modifier string) bool {
	for containerID := symbol.ContainerID; containerID != ""; {
		container, ok := i.symbols[containerID]
		if !ok {
			return false
		}
		if containsString(container.Modifiers, modifier) {
			return true
		}
		containerID = container.ContainerID
	}
	return false
}

func (i *Index) SymbolsInFile(uri protocol.URI) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	f := i.files[uri]
	if f == nil {
		return nil
	}
	out := make([]analysis.Symbol, 0, len(f.Symbols))
	for _, symbol := range f.Symbols {
		if !symbol.Synthetic {
			out = append(out, symbol)
		}
	}
	return out
}

func (i *Index) WorkspaceSymbols(query string, limit int) []analysis.Symbol {
	limited := limit > 0
	q := strings.ToLower(query)
	type scored struct {
		s     analysis.Symbol
		score int
	}
	var all []scored
	i.mu.RLock()
	if ids := i.workspaceByName[query]; len(ids) > 0 {
		exact := make([]analysis.Symbol, 0, len(ids))
		for _, id := range ids {
			if symbol, ok := i.symbols[id]; ok {
				exact = append(exact, *symbol)
			}
		}
		i.mu.RUnlock()
		sortSymbols(exact)
		if limited && len(exact) > limit {
			exact = exact[:limit]
		}
		return exact
	}
	names := i.workspaceNames
	if len(q) > 0 && q[0] < 128 {
		// Fuzzy queries may match after the first character (e.g. "NPE" ->
		// NullPointerException), so use the any-position character bucket.
		names = i.workspaceByChar[q[0]]
	}
	for _, name := range names {
		if limited && len(all) >= limit*8 {
			break
		}
		if len(i.workspaceByName[name]) == 0 {
			continue
		}
		score := fuzzyScore(strings.ToLower(name), q)
		if score >= 0 {
			ids := i.workspaceByName[name]
			for _, id := range ids {
				if symbol, ok := i.symbols[id]; ok {
					all = append(all, scored{*symbol, score})
				}
				if limited && len(all) >= limit*8 {
					break
				}
			}
		}
	}
	i.mu.RUnlock()
	sort.SliceStable(all, func(a, b int) bool {
		if all[a].score == all[b].score {
			return all[a].s.FQN < all[b].s.FQN
		}
		return all[a].score > all[b].score
	})
	if limited && len(all) > limit {
		all = all[:limit]
	}
	out := make([]analysis.Symbol, len(all))
	for n := range all {
		out[n] = all[n].s
	}
	return out
}

func (i *Index) Completion(uri protocol.URI, pos protocol.Position, limit int) []analysis.Symbol {
	limited := limit > 0
	doc, ok := i.Document(uri)
	if !ok {
		return nil
	}
	offset := doc.Offset(pos)
	prefix, qualifier := completionContext(doc.Text, offset)
	annotationOwner := AnnotationAttributeOwner(doc.Text, offset)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	initialCapacity := 256
	if limited {
		initialCapacity = limit * 4
	}
	ids := make([]string, 0, initialCapacity)
	synthetic := make([]analysis.Symbol, 0, 8)
	if annotationOwner != "" {
		usedAttributes := AnnotationAttributeNames(doc.Text, offset)
		for _, owner := range i.resolveTypeSymbolsLocked(file, annotationOwner) {
			if owner.Kind != analysis.KindAnnotation {
				continue
			}
			for _, candidateID := range i.byContainerName[owner.Name] {
				symbol := i.symbols[candidateID]
				if symbol.ContainerID == owner.ID && !usedAttributes[symbol.Name] && analysis.IsCallableKind(symbol.Kind) && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
					ids = append(ids, candidateID)
				}
			}
		}
	} else if qualifier != "" {
		typeQualifierSymbols := i.resolveTypeSymbolsLocked(file, qualifier)
		typeQualifier := len(typeQualifierSymbols) > 0
		typeQualifierValue := i.typeQualifierActsAsValueLocked(file, typeQualifierSymbols)
		ids = append(ids, i.anonymousObjectMemberIDsLocked(file, qualifier, "", offset)...)
		typ := i.typeOfExpressionLocked(file, qualifier, offset)
		if explicit := explicitReceiverType(qualifier); explicit != "" {
			typ = explicit
		}
		if typ != "" {
			containers := i.typeAndSupertypesLocked(file, typ)
			for _, container := range containers {
				for _, candidateID := range i.byContainerName[container] {
					s := i.symbols[candidateID]
					if !i.memberInheritedForReceiverLocked(file, *s, typ) {
						continue
					}
					if typeQualifier && !i.memberAvailableThroughTypeQualifierLocked(file, *s, typeQualifierSymbols) {
						continue
					}
					if i.accessibleLocked(file, *s, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
						ids = append(ids, candidateID)
						if limited && len(ids) >= limit*4 {
							break
						}
					}
				}
				for _, candidateID := range i.byReceiver[container] {
					s := i.symbols[candidateID]
					if (!typeQualifier || typeQualifierValue) && i.extensionReceiverApplicableLocked(file, *s, typ) && i.accessibleLocked(file, *s, offset) && i.extensionVisibleLocked(file, *s, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
						ids = append(ids, candidateID)
					}
				}
				if file.Language == analysis.LanguageKotlin && typeQualifier {
					for _, companion := range i.companionMembersLocked(file, container) {
						if i.accessibleLocked(file, companion, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(companion.Name), strings.ToLower(prefix))) {
							ids = append(ids, companion.ID)
						}
					}
				}
			}
		} else {
			for _, child := range i.packageChildren[qualifier] {
				if prefix == "" || strings.HasPrefix(strings.ToLower(child), strings.ToLower(prefix)) {
					fqn := child
					if qualifier != "" {
						fqn = qualifier + "." + child
					}
					id := "package:" + fqn
					synthetic = append(synthetic, analysis.Symbol{ID: id, Name: child, FQN: fqn, Kind: analysis.KindPackage})
				}
			}
			for _, candidateID := range i.byPackage[qualifier] {
				symbol := i.symbols[candidateID]
				if symbol.ContainerID == "" && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
					ids = append(ids, candidateID)
				}
			}
		}
	} else {
		for _, child := range i.packageChildren[""] {
			if prefix == "" || strings.HasPrefix(strings.ToLower(child), strings.ToLower(prefix)) {
				synthetic = append(synthetic, analysis.Symbol{ID: "package:" + child, Name: child, FQN: child, Kind: analysis.KindPackage})
			}
		}
		currentType := i.enclosingTypeLocked(file, offset)
		if enumType := i.javaSwitchLabelReceiverTypeLocked(file, offset); enumType != "" {
			for _, container := range i.typeAndSupertypesLocked(file, enumType) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if symbol.Kind == analysis.KindEnumMember && i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		for _, symbol := range file.Symbols {
			if symbol.StartByte <= offset && (symbol.ContainerID == "" || symbol.ContainerID == currentType.ID || symbol.ContainerID != "" && i.symbolWithinCallableScopeLocked(file, symbol, offset)) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
				ids = append(ids, symbol.ID)
			}
		}
		if currentType.ID != "" {
			for _, container := range i.typeAndSupertypesLocked(file, currentType.Name) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		implicitReceiverTypes := []string{i.contextualLambdaReceiverTypeLocked(file, offset), i.enclosingExtensionReceiverTypeLocked(file, offset)}
		implicitReceiverTypes = append(implicitReceiverTypes, i.enclosingContextReceiverTypesLocked(file, offset)...)
		if enclosing := i.enclosingTypeLocked(file, offset); enclosing.ID != "" {
			implicitReceiverTypes = append(implicitReceiverTypes, enclosing.Name)
		}
		for _, receiverType := range implicitReceiverTypes {
			if receiverType == "" {
				continue
			}
			for _, container := range i.typeAndSupertypesLocked(file, receiverType) {
				for _, id := range i.byContainerName[container] {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
				for _, id := range i.byReceiver[container] {
					symbol := i.symbols[id]
					if i.extensionReceiverApplicableLocked(file, *symbol, receiverType) && i.accessibleLocked(file, *symbol, offset) && i.extensionVisibleLocked(file, *symbol, offset) && (prefix == "" || strings.HasPrefix(strings.ToLower(symbol.Name), strings.ToLower(prefix))) {
						ids = append(ids, id)
					}
				}
			}
		}
		names := i.completionNames
		if len(prefix) > 0 {
			lower := strings.ToLower(prefix)
			if key, ok := asciiPrefix(lower, 3); ok {
				names = i.completionByPrefix[key]
			} else if lower[0] < 128 {
				names = i.completionByInitial[lower[0]]
			}
		}
		for _, name := range names {
			values := i.completionByName[name]
			if prefix == "" || strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				for _, id := range values {
					symbol := i.symbols[id]
					if i.accessibleLocked(file, *symbol, offset) && i.extensionVisibleLocked(file, *symbol, offset) {
						ids = append(ids, id)
					}
				}
				if limited && len(ids) >= limit*4 {
					break
				}
			}
		}
	}
	seen := map[string]bool{}
	outCapacity := len(ids) + len(synthetic)
	if limited && outCapacity > limit {
		outCapacity = limit
	}
	out := make([]analysis.Symbol, 0, outCapacity)
	for _, symbol := range synthetic {
		key := symbol.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, symbol)
		if limited && len(out) >= limit {
			return out
		}
	}
	for _, id := range ids {
		s := i.symbols[id]
		key := s.ID
		if seen[key] || (!strings.HasPrefix(strings.ToLower(s.Name), strings.ToLower(prefix))) {
			continue
		}
		seen[key] = true
		out = append(out, *s)
		if limited && len(out) >= limit {
			break
		}
	}
	return out
}

func AnnotationAttributeOwner(source string, offset int) string {
	if offset < 0 || offset > len(source) {
		return ""
	}
	start := strings.LastIndexByte(source[:offset], '@')
	if start < 0 {
		return ""
	}
	openRelative := strings.IndexByte(source[start:offset], '(')
	if openRelative < 0 {
		return ""
	}
	open := start + openRelative
	depth := 0
	for index := open; index < offset; index++ {
		switch source[index] {
		case '(':
			depth++
		case ')':
			depth--
		}
	}
	if depth <= 0 {
		return ""
	}
	owner := strings.TrimSpace(source[start+1 : open])
	for _, value := range owner {
		if value != '.' && value != '$' && value != '_' && !unicode.IsLetter(value) && !unicode.IsDigit(value) {
			return ""
		}
	}
	return owner
}

func AnnotationAttributeNames(source string, offset int) map[string]bool {
	used := make(map[string]bool)
	if offset < 0 || offset > len(source) {
		return used
	}
	start := strings.LastIndexByte(source[:offset], '@')
	if start < 0 {
		return used
	}
	openRelative := strings.IndexByte(source[start:offset], '(')
	if openRelative < 0 {
		return used
	}
	value := source[start+openRelative+1 : offset]
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		after := end
		for after < len(value) && unicode.IsSpace(rune(value[after])) {
			after++
		}
		if after < len(value) && value[after] == '=' {
			used[value[index:end]] = true
		}
		index = end
	}
	return used
}

func (i *Index) FunctionalParameterTypes(uri protocol.URI, typeName string) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	return i.functionalParameterTypesLocked(file, typeName)
}

func (i *Index) functionalParameterTypesLocked(file *analysis.ParsedFile, typeName string) []string {
	base, arguments := splitInstantiatedType(typeName)
	var methods []analysis.Symbol
	for _, owner := range i.resolveTypeSymbolsLocked(file, base) {
		if owner.Kind != analysis.KindInterface {
			continue
		}
		for _, id := range i.byContainerName[owner.Name] {
			method := i.symbols[id]
			if method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
				continue
			}
			methods = append(methods, *method)
		}
		if len(methods) == 1 {
			out := make([]string, len(methods[0].Parameters))
			for index, parameter := range methods[0].Parameters {
				out[index] = substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments)
			}
			return out
		}
	}
	return nil
}

// InferredType resolves a declaration initializer using the same constructor,
// factory, literal, and collection inference used by member completion.
func (i *Index) InferredType(uri protocol.URI, symbolID string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	symbol, ok := i.symbols[symbolID]
	if file == nil || !ok || symbol.URI != uri {
		return ""
	}
	if symbol.Type != "" && symbol.Type != "var" {
		return simpleType(symbol.Type)
	}
	return simpleType(i.inferExpressionTypeLocked(file, symbol.Initializer, symbol.StartByte))
}

func (i *Index) Supertypes(item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []analysis.Symbol
	for _, name := range item.Supertypes {
		out = append(out, i.symbolsForIDsLocked(i.byName[simpleType(name)], func(s analysis.Symbol) bool { return analysis.IsTypeKind(s.Kind) })...)
	}
	return uniqueSymbols(out)
}

func (i *Index) Subtypes(item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	ids := append([]string(nil), i.bySuper[item.Name]...)
	ids = append(ids, i.bySuper[item.FQN]...)
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if symbol, ok := i.symbols[id]; ok {
			out = append(out, *symbol)
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) CallsFrom(item analysis.Symbol) map[string][]analysis.Reference {
	if document, ok := i.Document(item.URI); ok {
		i.ensureLibraryReferences(item.URI, document)
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := map[string][]analysis.Reference{}
	f := i.files[item.URI]
	if f == nil {
		return out
	}
	for _, r := range f.References {
		if r.ContainerID != item.ID || r.Role != analysis.RoleCall {
			continue
		}
		for _, s := range i.resolveLocked(f, r) {
			out[s.ID] = append(out[s.ID], r)
		}
	}
	return out
}

func (i *Index) CallsTo(item analysis.Symbol) map[string][]analysis.Reference {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := map[string][]analysis.Reference{}
	for _, r := range i.refsByName[item.Name] {
		f := i.files[r.URI]
		if f == nil || r.Role != analysis.RoleCall {
			continue
		}
		for _, s := range i.resolveLocked(f, r) {
			if s.ID == item.ID {
				out[r.ContainerID] = append(out[r.ContainerID], r)
			}
		}
	}
	return out
}

func (i *Index) Rename(uri protocol.URI, pos protocol.Position, newName string) protocol.WorkspaceEdit {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok {
		return protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{}}
	}
	changes := make(map[protocol.URI][]protocol.TextEdit)
	i.mu.RLock()
	origin := target
	if target.OriginID != "" {
		if value, exists := i.symbols[target.OriginID]; exists {
			origin = *value
		}
	}
	propertyName, interopFamily := interopRenamePropertyName(target, origin, newName)
	family := i.referenceFamilyLocked(origin)
	seen := make(map[string]bool)
	add := func(location protocol.Location, replacement string) {
		key := string(location.URI) + "|" + itoa(location.Range.Start.Line) + ":" + itoa(location.Range.Start.Character) + "-" + itoa(location.Range.End.Line) + ":" + itoa(location.Range.End.Character)
		if !seen[key] {
			seen[key] = true
			changes[location.URI] = append(changes[location.URI], protocol.TextEdit{Range: location.Range, NewText: replacement})
		}
	}
	for _, member := range family {
		replacement := newName
		if interopFamily {
			replacement = interopRenameMemberName(member, propertyName)
		}
		add(member.Location(), replacement)
		for _, reference := range i.refsByName[member.Name] {
			file := i.files[reference.URI]
			if file == nil {
				continue
			}
			for _, resolved := range i.resolveLocked(file, reference) {
				if resolved.ID == member.ID {
					text := i.documentTextLocked(reference.URI)
					if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != member.Name {
						// Kotlin operator/convention references are structural
						// syntax, not identifier tokens. IntelliJ leaves them
						// untouched and removes `operator` when necessary.
						break
					}
					add(protocol.Location{URI: reference.URI, Range: reference.Range}, replacement)
					break
				}
			}
		}
	}
	i.mu.RUnlock()
	return protocol.WorkspaceEdit{Changes: changes}
}

// Renameable reports whether every resolved use can be changed by replacing
// an identifier token. Kotlin convention calls such as `left + right`,
// destructuring, indexing, and delegation are semantic references whose
// source range is punctuation or another structural form. Replacing those
// ranges with the requested identifier would produce invalid source, while
// omitting them would silently break the program, so the LSP rejects that
// rename until it has a full structural refactoring for the convention.
func (i *Index) Renameable(uri protocol.URI, pos protocol.Position) bool {
	target, _, ok := i.SymbolAt(uri, pos)
	if !ok || target.Library {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	origin := target
	if target.OriginID != "" {
		if value, exists := i.symbols[target.OriginID]; exists {
			origin = *value
		}
	}
	for _, member := range i.referenceFamilyLocked(origin) {
		for _, reference := range i.refsByName[member.Name] {
			file := i.files[reference.URI]
			if file == nil {
				continue
			}
			resolvedToMember := false
			for _, resolved := range i.resolveLocked(file, reference) {
				if resolved.ID == member.ID {
					resolvedToMember = true
					break
				}
			}
			if !resolvedToMember {
				continue
			}
			text := i.documentTextLocked(reference.URI)
			if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != member.Name {
				return false
			}
		}
	}
	return true
}

func interopRenamePropertyName(target, origin analysis.Symbol, requested string) (string, bool) {
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		if target.Synthetic && target.InteropLanguage == analysis.LanguageJava {
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
		return strings.Trim(requested, "`"), true
	}
	if origin.Language == analysis.LanguageJava {
		if _, bean := beanPropertyName(origin.Name); bean {
			if target.Synthetic && target.InteropLanguage == analysis.LanguageKotlin {
				return strings.Trim(requested, "`"), true
			}
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
	}
	return "", false
}

func interopRenameMemberName(member analysis.Symbol, propertyName string) string {
	if member.InteropLanguage == analysis.LanguageKotlin || member.Language == analysis.LanguageKotlin && member.Kind == analysis.KindProperty && !member.Synthetic {
		return propertyName
	}
	if _, ok := beanPropertyName(member.Name); ok {
		stem := propertyName
		if len(stem) > 0 && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		switch {
		case strings.HasPrefix(member.Name, "set"):
			return "set" + stem
		case strings.HasPrefix(member.Name, "is"):
			return "is" + stem
		default:
			return "get" + stem
		}
	}
	return propertyName
}

func beanPropertyName(accessor string) (string, bool) {
	for _, prefix := range []string{"get", "set", "is"} {
		if strings.HasPrefix(accessor, prefix) {
			return decapitalizeBean(accessor[len(prefix):])
		}
	}
	return "", false
}

func (i *Index) AllFiles() []protocol.URI {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]protocol.URI, 0, len(i.files))
	for u := range i.files {
		out = append(out, u)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// WorkspaceFiles returns immutable parsed snapshots backed by file URIs. It
// intentionally excludes JAR/JRT sources and takes one lock so file-operation
// providers can stay within the foreground latency budget.
func (i *Index) WorkspaceFiles() []*analysis.ParsedFile {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]*analysis.ParsedFile, 0, len(i.files))
	for uri, file := range i.files {
		if _, ok := uriutil.Path(uri); ok {
			out = append(out, file)
		}
	}
	return out
}

// SemanticTokens returns lexical/declaration tokens plus references classified
// from the symbol each reference actually resolves to. The parser's role-based
// token remains as a fallback for temporarily unresolved code.
func (i *Index) SemanticTokens(uri protocol.URI) ([]analysis.Token, uint64, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil, 0, false
	}
	tokens := append([]analysis.Token(nil), file.Tokens...)
	type semanticClassification struct {
		typ       uint32
		modifiers uint32
	}
	classifications := make(map[[2]int]semanticClassification, len(file.Symbols)+len(file.References))
	declarationSpans := make(map[[2]int]bool, len(file.Symbols))
	declarationSymbols := make(map[[2]int]analysis.Symbol, len(file.Symbols))
	for _, symbol := range file.Symbols {
		key := [2]int{symbol.NameStartByte, symbol.NameEndByte}
		declarationSpans[key] = true
		if previous, exists := declarationSymbols[key]; !exists || previous.Synthetic && !symbol.Synthetic {
			declarationSymbols[key] = symbol
		}
	}
	for key, symbol := range declarationSymbols {
		classifications[key] = semanticClassification{
			typ: symbol.Kind.SemanticToken(), modifiers: semanticModifiersForSymbol(symbol, true, analysis.RoleRead),
		}
	}
	for _, reference := range file.References {
		key := [2]int{reference.StartByte, reference.EndByte}
		if declarationSpans[key] {
			continue
		}
		resolved := i.resolveLocked(file, reference)
		if len(resolved) > 0 {
			classifications[key] = semanticClassification{
				typ: resolved[0].Kind.SemanticToken(), modifiers: semanticModifiersForSymbol(resolved[0], false, reference.Role),
			}
		}
	}
	for n := range tokens {
		if classification, ok := classifications[[2]int{tokens[n].StartByte, tokens[n].EndByte}]; ok {
			tokens[n].Type = classification.typ
			tokens[n].Modifiers = classification.modifiers
		}
	}
	return tokens, file.TextHash, true
}

func semanticModifiersForSymbol(symbol analysis.Symbol, declaration bool, role analysis.ReferenceRole) uint32 {
	var modifiers uint32
	if declaration {
		modifiers |= 1 << 0 // declaration
	}
	if containsString(symbol.Modifiers, "final") || containsString(symbol.Modifiers, "const") || containsString(symbol.Modifiers, "val") {
		modifiers |= 1 << 2 // readonly
	}
	static := containsString(symbol.Modifiers, "static") || containsString(symbol.Modifiers, "JvmStatic") || containsString(symbol.Modifiers, "companion")
	if symbol.Language == analysis.LanguageKotlin && symbol.ContainerID == "" && (symbol.Kind == analysis.KindProperty || analysis.IsCallableKind(symbol.Kind)) {
		static = true
	}
	if static {
		modifiers |= 1 << 3
	}
	if symbol.Deprecated || containsString(symbol.Modifiers, "deprecated") || containsString(symbol.Modifiers, "Deprecated") {
		modifiers |= 1 << 4
	}
	if containsString(symbol.Modifiers, "abstract") {
		modifiers |= 1 << 5
	}
	if containsString(symbol.Modifiers, "suspend") {
		modifiers |= 1 << 6 // async
	}
	variable := symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || symbol.Kind == analysis.KindVariable
	readonly := modifiers&(1<<2) != 0
	if variable && !readonly || !declaration && role == analysis.RoleWrite {
		modifiers |= 1 << 7 // modification
	}
	if symbol.Library && (symbol.Package == "kotlin" || strings.HasPrefix(symbol.Package, "kotlin.")) {
		modifiers |= 1 << 9 // defaultLibrary
	}
	return modifiers
}

// FilesImportingPrefix returns only workspace files whose import path is equal
// to prefix or starts with prefix plus a dot. Import prefixes are maintained as
// files enter the index, avoiding a whole-workspace scan on package moves.
func (i *Index) FilesImportingPrefix(prefix string) []*analysis.ParsedFile {
	i.mu.RLock()
	defer i.mu.RUnlock()
	seen := make(map[protocol.URI]bool)
	out := make([]*analysis.ParsedFile, 0, len(i.importersByPrefix[prefix]))
	for _, uri := range i.importersByPrefix[prefix] {
		if seen[uri] {
			continue
		}
		file := i.files[uri]
		if file == nil {
			continue
		}
		if _, ok := uriutil.Path(uri); !ok {
			continue
		}
		seen[uri] = true
		out = append(out, file)
	}
	return out
}

// UsedImports reports imports that contribute an unqualified semantic
// reference. Comments, strings, and fully-qualified expressions never enter
// the parser's reference stream and therefore cannot keep an import alive.
func (i *Index) UsedImports(uri protocol.URI) map[string]bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	used := make(map[string]bool)
	if file == nil {
		return used
	}
	for _, imported := range file.Imports {
		for _, reference := range file.References {
			if reference.Role == analysis.RoleImport || reference.Qualifier != "" {
				continue
			}
			if !imported.Wildcard && reference.Name == imported.LocalName() {
				used[imported.Path] = true
				break
			}
			if imported.Wildcard {
				for _, symbol := range i.resolveLocked(file, reference) {
					if symbol.Package == imported.Path || strings.HasPrefix(symbol.FQN, imported.Path+".") {
						used[imported.Path] = true
						break
					}
				}
			}
			if used[imported.Path] {
				break
			}
		}
	}
	return used
}

func (i *Index) AddLibraryBatch(files []LibraryFile) {
	i.addLibraryBatch(files, i.generation.Load())
}

func (i *Index) addLibraryBatch(files []LibraryFile, generation uint64) {
	// One parsed source file per critical section bounds reader wait time even
	// when a cached archive contains tens of thousands of classes. Library
	// loading is background work; foreground completion/navigation wins every
	// scheduling opportunity between files.
	const chunkSize = 1
	for start := 0; start < len(files); start += chunkSize {
		if i.generation.Load() != generation {
			return
		}
		end := start + chunkSize
		if end > len(files) {
			end = len(files)
		}
		i.mu.Lock()
		if i.generation.Load() != generation {
			i.mu.Unlock()
			return
		}
		for n := start; n < end; n++ {
			file := &files[n]
			for symbol := range file.Parsed.Symbols {
				file.Parsed.Symbols[symbol].Library = true
			}
			i.librarySources[file.Parsed.URI] = file.Source
			matched := i.attachLibrarySourceLocked(file)
			if len(matched) > 0 {
				retainLibrarySourceOnlySymbols(&file.Parsed, matched)
			}
			if file.Content != "" {
				i.libraryDocs[file.Parsed.URI] = textdoc.NewDocument(file.Parsed.URI, file.Source.LanguageID, 0, file.Content)
			}
			i.replaceLocked(&file.Parsed)
		}
		i.mu.Unlock()
	}
}

func (i *Index) attachLibrarySourceLocked(file *LibraryFile) map[string]bool {
	if file == nil || file.Source.Archive == "" || file.Source.Binary {
		return nil
	}
	matched := make(map[string]bool)
	for symbolIndex := range file.Parsed.Symbols {
		incoming := &file.Parsed.Symbols[symbolIndex]
		if incoming.FQN == "" {
			continue
		}
		var best *analysis.Symbol
		bestScore := -1
		for _, existingID := range i.byFQN[incoming.FQN] {
			existing := i.symbols[existingID]
			if existing == nil {
				continue
			}
			existingSource, ok := i.librarySources[existing.URI]
			if !ok || !existingSource.Binary {
				continue
			}
			if score := libraryDeclarationMatchScore(*existing, *incoming); score > bestScore {
				best, bestScore = existing, score
			}
		}
		if best == nil || bestScore < 0 {
			continue
		}
		best.SourceURI = incoming.URI
		best.SourceRange = incoming.SelectionRange
		if incoming.Documentation != "" {
			best.Documentation = incoming.Documentation
		}
		matched[incoming.ID] = true
	}
	return matched
}

func libraryDeclarationMatchScore(first, second analysis.Symbol) int {
	if first.FQN != second.FQN || first.Name != second.Name {
		return -1
	}
	if analysis.IsCallableKind(first.Kind) || analysis.IsCallableKind(second.Kind) {
		if !analysis.IsCallableKind(first.Kind) || !analysis.IsCallableKind(second.Kind) || len(first.Parameters) != len(second.Parameters) {
			return -1
		}
		score := 100
		for parameter := range first.Parameters {
			left, right := first.Parameters[parameter].Type, second.Parameters[parameter].Type
			if left == "" || right == "" {
				continue
			}
			if !sameJvmType(left, right) {
				return -1
			}
			score += 10
		}
		return score
	}
	if first.Kind != second.Kind {
		return -1
	}
	return 100
}

// Matching source declarations are navigation metadata for the authoritative
// bytecode symbols, not a second semantic universe. Retain only declarations
// absent from bytecode, plus any matched containers they require.
func retainLibrarySourceOnlySymbols(parsed *analysis.ParsedFile, matched map[string]bool) {
	if parsed == nil || len(matched) == 0 {
		return
	}
	byID := make(map[string]analysis.Symbol, len(parsed.Symbols))
	needed := make(map[string]bool)
	for _, symbol := range parsed.Symbols {
		byID[symbol.ID] = symbol
		if !matched[symbol.ID] {
			needed[symbol.ID] = true
		}
	}
	for id := range needed {
		for container := byID[id].ContainerID; container != "" && !needed[container]; container = byID[container].ContainerID {
			needed[container] = true
		}
	}
	kept := parsed.Symbols[:0]
	for _, symbol := range parsed.Symbols {
		if !matched[symbol.ID] || needed[symbol.ID] {
			kept = append(kept, symbol)
		}
	}
	parsed.Symbols = kept
}

func (i *Index) replaceLocked(file *analysis.ParsedFile) {
	if old := i.files[file.URI]; old != nil {
		preserveLibraryAttachments(old, file)
		i.removeFileContentsLocked(old)
	}
	base := file.Symbols[:0]
	for _, symbol := range file.Symbols {
		if !symbol.Synthetic || symbol.OriginID == "" {
			base = append(base, symbol)
		}
	}
	file.Symbols = base
	interop := interopSymbols(file)
	if len(interop) > 0 {
		combined := make([]analysis.Symbol, len(file.Symbols)+len(interop))
		copy(combined, file.Symbols)
		copy(combined[len(file.Symbols):], interop)
		file.Symbols = combined
	}
	i.files[file.URI] = file
	libraryFile := false
	if _, exists := i.librarySources[file.URI]; exists {
		libraryFile = true
	}
	if !libraryFile {
		fileSymbols := make(map[string][]*analysis.Symbol)
		fileAnonymous := make(map[string][]*analysis.Symbol)
		for symbolIndex := range file.Symbols {
			symbol := &file.Symbols[symbolIndex]
			fileSymbols[symbol.Name] = append(fileSymbols[symbol.Name], symbol)
			if strings.HasPrefix(strings.TrimSpace(symbol.Initializer), "object") {
				fileAnonymous[symbol.Name] = append(fileAnonymous[symbol.Name], symbol)
			}
		}
		for name := range fileSymbols {
			sort.SliceStable(fileSymbols[name], func(left, right int) bool {
				return fileSymbols[name][left].StartByte < fileSymbols[name][right].StartByte
			})
		}
		for name := range fileAnonymous {
			sort.SliceStable(fileAnonymous[name], func(left, right int) bool {
				return fileAnonymous[name][left].StartByte < fileAnonymous[name][right].StartByte
			})
		}
		i.fileSymbolsByName[file.URI] = fileSymbols
		i.fileAnonymousByName[file.URI] = fileAnonymous
		fileSmartCasts := make(map[string][]analysis.SmartCast)
		for _, smartCast := range file.SmartCasts {
			fileSmartCasts[smartCast.Name] = append(fileSmartCasts[smartCast.Name], smartCast)
		}
		i.fileSmartCastsByName[file.URI] = fileSmartCasts
	}
	delete(i.compilerDiagnostics, file.URI)
	i.addPackageLocked(file)
	i.addCompletionPackageLocked(file.Package)
	for symbolIndex := range file.Symbols {
		s := &file.Symbols[symbolIndex]
		i.symbols[s.ID] = s
		if s.Synthetic && s.OriginID == "" && s.InteropLanguage == analysis.LanguageUnknown {
			continue
		}
		if isLexicalSymbol(*s) {
			// Lexical declarations are resolved from their immutable file scope
			// and direct ResolvedID bindings. Keeping thousands of parameters in
			// every global name/container index wastes both update time and memory.
			continue
		}
		i.byName[s.Name] = append(i.byName[s.Name], s.ID)
		if s.OriginID != "" {
			i.byOrigin[s.OriginID] = append(i.byOrigin[s.OriginID], s.ID)
		}
		if s.FQN != "" {
			i.byFQN[s.FQN] = append(i.byFQN[s.FQN], s.ID)
		}
		if s.ContainerName != "" {
			i.byContainerName[s.ContainerName] = append(i.byContainerName[s.ContainerName], s.ID)
			i.byContainerMember[memberKey(s.ContainerName, s.Name)] = append(i.byContainerMember[memberKey(s.ContainerName, s.Name)], s.ID)
		}
		if s.ReceiverType != "" {
			receiver := simpleType(s.ReceiverType)
			i.byReceiver[receiver] = append(i.byReceiver[receiver], s.ID)
			i.byReceiverMember[memberKey(receiver, s.Name)] = append(i.byReceiverMember[memberKey(receiver, s.Name)], s.ID)
		}
		if s.ContainerID == "" && s.Package != "" {
			i.byPackage[s.Package] = append(i.byPackage[s.Package], s.ID)
		}
		if isWorkspaceSymbol(*s) {
			if len(i.workspaceByName[s.Name]) == 0 {
				i.addWorkspaceNameLocked(s.Name)
			}
			i.workspaceByName[s.Name] = append(i.workspaceByName[s.Name], s.ID)
		}
		if isUnqualifiedCompletionSymbol(*s) {
			if len(i.completionByName[s.Name]) == 0 {
				i.addCompletionNameLocked(s.Name)
			}
			i.completionByName[s.Name] = append(i.completionByName[s.Name], s.ID)
		}
		for _, supertype := range s.Supertypes {
			simple := simpleType(supertype)
			i.bySuper[simple] = append(i.bySuper[simple], s.ID)
			if simple != supertype {
				i.bySuper[supertype] = append(i.bySuper[supertype], s.ID)
			}
		}
	}
	type lexicalKey struct{ container, name string }
	lexicalByContainer := make(map[lexicalKey]analysis.Symbol)
	lexicalDuplicates := make(map[lexicalKey][]analysis.Symbol)
	lexicalNames := make(map[string]bool)
	for _, symbol := range file.Symbols {
		if !isLexicalSymbol(symbol) {
			continue
		}
		lexicalNames[symbol.Name] = true
		if symbol.ContainerID == "" {
			continue
		}
		key := lexicalKey{symbol.ContainerID, symbol.Name}
		if previous, exists := lexicalByContainer[key]; exists {
			if len(lexicalDuplicates[key]) == 0 {
				lexicalDuplicates[key] = append(lexicalDuplicates[key], previous)
			}
			lexicalDuplicates[key] = append(lexicalDuplicates[key], symbol)
		} else {
			lexicalByContainer[key] = symbol
		}
	}
	for referenceIndex := range file.References {
		reference := &file.References[referenceIndex]
		unqualified := reference.Qualifier == ""
		if unqualified {
			unqualified = expressionQualifierBefore(i.documentTextLocked(file.URI), reference.StartByte) == ""
		}
		// Lexical bindings cannot be invalidated by another file being indexed.
		// Resolve them once at snapshot insertion instead of repeating the same
		// scope search for every definition/reference/semantic-token request.
		if reference.ResolvedID == "" && !reference.ArgumentLabel && unqualified {
			key := lexicalKey{reference.ContainerID, reference.Name}
			if candidates := lexicalDuplicates[key]; len(candidates) > 0 {
				reference.ResolvedID = lexicalBinding(file, *reference, candidates)
			} else if candidate, exists := lexicalByContainer[key]; exists && lexicalCandidateMatches(*reference, candidate) {
				reference.ResolvedID = candidate.ID
			} else if lexicalNames[reference.Name] {
				reference.ResolvedID = lexicalBinding(file, *reference, file.Symbols)
			}
		}
		i.refsByName[reference.Name] = append(i.refsByName[reference.Name], *reference)
	}
	if _, workspace := uriutil.Path(file.URI); workspace {
		for _, imported := range file.Imports {
			for _, prefix := range importPrefixes(imported.Path) {
				i.importersByPrefix[prefix] = appendUniqueURI(i.importersByPrefix[prefix], file.URI)
			}
		}
	}
}

func preserveLibraryAttachments(old, replacement *analysis.ParsedFile) {
	if old == nil || replacement == nil {
		return
	}
	attached := make(map[string][]analysis.Symbol)
	for _, symbol := range old.Symbols {
		if symbol.SourceURI != "" {
			attached[symbol.FQN] = append(attached[symbol.FQN], symbol)
		}
	}
	for index := range replacement.Symbols {
		symbol := &replacement.Symbols[index]
		bestScore := -1
		var best analysis.Symbol
		for _, candidate := range attached[symbol.FQN] {
			if score := libraryDeclarationMatchScore(candidate, *symbol); score > bestScore {
				best, bestScore = candidate, score
			}
		}
		if bestScore >= 0 {
			symbol.SourceURI = best.SourceURI
			symbol.SourceRange = best.SourceRange
			if best.Documentation != "" {
				symbol.Documentation = best.Documentation
			}
		}
	}
}

// interopSymbols materializes the JVM source views which IntelliJ exposes
// across the Java/Kotlin boundary. They intentionally point back at the
// original declaration range and are hidden from document/workspace symbols.
func interopSymbols(file *analysis.ParsedFile) []analysis.Symbol {
	owners := make(map[string]bool)
	ownerSymbols := make(map[string]analysis.Symbol)
	recordOwners := make(map[string]bool)
	for _, symbol := range file.Symbols {
		if analysis.IsTypeKind(symbol.Kind) {
			owners[symbol.ID] = true
			ownerSymbols[symbol.ID] = symbol
			if symbol.Kind == analysis.KindRecord {
				recordOwners[symbol.ID] = true
			}
		}
	}
	var out []analysis.Symbol
	out = append(out, generatedSourceAPISymbols(file, ownerSymbols)...)
	if file.Language == analysis.LanguageKotlin {
		for _, property := range file.Symbols {
			if property.Kind != analysis.KindProperty || property.ContainerID == "" || !owners[property.ContainerID] || containsString(property.Modifiers, "JvmField") {
				continue
			}
			getter, setter := kotlinAccessorNames(property)
			out = append(out, interopSymbol(property, getter, analysis.KindMethod, property.Type, nil, analysis.LanguageJava))
			if containsString(property.Modifiers, "var") {
				parameter := analysis.Parameter{Name: "value", Type: property.Type, Range: property.SelectionRange}
				out = append(out, interopSymbol(property, setter, analysis.KindMethod, "void", []analysis.Parameter{parameter}, analysis.LanguageJava))
			}
		}
		var topLevel []analysis.Symbol
		for _, symbol := range file.Symbols {
			if symbol.ContainerID == "" && (analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty) {
				topLevel = append(topLevel, symbol)
			}
		}
		if len(topLevel) > 0 {
			facadeName := kotlinFacadeName(file)
			anchor := topLevel[0]
			facade := analysis.Symbol{ID: analysis.SymbolID(file.URI, anchor.StartByte, analysis.KindClass, facadeName), Name: facadeName, FQN: facadeName, Kind: analysis.KindClass, Language: analysis.LanguageKotlin, URI: file.URI, Range: anchor.Range, SelectionRange: anchor.SelectionRange, StartByte: anchor.StartByte, EndByte: anchor.EndByte, NameStartByte: anchor.NameStartByte, NameEndByte: anchor.NameEndByte, Package: file.Package, Modifiers: []string{"public", "final"}, Synthetic: true, InteropLanguage: analysis.LanguageJava, Signature: "class " + facadeName}
			if file.Package != "" {
				facade.FQN = file.Package + "." + facadeName
			}
			out = append(out, facade)
			for _, symbol := range topLevel {
				if analysis.IsCallableKind(symbol.Kind) {
					for overload, parameters := range jvmOverloadParameterSets(symbol) {
						name := symbol.Name
						if symbol.JVMName != "" {
							name = symbol.JVMName
						}
						projection := jvmMemberProjection(symbol, facade, name, analysis.KindMethod, symbol.Type, parameters, true)
						projection.ID += "#facade:" + itoa(overload)
						out = append(out, projection)
					}
				} else if containsString(symbol.Modifiers, "JvmField") || containsString(symbol.Modifiers, "const") {
					out = append(out, jvmMemberProjection(symbol, facade, symbol.Name, analysis.KindField, symbol.Type, nil, true))
				} else {
					getter, setter := kotlinAccessorNames(symbol)
					out = append(out, jvmMemberProjection(symbol, facade, getter, analysis.KindMethod, symbol.Type, nil, true))
					if containsString(symbol.Modifiers, "var") {
						out = append(out, jvmMemberProjection(symbol, facade, setter, analysis.KindMethod, "void", []analysis.Parameter{{Name: "value", Type: symbol.Type, Range: symbol.SelectionRange}}, true))
					}
				}
			}
		}
		for _, owner := range file.Symbols {
			if owner.Kind != analysis.KindObject {
				continue
			}
			if containsString(owner.Modifiers, "companion") {
				if enclosing, ok := ownerSymbols[owner.ContainerID]; ok {
					out = append(out, jvmMemberProjection(owner, enclosing, "Companion", analysis.KindField, owner.Name, nil, true))
				}
			} else {
				out = append(out, jvmMemberProjection(owner, owner, "INSTANCE", analysis.KindField, owner.Name, nil, true))
			}
		}
		for _, symbol := range file.Symbols {
			owner, hasOwner := ownerSymbols[symbol.ContainerID]
			if !hasOwner {
				continue
			}
			jvmName := symbol.Name
			if symbol.JVMName != "" {
				jvmName = symbol.JVMName
			}
			if analysis.IsCallableKind(symbol.Kind) && containsString(symbol.Modifiers, "JvmStatic") {
				projectionOwner, valid := owner, owner.Kind == analysis.KindObject && !containsString(owner.Modifiers, "companion")
				if containsString(owner.Modifiers, "companion") {
					projectionOwner, valid = ownerSymbols[owner.ContainerID]
				}
				if valid {
					for overload, parameters := range jvmOverloadParameterSets(symbol) {
						projection := jvmMemberProjection(symbol, projectionOwner, jvmName, analysis.KindMethod, symbol.Type, parameters, true)
						projection.ID += "#static:" + itoa(overload)
						out = append(out, projection)
					}
				}
				continue
			}
			if symbol.Kind == analysis.KindProperty && containsString(symbol.Modifiers, "JvmField") && containsString(owner.Modifiers, "companion") {
				if enclosing, ok := ownerSymbols[owner.ContainerID]; ok {
					out = append(out, jvmMemberProjection(symbol, enclosing, symbol.Name, analysis.KindField, symbol.Type, nil, true))
				}
				continue
			}
			if analysis.IsCallableKind(symbol.Kind) && symbol.JVMName != "" && !containsString(symbol.Modifiers, "JvmStatic") {
				for overload, parameters := range jvmOverloadParameterSets(symbol) {
					projection := jvmMemberProjection(symbol, owner, jvmName, analysis.KindMethod, symbol.Type, parameters, false)
					projection.ID += "#jvmname:" + itoa(overload)
					out = append(out, projection)
				}
				continue
			}
			if analysis.IsCallableKind(symbol.Kind) && containsString(symbol.Modifiers, "JvmOverloads") && !containsString(symbol.Modifiers, "JvmStatic") {
				sets := jvmOverloadParameterSets(symbol)
				for overload := 1; overload < len(sets); overload++ {
					projection := jvmMemberProjection(symbol, owner, symbol.Name, analysis.KindMethod, symbol.Type, sets[overload], false)
					projection.ID += "#overload:" + itoa(overload)
					out = append(out, projection)
				}
			}
		}
		return out
	}
	if file.Language != analysis.LanguageJava {
		return nil
	}
	for _, component := range file.Symbols {
		if component.Kind == analysis.KindProperty && recordOwners[component.ContainerID] {
			out = append(out, interopSymbol(component, component.Name, analysis.KindMethod, component.Type, nil, analysis.LanguageUnknown))
		}
	}
	// Prefer a getter as the navigation target. A write-only JavaBean still
	// contributes a Kotlin synthetic property through its setter.
	properties := make(map[string]analysis.Symbol)
	for _, method := range file.Symbols {
		if method.Kind != analysis.KindMethod || method.ContainerID == "" || !owners[method.ContainerID] || len(method.Parameters) != 0 {
			continue
		}
		name, ok := javaBeanGetterName(method)
		if ok {
			properties[method.ContainerID+"\x00"+name] = interopSymbol(method, name, analysis.KindProperty, kotlinizeBinaryType(method.Type), nil, analysis.LanguageKotlin)
		}
	}
	for _, method := range file.Symbols {
		if method.Kind != analysis.KindMethod || method.ContainerID == "" || !owners[method.ContainerID] || len(method.Parameters) != 1 || !strings.HasPrefix(method.Name, "set") {
			continue
		}
		name, ok := decapitalizeBean(method.Name[len("set"):])
		if !ok {
			continue
		}
		key := method.ContainerID + "\x00" + name
		if _, exists := properties[key]; !exists {
			properties[key] = interopSymbol(method, name, analysis.KindProperty, kotlinizeBinaryType(method.Parameters[0].Type), nil, analysis.LanguageKotlin)
		}
	}
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, properties[key])
	}
	return out
}

func kotlinFacadeName(file *analysis.ParsedFile) string {
	if file.JVMFacadeName != "" {
		return sanitizeJVMName(file.JVMFacadeName)
	}
	path, ok := uriutil.Path(file.URI)
	if !ok {
		path = string(file.URI)
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		name = "File"
	}
	name = sanitizeJVMName(name)
	if name == "" {
		name = "_"
	}
	runes := []rune(name)
	if runes[0] >= 'a' && runes[0] <= 'z' {
		runes[0] -= 'a' - 'A'
	}
	return string(runes) + "Kt"
}

func sanitizeJVMName(value string) string {
	var out strings.Builder
	for index, r := range value {
		valid := r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || index > 0 && r >= '0' && r <= '9'
		if valid {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

// generatedSourceAPISymbols exposes members which exist in compiler output
// even though no declaration node exists in source. They deliberately
// navigate to the owning type (or primary property for copy parameters),
// matching the useful source location an IDE can provide.
func generatedSourceAPISymbols(file *analysis.ParsedFile, owners map[string]analysis.Symbol) []analysis.Symbol {
	existing := make(map[string]bool)
	properties := make(map[string][]analysis.Symbol)
	for _, symbol := range file.Symbols {
		if symbol.ContainerID != "" {
			existing[symbol.ContainerID+"\x00"+symbol.Name+"\x00"+itoa(len(symbol.Parameters))] = true
		}
		if symbol.Kind == analysis.KindProperty && containsString(symbol.Modifiers, "constructor-property") {
			properties[symbol.ContainerID] = append(properties[symbol.ContainerID], symbol)
		}
	}
	var out []analysis.Symbol
	add := func(owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, modifiers ...string) {
		key := owner.ID + "\x00" + name + "\x00" + itoa(len(parameters))
		if existing[key] {
			return
		}
		existing[key] = true
		out = append(out, generatedMember(owner, name, kind, typ, parameters, modifiers))
	}
	for _, owner := range owners {
		if owner.Kind == analysis.KindEnum {
			arrayType := "Array<" + owner.Name + ">"
			if owner.Language == analysis.LanguageJava {
				arrayType = owner.Name + "[]"
			}
			add(owner, "values", analysis.KindMethod, arrayType, nil, "public", "static")
			add(owner, "valueOf", analysis.KindMethod, owner.Name, []analysis.Parameter{{Name: "value", Type: "String", Range: owner.SelectionRange}}, "public", "static")
			if owner.Language == analysis.LanguageKotlin {
				add(owner, "entries", analysis.KindProperty, "EnumEntries<"+owner.Name+">", nil, "public", "static", "val")
			}
		}
		if owner.Language != analysis.LanguageKotlin || owner.Kind != analysis.KindClass || !containsString(owner.Modifiers, "data") {
			continue
		}
		constructorProperties := properties[owner.ID]
		parameters := make([]analysis.Parameter, 0, len(constructorProperties))
		for index, property := range constructorProperties {
			parameters = append(parameters, analysis.Parameter{Name: property.Name, Type: property.Type, Default: "<default>", Range: property.SelectionRange})
			add(owner, "component"+itoa(index+1), analysis.KindMethod, property.Type, nil, "public", "operator")
		}
		add(owner, "copy", analysis.KindMethod, owner.Name, parameters, "public")
		add(owner, "equals", analysis.KindMethod, "Boolean", []analysis.Parameter{{Name: "other", Type: "Any?", Range: owner.SelectionRange}}, "public", "override")
		add(owner, "hashCode", analysis.KindMethod, "Int", nil, "public", "override")
		add(owner, "toString", analysis.KindMethod, "String", nil, "public", "override")
	}
	return out
}

func generatedMember(owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, modifiers []string) analysis.Symbol {
	member := analysis.Symbol{
		ID: owner.ID + "#generated:" + name + ":" + itoa(len(parameters)), Name: name,
		FQN: owner.FQN + "." + name, Kind: kind, Language: owner.Language,
		URI: owner.URI, Range: owner.Range, SelectionRange: owner.SelectionRange,
		StartByte: owner.StartByte, EndByte: owner.EndByte, NameStartByte: owner.NameStartByte, NameEndByte: owner.NameEndByte,
		ContainerID: owner.ID, ContainerName: owner.Name, Package: owner.Package,
		Type: typ, Parameters: parameters, Modifiers: append([]string(nil), modifiers...),
		Synthetic: true, OriginID: owner.ID, SourceURI: owner.URI, SourceRange: owner.SelectionRange,
	}
	var signature strings.Builder
	if kind == analysis.KindProperty {
		signature.WriteString(name + ": " + typ)
	} else {
		signature.WriteString(name)
		signature.WriteByte('(')
		for index, parameter := range parameters {
			if index > 0 {
				signature.WriteString(", ")
			}
			signature.WriteString(parameter.Name + ": " + parameter.Type)
			if parameter.Default != "" {
				signature.WriteString(" = " + parameter.Default)
			}
		}
		signature.WriteString("): " + typ)
	}
	member.Signature = signature.String()
	return member
}

func jvmOverloadParameterSets(symbol analysis.Symbol) [][]analysis.Parameter {
	full := make([]analysis.Parameter, len(symbol.Parameters))
	copy(full, symbol.Parameters)
	for index := range full {
		full[index].Default = ""
	}
	sets := [][]analysis.Parameter{full}
	if !containsString(symbol.Modifiers, "JvmOverloads") {
		return sets
	}
	for end := len(symbol.Parameters) - 1; end >= 0 && symbol.Parameters[end].Default != ""; end-- {
		parameters := make([]analysis.Parameter, end)
		copy(parameters, full[:end])
		sets = append(sets, parameters)
	}
	return sets
}

func jvmMemberProjection(origin, owner analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, static bool) analysis.Symbol {
	projection := interopSymbol(origin, name, kind, typ, parameters, analysis.LanguageJava)
	projection.ContainerID, projection.ContainerName = owner.ID, owner.Name
	projection.FQN = owner.FQN + "." + name
	projection.ID = analysis.SymbolID(origin.URI, origin.StartByte, kind, owner.Name+"."+name)
	if static && !containsString(projection.Modifiers, "static") {
		projection.Modifiers = append(projection.Modifiers, "static")
	}
	return projection
}

func interopSymbol(origin analysis.Symbol, name string, kind analysis.SymbolKind, typ string, parameters []analysis.Parameter, visibleIn analysis.Language) analysis.Symbol {
	originID := origin.ID
	originalName := origin.Name
	origin.ID = analysis.SymbolID(origin.URI, origin.StartByte, kind, name)
	origin.Name = name
	if origin.FQN != "" {
		origin.FQN = strings.TrimSuffix(origin.FQN, "."+originalName) + "." + name
	}
	origin.Kind, origin.Type, origin.Parameters = kind, typ, parameters
	origin.Initializer, origin.ReceiverType = "", ""
	origin.Synthetic, origin.InteropLanguage = true, visibleIn
	if visibleIn != analysis.LanguageUnknown {
		origin.Language = visibleIn
	}
	origin.OriginID = originID
	if analysis.IsCallableKind(kind) {
		var signature strings.Builder
		signature.WriteString(name)
		signature.WriteByte('(')
		for index, parameter := range parameters {
			if index > 0 {
				signature.WriteString(", ")
			}
			signature.WriteString(parameter.Name)
			signature.WriteString(": ")
			signature.WriteString(parameter.Type)
		}
		signature.WriteByte(')')
		if typ != "" {
			signature.WriteString(": ")
			signature.WriteString(typ)
		}
		origin.Signature = signature.String()
	} else {
		origin.Signature = name + ": " + typ
	}
	return origin
}

func kotlinAccessorNames(property analysis.Symbol) (string, string) {
	name := property.Name
	if strings.HasPrefix(name, "is") && len(name) > 2 && name[2] >= 'A' && name[2] <= 'Z' && sameJvmType(property.Type, "boolean") {
		return name, "set" + name[2:]
	}
	stem := name
	if len(stem) > 0 && stem[0] >= 'a' && stem[0] <= 'z' {
		stem = strings.ToUpper(stem[:1]) + stem[1:]
	}
	return "get" + stem, "set" + stem
}

func javaBeanGetterName(method analysis.Symbol) (string, bool) {
	if strings.HasPrefix(method.Name, "get") && !sameJvmType(method.Type, "void") {
		return decapitalizeBean(method.Name[len("get"):])
	}
	if strings.HasPrefix(method.Name, "is") && sameJvmType(method.Type, "boolean") {
		return decapitalizeBean(method.Name[len("is"):])
	}
	return "", false
}

func decapitalizeBean(stem string) (string, bool) {
	if stem == "" || stem[0] < 'A' || stem[0] > 'Z' {
		return "", false
	}
	if len(stem) > 1 && stem[1] >= 'A' && stem[1] <= 'Z' {
		return stem, true // JavaBeans Introspector.decapitalize rule.
	}
	return strings.ToLower(stem[:1]) + stem[1:], true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (i *Index) removeFileContentsLocked(file *analysis.ParsedFile) {
	delete(i.fileSymbolsByName, file.URI)
	delete(i.fileSmartCastsByName, file.URI)
	delete(i.fileAnonymousByName, file.URI)
	i.removePackageLocked(file)
	i.removeCompletionPackageLocked(file.Package)
	removed := make(map[string]bool, len(file.Symbols))
	byNameKeys, byOriginKeys, byFQNKeys := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	byContainerNameKeys, byContainerMemberKeys := make(map[string]bool), make(map[string]bool)
	byReceiverKeys, byReceiverMemberKeys := make(map[string]bool), make(map[string]bool)
	byPackageKeys, workspaceKeys, completionKeys, bySuperKeys := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, s := range file.Symbols {
		delete(i.symbols, s.ID)
		removed[s.ID] = true
		if isLexicalSymbol(s) {
			continue
		}
		byNameKeys[s.Name] = true
		if s.OriginID != "" {
			byOriginKeys[s.OriginID] = true
		}
		byFQNKeys[s.FQN] = true
		if s.ContainerName != "" {
			byContainerNameKeys[s.ContainerName] = true
			byContainerMemberKeys[memberKey(s.ContainerName, s.Name)] = true
		}
		if s.ReceiverType != "" {
			receiver := simpleType(s.ReceiverType)
			byReceiverKeys[receiver] = true
			byReceiverMemberKeys[memberKey(receiver, s.Name)] = true
		}
		if s.ContainerID == "" && s.Package != "" {
			byPackageKeys[s.Package] = true
		}
		if isWorkspaceSymbol(s) {
			workspaceKeys[s.Name] = true
		}
		if isUnqualifiedCompletionSymbol(s) {
			completionKeys[s.Name] = true
		}
		for _, supertype := range s.Supertypes {
			simple := simpleType(supertype)
			bySuperKeys[simple] = true
			if simple != supertype {
				bySuperKeys[supertype] = true
			}
		}
	}
	filterStringIndexBuckets(i.byName, byNameKeys, removed)
	filterStringIndexBuckets(i.byOrigin, byOriginKeys, removed)
	filterStringIndexBuckets(i.byFQN, byFQNKeys, removed)
	filterStringIndexBuckets(i.byContainerName, byContainerNameKeys, removed)
	filterStringIndexBuckets(i.byContainerMember, byContainerMemberKeys, removed)
	filterStringIndexBuckets(i.byReceiver, byReceiverKeys, removed)
	filterStringIndexBuckets(i.byReceiverMember, byReceiverMemberKeys, removed)
	filterStringIndexBuckets(i.byPackage, byPackageKeys, removed)
	filterStringIndexBuckets(i.workspaceByName, workspaceKeys, removed)
	filterStringIndexBuckets(i.completionByName, completionKeys, removed)
	filterStringIndexBuckets(i.bySuper, bySuperKeys, removed)
	referenceNames := make(map[string]bool)
	for _, r := range file.References {
		referenceNames[r.Name] = true
	}
	for name := range referenceNames {
		bucket := i.refsByName[name]
		out := bucket[:0]
		for _, reference := range bucket {
			if reference.URI != file.URI {
				out = append(out, reference)
			}
		}
		if len(out) == 0 {
			delete(i.refsByName, name)
		} else {
			i.refsByName[name] = out
		}
	}
	if _, workspace := uriutil.Path(file.URI); workspace {
		prefixes := make(map[string]bool)
		for _, imported := range file.Imports {
			for _, prefix := range importPrefixes(imported.Path) {
				prefixes[prefix] = true
			}
		}
		for prefix := range prefixes {
			i.importersByPrefix[prefix] = withoutURI(i.importersByPrefix[prefix], file.URI)
		}
	}
}

func filterStringIndexBuckets(index map[string][]string, keys, removed map[string]bool) {
	for key := range keys {
		bucket := index[key]
		out := bucket[:0]
		for _, id := range bucket {
			if !removed[id] {
				out = append(out, id)
			}
		}
		if len(out) == 0 {
			delete(index, key)
		} else {
			index[key] = out
		}
	}
}

func (i *Index) addPackageLocked(file *analysis.ParsedFile) {
	if file.Package == "" {
		return
	}
	path, ok := uriutil.Path(file.URI)
	if !ok { // IntelliJ's package-definition providers exclude libraries.
		return
	}
	directory := uriutil.File(filepath.Dir(path))
	for _, existing := range i.packages[file.Package] {
		if existing == directory {
			return
		}
	}
	i.packages[file.Package] = append(i.packages[file.Package], directory)
}

func (i *Index) removePackageLocked(file *analysis.ParsedFile) {
	if file.Package == "" {
		return
	}
	path, ok := uriutil.Path(file.URI)
	if !ok {
		return
	}
	directory := uriutil.File(filepath.Dir(path))
	// Retain a directory while another file in that directory declares the
	// same package.
	for uri, candidate := range i.files {
		if uri == file.URI || candidate.Package != file.Package {
			continue
		}
		candidatePath, fileURI := uriutil.Path(uri)
		if fileURI && uriutil.File(filepath.Dir(candidatePath)) == directory {
			return
		}
	}
	i.packages[file.Package] = withoutURI(i.packages[file.Package], directory)
}

func (i *Index) addCompletionPackageLocked(packageName string) {
	if packageName == "" {
		return
	}
	if i.packageCounts[packageName] == 0 {
		parts := strings.Split(packageName, ".")
		parent := ""
		for _, child := range parts {
			i.packageChildren[parent] = appendUniqueString(i.packageChildren[parent], child)
			if parent == "" {
				parent = child
			} else {
				parent += "." + child
			}
		}
	}
	i.packageCounts[packageName]++
}

func (i *Index) removeCompletionPackageLocked(packageName string) {
	if packageName == "" || i.packageCounts[packageName] <= 0 {
		return
	}
	i.packageCounts[packageName]--
	if i.packageCounts[packageName] > 0 {
		return
	}
	delete(i.packageCounts, packageName)
	parts := strings.Split(packageName, ".")
	parent := ""
	for _, child := range parts {
		full := child
		if parent != "" {
			full = parent + "." + child
		}
		used := false
		for candidate, count := range i.packageCounts {
			if count > 0 && (candidate == full || strings.HasPrefix(candidate, full+".")) {
				used = true
				break
			}
		}
		if !used {
			i.packageChildren[parent] = without(i.packageChildren[parent], child)
		}
		parent = full
	}
}

func (i *Index) resolveLocked(file *analysis.ParsedFile, r analysis.Reference) []analysis.Symbol {
	if r.ResolvedID != "" {
		if symbol, ok := i.symbols[r.ResolvedID]; ok {
			return []analysis.Symbol{*symbol}
		}
	}
	if r.ArgumentLabel {
		if file.Language == analysis.LanguageJava {
			if symbols := i.resolveAnnotationAttributeLabelLocked(file, r); len(symbols) > 0 {
				return symbols
			}
		}
		return i.resolveArgumentLabelLocked(file, r)
	}
	ids := make([]string, 0)
	qualifier := r.Qualifier
	implicitReceiverTypes := make([]string, 0, 4)
	if document := i.docs[file.URI]; document != nil {
		// Tree-sitter's qualifier field commonly contains only the final token
		// (`value` in wrap(x).value.member). Prefer the complete balanced source
		// expression so generic return arguments survive through longer chains.
		if textual := expressionQualifierBefore(document.Text, r.StartByte); textual != "" {
			qualifier = textual
		}
	}
	if qualifier == "" {
		if qualifier == "" && file.Language == analysis.LanguageKotlin {
			implicitReceiverTypes = append(implicitReceiverTypes, i.contextualLambdaReceiverTypeLocked(file, r.StartByte), i.enclosingExtensionReceiverTypeLocked(file, r.StartByte))
			implicitReceiverTypes = append(implicitReceiverTypes, i.enclosingContextReceiverTypesLocked(file, r.StartByte)...)
			if enclosing := i.enclosingTypeLocked(file, r.StartByte); enclosing.ID != "" {
				implicitReceiverTypes = append(implicitReceiverTypes, enclosing.Name)
			}
		} else if file.Language == analysis.LanguageJava {
			implicitReceiverTypes = append(implicitReceiverTypes, i.javaSwitchLabelReceiverTypeLocked(file, r.StartByte))
		}
	}
	typeQualifierSymbols := i.resolveTypeSymbolsLocked(file, qualifier)
	typeQualifier := qualifier != "" && !strings.ContainsAny(qualifier, "()[]{} ") && !strings.Contains(qualifier, "::") && len(typeQualifierSymbols) > 0
	typeQualifierValue := i.typeQualifierActsAsValueLocked(file, typeQualifierSymbols)
	callableReference := callableReferenceOperatorBefore(i.documentTextLocked(file.URI), r.StartByte)
	unboundCallableReference := typeQualifier && callableReference
	if r.Role == analysis.RoleImport && r.Qualifier != "" {
		ids = append(ids, i.byFQN[r.Qualifier+"."+r.Name]...)
	}
	if qualifier != "" {
		ids = append(ids, i.anonymousObjectMemberIDsLocked(file, qualifier, r.Name, r.StartByte)...)
		typ := i.typeOfExpressionLocked(file, qualifier, r.StartByte)
		if explicit := explicitReceiverType(qualifier); explicit != "" {
			typ = explicit
		}
		if typ != "" {
			nullableReceiver := file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(typ), "?")
			memberAccessAllowed := !nullableReceiver || kotlinNullableMemberAccessAllowed(i.documentTextLocked(file.URI), r.StartByte)
			validContainers := i.typeAndSupertypesLocked(file, typ)
			for _, container := range validContainers {
				if memberAccessAllowed {
					for _, id := range i.byContainerMember[memberKey(container, r.Name)] {
						if symbol := i.symbols[id]; i.memberInheritedForReceiverLocked(file, *symbol, typ) && (!typeQualifier || unboundCallableReference || i.memberAvailableThroughTypeQualifierLocked(file, *symbol, typeQualifierSymbols)) && i.accessibleLocked(file, *symbol, r.StartByte) {
							ids = append(ids, id)
						}
					}
				}
				for _, id := range i.byReceiverMember[memberKey(container, r.Name)] {
					if symbol := i.symbols[id]; (!typeQualifier || typeQualifierValue || unboundCallableReference) && i.extensionReceiverApplicableLocked(file, *symbol, typ) && (memberAccessAllowed || strings.HasSuffix(strings.TrimSpace(symbol.ReceiverType), "?")) && i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
						ids = append(ids, id)
					}
				}
				if file.Language == analysis.LanguageKotlin {
					for _, id := range i.companionMemberIDsLocked(file, container, r.Name) {
						if i.accessibleLocked(file, *i.symbols[id], r.StartByte) {
							ids = append(ids, id)
						}
					}
				}
			}
		} else {
			ids = append(ids, i.byFQN[qualifier+"."+r.Name]...)
		}
	}
	for _, implicitReceiverType := range implicitReceiverTypes {
		if implicitReceiverType == "" {
			continue
		}
		for _, container := range i.typeAndSupertypesLocked(file, implicitReceiverType) {
			for _, id := range i.byContainerMember[memberKey(container, r.Name)] {
				if symbol := i.symbols[id]; i.memberInheritedForReceiverLocked(file, *symbol, implicitReceiverType) && i.accessibleLocked(file, *symbol, r.StartByte) {
					ids = append(ids, id)
				}
			}
			for _, id := range i.byReceiverMember[memberKey(container, r.Name)] {
				if symbol := i.symbols[id]; i.extensionReceiverApplicableLocked(file, *symbol, implicitReceiverType) && i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
					ids = append(ids, id)
				}
			}
		}
	}
	for _, imp := range file.Imports {
		if imp.Static && file.Language == analysis.LanguageJava {
			if imp.Wildcard || imp.LocalName() == r.Name {
				ids = append(ids, i.staticImportMemberIDsLocked(file, imp, r.Name, r.StartByte)...)
			}
			continue
		}
		if !imp.Wildcard && imp.LocalName() == r.Name {
			ids = append(ids, i.byFQN[imp.Path]...)
		}
		if imp.Wildcard {
			ids = append(ids, i.byFQN[imp.Path+"."+r.Name]...)
		}
	}
	if file.Package != "" {
		ids = append(ids, i.byFQN[file.Package+"."+r.Name]...)
	}
	if r.ContainerID != "" && qualifier == "" {
		instanceReceiver := !i.staticLikeContextLocked(file, r.StartByte)
		for containerID := r.ContainerID; containerID != ""; {
			c, ok := i.symbols[containerID]
			if !ok {
				break
			}
			for _, id := range i.byContainerMember[memberKey(c.Name, r.Name)] {
				s := i.symbols[id]
				if (s.ContainerID == c.ID || s.ContainerName == c.Name) && (instanceReceiver || i.staticOrNestedMemberLocked(*s)) {
					ids = append(ids, id)
				}
			}
			nextID := c.ContainerID
			if next, exists := i.symbols[nextID]; exists && analysis.IsTypeKind(c.Kind) && analysis.IsTypeKind(next.Kind) && !nestedTypeCapturesOuter(*c, *next) {
				instanceReceiver = false
			}
			containerID = nextID
		}
	}
	if len(ids) == 0 && qualifier == "" {
		for _, id := range i.byName[r.Name] {
			symbol := i.symbols[id]
			if i.accessibleLocked(file, *symbol, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) && (analysis.IsTypeKind(symbol.Kind) || symbol.ContainerID == "") {
				ids = append(ids, id)
			}
		}
	}
	if r.Role == analysis.RoleCall {
		for _, id := range append([]string(nil), ids...) {
			owner := i.symbols[id]
			if !analysis.IsTypeKind(owner.Kind) {
				continue
			}
			for _, constructorID := range i.byContainerMember[memberKey(owner.Name, owner.Name)] {
				constructor := i.symbols[constructorID]
				if constructor.Kind == analysis.KindConstructor && constructor.ContainerID == owner.ID {
					ids = append(ids, constructorID)
				}
			}
		}
	}
	candidates := i.symbolsForIDsLocked(ids, func(s analysis.Symbol) bool {
		if !i.accessibleLocked(file, s, r.StartByte) || !i.extensionVisibleLocked(file, s, r.StartByte) {
			return false
		}
		if typeQualifier && !unboundCallableReference && !i.memberAvailableThroughTypeQualifierLocked(file, s, typeQualifierSymbols) {
			return false
		}
		if !i.protectedReceiverAccessibleLocked(file, s, r) {
			return false
		}
		if isLexicalSymbol(s) && s.URI == file.URI {
			if s.StartByte > r.StartByte || !symbolInScopeAt(s, r.StartByte) {
				return false
			}
		}
		if r.Role == analysis.RoleCall {
			return (analysis.IsCallableKind(s.Kind) || analysis.IsTypeKind(s.Kind)) && (r.Arity < 0 || matchesArityForLanguage(s, r.Arity, file.Language))
		}
		if r.Role == analysis.RoleType {
			return analysis.IsTypeKind(s.Kind)
		}
		return true
	})
	explicitImports := make(map[string]bool)
	if qualifier == "" {
		for _, imported := range file.Imports {
			if !imported.Wildcard && imported.LocalName() == r.Name {
				explicitImports[imported.Path] = true
			}
		}
	}
	fromModule := i.moduleForURILocked(file.URI)
	fromSourceSet := i.sourceSetForURILocked(file.URI, fromModule)
	sourceSetRank := func(symbol analysis.Symbol) int {
		targetModule := i.moduleForURILocked(symbol.URI)
		if fromModule == nil || targetModule == nil || fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir {
			return 0
		}
		targetSet := i.sourceSetForURILocked(symbol.URI, targetModule)
		if distance := sourceSetAccessDistance(fromModule, fromSourceSet, targetSet); distance >= 0 {
			return 40 - distance
		}
		return 0
	}
	receiverRanks := map[string]int{}
	if r.Qualifier != "" || len(implicitReceiverTypes) > 0 {
		receiverTypes := implicitReceiverTypes
		if r.Qualifier != "" {
			receiverTypes = []string{i.typeOfExpressionLocked(file, r.Qualifier, r.StartByte)}
		}
		for _, receiverType := range receiverTypes {
			if receiverType != "" {
				for rank, container := range i.typeAndSupertypesLocked(file, receiverType) {
					if _, exists := receiverRanks[container]; !exists {
						receiverRanks[container] = 1000 - rank
					}
				}
			}
		}
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		as, bs := sourceSetRank(candidates[a]), sourceSetRank(candidates[b])
		if explicitImports[candidates[a].FQN] {
			as += 30
		}
		if explicitImports[candidates[b].FQN] {
			bs += 30
		}
		as += receiverRanks[candidates[a].ContainerName]
		bs += receiverRanks[candidates[b].ContainerName]
		if owner, ok := i.symbols[candidates[a].ContainerID]; ok {
			as += receiverRanks[owner.FQN]
		}
		if owner, ok := i.symbols[candidates[b].ContainerID]; ok {
			bs += receiverRanks[owner.FQN]
		}
		if candidates[a].ContainerID == r.ContainerID {
			as += 100
		}
		if candidates[b].ContainerID == r.ContainerID {
			bs += 100
		}
		if candidates[a].URI == file.URI && candidates[a].StartByte <= r.StartByte && candidates[a].EndByte >= r.StartByte {
			as += 50
		}
		if candidates[b].URI == file.URI && candidates[b].StartByte <= r.StartByte && candidates[b].EndByte >= r.StartByte {
			bs += 50
		}
		if candidates[a].URI == file.URI {
			as += 20
		}
		if candidates[b].URI == file.URI {
			bs += 20
		}
		if candidates[a].Package == file.Package {
			as += 10
		}
		if candidates[b].Package == file.Package {
			bs += 10
		}
		if candidates[a].StartByte <= r.StartByte {
			as += 2
		}
		if candidates[b].StartByte <= r.StartByte {
			bs += 2
		}
		if as == bs {
			aLexical, bLexical := isLexicalSymbol(candidates[a]), isLexicalSymbol(candidates[b])
			if aLexical && bLexical && candidates[a].URI == file.URI && candidates[b].URI == file.URI {
				if candidates[a].ScopeEndByte != candidates[b].ScopeEndByte {
					// The innermost containing block wins; an inner declaration
					// must stop shadowing as soon as that block ends.
					return candidates[a].ScopeEndByte < candidates[b].ScopeEndByte
				}
				if candidates[a].StartByte != candidates[b].StartByte {
					return candidates[a].StartByte > candidates[b].StartByte
				}
			}
			return candidates[a].FQN < candidates[b].FQN
		}
		return as > bs
	})
	if callableReference && len(candidates) > 1 {
		if expected, ok := i.callableReferenceExpectedParametersLocked(file, r.StartByte); ok {
			filtered := make([]analysis.Symbol, 0, len(candidates))
			for _, candidate := range candidates {
				if !analysis.IsCallableKind(candidate.Kind) || len(candidate.Parameters) != len(expected) {
					continue
				}
				matches := true
				for index, parameter := range candidate.Parameters {
					left, right := simpleType(parameter.Type), simpleType(expected[index])
					if file.Language == analysis.LanguageJava {
						matches = javaInvocationType(left) == javaInvocationType(right)
					} else {
						matches = sameJvmType(left, right)
					}
					if !matches {
						break
					}
				}
				if matches {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
	}
	if r.Role == analysis.RoleCall && len(candidates) > 1 {
		scores := make([]int, len(candidates))
		typedScores := make([]bool, len(candidates))
		for n, candidate := range candidates {
			score, typed := i.callCompatibilityLocked(file, r, candidate)
			scores[n] = score
			typedScores[n] = typed
		}
		if file.Language == analysis.LanguageKotlin && (qualifier != "" || len(implicitReceiverTypes) > 0) {
			memberApplicable := false
			for n, candidate := range candidates {
				if candidate.ReceiverType == "" && (!typedScores[n] || scores[n] > -1<<19) {
					memberApplicable = true
					break
				}
			}
			if memberApplicable {
				memberCandidates := make([]analysis.Symbol, 0, len(candidates))
				memberScores := make([]int, 0, len(candidates))
				memberTyped := make([]bool, 0, len(candidates))
				for n, candidate := range candidates {
					if candidate.ReceiverType == "" {
						memberCandidates = append(memberCandidates, candidate)
						memberScores = append(memberScores, scores[n])
						memberTyped = append(memberTyped, typedScores[n])
					}
				}
				candidates, scores, typedScores = memberCandidates, memberScores, memberTyped
			}
		}
		bestScore, anyTyped := -1<<30, false
		for n, score := range scores {
			if typedScores[n] {
				anyTyped = true
				if score > bestScore {
					bestScore = score
				}
			}
		}
		if anyTyped {
			filtered := candidates[:0]
			for n, candidate := range candidates {
				if scores[n] == bestScore {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
	}
	if len(candidates) > 1 {
		if r.Role != analysis.RoleCall || candidates[0].FQN != candidates[1].FQN || candidates[0].URI == candidates[1].URI && !analysis.IsCallableKind(candidates[0].Kind) {
			return candidates[:1]
		}
	}
	return candidates
}

func (i *Index) callableReferenceExpectedParametersLocked(file *analysis.ParsedFile, at int) ([]string, bool) {
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	equals := strings.LastIndexByte(source[:at], '=')
	if equals < 0 {
		return nil, false
	}
	start := strings.LastIndexAny(source[:equals], "\n;{}") + 1
	left := strings.TrimSpace(source[start:equals])
	if file.Language == analysis.LanguageKotlin {
		colon := strings.LastIndexByte(left, ':')
		if colon < 0 {
			return nil, false
		}
		target := strings.TrimSpace(left[colon+1:])
		arrow := strings.Index(target, "->")
		if arrow < 0 {
			return nil, false
		}
		parameters := strings.TrimSpace(target[:arrow])
		parameters = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(parameters, "("), ")"))
		if parameters == "" {
			return []string{}, true
		}
		return splitTopLevelTypeArguments(parameters), true
	}
	fields := strings.Fields(left)
	if len(fields) < 2 {
		return nil, false
	}
	target := strings.Join(fields[:len(fields)-1], " ")
	for _, modifier := range []string{"public ", "protected ", "private ", "static ", "final ", "volatile ", "transient "} {
		target = strings.TrimSpace(strings.ReplaceAll(" "+target+" ", " "+modifier, " "))
	}
	base, arguments := splitInstantiatedType(target)
	switch simpleType(base) {
	case "Consumer", "Predicate", "Function", "UnaryOperator":
		if len(arguments) >= 1 {
			return arguments[:1], true
		}
	case "BiConsumer", "BiPredicate", "BiFunction", "BinaryOperator":
		if len(arguments) >= 2 {
			return arguments[:2], true
		}
	case "Supplier", "Runnable":
		return []string{}, true
	}
	for _, owner := range i.resolveTypeSymbolsLocked(file, base) {
		for _, id := range i.byContainerName[owner.Name] {
			method := i.symbols[id]
			if method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
				continue
			}
			parameters := make([]string, len(method.Parameters))
			for index, parameter := range method.Parameters {
				parameters[index] = substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments)
			}
			return parameters, true
		}
	}
	return nil, false
}

func (i *Index) anonymousObjectMemberIDsLocked(file *analysis.ParsedFile, qualifier, name string, at int) []string {
	qualifier = strings.TrimSpace(qualifier)
	if strings.ContainsAny(qualifier, ".()[]{} 	\r\n") {
		return nil
	}
	var owner analysis.Symbol
	candidates := i.fileAnonymousByName[file.URI][qualifier]
	before := sort.Search(len(candidates), func(index int) bool { return candidates[index].StartByte > at })
	for index := before - 1; index >= 0; index-- {
		symbol := candidates[index]
		if symbol.ScopeEndByte > 0 && at > symbol.ScopeEndByte {
			continue
		}
		owner = *symbol
		break
	}
	if owner.ID == "" {
		return nil
	}
	var ids []string
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		if symbol.StartByte <= owner.NameEndByte || symbol.EndByte > owner.EndByte || name != "" && symbol.Name != name {
			continue
		}
		if analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || analysis.IsTypeKind(symbol.Kind) {
			ids = append(ids, symbol.ID)
		}
	}
	return ids
}

func (i *Index) resolveAnnotationAttributeLabelLocked(file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	ownerName := AnnotationAttributeOwner(i.documentTextLocked(file.URI), label.StartByte)
	if ownerName == "" {
		return nil
	}
	var ids []string
	for _, owner := range i.resolveTypeSymbolsLocked(file, ownerName) {
		if owner.Kind != analysis.KindAnnotation {
			continue
		}
		for _, id := range i.byContainerMember[memberKey(owner.Name, label.Name)] {
			if symbol := i.symbols[id]; symbol.ContainerID == owner.ID && i.accessibleLocked(file, *symbol, label.StartByte) {
				ids = append(ids, id)
			}
		}
	}
	return i.symbolsForIDsLocked(ids, nil)
}

func (i *Index) memberInheritedForReceiverLocked(file *analysis.ParsedFile, symbol analysis.Symbol, receiverType string) bool {
	if file.Language != analysis.LanguageJava || !containsString(symbol.Modifiers, "static") || symbol.ContainerID == "" {
		return true
	}
	owner, ok := i.symbols[symbol.ContainerID]
	if !ok || owner.Kind != analysis.KindInterface && owner.Kind != analysis.KindAnnotation {
		return true
	}
	for _, receiver := range i.resolveTypeSymbolsLocked(file, receiverType) {
		if receiver.ID == owner.ID {
			return true
		}
	}
	return false
}

func (i *Index) staticImportMemberIDsLocked(file *analysis.ParsedFile, imported analysis.Import, name string, at int) []string {
	ownerName := imported.Path
	if !imported.Wildcard {
		if dot := strings.LastIndexByte(ownerName, '.'); dot >= 0 {
			ownerName = ownerName[:dot]
		}
	}
	var ids []string
	for _, owner := range i.resolveTypeSymbolsLocked(file, ownerName) {
		for _, container := range i.typeAndSupertypesLocked(file, owner.FQN) {
			for _, id := range i.byContainerName[container] {
				symbol := i.symbols[id]
				if symbol.Name == name && i.staticOrNestedMemberLocked(*symbol) && i.memberInheritedForReceiverLocked(file, *symbol, owner.FQN) && i.accessibleLocked(file, *symbol, at) {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func (i *Index) javaSwitchLabelReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	if file.Language != analysis.LanguageJava {
		return ""
	}
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	caseAt := strings.LastIndex(source[:at], "case")
	if caseAt < 0 || caseAt > 0 && isIdentRune(rune(source[caseAt-1])) || caseAt+4 < len(source) && isIdentRune(rune(source[caseAt+4])) {
		return ""
	}
	labelPrefix := source[caseAt+4 : at]
	if strings.Contains(labelPrefix, "->") || strings.Contains(labelPrefix, ":") {
		return ""
	}
	switchAt := strings.LastIndex(source[:caseAt], "switch")
	if switchAt < 0 {
		return ""
	}
	openRelative := strings.IndexByte(source[switchAt:caseAt], '(')
	if openRelative < 0 {
		return ""
	}
	open := switchAt + openRelative
	close := matchingDelimiter(source, open, '(', ')')
	if close < 0 || close >= caseAt {
		return ""
	}
	return i.typeOfExpressionLocked(file, strings.TrimSpace(source[open+1:close]), at)
}

func matchingDelimiter(source string, open int, opening, closing byte) int {
	depth := 0
	for index := open; index < len(source); index++ {
		switch source[index] {
		case opening:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func callableReferenceOperatorBefore(source string, start int) bool {
	if start > len(source) {
		start = len(source)
	}
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(source[:start])
		if !unicode.IsSpace(r) {
			break
		}
		start -= size
	}
	return start >= 2 && source[start-2:start] == "::"
}

func (i *Index) resolveArgumentLabelLocked(file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		document = i.libraryDocs[file.URI]
	}
	if document == nil {
		return nil
	}
	var call *analysis.Reference
	bestSpan := int(^uint(0) >> 1)
	for index := range file.References {
		candidate := &file.References[index]
		if candidate.Role != analysis.RoleCall || candidate.ArgumentLabel || candidate.StartByte >= label.StartByte {
			continue
		}
		for _, argumentRange := range candidate.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start <= label.StartByte && label.EndByte <= end && end-start < bestSpan {
				call, bestSpan = candidate, end-start
			}
		}
	}
	if call == nil {
		return nil
	}
	var out []analysis.Symbol
	for _, callable := range i.resolveLocked(file, *call) {
		if !analysis.IsCallableKind(callable.Kind) {
			continue
		}
		before := len(out)
		if declaration := i.files[callable.URI]; declaration != nil {
			for _, symbol := range declaration.Symbols {
				if symbol.Kind == analysis.KindParameter && symbol.ContainerID == callable.ID && symbol.Name == label.Name {
					out = append(out, symbol)
				}
			}
		}
		if len(out) > before {
			continue
		}
		for _, parameter := range callable.Parameters {
			if parameter.Name == label.Name {
				out = append(out, analysis.Symbol{
					ID: callable.ID + "#parameter:" + label.Name, Name: label.Name, FQN: callable.FQN + "." + label.Name,
					Kind: analysis.KindParameter, Language: callable.Language, URI: callable.URI,
					Range: parameter.Range, SelectionRange: parameter.Range, ContainerID: callable.ID,
					ContainerName: callable.Name, Package: callable.Package, Type: parameter.Type,
					Signature: label.Name + ": " + parameter.Type, Library: callable.Library,
				})
			}
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) companionMembersLocked(file *analysis.ParsedFile, container string) []analysis.Symbol {
	seen := make(map[string]bool)
	var members []analysis.Symbol
	for _, owner := range i.resolveTypeSymbolsLocked(file, container) {
		for _, companionID := range i.byContainerName[owner.Name] {
			companion, ok := i.symbols[companionID]
			if !ok || companion.ContainerID != owner.ID || companion.Kind != analysis.KindObject || !containsString(companion.Modifiers, "companion") {
				continue
			}
			for _, memberID := range i.byContainerName[companion.Name] {
				member, exists := i.symbols[memberID]
				if !exists || member.ContainerID != companion.ID || seen[member.ID] {
					continue
				}
				seen[member.ID] = true
				members = append(members, *member)
			}
		}
	}
	return members
}

func (i *Index) companionMemberIDsLocked(file *analysis.ParsedFile, container, name string) []string {
	members := i.companionMembersLocked(file, container)
	ids := make([]string, 0, len(members))
	for _, member := range members {
		if member.Name == name {
			ids = append(ids, member.ID)
		}
	}
	return ids
}

func sameCallableShape(left, right analysis.Symbol) bool {
	if left.Name != right.Name || len(left.Parameters) != len(right.Parameters) {
		return false
	}
	for index := range left.Parameters {
		if simpleType(left.Parameters[index].Type) != simpleType(right.Parameters[index].Type) {
			return false
		}
	}
	return true
}

func (i *Index) protectedReceiverAccessibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, reference analysis.Reference) bool {
	if symbol.Language != analysis.LanguageJava || symbol.Package == file.Package || !containsString(symbol.Modifiers, "protected") {
		return true
	}
	if symbol.ContainerID == "" {
		return false
	}
	current := i.enclosingTypeLocked(file, reference.StartByte)
	if current.ID == "" || !i.containerInheritsLocked(current.ID, symbol.ContainerID) {
		return false
	}
	qualifier := strings.TrimSpace(reference.Qualifier)
	if qualifier == "" || qualifier == "this" || qualifier == "super" {
		return true
	}
	receiverType := i.typeOfExpressionLocked(file, qualifier, reference.StartByte)
	for _, receiver := range i.resolveTypeSymbolsLocked(file, receiverType) {
		if receiver.ID == current.ID || i.containerInheritsLocked(receiver.ID, current.ID) {
			return true
		}
	}
	return false
}

func lexicalBinding(file *analysis.ParsedFile, reference analysis.Reference, candidates []analysis.Symbol) string {
	if reference.Qualifier != "" || reference.Role == analysis.RoleImport {
		return ""
	}
	bestID := ""
	bestContainer, bestScope, bestStart := -1, int(^uint(0)>>1), -1
	for _, symbol := range candidates {
		if symbol.URI != file.URI || symbol.Name != reference.Name || !isLexicalSymbol(symbol) || !lexicalCandidateMatches(reference, symbol) {
			continue
		}
		containerScore := 0
		if symbol.ContainerID != "" && symbol.ContainerID == reference.ContainerID {
			containerScore = 1
		}
		scopeSize := symbol.ScopeEndByte - symbol.ScopeStartByte
		if scopeSize <= 0 {
			scopeSize = int(^uint(0) >> 1)
		}
		if containerScore > bestContainer || containerScore == bestContainer && (scopeSize < bestScope || scopeSize == bestScope && symbol.StartByte > bestStart) {
			bestID, bestContainer, bestScope, bestStart = symbol.ID, containerScore, scopeSize, symbol.StartByte
		}
	}
	return bestID
}

func lexicalCandidateMatches(reference analysis.Reference, symbol analysis.Symbol) bool {
	if symbol.NameEndByte > reference.StartByte {
		return false
	}
	if reference.Role == analysis.RoleType && symbol.Kind != analysis.KindTypeParameter || reference.Role != analysis.RoleType && symbol.Kind == analysis.KindTypeParameter {
		return false
	}
	if reference.Role == analysis.RoleLabel && symbol.Kind != analysis.KindLabel || reference.Role != analysis.RoleLabel && symbol.Kind == analysis.KindLabel {
		return false
	}
	return symbolInScopeAt(symbol, reference.StartByte)
}

func symbolInScopeAt(symbol analysis.Symbol, at int) bool {
	if !(symbol.ScopeStartByte > 0 && at < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && at > symbol.ScopeEndByte) {
		return true
	}
	for _, scope := range symbol.AdditionalScopes {
		if scope.StartByte <= at && at <= scope.EndByte {
			return true
		}
	}
	return false
}

func expressionQualifierBefore(source string, start int) string {
	if start <= 0 || start > len(source) || source[start-1] != '.' {
		return ""
	}
	if explicit := explicitReceiverSourceBefore(source, start); explicit != "" {
		return explicit
	}
	end, index := start-1, start-2
	parenDepth, bracketDepth, braceDepth, angleDepth := 0, 0, 0, 0
	allowLambdaGap := false
	for index >= 0 {
		value := source[index]
		switch value {
		case ')':
			parenDepth++
		case '(':
			if parenDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			parenDepth--
		case ']':
			bracketDepth++
		case '[':
			if bracketDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			bracketDepth--
		case '}':
			braceDepth++
		case '{':
			if braceDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			braceDepth--
			if braceDepth == 0 {
				allowLambdaGap = true
			}
		case '>':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				angleDepth++
			}
		case '<':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth > 0 {
				angleDepth--
			}
		default:
			lambdaGap := allowLambdaGap && braceDepth == 0 && (value == ' ' || value == '\t' || value == '\r' || value == '\n')
			if !lambdaGap {
				allowLambdaGap = false
			}
			if !lambdaGap && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 && !(isIdentRune(rune(value)) || value == '.' || value == ':' || value == '?' || value == '!' || value == '`') {
				return strings.Trim(strings.TrimSpace(source[index+1:end]), ".?!")
			}
		}
		index--
	}
	return strings.Trim(strings.TrimSpace(source[:end]), ".?!")
}

func explicitReceiverSourceBefore(source string, start int) string {
	end := start - 1
	for end > 0 && unicode.IsSpace(rune(source[end-1])) {
		end--
	}
	prefix := source[:end]
	for _, marker := range []string{"super<", "this@"} {
		if at := strings.LastIndex(prefix, marker); at >= 0 {
			candidate := strings.TrimSpace(prefix[at:])
			if marker == "super<" && strings.HasSuffix(candidate, ">") || marker == "this@" && len(candidate) > len(marker) && !strings.ContainsAny(candidate[len(marker):], " \t\r\n.(){}[]") {
				return candidate
			}
		}
	}
	return ""
}

func explicitReceiverType(qualifier string) string {
	qualifier = strings.TrimSpace(qualifier)
	if strings.HasPrefix(qualifier, "super<") && strings.HasSuffix(qualifier, ">") {
		return strings.TrimSpace(qualifier[len("super<") : len(qualifier)-1])
	}
	if strings.HasPrefix(qualifier, "this@") {
		return strings.TrimSpace(strings.TrimPrefix(qualifier, "this@"))
	}
	if strings.HasSuffix(qualifier, ".super") {
		return strings.TrimSuffix(qualifier, ".super")
	}
	if strings.HasSuffix(qualifier, ".this") {
		return strings.TrimSuffix(qualifier, ".this")
	}
	return ""
}

func isLexicalSymbol(symbol analysis.Symbol) bool {
	return symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindTypeParameter || symbol.Kind == analysis.KindLabel ||
		symbol.Kind == analysis.KindProperty && symbol.ScopeEndByte > symbol.EndByte
}

func (i *Index) callCompatibilityLocked(file *analysis.ParsedFile, ref analysis.Reference, candidate analysis.Symbol) (int, bool) {
	doc := i.docs[file.URI]
	if doc == nil {
		return 0, false
	}
	if len(candidate.Parameters) == 0 {
		return 16, len(ref.Arguments) == 0
	}
	score, typed := 0, true
	provided := make(map[int]bool, len(ref.Arguments))
	for n, argumentRange := range ref.Arguments {
		parameterIndex := n
		expression := doc.Slice(argumentRange)
		if name, value, named := namedArgument(expression); named {
			parameterIndex = -1
			for index, parameter := range candidate.Parameters {
				if parameter.Name == name {
					parameterIndex = index
					break
				}
			}
			if parameterIndex < 0 {
				// A named argument makes a candidate without that parameter
				// inapplicable even when its positional types happen to match.
				return -1 << 20, true
			}
			expression = value
		}
		if parameterIndex >= len(candidate.Parameters) {
			parameterIndex = len(candidate.Parameters) - 1
		}
		provided[parameterIndex] = true
		expectedType := strings.TrimSpace(candidate.Parameters[parameterIndex].Type)
		if lambdaTypes, explicitLambda := explicitLambdaParameterTypes(expression, file.Language); explicitLambda {
			expectedParameters := kotlinFunctionParameterTypes(expectedType)
			if file.Language == analysis.LanguageJava {
				expectedParameters = i.functionalParameterTypesLocked(file, expectedType)
			}
			if len(expectedParameters) != len(lambdaTypes) {
				return -1 << 20, true
			}
			for index := range lambdaTypes {
				matches := sameJvmType(lambdaTypes[index], expectedParameters[index])
				if file.Language == analysis.LanguageJava {
					matches = javaInvocationType(simpleType(lambdaTypes[index])) == javaInvocationType(simpleType(expectedParameters[index]))
				}
				if !matches {
					return -1 << 20, true
				}
			}
			score += 48
			continue
		}
		if file.Language == analysis.LanguageKotlin && strings.TrimSpace(expression) == "null" {
			if strings.HasSuffix(expectedType, "?") {
				score += 40
				continue
			}
			return -1 << 20, true
		}
		actualType := strings.TrimSpace(i.inferExpressionTypeLocked(file, expression, ref.StartByte))
		if file.Language == analysis.LanguageKotlin && strings.HasSuffix(actualType, "?") && !strings.HasSuffix(expectedType, "?") {
			return -1 << 20, true
		}
		actual := simpleType(actualType)
		expected := simpleType(expectedType)
		if actual == "" || expected == "" {
			typed = false
			continue
		}
		genericParameter := ""
		for _, parameter := range candidate.TypeParameters {
			if expected == parameter {
				genericParameter = parameter
				break
			}
		}
		if genericParameter != "" {
			if !i.typeArgumentSatisfiesBoundsLocked(file, actualType, candidate.TypeParameterBounds[genericParameter]) {
				return -1 << 20, true
			}
			// A type variable captures the argument precisely, but a concrete
			// identity overload remains more specific when both are applicable.
			score += 30
			continue
		}
		identity := sameJvmType(actual, expected)
		if file.Language == analysis.LanguageJava {
			identity = javaInvocationType(actual) == javaInvocationType(expected)
		}
		if identity {
			score += 32
		} else if file.Language == analysis.LanguageKotlin {
			if conversion, ok := kotlinIntegerLiteralConversionScore(expression, expected); ok {
				score += conversion
			} else if i.isSubtypeLocked(file, actual, expected) {
				score += 24
			} else {
				return -1 << 20, true
			}
		} else if i.isSubtypeLocked(file, actual, expected) {
			score += 24
		} else if file.Language == analysis.LanguageJava {
			if conversion, ok := javaInvocationConversionScore(actual, expected); ok {
				score += conversion
			} else {
				return -1 << 20, true
			}
		}
	}
	defaultsUsed, variadic := 0, false
	for index, parameter := range candidate.Parameters {
		if !provided[index] && parameter.Default != "" {
			defaultsUsed++
		}
		variadic = variadic || parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
	}
	if len(ref.Arguments) == len(candidate.Parameters) {
		score += 16
	}
	score -= defaultsUsed * 4
	if variadic {
		score -= 2
	}
	// Arity/default ranking is semantic evidence even when an incomplete
	// argument expression has no inferable type yet.
	typed = true
	return score, typed
}

func explicitLambdaParameterTypes(expression string, language analysis.Language) ([]string, bool) {
	expression = strings.TrimSpace(expression)
	arrow := strings.Index(expression, "->")
	if arrow < 0 {
		return nil, false
	}
	prefix := strings.TrimSpace(expression[:arrow])
	prefix = strings.TrimSpace(strings.TrimPrefix(prefix, "{"))
	if strings.HasPrefix(prefix, "(") && strings.HasSuffix(prefix, ")") {
		prefix = strings.TrimSpace(prefix[1 : len(prefix)-1])
	}
	if prefix == "" {
		return []string{}, true
	}
	parameters := splitTopLevelCallArguments(prefix)
	types := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		parameter = strings.TrimSpace(parameter)
		if language == analysis.LanguageKotlin {
			colon := topLevelExpressionOperator(parameter, ":")
			if colon < 0 {
				return nil, false
			}
			typ := strings.TrimSpace(parameter[colon+1:])
			if typ == "" {
				return nil, false
			}
			types = append(types, typ)
			continue
		}
		fields := strings.Fields(parameter)
		filtered := fields[:0]
		for _, field := range fields {
			if field != "final" && !strings.HasPrefix(field, "@") {
				filtered = append(filtered, field)
			}
		}
		if len(filtered) < 2 {
			return nil, false
		}
		types = append(types, strings.Join(filtered[:len(filtered)-1], " "))
	}
	return types, true
}

func (i *Index) typeArgumentSatisfiesBoundsLocked(file *analysis.ParsedFile, actual string, bounds []string) bool {
	for _, bound := range bounds {
		if !sameJvmType(actual, bound) && !i.isSubtypeLocked(file, actual, bound) {
			return false
		}
	}
	return true
}

func kotlinIntegerLiteralConversionScore(expression, expected string) (int, bool) {
	expression = strings.ReplaceAll(strings.TrimSpace(expression), "_", "")
	if expression == "" || strings.ContainsAny(expression, ".eEfF") {
		return 0, false
	}
	lower := strings.ToLower(expression)
	if strings.HasSuffix(lower, "l") || strings.HasSuffix(lower, "u") || strings.HasSuffix(lower, "ul") || strings.HasSuffix(lower, "lu") {
		return 0, false
	}
	value, ok := new(big.Int).SetString(expression, 0)
	if !ok {
		return 0, false
	}
	bits, signed := 0, true
	switch simpleType(expected) {
	case "Byte":
		bits = 8
	case "Short":
		bits = 16
	case "Int":
		bits = 32
	case "Long":
		bits = 64
	case "UByte":
		bits, signed = 8, false
	case "UShort":
		bits, signed = 16, false
	case "UInt":
		bits, signed = 32, false
	case "ULong":
		bits, signed = 64, false
	default:
		return 0, false
	}
	if !signed {
		return 28, value.Sign() >= 0 && value.BitLen() <= bits
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	minimum := new(big.Int).Neg(new(big.Int).Set(limit))
	maximum := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
	return 28, value.Cmp(minimum) >= 0 && value.Cmp(maximum) <= 0
}

func namedArgument(expression string) (name, value string, ok bool) {
	expression = strings.TrimSpace(expression)
	for index := 0; index < len(expression); index++ {
		if expression[index] != '=' || index+1 < len(expression) && expression[index+1] == '=' || index > 0 && strings.ContainsRune("=!<>", rune(expression[index-1])) {
			continue
		}
		candidate := strings.TrimSpace(expression[:index])
		if candidate == "" {
			return "", "", false
		}
		for offset, char := range candidate {
			if !(char == '_' || char == '`' || unicode.IsLetter(char) || offset > 0 && unicode.IsDigit(char)) {
				return "", "", false
			}
		}
		return strings.Trim(candidate, "`"), strings.TrimSpace(expression[index+1:]), true
	}
	return "", "", false
}

func sameJvmType(a, b string) bool {
	return canonicalJvmType(a) == canonicalJvmType(b)
}

func canonicalJvmType(value string) string {
	switch strings.ToLower(simpleType(value)) {
	case "byte", "java.lang.byte":
		return "byte"
	case "short", "java.lang.short":
		return "short"
	case "int", "integer", "java.lang.integer":
		return "int"
	case "long", "java.lang.long":
		return "long"
	case "float", "java.lang.float":
		return "float"
	case "double", "java.lang.double":
		return "double"
	case "char", "character", "java.lang.character":
		return "char"
	case "boolean", "java.lang.boolean":
		return "boolean"
	case "string", "java.lang.string":
		return "string"
	default:
		return strings.ToLower(simpleType(value))
	}
}

func javaInvocationConversionScore(actual, expected string) (int, bool) {
	actual, expected = javaInvocationType(actual), javaInvocationType(expected)
	primitiveWidening := map[string][]string{
		"byte":  {"short", "int", "long", "float", "double"},
		"short": {"int", "long", "float", "double"},
		"char":  {"int", "long", "float", "double"},
		"int":   {"long", "float", "double"},
		"long":  {"float", "double"},
		"float": {"double"},
	}
	for distance, candidate := range primitiveWidening[actual] {
		if candidate == expected {
			return 20 - distance, true
		}
	}
	boxed := map[string]string{
		"byte": "java.lang.byte", "short": "java.lang.short", "int": "java.lang.integer", "long": "java.lang.long",
		"float": "java.lang.float", "double": "java.lang.double", "char": "java.lang.character", "boolean": "java.lang.boolean",
	}
	if wrapper := boxed[actual]; wrapper != "" {
		if expected == wrapper {
			return 12, true
		}
		if expected == "java.lang.object" || expected == "java.lang.number" && actual != "char" && actual != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			return 8, true
		}
	}
	unboxed := map[string]string{}
	for primitive, wrapper := range boxed {
		unboxed[wrapper] = primitive
	}
	if primitive := unboxed[actual]; primitive != "" {
		if expected == "java.lang.object" || expected == "java.lang.number" && primitive != "char" && primitive != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			// Widening reference conversion is a strict-invocation candidate and
			// therefore wins before loose unboxing/widening is considered.
			return 24, true
		}
		if primitive == expected {
			return 12, true
		}
		for distance, candidate := range primitiveWidening[primitive] {
			if candidate == expected {
				return 10 - distance, true
			}
		}
	}
	if actual == "java.lang.string" && (expected == "java.lang.object" || expected == "java.lang.charsequence" || expected == "java.io.serializable" || expected == "java.lang.comparable") {
		return 16, true
	}
	return 0, false
}

func javaInvocationType(value string) string {
	value = simpleType(value)
	switch value {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return value
	case "Byte", "Short", "Integer", "Long", "Float", "Double", "Character", "Boolean":
		return "java.lang." + strings.ToLower(value)
	case "integer":
		return "java.lang.integer"
	case "character":
		return "java.lang.character"
	case "String", "string":
		return "java.lang.string"
	case "Object", "Number", "Comparable", "CharSequence":
		return "java.lang." + strings.ToLower(value)
	case "Serializable":
		return "java.io.serializable"
	default:
		return strings.ToLower(value)
	}
}

func (i *Index) isSubtypeLocked(file *analysis.ParsedFile, actual, expected string) bool {
	if file.Language == analysis.LanguageKotlin && simpleType(expected) == "Any" && actual != "" {
		return true
	}
	for _, candidate := range i.typeAndSupertypesLocked(file, actual) {
		if sameJvmType(candidate, expected) {
			return true
		}
	}
	return false
}

func memberKey(container, name string) string { return container + "\x00" + name }

func matchesArity(symbol analysis.Symbol, count int) bool {
	return matchesArityForLanguage(symbol, count, analysis.LanguageKotlin)
}

func matchesArityForLanguage(symbol analysis.Symbol, count int, language analysis.Language) bool {
	if len(symbol.Parameters) == count {
		return true
	}
	if !analysis.IsCallableKind(symbol.Kind) {
		return count == 0
	}
	required := 0
	variadic := false
	for _, parameter := range symbol.Parameters {
		if parameter.Default == "" || language == analysis.LanguageJava {
			required++
		}
		if parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg") {
			variadic = true
		}
	}
	return count >= required && (variadic || count <= len(symbol.Parameters))
}

func (i *Index) resolveTypeSymbolsLocked(file *analysis.ParsedFile, typeName string) []analysis.Symbol {
	base, _ := splitInstantiatedType(typeName)
	base = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(base, "out "), "in "))
	base = strings.TrimPrefix(base, "? extends ")
	base = strings.TrimPrefix(base, "? super ")
	base = strings.TrimSuffix(base, "?")
	for strings.HasSuffix(base, "[]") {
		base = strings.TrimSuffix(base, "[]")
	}
	if base == "" {
		return nil
	}
	filter := func(ids []string) []analysis.Symbol {
		return i.symbolsForIDsLocked(ids, func(symbol analysis.Symbol) bool {
			return analysis.IsTypeKind(symbol.Kind) && i.accessibleLocked(file, symbol)
		})
	}
	if strings.Contains(base, ".") {
		return filter(i.byFQN[base])
	}
	// Lexically declared type parameters and nested/local types have priority.
	var local []string
	for _, id := range i.byName[base] {
		symbol := i.symbols[id]
		if symbol.URI == file.URI && analysis.IsTypeKind(symbol.Kind) {
			local = append(local, id)
		}
	}
	if values := filter(local); len(values) > 0 {
		return values[:1]
	}
	for _, imported := range file.Imports {
		if !imported.Wildcard && imported.LocalName() == base {
			if values := filter(i.byFQN[imported.Path]); len(values) > 0 {
				return values
			}
		}
	}
	if file.Package != "" {
		if values := filter(i.byFQN[file.Package+"."+base]); len(values) > 0 {
			return values
		}
	}
	defaults := []string{"java.lang." + base}
	if file.Language == analysis.LanguageKotlin {
		for _, prefix := range []string{"kotlin.", "kotlin.annotation.", "kotlin.collections.", "kotlin.comparisons.", "kotlin.io.", "kotlin.ranges.", "kotlin.sequences.", "kotlin.text.", "kotlin.jvm."} {
			defaults = append(defaults, prefix+base)
		}
	}
	for _, fqn := range defaults {
		if values := filter(i.byFQN[fqn]); len(values) > 0 {
			return values
		}
	}
	for _, imported := range file.Imports {
		if imported.Wildcard {
			if values := filter(i.byFQN[imported.Path+"."+base]); len(values) > 0 {
				return values
			}
		}
	}
	values := filter(i.byName[base])
	if len(values) == 1 {
		return values
	}
	return nil
}

func splitInstantiatedType(value string) (string, []string) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
	open := strings.IndexByte(value, '<')
	if open < 0 {
		return value, nil
	}
	close := matchingTypeArgumentEnd(value, open)
	if close < 0 {
		return strings.TrimSpace(value[:open]), nil
	}
	return strings.TrimSpace(value[:open]), splitTopLevelTypeArguments(value[open+1 : close])
}

func matchingTypeArgumentEnd(value string, open int) int {
	depth := 0
	for index := open; index < len(value); index++ {
		switch value[index] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func splitTopLevelTypeArguments(value string) []string {
	depth, start := 0, 0
	var result []string
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' && depth == 0 {
			if argument := strings.TrimSpace(value[start:index]); argument != "" {
				result = append(result, argument)
			}
			start = index + 1
			continue
		}
		if value[index] == '<' {
			depth++
		} else if value[index] == '>' {
			depth--
		}
	}
	return result
}

func substituteTypeParameters(value string, parameters, arguments []string) string {
	if value == "" || len(parameters) == 0 || len(arguments) == 0 {
		return value
	}
	replacements := make(map[string]string, len(parameters))
	for index, parameter := range parameters {
		if index < len(arguments) {
			replacements[parameter] = arguments[index]
		}
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		word := value[index:end]
		if replacement := replacements[word]; replacement != "" {
			result.WriteString(replacement)
		} else {
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) directSupertypeMatchesLocked(candidate analysis.Symbol, targetID string) bool {
	file := i.files[candidate.URI]
	if file == nil {
		return false
	}
	for _, declared := range candidate.Supertypes {
		for _, resolved := range i.resolveTypeSymbolsLocked(file, declared) {
			if resolved.ID == targetID {
				return true
			}
		}
	}
	return false
}

func (i *Index) typeOfNameLocked(file *analysis.ParsedFile, name string, at int) string {
	if name == "this" || name == "super" {
		if enclosing := i.enclosingTypeLocked(file, at); enclosing.ID != "" {
			if name == "super" && len(enclosing.Supertypes) > 0 {
				return simpleType(enclosing.Supertypes[0])
			}
			return enclosing.Name
		}
	}
	bestSmartCast := ""
	nonNullSmartCast := false
	seenSmartCasts := make(map[string]bool)
	for _, smartCast := range i.fileSmartCastsByName[file.URI][name] {
		if smartCast.Name == name && smartCast.StartByte <= at && at <= smartCast.EndByte {
			if smartCast.Type == "!" {
				nonNullSmartCast = true
			} else if !seenSmartCasts[smartCast.Type] {
				seenSmartCasts[smartCast.Type] = true
				if bestSmartCast != "" {
					bestSmartCast += " & "
				}
				bestSmartCast += smartCast.Type
			}
		}
	}
	if bestSmartCast != "" {
		if bestSmartCast != "!" {
			return bestSmartCast
		}
	}
	best := ""
	var bestSymbol *analysis.Symbol
	candidates := i.fileSymbolsByName[file.URI][name]
	before := sort.Search(len(candidates), func(index int) bool { return candidates[index].StartByte > at })
	for index := before - 1; index >= 0; index-- {
		symbol := candidates[index]
		inScope := !isLexicalSymbol(*symbol) || symbolInScopeAt(*symbol, at)
		if !inScope {
			continue
		}
		bestSymbol = symbol
		best = symbol.Type
		if best == "" || best == "var" || best == "val" {
			best = i.inferredConventionBindingTypeLocked(file, *symbol)
			if best == "" && symbol.Initializer != "" {
				best = i.inferExpressionTypeLocked(file, symbol.Initializer, symbol.StartByte)
			}
		}
		break
	}
	if best != "" {
		if nonNullSmartCast {
			return strings.TrimSuffix(strings.TrimSpace(best), "?")
		}
		return best
	}
	if bestSymbol != nil {
		if contextual := i.contextualLambdaParameterTypeLocked(file, *bestSymbol); contextual != "" {
			return contextual
		}
	}
	if symbols := i.resolveTypeSymbolsLocked(file, name); len(symbols) > 0 {
		return symbols[0].FQN
	}
	return ""
}

func (i *Index) inferredConventionBindingTypeLocked(file *analysis.ParsedFile, symbol analysis.Symbol) string {
	text := i.documentTextLocked(file.URI)
	for _, reference := range file.References {
		if strings.HasPrefix(reference.Name, "component") && reference.StartByte <= symbol.NameStartByte && symbol.NameEndByte <= reference.EndByte {
			receiver := i.inferExpressionTypeLocked(file, reference.Qualifier, symbol.StartByte)
			if receiver != "" {
				return i.memberResultTypeLocked(file, receiver, reference.Name, symbol.StartByte)
			}
		}
		if reference.Name != "next" || reference.StartByte < symbol.NameEndByte || reference.StartByte > symbol.ScopeEndByte || symbol.NameEndByte > len(text) || reference.EndByte > len(text) {
			continue
		}
		between := strings.TrimSpace(text[symbol.NameEndByte:reference.EndByte])
		if between != "in" {
			continue
		}
		iteratorType := i.typeOfExpressionLocked(file, reference.Qualifier, reference.StartByte)
		if iteratorType != "" {
			return i.memberResultTypeLocked(file, iteratorType, "next", reference.StartByte)
		}
	}
	return ""
}

func (i *Index) contextualLambdaParameterTypeLocked(file *analysis.ParsedFile, parameter analysis.Symbol) string {
	if file.Language != analysis.LanguageKotlin || parameter.ScopeEndByte <= parameter.ScopeStartByte {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return ""
	}
	parameterIndex := 0
	if parameter.Name != "it" {
		peers := make([]analysis.Symbol, 0, 2)
		for _, symbol := range file.Symbols {
			if (symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindVariable) && symbol.ScopeStartByte == parameter.ScopeStartByte && symbol.ScopeEndByte == parameter.ScopeEndByte {
				peers = append(peers, symbol)
			}
		}
		sort.Slice(peers, func(left, right int) bool { return peers[left].NameStartByte < peers[right].NameStartByte })
		for index, peer := range peers {
			if peer.ID == parameter.ID {
				parameterIndex = index
				break
			}
		}
	}
	for _, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start > parameter.StartByte || parameter.EndByte > end {
				continue
			}
			for _, callable := range i.resolveLocked(file, call) {
				if len(callable.Parameters) == 0 {
					continue
				}
				callableParameter := argumentIndex
				if callableParameter >= len(callable.Parameters) {
					callableParameter = len(callable.Parameters) - 1
				}
				parameterType := i.contextualCallableParameterTypeLocked(file, call, callable, callableParameter, document)
				types := kotlinFunctionParameterTypes(parameterType)
				if parameterIndex < len(types) {
					return types[parameterIndex]
				}
			}
		}
	}
	return ""
}

func (i *Index) contextualLambdaReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	if file.Language != analysis.LanguageKotlin {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return ""
	}
	best, bestSpan := "", int(^uint(0)>>1)
	for _, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if at < start || end < at || end-start >= bestSpan {
				continue
			}
			for _, callable := range i.resolveLocked(file, call) {
				if len(callable.Parameters) == 0 {
					continue
				}
				callableParameter := argumentIndex
				if callableParameter >= len(callable.Parameters) {
					callableParameter = len(callable.Parameters) - 1
				}
				parameterType := i.contextualCallableParameterTypeLocked(file, call, callable, callableParameter, document)
				if receiver := kotlinFunctionReceiverType(parameterType); receiver != "" {
					best, bestSpan = receiver, end-start
					break
				}
			}
		}
	}
	return best
}

func (i *Index) enclosingExtensionReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	bestStart, bestEnd, receiver := -1, len(i.documentTextLocked(file.URI))+1, ""
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.ReceiverType == "" || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if symbol.StartByte > bestStart || symbol.StartByte == bestStart && symbol.EndByte < bestEnd {
			bestStart, bestEnd, receiver = symbol.StartByte, symbol.EndByte, symbol.ReceiverType
		}
	}
	return receiver
}

func (i *Index) enclosingContextReceiverTypesLocked(file *analysis.ParsedFile, at int) []string {
	if file.Language != analysis.LanguageKotlin {
		return nil
	}
	text := i.documentTextLocked(file.URI)
	if text == "" {
		return nil
	}
	var callable analysis.Symbol
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if callable.ID == "" || symbol.StartByte >= callable.StartByte && symbol.EndByte <= callable.EndByte {
			callable = symbol
		}
	}
	if callable.ID == "" || callable.StartByte <= 0 || callable.StartByte > len(text) {
		return nil
	}
	end := callable.StartByte
	for end > 0 && unicode.IsSpace(rune(text[end-1])) {
		end--
	}
	if end == 0 || text[end-1] != ')' {
		return nil
	}
	closeAt := end - 1
	depth, openAt := 0, -1
	for index := closeAt; index >= 0; index-- {
		switch text[index] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				openAt = index
				index = -1
			}
		}
	}
	if openAt < 0 {
		return nil
	}
	wordEnd := openAt
	for wordEnd > 0 && unicode.IsSpace(rune(text[wordEnd-1])) {
		wordEnd--
	}
	wordStart := wordEnd
	for wordStart > 0 && isIdentRune(rune(text[wordStart-1])) {
		wordStart--
	}
	if text[wordStart:wordEnd] != "context" {
		return nil
	}
	items := splitTopLevelCallArguments(text[openAt+1 : closeAt])
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if colon := strings.IndexByte(item, ':'); colon >= 0 {
			item = strings.TrimSpace(item[colon+1:])
		}
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (i *Index) contextualCallableParameterTypeLocked(file *analysis.ParsedFile, call analysis.Reference, callable analysis.Symbol, parameterIndex int, document *textdoc.Document) string {
	if parameterIndex < 0 || parameterIndex >= len(callable.Parameters) {
		return ""
	}
	parameterType := callable.Parameters[parameterIndex].Type
	if len(callable.TypeParameters) == 0 || len(call.Arguments) == 0 {
		return parameterType
	}
	inferred := make(map[string]string, len(callable.TypeParameters))
	for argumentIndex, argumentRange := range call.Arguments {
		callableIndex := argumentIndex
		if callableIndex >= len(callable.Parameters) {
			callableIndex = len(callable.Parameters) - 1
		}
		if callableIndex < 0 || callableIndex == parameterIndex {
			continue
		}
		start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
		if start < 0 || end < start || end > len(document.Text) {
			continue
		}
		expression := strings.TrimSpace(document.Text[start:end])
		if equals := topLevelNamedArgumentEquals(expression); equals >= 0 {
			expression = strings.TrimSpace(expression[equals+1:])
		}
		actual := i.inferExpressionTypeLocked(file, expression, call.StartByte)
		if actual != "" {
			inferTypeParameterBindings(callable.Parameters[callableIndex].Type, actual, callable.TypeParameters, inferred)
		}
	}
	arguments := make([]string, len(callable.TypeParameters))
	for index, parameter := range callable.TypeParameters {
		arguments[index] = inferred[parameter]
	}
	return substituteTypeParameters(parameterType, callable.TypeParameters, arguments)
}

func topLevelNamedArgumentEquals(expression string) int {
	angles, parens, brackets, braces := 0, 0, 0, 0
	for index, r := range expression {
		switch r {
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '=':
			if angles == 0 && parens == 0 && brackets == 0 && braces == 0 {
				return index
			}
		}
	}
	return -1
}

func kotlinFunctionParameterTypes(functionType string) []string {
	functionType = strings.TrimSpace(strings.TrimSuffix(functionType, "?"))
	arrow := strings.LastIndex(functionType, "->")
	if arrow < 0 {
		return nil
	}
	parameters := strings.TrimSpace(functionType[:arrow])
	if dot := strings.LastIndex(parameters, ".("); dot >= 0 {
		parameters = parameters[dot+1:]
	}
	if len(parameters) < 2 || parameters[0] != '(' || parameters[len(parameters)-1] != ')' {
		return nil
	}
	parameters = strings.TrimSpace(parameters[1 : len(parameters)-1])
	if parameters == "" {
		return nil
	}
	return splitTopLevelCallArguments(parameters)
}

func kotlinFunctionReceiverType(functionType string) string {
	functionType = strings.TrimSpace(strings.TrimSuffix(functionType, "?"))
	arrow := strings.LastIndex(functionType, "->")
	if arrow < 0 {
		return ""
	}
	parameters := strings.TrimSpace(functionType[:arrow])
	dot := strings.LastIndex(parameters, ".(")
	if dot <= 0 {
		return ""
	}
	receiver := strings.TrimSpace(parameters[:dot])
	receiver = strings.TrimSpace(strings.TrimPrefix(receiver, "suspend "))
	return receiver
}

func (i *Index) inferExpressionTypeLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(strings.TrimSuffix(expression, ";"))
	expression = unwrapEnclosingParentheses(expression)
	if file.Language == analysis.LanguageKotlin {
		if strings.HasPrefix(expression, "by ") {
			delegate := strings.TrimSpace(strings.TrimPrefix(expression, "by "))
			if open := topLevelExpressionOperator(delegate, "{"); open >= 0 {
				if close := matchingDelimiter(delegate, open, '{', '}'); close > open {
					body := unwrapExpressionBlock(delegate[open : close+1])
					return i.inferExpressionTypeLocked(file, body, at)
				}
			}
			if delegateType := i.inferExpressionTypeLocked(file, delegate, at); delegateType != "" {
				for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, delegateType) {
					owner, arguments := instantiated.symbol, instantiated.arguments
					for _, id := range i.byContainerMember[memberKey(owner.Name, "getValue")] {
						getter := i.symbols[id]
						if getter.ContainerID == owner.ID && analysis.IsCallableKind(getter.Kind) && getter.Type != "" && i.accessibleLocked(file, *getter, at) {
							return substituteTypeParameters(getter.Type, owner.TypeParameters, arguments)
						}
					}
				}
				for _, container := range i.typeAndSupertypesLocked(file, delegateType) {
					for _, id := range i.byReceiverMember[memberKey(container, "getValue")] {
						getter := i.symbols[id]
						if getter.Type == "" || !analysis.IsCallableKind(getter.Kind) || !i.accessibleLocked(file, *getter, at) || !i.extensionVisibleLocked(file, *getter, at) {
							continue
						}
						if bindings, applicable := i.extensionReceiverBindingsLocked(file, *getter, delegateType); applicable {
							return substituteTypeBindings(getter.Type, bindings)
						}
					}
				}
			}
		}
		if inferred := i.inferKotlinCompositeExpressionLocked(file, expression, at); inferred != "" {
			return inferred
		}
		if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
			body := strings.TrimSpace(expression[1 : len(expression)-1])
			parameters := ""
			if arrow := topLevelExpressionOperator(body, "->"); arrow >= 0 {
				parameters = strings.TrimSpace(body[:arrow])
				body = strings.TrimSpace(body[arrow+2:])
			}
			result := i.inferExpressionTypeLocked(file, unwrapExpressionBlock("{"+body+"}"), at)
			if result != "" {
				parameterTypes := make([]string, 0)
				for _, parameter := range splitTopLevelExpressions(parameters, ',') {
					if colon := strings.LastIndexByte(parameter, ':'); colon >= 0 {
						parameterTypes = append(parameterTypes, strings.TrimSpace(parameter[colon+1:]))
					} else if parameter != "" {
						parameterTypes = append(parameterTypes, "Any")
					}
				}
				return "(" + strings.Join(parameterTypes, ", ") + ") -> " + result
			}
		}
		if strings.HasPrefix(expression, "::") {
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(expression, "::")), "`")
			for _, id := range i.byName[name] {
				callable := i.symbols[id]
				if !analysis.IsCallableKind(callable.Kind) || callable.Type == "" || !i.accessibleLocked(file, *callable, at) {
					continue
				}
				parameterTypes := make([]string, 0, len(callable.Parameters))
				for _, parameter := range callable.Parameters {
					parameterTypes = append(parameterTypes, parameter.Type)
				}
				return "(" + strings.Join(parameterTypes, ", ") + ") -> " + callable.Type
			}
		}
	} else if inferred := i.inferJavaCompositeExpressionLocked(file, expression, at); inferred != "" {
		return inferred
	}
	if open := strings.IndexByte(expression, '('); open >= 0 {
		if close := callClosingParen(expression, open); close >= open && close < len(expression)-1 {
			remainder := strings.TrimSpace(expression[close+1:])
			if strings.HasPrefix(remainder, "(") {
				typ := i.inferExpressionTypeLocked(file, expression[:close+1], at)
				for strings.HasPrefix(remainder, "(") && typ != "" {
					end := callClosingParen(remainder, 0)
					if end < 0 || end >= len(remainder) {
						typ = i.invocationResultTypeLocked(file, typ, at)
						remainder = ""
						break
					}
					typ = i.invocationResultTypeLocked(file, typ, at)
					remainder = strings.TrimSpace(remainder[end+1:])
				}
				if remainder == "" {
					return typ
				}
			}
		}
	}
	switch {
	case expression == "true" || expression == "false":
		if file.Language == analysis.LanguageJava {
			return "boolean"
		}
		return "Boolean"
	case strings.HasPrefix(expression, "\"") || strings.HasPrefix(expression, "\"\"\""):
		return "String"
	case strings.HasPrefix(expression, "'"):
		if file.Language == analysis.LanguageJava {
			return "char"
		}
		return "Char"
	case numericExpression(expression):
		if strings.ContainsAny(expression, ".eEfFdD") {
			if file.Language == analysis.LanguageJava {
				return "double"
			}
			return "Double"
		}
		if strings.HasSuffix(strings.ToLower(expression), "l") {
			if file.Language == analysis.LanguageJava {
				return "long"
			}
			return "Long"
		}
		if file.Language == analysis.LanguageJava {
			return "int"
		}
		return "Int"
	}
	if strings.HasPrefix(expression, "new ") {
		expression = strings.TrimSpace(strings.TrimPrefix(expression, "new "))
	}
	open := strings.IndexByte(expression, '(')
	if open < 0 {
		if !strings.ContainsAny(expression, " +-*/%?:[]{}") {
			if !strings.Contains(expression, ".") {
				return i.declaredTypeOfNameLocked(file, expression, at)
			}
			return i.typeOfExpressionLocked(file, expression, at)
		}
		return ""
	}
	callee := strings.TrimSpace(expression[:open])
	if dot := strings.LastIndexByte(callee, '.'); dot >= 0 {
		callee = callee[dot+1:]
	}
	callee = strings.Trim(callee, "`")
	base, explicitArguments := splitInstantiatedType(callee)
	if declared := i.declaredTypeOfNameLocked(file, base, at); declared != "" {
		if result := i.invocationResultTypeLocked(file, declared, at); result != "" {
			return result
		}
	}
	for _, symbol := range i.fileSymbolsByName[file.URI][base] {
		if analysis.IsTypeKind(symbol.Kind) || symbol.StartByte > at || !symbolInScopeAt(*symbol, at) {
			continue
		}
		if valueType := i.typeOfNameLocked(file, base, at); valueType != "" {
			if result := i.invocationResultTypeLocked(file, valueType, at); result != "" {
				return result
			}
		}
		break
	}
	callValues := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
	switch base {
	case "listOf", "emptyList":
		return kotlinCollectionFactoryType(i, file, "List", explicitArguments, callValues, at)
	case "mutableListOf":
		return kotlinCollectionFactoryType(i, file, "MutableList", explicitArguments, callValues, at)
	case "setOf", "emptySet":
		return kotlinCollectionFactoryType(i, file, "Set", explicitArguments, callValues, at)
	case "mutableSetOf":
		return kotlinCollectionFactoryType(i, file, "MutableSet", explicitArguments, callValues, at)
	case "mapOf", "emptyMap":
		return i.kotlinMapFactoryTypeLocked(file, "Map", explicitArguments, callValues, at)
	case "mutableMapOf":
		return i.kotlinMapFactoryTypeLocked(file, "MutableMap", explicitArguments, callValues, at)
	case "arrayOf":
		return kotlinCollectionFactoryType(i, file, "Array", explicitArguments, callValues, at)
	}
	if types := i.resolveTypeSymbolsLocked(file, base); len(types) > 0 {
		owner := types[0]
		arguments := explicitArguments
		if len(arguments) == 0 && len(owner.TypeParameters) > 0 {
			callArguments := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
			constructorOwners := []analysis.Symbol{owner}
			if owner.Kind == analysis.KindTypeAlias && owner.Type != "" {
				underlying, _ := splitInstantiatedType(owner.Type)
				constructorOwners = append(constructorOwners, i.resolveTypeSymbolsLocked(file, underlying)...)
			}
			for _, constructorOwner := range constructorOwners {
				for _, id := range i.byContainerMember[memberKey(constructorOwner.Name, constructorOwner.Name)] {
					constructor := i.symbols[id]
					if constructor.Kind != analysis.KindConstructor || constructor.ContainerID != constructorOwner.ID {
						continue
					}
					inferred := make(map[string]string)
					for index, parameter := range constructor.Parameters {
						if index >= len(callArguments) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, callArguments[index], at)
						inferTypeParameterBindings(parameter.Type, actual, owner.TypeParameters, inferred)
					}
					for _, typeParameter := range owner.TypeParameters {
						if inferred[typeParameter] == "" {
							arguments = nil
							break
						}
						arguments = append(arguments, inferred[typeParameter])
					}
					if len(arguments) > 0 {
						break
					}
				}
				if len(arguments) > 0 {
					break
				}
			}
		}
		if len(arguments) > 0 {
			return owner.Name + "<" + strings.Join(arguments, ", ") + ">"
		}
		return owner.Name
	}
	for _, id := range i.byName[base] {
		candidate := i.symbols[id]
		if !i.accessibleLocked(file, *candidate, at) {
			continue
		}
		if analysis.IsTypeKind(candidate.Kind) {
			return candidate.Name
		}
		if analysis.IsCallableKind(candidate.Kind) && candidate.Type != "" {
			result := candidate.Type
			if len(candidate.TypeParameters) > 0 {
				arguments := explicitArguments
				if len(arguments) == 0 {
					values := splitTopLevelCallArguments(expression[open+1 : callClosingParen(expression, open)])
					inferred := make(map[string]string, len(candidate.TypeParameters))
					for parameterIndex, parameter := range candidate.Parameters {
						if parameterIndex >= len(values) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, values[parameterIndex], at)
						inferTypeParameterBindings(parameter.Type, actual, candidate.TypeParameters, inferred)
					}
					for _, parameter := range candidate.TypeParameters {
						if inferred[parameter] == "" {
							arguments = nil
							break
						}
						arguments = append(arguments, inferred[parameter])
					}
				}
				result = substituteTypeParameters(result, candidate.TypeParameters, arguments)
			}
			return result
		}
	}
	return ""
}

func kotlinCollectionFactoryType(i *Index, file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) == 0 {
		var element string
		for _, value := range values {
			element = i.commonExpressionTypeLocked(file, element, i.inferExpressionTypeLocked(file, value, at))
		}
		if element == "" {
			element = "Nothing"
		}
		arguments = []string{element}
	}
	return collection + "<" + strings.Join(arguments, ", ") + ">"
}

func (i *Index) kotlinMapFactoryTypeLocked(file *analysis.ParsedFile, collection string, explicit, values []string, at int) string {
	arguments := append([]string(nil), explicit...)
	if len(arguments) < 2 {
		keyType, valueType := "", ""
		for _, value := range values {
			if separator := topLevelWordIndex(value, "to"); separator >= 0 {
				keyType = i.commonExpressionTypeLocked(file, keyType, i.inferExpressionTypeLocked(file, value[:separator], at))
				valueType = i.commonExpressionTypeLocked(file, valueType, i.inferExpressionTypeLocked(file, value[separator+len("to"):], at))
			}
		}
		if keyType == "" {
			keyType = "Nothing"
		}
		if valueType == "" {
			valueType = "Nothing"
		}
		arguments = []string{keyType, valueType}
	}
	return collection + "<" + strings.Join(arguments, ", ") + ">"
}

func (i *Index) inferJavaCompositeExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	if strings.HasPrefix(expression, "(") {
		if close := matchingDelimiter(expression, 0, '(', ')'); close > 1 && close < len(expression)-1 {
			candidate := strings.TrimSpace(expression[1:close])
			if isJavaPrimitiveType(candidate) || len(i.resolveTypeSymbolsLocked(file, candidate)) > 0 {
				return candidate
			}
		}
	}
	if question := topLevelExpressionOperator(expression, "?"); question >= 0 {
		remainder := expression[question+1:]
		if colon := topLevelExpressionOperator(remainder, ":"); colon >= 0 {
			left := i.inferExpressionTypeLocked(file, remainder[:colon], at)
			right := i.inferExpressionTypeLocked(file, remainder[colon+1:], at)
			return i.commonExpressionTypeLocked(file, left, right)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(expression), "switch") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			if close := matchingDelimiter(expression, open, '{', '}'); close > open {
				var inferred string
				for _, entry := range splitTopLevelExpressions(expression[open+1:close], ';') {
					if arrow := strings.Index(entry, "->"); arrow >= 0 {
						branch := strings.TrimSpace(entry[arrow+2:])
						branch = strings.TrimSpace(strings.TrimPrefix(branch, "yield "))
						inferred = i.commonExpressionTypeLocked(file, inferred, i.inferExpressionTypeLocked(file, unwrapExpressionBlock(branch), at))
					}
				}
				return inferred
			}
		}
	}
	return ""
}

func isJavaPrimitiveType(value string) bool {
	switch strings.TrimSpace(value) {
	case "boolean", "byte", "short", "int", "long", "float", "double", "char":
		return true
	default:
		return false
	}
}

func unwrapEnclosingParentheses(expression string) string {
	for strings.HasPrefix(expression, "(") {
		close := matchingDelimiter(expression, 0, '(', ')')
		if close != len(expression)-1 {
			break
		}
		expression = strings.TrimSpace(expression[1:close])
	}
	return expression
}

func (i *Index) inferKotlinCompositeExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	if operator := topLevelWordIndex(expression, "to"); operator >= 0 {
		left := i.inferExpressionTypeLocked(file, expression[:operator], at)
		right := i.inferExpressionTypeLocked(file, expression[operator+len("to"):], at)
		if left != "" && right != "" {
			return "Pair<" + left + ", " + right + ">"
		}
	}
	for _, name := range []string{"run", "with"} {
		if !strings.HasPrefix(strings.TrimSpace(expression), name) {
			continue
		}
		brace := topLevelExpressionOperator(expression, "{")
		if brace < 0 {
			continue
		}
		close := matchingDelimiter(expression, brace, '{', '}')
		if close <= brace {
			continue
		}
		body := unwrapExpressionBlock(expression[brace : close+1])
		receiver := ""
		if name == "with" {
			if open := strings.IndexByte(expression, '('); open >= 0 {
				if end := callClosingParen(expression, open); end > open {
					receiver = i.inferExpressionTypeLocked(file, expression[open+1:end], at)
				}
			}
		}
		if (body == "this" || body == "it") && receiver != "" {
			return receiver
		}
		if inferred := i.inferExpressionTypeLocked(file, body, at); inferred != "" {
			return inferred
		}
	}
	if operator := topLevelExpressionOperator(expression, "?:"); operator >= 0 {
		left := strings.TrimSuffix(strings.TrimSpace(i.inferExpressionTypeLocked(file, expression[:operator], at)), "?")
		right := i.inferExpressionTypeLocked(file, expression[operator+2:], at)
		return i.commonExpressionTypeLocked(file, left, right)
	}
	for _, operator := range []string{" as? ", " as "} {
		if index := topLevelExpressionOperator(expression, operator); index >= 0 {
			typ := strings.TrimSpace(expression[index+len(operator):])
			if operator == " as? " && typ != "" && !strings.HasSuffix(typ, "?") {
				typ += "?"
			}
			return typ
		}
	}
	if strings.HasPrefix(expression, "if") {
		open := strings.IndexByte(expression, '(')
		if open >= 0 {
			if close := matchingDelimiter(expression, open, '(', ')'); close >= 0 {
				rest := strings.TrimSpace(expression[close+1:])
				if elseAt := topLevelWordIndex(rest, "else"); elseAt >= 0 {
					left := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(rest[:elseAt]), at)
					right := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(rest[elseAt+len("else"):]), at)
					return i.commonExpressionTypeLocked(file, left, right)
				}
			}
		}
	}
	if strings.HasPrefix(expression, "when") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			close := matchingDelimiter(expression, open, '{', '}')
			if close > open {
				var inferred string
				for _, entry := range splitTopLevelExpressions(expression[open+1:close], ';') {
					if arrow := strings.Index(entry, "->"); arrow >= 0 {
						branch := i.inferExpressionTypeLocked(file, unwrapExpressionBlock(entry[arrow+2:]), at)
						inferred = i.commonExpressionTypeLocked(file, inferred, branch)
					}
				}
				return inferred
			}
		}
	}
	if strings.HasPrefix(expression, "try") {
		open := strings.IndexByte(expression, '{')
		if open >= 0 {
			var inferred string
			for cursor := open; cursor >= 0 && cursor < len(expression); {
				close := matchingDelimiter(expression, cursor, '{', '}')
				if close <= cursor {
					break
				}
				inferred = i.commonExpressionTypeLocked(file, inferred, i.inferExpressionTypeLocked(file, unwrapExpressionBlock(expression[cursor:close+1]), at))
				rest := strings.TrimSpace(expression[close+1:])
				if strings.HasPrefix(rest, "finally") {
					break
				}
				if !strings.HasPrefix(rest, "catch") {
					break
				}
				next := strings.IndexByte(rest, '{')
				if next < 0 {
					break
				}
				cursor = close + 1 + strings.Index(expression[close+1:], "{")
			}
			return inferred
		}
	}
	return ""
}

func (i *Index) commonExpressionTypeLocked(file *analysis.ParsedFile, left, right string) string {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	if sameJvmType(left, right) {
		if !strings.HasSuffix(left, "?") || !strings.HasSuffix(right, "?") {
			return strings.TrimSuffix(left, "?")
		}
		return left
	}
	if i.isSubtypeLocked(file, left, right) {
		return right
	}
	if i.isSubtypeLocked(file, right, left) {
		return left
	}
	if file.Language == analysis.LanguageJava {
		return "Object"
	}
	return "Any"
}

func topLevelExpressionOperator(expression, operator string) int {
	parens, brackets, braces, angles := 0, 0, 0, 0
	for index := 0; index+len(operator) <= len(expression); index++ {
		if parens == 0 && brackets == 0 && braces == 0 && angles == 0 && strings.HasPrefix(expression[index:], operator) {
			return index
		}
		switch expression[index] {
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		}
	}
	return -1
}

func topLevelWordIndex(expression, word string) int {
	for search := 0; search < len(expression); {
		index := strings.Index(expression[search:], word)
		if index < 0 {
			return -1
		}
		index += search
		if topLevelExpressionOperator(expression, expression[index:index+len(word)]) == index && (index == 0 || !isIdentRune(rune(expression[index-1]))) && (index+len(word) == len(expression) || !isIdentRune(rune(expression[index+len(word)]))) {
			return index
		}
		search = index + len(word)
	}
	return -1
}

func splitTopLevelExpressions(expression string, separator byte) []string {
	var out []string
	start, parens, brackets, braces := 0, 0, 0, 0
	for index := 0; index <= len(expression); index++ {
		if index == len(expression) || expression[index] == separator && parens == 0 && brackets == 0 && braces == 0 {
			if value := strings.TrimSpace(expression[start:index]); value != "" {
				out = append(out, value)
			}
			start = index + 1
			continue
		}
		switch expression[index] {
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		}
	}
	return out
}

func unwrapExpressionBlock(expression string) string {
	expression = strings.TrimSpace(expression)
	if strings.HasPrefix(expression, "{") && strings.HasSuffix(expression, "}") {
		expression = strings.TrimSpace(expression[1 : len(expression)-1])
		if statements := splitTopLevelExpressions(expression, ';'); len(statements) > 0 {
			return statements[len(statements)-1]
		}
	}
	return expression
}

func inferTypeParameterBindings(pattern, actual string, parameters []string, inferred map[string]string) {
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	for _, parameter := range parameters {
		if simpleType(patternBase) == parameter && actual != "" {
			inferred[parameter] = actual
			return
		}
	}
	if simpleType(patternBase) != simpleType(actualBase) || len(patternArguments) != len(actualArguments) {
		return
	}
	for index := range patternArguments {
		inferTypeParameterBindings(patternArguments[index], actualArguments[index], parameters, inferred)
	}
}

func matchTypePattern(pattern, actual string, parameters map[string]bool, inferred map[string]string) bool {
	pattern = strings.TrimSpace(pattern)
	actual = strings.TrimSpace(actual)
	if strings.HasSuffix(actual, "?") && !strings.HasSuffix(pattern, "?") {
		return false
	}
	pattern = strings.TrimSuffix(pattern, "?")
	actual = strings.TrimSuffix(actual, "?")
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	patternSimple := simpleType(strings.TrimPrefix(strings.TrimPrefix(patternBase, "out "), "in "))
	if parameters[patternSimple] {
		if previous := inferred[patternSimple]; previous != "" {
			return sameJvmType(previous, actual)
		}
		inferred[patternSimple] = actual
		return true
	}
	if simpleType(patternBase) != simpleType(actualBase) || len(patternArguments) != len(actualArguments) {
		return false
	}
	for index := range patternArguments {
		if !matchTypePattern(patternArguments[index], actualArguments[index], parameters, inferred) {
			return false
		}
	}
	return true
}

func instantiatedTypeName(name string, arguments []string) string {
	if len(arguments) == 0 {
		return name
	}
	return name + "<" + strings.Join(arguments, ", ") + ">"
}

func substituteTypeBindings(value string, bindings map[string]string) string {
	if value == "" || len(bindings) == 0 {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			result.WriteByte(value[index])
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		word := value[index:end]
		if replacement := bindings[word]; replacement != "" {
			result.WriteString(replacement)
		} else {
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) extensionReceiverBindingsLocked(file *analysis.ParsedFile, extension analysis.Symbol, actualType string) (map[string]string, bool) {
	if extension.ReceiverType == "" || actualType == "" {
		return nil, false
	}
	parameters := make(map[string]bool, len(extension.TypeParameters))
	for _, parameter := range extension.TypeParameters {
		parameters[parameter] = true
	}
	actualTypes := []string{actualType}
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, actualType) {
		actualTypes = append(actualTypes, instantiatedTypeName(instantiated.symbol.Name, instantiated.arguments))
		if instantiated.symbol.FQN != "" && instantiated.symbol.FQN != instantiated.symbol.Name {
			actualTypes = append(actualTypes, instantiatedTypeName(instantiated.symbol.FQN, instantiated.arguments))
		}
	}
	for _, actual := range actualTypes {
		bindings := make(map[string]string, len(parameters))
		if !matchTypePattern(extension.ReceiverType, actual, parameters, bindings) {
			continue
		}
		valid := true
		for parameter, actualType := range bindings {
			if !i.typeArgumentSatisfiesBoundsLocked(file, actualType, extension.TypeParameterBounds[parameter]) {
				valid = false
				break
			}
		}
		if valid {
			return bindings, true
		}
	}
	return nil, false
}

func (i *Index) extensionReceiverApplicableLocked(file *analysis.ParsedFile, extension analysis.Symbol, actualType string) bool {
	_, applicable := i.extensionReceiverBindingsLocked(file, extension, actualType)
	return applicable
}

func (i *Index) declaredTypeOfNameLocked(file *analysis.ParsedFile, name string, at int) string {
	best, bestStart := "", -1
	for _, symbol := range file.Symbols {
		inScope := !isLexicalSymbol(symbol) || symbolInScopeAt(symbol, at)
		if symbol.Name == name && symbol.Type != "" && symbol.StartByte <= at && symbol.StartByte >= bestStart && inScope {
			best, bestStart = symbol.Type, symbol.StartByte
		}
	}
	return best
}

func callClosingParen(expression string, open int) int {
	depth := 0
	for index := open; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return len(expression)
}

func splitTopLevelCallArguments(value string) []string {
	start, parens, brackets, braces, angles := 0, 0, 0, 0, 0
	var result []string
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' && parens == 0 && brackets == 0 && braces == 0 && angles == 0 {
			if argument := strings.TrimSpace(value[start:index]); argument != "" {
				result = append(result, argument)
			}
			start = index + 1
			continue
		}
		switch value[index] {
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		case '<':
			angles++
		case '>':
			angles--
		}
	}
	return result
}

func numericExpression(value string) bool {
	if value == "" {
		return false
	}
	for index, r := range value {
		if r >= '0' && r <= '9' || strings.ContainsRune("._xXbBeEfFdDlL+-", r) && index > 0 {
			continue
		}
		return false
	}
	return true
}

func (i *Index) typeOfExpressionLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	nullableResult := false
	if file.Language == analysis.LanguageKotlin {
		nullableResult = strings.Contains(expression, "?.") && !strings.HasSuffix(expression, "!!")
		expression = strings.ReplaceAll(expression, "?.", ".")
		expression = strings.ReplaceAll(expression, "!!", "")
		if strings.HasSuffix(expression, "::class") {
			literal := strings.TrimSpace(strings.TrimSuffix(expression, "::class"))
			if literalType := i.typeOfExpressionLocked(file, literal, at); literalType != "" {
				return "KClass<" + literalType + ">"
			}
		}
	}
	if !strings.Contains(expression, ".") {
		if strings.Contains(expression, "[") {
			return i.indexedExpressionTypeLocked(file, expression, at)
		}
		if strings.Contains(expression, "(") {
			return i.inferExpressionTypeLocked(file, expression, at)
		}
		return i.typeOfNameLocked(file, expression, at)
	}
	parts := splitTopLevelMemberChain(expression)
	if len(parts) == 0 {
		return ""
	}
	typ := i.typeOfNameLocked(file, parts[0], at)
	if file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(parts[0]), "::class") {
		literal := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[0]), "::class"))
		if literalType := i.typeOfExpressionLocked(file, literal, at); literalType != "" {
			typ = "KClass<" + literalType + ">"
		}
	} else if strings.Contains(parts[0], "[") {
		typ = i.indexedExpressionTypeLocked(file, parts[0], at)
	} else if strings.Contains(parts[0], "(") {
		typ = i.inferExpressionTypeLocked(file, parts[0], at)
	}
	for _, member := range parts[1:] {
		if typ == "" {
			return ""
		}
		memberName := member
		callArguments := []string(nil)
		call := false
		if open := strings.IndexByte(member, '('); open >= 0 {
			call = true
			memberName = strings.TrimSpace(member[:open])
			close := callClosingParen(member, open)
			callArguments = splitTopLevelCallArguments(member[open+1 : close])
		} else if open := strings.IndexByte(member, '{'); open >= 0 && strings.HasSuffix(strings.TrimSpace(member), "}") {
			call = true
			memberName = strings.TrimSpace(member[:open])
			callArguments = []string{strings.TrimSpace(member[open:])}
		}
		next := ""
		if file.Language == analysis.LanguageJava && !call && memberName == "class" {
			next = "Class<" + typ + ">"
		}
		if file.Language == analysis.LanguageKotlin {
			base, arguments := splitInstantiatedType(typ)
			if len(arguments) > 1 && simpleType(base) == "Pair" {
				if memberName == "first" {
					next = arguments[0]
				} else if memberName == "second" {
					next = arguments[1]
				}
			}
			if call && len(arguments) > 0 && (simpleType(base) == "Set" || simpleType(base) == "MutableSet" || simpleType(base) == "List" || simpleType(base) == "MutableList" || simpleType(base) == "Collection" || simpleType(base) == "Iterable" || simpleType(base) == "Sequence") {
				switch memberName {
				case "first", "last", "single", "random":
					next = arguments[0]
				case "firstOrNull", "lastOrNull", "singleOrNull", "randomOrNull":
					next = strings.TrimSuffix(strings.TrimSpace(arguments[0]), "?") + "?"
				}
			}
			if call && len(callArguments) > 0 {
				body := unwrapExpressionBlock(callArguments[len(callArguments)-1])
				switch memberName {
				case "apply", "also":
					next = typ
				case "let", "run":
					if body == "it" || body == "this" {
						next = typ
					} else if inferred := i.inferExpressionTypeLocked(file, body, at); inferred != "" {
						next = inferred
					}
				}
			}
		}
		for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, typ) {
			if next != "" {
				break
			}
			owner, arguments := instantiated.symbol, instantiated.arguments
			for _, id := range i.byContainerMember[memberKey(owner.Name, memberName)] {
				symbol := i.symbols[id]
				if symbol.ContainerID == owner.ID && symbol.Type != "" && (call == analysis.IsCallableKind(symbol.Kind) || !call && !analysis.IsCallableKind(symbol.Kind)) && i.accessibleLocked(file, *symbol, at) {
					next = substituteTypeParameters(symbol.Type, owner.TypeParameters, arguments)
					break
				}
			}
			if next != "" {
				break
			}
		}
		if next == "" && file.Language == analysis.LanguageKotlin {
			for _, container := range i.typeAndSupertypesLocked(file, typ) {
				for _, id := range i.byReceiverMember[memberKey(container, memberName)] {
					extension := i.symbols[id]
					if extension.Type == "" || call != analysis.IsCallableKind(extension.Kind) || !i.accessibleLocked(file, *extension, at) || !i.extensionVisibleLocked(file, *extension, at) {
						continue
					}
					bindings, applicable := i.extensionReceiverBindingsLocked(file, *extension, typ)
					if !applicable || call && !matchesArityForLanguage(*extension, len(callArguments), file.Language) {
						continue
					}
					parameters := make(map[string]bool, len(extension.TypeParameters))
					for _, parameter := range extension.TypeParameters {
						parameters[parameter] = true
					}
					for index, argument := range callArguments {
						if index >= len(extension.Parameters) {
							break
						}
						actual := i.inferExpressionTypeLocked(file, argument, at)
						if !matchTypePattern(extension.Parameters[index].Type, actual, parameters, bindings) {
							applicable = false
							break
						}
					}
					if applicable {
						next = substituteTypeBindings(extension.Type, bindings)
						break
					}
				}
				if next != "" {
					break
				}
			}
		}
		typ = next
	}
	if nullableResult && typ != "" && !strings.HasSuffix(strings.TrimSpace(typ), "?") {
		return typ + "?"
	}
	return typ
}

func (i *Index) memberResultTypeLocked(file *analysis.ParsedFile, receiverType, name string, at int) string {
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, receiverType) {
		owner, arguments := instantiated.symbol, instantiated.arguments
		for _, id := range i.byContainerMember[memberKey(owner.Name, name)] {
			member := i.symbols[id]
			if member.ContainerID == owner.ID && analysis.IsCallableKind(member.Kind) && member.Type != "" && i.accessibleLocked(file, *member, at) {
				return substituteTypeParameters(member.Type, owner.TypeParameters, arguments)
			}
		}
	}
	if file.Language == analysis.LanguageKotlin {
		for _, container := range i.typeAndSupertypesLocked(file, receiverType) {
			for _, id := range i.byReceiverMember[memberKey(container, name)] {
				member := i.symbols[id]
				if member.Type == "" || !analysis.IsCallableKind(member.Kind) || !i.accessibleLocked(file, *member, at) || !i.extensionVisibleLocked(file, *member, at) {
					continue
				}
				if bindings, applicable := i.extensionReceiverBindingsLocked(file, *member, receiverType); applicable {
					return substituteTypeBindings(member.Type, bindings)
				}
			}
		}
	}
	return ""
}

func (i *Index) invocationResultTypeLocked(file *analysis.ParsedFile, receiverType string, at int) string {
	receiverType = strings.TrimSpace(strings.TrimSuffix(receiverType, "?"))
	if arrow := strings.LastIndex(receiverType, "->"); arrow >= 0 {
		return strings.TrimSpace(receiverType[arrow+2:])
	}
	return i.memberResultTypeLocked(file, receiverType, "invoke", at)
}

func (i *Index) indexedExpressionTypeLocked(file *analysis.ParsedFile, expression string, at int) string {
	expression = strings.TrimSpace(expression)
	open := firstTopLevelIndexOpen(expression)
	if open <= 0 {
		return ""
	}
	typ := i.typeOfExpressionLocked(file, strings.TrimSpace(expression[:open]), at)
	for open >= 0 && open < len(expression) {
		close := matchingDelimiter(expression, open, '[', ']')
		if close < 0 || typ == "" {
			return ""
		}
		if strings.HasSuffix(strings.TrimSpace(typ), "[]") {
			typ = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(typ), "[]"))
		} else {
			next := ""
			for _, instantiated := range i.instantiatedTypeHierarchyLocked(file, typ) {
				owner, arguments := instantiated.symbol, instantiated.arguments
				for _, id := range i.byContainerMember[memberKey(owner.Name, "get")] {
					symbol := i.symbols[id]
					if symbol.ContainerID == owner.ID && analysis.IsCallableKind(symbol.Kind) && symbol.Type != "" && i.accessibleLocked(file, *symbol, at) {
						next = substituteTypeParameters(symbol.Type, owner.TypeParameters, arguments)
						break
					}
				}
				if next != "" {
					break
				}
			}
			if next == "" {
				base, arguments := splitInstantiatedType(typ)
				if (simpleType(base) == "Array" || simpleType(base) == "List" || simpleType(base) == "MutableList") && len(arguments) > 0 {
					next = arguments[0]
				} else if (simpleType(base) == "Map" || simpleType(base) == "MutableMap") && len(arguments) > 1 {
					next = arguments[1]
					if file.Language == analysis.LanguageKotlin && !strings.HasSuffix(strings.TrimSpace(next), "?") {
						next += "?"
					}
				}
			}
			typ = next
		}
		remainder := strings.TrimSpace(expression[close+1:])
		if remainder == "" {
			break
		}
		if remainder[0] != '[' {
			return ""
		}
		open = close + 1 + strings.Index(expression[close+1:], "[")
	}
	return typ
}

func firstTopLevelIndexOpen(expression string) int {
	parens, braces, angles := 0, 0, 0
	for index := 0; index < len(expression); index++ {
		switch expression[index] {
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		case '[':
			if parens == 0 && braces == 0 && angles == 0 {
				return index
			}
		}
	}
	return -1
}

func splitTopLevelMemberChain(expression string) []string {
	start, parens, brackets, braces, angles := 0, 0, 0, 0, 0
	var result []string
	for index := 0; index <= len(expression); index++ {
		if index == len(expression) || expression[index] == '.' && parens == 0 && brackets == 0 && braces == 0 && angles == 0 {
			if part := strings.TrimSpace(expression[start:index]); part != "" {
				result = append(result, part)
			}
			start = index + 1
			continue
		}
		switch expression[index] {
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		}
	}
	return result
}

func (i *Index) documentTextLocked(uri protocol.URI) string {
	if document := i.docs[uri]; document != nil {
		return document.Text
	}
	if document := i.indexedDocs[uri]; document != nil {
		return document.Text
	}
	return ""
}

func kotlinNullableMemberAccessAllowed(source string, memberStart int) bool {
	if memberStart >= 2 && memberStart <= len(source) && source[memberStart-1] == '.' && source[memberStart-2] == '?' {
		return true
	}
	return memberStart >= 3 && memberStart <= len(source) && source[memberStart-1] == '.' && source[memberStart-2] == '!' && source[memberStart-3] == '!'
}

type instantiatedTypeOwner struct {
	symbol    analysis.Symbol
	arguments []string
}

func (i *Index) instantiatedTypeHierarchyLocked(file *analysis.ParsedFile, typeName string) []instantiatedTypeOwner {
	queue := splitIntersectionTypes(typeName)
	seen := make(map[string]bool)
	result := make([]instantiatedTypeOwner, 0, 4)
	for len(queue) > 0 {
		instantiated := queue[0]
		queue = queue[1:]
		base, arguments := splitInstantiatedType(instantiated)
		for _, symbol := range i.resolveTypeSymbolsLocked(file, base) {
			key := symbol.ID + "\x00" + strings.Join(arguments, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, instantiatedTypeOwner{symbol: symbol, arguments: arguments})
			if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
				queue = append(queue, substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments))
			}
			for _, supertype := range symbol.Supertypes {
				queue = append(queue, substituteTypeParameters(supertype, symbol.TypeParameters, arguments))
			}
		}
	}
	return result
}

func (i *Index) enclosingTypeLocked(file *analysis.ParsedFile, at int) analysis.Symbol {
	var found analysis.Symbol
	for _, symbol := range file.Symbols {
		if analysis.IsTypeKind(symbol.Kind) && symbol.StartByte <= at && at <= symbol.EndByte && (found.ID == "" || symbol.StartByte >= found.StartByte && symbol.EndByte <= found.EndByte) {
			found = symbol
		}
	}
	return found
}

func (i *Index) symbolWithinCallableScopeLocked(file *analysis.ParsedFile, symbol analysis.Symbol, at int) bool {
	container, ok := i.symbols[symbol.ContainerID]
	return ok && analysis.IsCallableKind(container.Kind) && container.URI == file.URI && container.StartByte <= at && at <= container.EndByte
}

func (i *Index) typeAndSupertypesLocked(file *analysis.ParsedFile, typeName string) []string {
	queue := splitIntersectionTypes(typeName)
	seenTypes := map[string]bool{}
	seenSymbols := map[string]bool{}
	var out []string
	for len(queue) > 0 {
		instantiated := queue[0]
		queue = queue[1:]
		if instantiated == "" || seenTypes[instantiated] {
			continue
		}
		seenTypes[instantiated] = true
		base, arguments := splitInstantiatedType(instantiated)
		symbols := i.resolveTypeSymbolsLocked(file, base)
		if len(symbols) == 0 {
			out = append(out, simpleType(base))
			continue
		}
		for _, symbol := range symbols {
			if seenSymbols[symbol.ID] {
				continue
			}
			seenSymbols[symbol.ID] = true
			out = append(out, symbol.Name)
			if symbol.FQN != "" && symbol.FQN != symbol.Name {
				out = append(out, symbol.FQN)
			}
			if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
				queue = append(queue, substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments))
			}
			for _, supertype := range symbol.Supertypes {
				queue = append(queue, substituteTypeParameters(supertype, symbol.TypeParameters, arguments))
			}
		}
	}
	return out
}

func splitIntersectionTypes(typeName string) []string {
	angles, start := 0, 0
	var result []string
	for index := 0; index <= len(typeName); index++ {
		if index == len(typeName) || typeName[index] == '&' && angles == 0 {
			if value := strings.TrimSpace(typeName[start:index]); value != "" {
				result = append(result, value)
			}
			start = index + 1
			continue
		}
		if typeName[index] == '<' {
			angles++
		} else if typeName[index] == '>' && angles > 0 {
			angles--
		}
	}
	if len(result) == 0 {
		return []string{typeName}
	}
	return result
}

func (i *Index) accessibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	if symbol.InteropLanguage != analysis.LanguageUnknown && symbol.InteropLanguage != file.Language {
		return false
	}
	if file.Language == analysis.LanguageJava && containsString(symbol.Modifiers, "JvmSynthetic") {
		return false
	}
	if file.Language == analysis.LanguageJava && symbol.Language == analysis.LanguageKotlin && !symbol.Synthetic {
		if symbol.JVMName != "" || symbol.ContainerID == "" && (analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty) {
			return false
		}
	}
	fromModule, targetModule := i.moduleForURILocked(file.URI), i.moduleForURILocked(symbol.URI)
	fromSourceSet := i.sourceSetForURILocked(file.URI, fromModule)
	targetSourceSet := i.sourceSetForURILocked(symbol.URI, targetModule)
	if symbol.Library && fromModule != nil {
		if source, exists := i.librarySources[symbol.URI]; exists {
			if access := i.libraryAccess[filepath.Clean(source.Archive)]; len(access) > 0 && !access[fromModule.Dir] && !access[libraryAccessKey(fromModule.Dir, fromSourceSet)] {
				return false
			}
		}
	}
	if targetModule != nil && !i.moduleCanAccessLocked(fromModule, targetModule, fromSourceSet, targetSourceSet) {
		return false
	}
	visibility := ""
	for _, modifier := range symbol.Modifiers {
		if modifier == "private" || modifier == "protected" || modifier == "public" || modifier == "internal" {
			visibility = modifier
		}
	}
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok {
			if IsLocalDeclarationOwner(*owner) {
				if owner.URI != file.URI || len(positions) == 0 || symbol.ScopeStartByte > 0 && positions[0] < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && positions[0] > symbol.ScopeEndByte {
					return false
				}
			}
			if analysis.IsTypeKind(owner.Kind) && !i.accessibleLocked(file, *owner, positions...) {
				return false
			}
		}
	}
	if visibility == "protected" && symbol.Language == analysis.LanguageKotlin {
		if symbol.ContainerID == "" || len(positions) == 0 {
			return false
		}
		owner := i.symbols[symbol.ContainerID]
		for owner != nil && !analysis.IsTypeKind(owner.Kind) && owner.ContainerID != "" {
			owner = i.symbols[owner.ContainerID]
		}
		current := i.enclosingTypeLocked(file, positions[0])
		if owner == nil || current.ID == "" || current.ID != owner.ID && !i.containerInheritsLocked(current.ID, owner.ID) {
			return false
		}
	}
	if symbol.URI == file.URI {
		if visibility != "private" || symbol.ContainerID == "" {
			return true
		}
		if len(positions) == 0 {
			return false
		}
		owner, ok := i.symbols[symbol.ContainerID]
		if !ok {
			return false
		}
		if symbol.Language == analysis.LanguageJava {
			for owner.ContainerID != "" {
				parent, exists := i.symbols[owner.ContainerID]
				if !exists || !analysis.IsTypeKind(parent.Kind) {
					break
				}
				owner = parent
			}
		}
		return owner.StartByte <= positions[0] && positions[0] <= owner.EndByte
	}
	if visibility == "private" {
		return false
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && (owner.Kind == analysis.KindInterface || owner.Kind == analysis.KindAnnotation) {
			visibility = "public"
		}
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.Package != file.Package {
		return false // Java package-private declaration.
	}
	if visibility == "protected" && symbol.Package != file.Package {
		if symbol.ContainerID == "" {
			return false
		}
		for _, candidate := range file.Symbols {
			if analysis.IsTypeKind(candidate.Kind) && i.containerInheritsLocked(candidate.ID, symbol.ContainerID) {
				return true
			}
		}
		return false
	}
	if visibility == "internal" && file.Language == analysis.LanguageKotlin && fromModule != nil && targetModule != nil && (fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir) {
		return false
	}
	return true
}

func IsLocalDeclarationOwner(symbol analysis.Symbol) bool {
	return analysis.IsCallableKind(symbol.Kind)
}

func (i *Index) kotlinObjectInstanceMemberLocked(symbol analysis.Symbol) bool {
	if symbol.Language != analysis.LanguageKotlin || symbol.Synthetic || symbol.ContainerID == "" {
		return false
	}
	owner, ok := i.symbols[symbol.ContainerID]
	return ok && owner.Kind == analysis.KindObject
}

func (i *Index) typeQualifierActsAsValueLocked(file *analysis.ParsedFile, types []analysis.Symbol) bool {
	if file.Language != analysis.LanguageKotlin {
		return false
	}
	for _, symbol := range types {
		if symbol.Kind == analysis.KindObject {
			return true
		}
	}
	return false
}

func (i *Index) memberAvailableThroughTypeQualifierLocked(file *analysis.ParsedFile, symbol analysis.Symbol, types []analysis.Symbol) bool {
	if i.staticOrNestedMemberLocked(symbol) {
		return true
	}
	if file.Language == analysis.LanguageKotlin && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && owner.Kind == analysis.KindObject && containsString(owner.Modifiers, "companion") {
			return true
		}
	}
	return i.typeQualifierActsAsValueLocked(file, types) && !symbol.Synthetic
}

func (i *Index) staticOrNestedMemberLocked(symbol analysis.Symbol) bool {
	return analysis.IsTypeKind(symbol.Kind) || containsString(symbol.Modifiers, "static") || symbol.Kind == analysis.KindEnumMember
}

func (i *Index) staticLikeContextLocked(file *analysis.ParsedFile, at int) bool {
	for _, symbol := range file.Symbols {
		if symbol.StartByte <= at && at <= symbol.EndByte {
			if symbol.Language == analysis.LanguageJava && !analysis.IsTypeKind(symbol.Kind) && containsString(symbol.Modifiers, "static") {
				return true
			}
		}
	}
	return false
}

func nestedTypeCapturesOuter(nested, outer analysis.Symbol) bool {
	if nested.Language == analysis.LanguageKotlin {
		return containsString(nested.Modifiers, "inner")
	}
	if nested.Language == analysis.LanguageJava {
		return nested.Kind == analysis.KindClass && outer.Kind != analysis.KindInterface && outer.Kind != analysis.KindAnnotation && !containsString(nested.Modifiers, "static")
	}
	return false
}

func (i *Index) extensionVisibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && analysis.IsCallableKind(owner.Kind) {
			if symbol.URI != file.URI || len(positions) == 0 || symbol.ScopeStartByte > 0 && positions[0] < symbol.ScopeStartByte || symbol.ScopeEndByte > 0 && positions[0] > symbol.ScopeEndByte {
				return false
			}
		}
	}
	if symbol.ReceiverType == "" || symbol.URI == file.URI || symbol.Package == file.Package {
		return true
	}
	for _, imp := range file.Imports {
		if imp.Path == symbol.FQN || imp.Wildcard && imp.Path == symbol.Package {
			return true
		}
	}
	return false
}

func (i *Index) containerInheritsLocked(containerID, targetContainerID string) bool {
	target, ok := i.symbols[targetContainerID]
	if !ok {
		return false
	}
	queue := []string{containerID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		container, exists := i.symbols[id]
		if !exists {
			continue
		}
		file := i.files[container.URI]
		if file == nil {
			continue
		}
		for _, supertype := range container.Supertypes {
			for _, parent := range i.resolveTypeSymbolsLocked(file, supertype) {
				if parent.ID == target.ID {
					return true
				}
				queue = append(queue, parent.ID)
			}
		}
	}
	return false
}

func (i *Index) symbolsForIDsLocked(ids []string, accept func(analysis.Symbol) bool) []analysis.Symbol {
	seen := map[string]bool{}
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		s, ok := i.symbols[id]
		if ok && (accept == nil || accept(*s)) {
			seen[id] = true
			out = append(out, *s)
		}
	}
	return out
}

func (i *Index) scan(ctx context.Context, roots []string, generation uint64) {
	modules := discoverModules(roots)
	defaultJavaHome := i.DefaultJavaHome()
	if defaultJavaHome != "" {
		for moduleIndex := range modules {
			if modules[moduleIndex].JavaHome == "" {
				modules[moduleIndex].JavaHome = defaultJavaHome
			}
		}
	}
	i.setModules(modules)
	var paths []string
	seenPaths := make(map[string]bool)
	addPath := func(path string) {
		path = filepath.Clean(path)
		if !seenPaths[path] {
			seenPaths[path] = true
			paths = append(paths, path)
		}
	}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && ignoredDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if isSource(path) {
				addPath(path)
			}
			return nil
		})
	}
	// Generated roots are explicit module inputs, not arbitrary build output.
	// Scan them separately after the broad walk skips build/target trees.
	for _, module := range modules {
		for _, sourceRoot := range module.SourceRoots {
			_ = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if entry.IsDir() {
					if path != sourceRoot && ignoredDir(entry.Name()) {
						return filepath.SkipDir
					}
					return nil
				}
				if isSource(path) {
					addPath(path)
				}
				return nil
			})
		}
	}
	p := Progress{FilesTotal: int64(len(paths))}
	if i.generation.Load() != generation {
		return
	}
	i.progress.Store(&p)
	jobs := make(chan string, 64)
	var wg sync.WaitGroup
	workers := 4
	if len(paths) < workers {
		workers = len(paths)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				if i.generation.Load() != generation {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				i.backgroundMu.RLock()
				data, err := os.ReadFile(path)
				if err != nil {
					i.backgroundMu.RUnlock()
					continue
				}
				u := uriutil.File(path)
				doc := textdoc.NewDocument(u, uriutil.LanguageID(path), 0, string(data))
				parsed := analysis.Parse(ctx, doc)
				i.mu.Lock()
				if i.generation.Load() != generation {
					i.mu.Unlock()
					i.backgroundMu.RUnlock()
					return
				}
				if _, open := i.docs[u]; !open {
					i.indexedDocs[u] = doc
					i.replaceLocked(parsed)
				}
				i.mu.Unlock()
				i.backgroundMu.RUnlock()
				count := atomic.AddInt64(&p.FilesParsed, 1)
				if i.generation.Load() == generation {
					i.progress.Store(&Progress{FilesParsed: count, FilesTotal: p.FilesTotal})
				}
			}
		}()
	}
	for _, path := range paths {
		select {
		case jobs <- path:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
	if i.generation.Load() != generation {
		return
	}
	// Let the first editor document claim foreground priority before a cold
	// cache decoder starts allocating. Headless workspace-symbol sessions still
	// begin library indexing after the bounded fallback.
	select {
	case <-i.interactiveStarted:
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return
	}
	i.scanLibraries(ctx, roots, generation)
	if i.generation.Load() != generation {
		return
	}
	done := i.Progress()
	done.Ready = true
	i.progress.Store(&done)
	go func() {
		i.compilerMu.Lock()
		defer i.compilerMu.Unlock()
		i.scanJavaCompilerDiagnostics(ctx, generation)
		i.scanKotlinCompilerDiagnostics(ctx, generation)
	}()
}

func ignoredDir(name string) bool {
	switch name {
	case ".git", ".gradle", ".idea", "bin", "build", "out", "target", "node_modules", "vendor", ".kotlin", ".kotlsp":
		return true
	default:
		return strings.HasPrefix(name, ".") && name != "."
	}
}
func isSource(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".kt") || strings.HasSuffix(p, ".kts") || strings.HasSuffix(p, ".java")
}
func without(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
func withoutRef(xs []analysis.Reference, x analysis.Reference) []analysis.Reference {
	out := xs[:0]
	for _, v := range xs {
		if v.URI != x.URI || v.StartByte != x.StartByte {
			out = append(out, v)
		}
	}
	return out
}
func withoutURI(xs []protocol.URI, x protocol.URI) []protocol.URI {
	out := xs[:0]
	for _, value := range xs {
		if value != x {
			out = append(out, value)
		}
	}
	return out
}
func simpleType(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "?")
	for strings.HasSuffix(s, "[]") {
		s = strings.TrimSuffix(s, "[]")
	}
	if i := strings.IndexByte(s, '<'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}
func completionContext(s string, at int) (string, string) {
	if at > len(s) {
		at = len(s)
	}
	start := at
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:start])
		if r == utf8.RuneError && size == 1 || !isIdentRune(r) {
			break
		}
		start -= size
	}
	prefix := s[start:at]
	if start > 0 && s[start-1] == '.' {
		return prefix, expressionQualifierBefore(s, start)
	}
	return prefix, ""
}
func isIdentRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$' || r == '`'
}
func sortSymbols(xs []analysis.Symbol) {
	sort.SliceStable(xs, func(a, b int) bool {
		if xs[a].FQN == xs[b].FQN {
			return xs[a].StartByte < xs[b].StartByte
		}
		return xs[a].FQN < xs[b].FQN
	})
}
func uniqueSymbols(xs []analysis.Symbol) []analysis.Symbol {
	seen := map[string]bool{}
	out := xs[:0]
	for _, s := range xs {
		if !seen[s.ID] {
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}
func uniqueLocations(xs []protocol.Location) []protocol.Location {
	type locationKey struct {
		uri                       protocol.URI
		startLine, startCharacter int
		endLine, endCharacter     int
	}
	seen := make(map[locationKey]bool, len(xs))
	out := xs[:0]
	for _, x := range xs {
		k := locationKey{x.URI, x.Range.Start.Line, x.Range.Start.Character, x.Range.End.Line, x.Range.End.Character}
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [24]byte
	n := len(b)
	for v > 0 {
		n--
		b[n] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
func fuzzyScore(candidate, query string) int {
	if query == "" {
		return 0
	}
	if candidate == query {
		return 1000
	}
	if strings.HasPrefix(candidate, query) {
		return 800 - len(candidate)
	}
	score, pos := 0, 0
	for _, r := range query {
		idx := strings.IndexRune(candidate[pos:], r)
		if idx < 0 {
			return -1
		}
		score += 10 - idx
		pos += idx + 1
	}
	return score
}
func ReadFile(uri protocol.URI) (string, error) {
	path, ok := uriutil.Path(uri)
	if !ok {
		return "", errors.New("not a file URI")
	}
	data, err := os.ReadFile(path)
	return string(data), err
}

func isWorkspaceSymbol(symbol analysis.Symbol) bool {
	if symbol.Synthetic {
		return false
	}
	if symbol.Library && symbol.InteropLanguage == analysis.LanguageJava {
		return false
	}
	switch symbol.Kind {
	case analysis.KindParameter, analysis.KindVariable, analysis.KindTypeParameter:
		return false
	default:
		return true
	}
}

func isUnqualifiedCompletionSymbol(symbol analysis.Symbol) bool {
	return symbol.ContainerID == "" && isWorkspaceSymbol(symbol)
}

func (i *Index) addWorkspaceNameLocked(name string) {
	if i.workspaceKnown[name] {
		return
	}
	i.workspaceKnown[name] = true
	i.workspaceNames = append(i.workspaceNames, name)
	lower := strings.ToLower(name)
	if len(lower) > 0 && lower[0] < 128 {
		i.workspaceByInitial[lower[0]] = append(i.workspaceByInitial[lower[0]], name)
		for length := 1; length <= 3 && length <= len(lower); length++ {
			key, ok := asciiPrefix(lower, length)
			if !ok {
				break
			}
			i.workspaceByPrefix[key] = append(i.workspaceByPrefix[key], name)
		}
	}
	var seen [128]bool
	for n := 0; n < len(lower); n++ {
		char := lower[n]
		if char >= 128 || seen[char] {
			continue
		}
		seen[char] = true
		i.workspaceByChar[char] = append(i.workspaceByChar[char], name)
	}
}

func (i *Index) addCompletionNameLocked(name string) {
	if i.completionKnown[name] {
		return
	}
	i.completionKnown[name] = true
	i.completionNames = append(i.completionNames, name)
	lower := strings.ToLower(name)
	if len(lower) == 0 || lower[0] >= 128 {
		return
	}
	i.completionByInitial[lower[0]] = append(i.completionByInitial[lower[0]], name)
	for length := 1; length <= 3 && length <= len(lower); length++ {
		key, ok := asciiPrefix(lower, length)
		if !ok {
			break
		}
		i.completionByPrefix[key] = append(i.completionByPrefix[key], name)
	}
}

func importPrefixes(path string) []string {
	parts := strings.Split(strings.TrimSpace(path), ".")
	out := make([]string, 0, len(parts))
	for n, part := range parts {
		if part == "" {
			break
		}
		out = append(out, strings.Join(parts[:n+1], "."))
	}
	return out
}

func appendUniqueURI(values []protocol.URI, value protocol.URI) []protocol.URI {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func asciiPrefix(value string, maximum int) (string, bool) {
	if value == "" {
		return "", false
	}
	length := len(value)
	if length > maximum {
		length = maximum
	}
	for n := 0; n < length; n++ {
		if value[n] >= 128 {
			return "", false
		}
	}
	return value[:length], true
}

var _ = time.Now
