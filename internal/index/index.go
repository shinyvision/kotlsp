package index

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
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
	workspaceIndex        nameIndex[string]
	completionIndex       nameIndex[string]
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
	diagnosticsListenerMu sync.RWMutex
	compilerHosts         compilerHostPool
	compilerStatus        compilerStatusTracker
	compilerTrigger       atomic.Int32
	generatedSources      generatedSourceState
	librariesScanned      atomic.Bool
	onDiagnosticsChanged  func()
}

func (i *Index) DiagnosticsVersion() uint64 { return i.diagnosticsVersion.Load() }

// WaitForLibraries blocks until the initial library scan has landed (or ctx
// ends). Until then ClasspathFor answers with module output directories only,
// which is fatally incomplete for run/debug classpaths. An index without any
// workspace scan is complete by construction and never blocks.
func (i *Index) WaitForLibraries(ctx context.Context) bool {
	for {
		if i.generation.Load() == 0 || i.librariesScanned.Load() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// SetDiagnosticsListener registers a callback for diagnostics that change
// outside a document edit. Compiler validation runs in the background long
// after the edit that triggered it, and a client that pulls diagnostics only
// re-requests when told to: without this the recomputed set sits in the index,
// correct and unread, until something else makes the client ask again.
func (i *Index) SetDiagnosticsListener(listener func()) {
	i.diagnosticsListenerMu.Lock()
	i.onDiagnosticsChanged = listener
	i.diagnosticsListenerMu.Unlock()
}

func (i *Index) notifyDiagnosticsChanged() {
	i.diagnosticsListenerMu.RLock()
	listener := i.onDiagnosticsChanged
	i.diagnosticsListenerMu.RUnlock()
	if listener != nil {
		listener()
	}
}

func New(onParsed func(protocol.URI, []protocol.Diagnostic)) *Index {
	i := &Index{
		files:                make(map[protocol.URI]*analysis.ParsedFile),
		fileSymbolsByName:    make(map[protocol.URI]map[string][]*analysis.Symbol),
		fileSmartCastsByName: make(map[protocol.URI]map[string][]analysis.SmartCast),
		fileAnonymousByName:  make(map[protocol.URI]map[string][]*analysis.Symbol),
		interactiveStarted:   make(chan struct{}),
		docs:                 make(map[protocol.URI]*textdoc.Document),
		indexedDocs:          make(map[protocol.URI]*textdoc.Document),
		libraryDocs:          make(map[protocol.URI]*textdoc.Document),
		librarySources:       make(map[protocol.URI]LibrarySource),
		libraryAccess:        make(map[string]map[string]bool),
		libraryStrings:       make(map[string]string),
		symbols:              make(map[string]*analysis.Symbol),
		byName:               make(map[string][]string),
		byFQN:                make(map[string][]string),
		bySuper:              make(map[string][]string),
		byContainerName:      make(map[string][]string),
		byContainerMember:    make(map[string][]string),
		byReceiver:           make(map[string][]string),
		byReceiverMember:     make(map[string][]string),
		byOrigin:             make(map[string][]string),
		byPackage:            make(map[string][]string),
		packageChildren:      make(map[string][]string),
		packageCounts:        make(map[string]int),
		workspaceIndex:       newNameIndex[string](true),
		completionIndex:      newNameIndex[string](false),
		refsByName:           make(map[string][]analysis.Reference),
		packages:             make(map[string][]protocol.URI),
		importersByPrefix:    make(map[string][]protocol.URI),
		compilerDiagnostics:  make(map[protocol.URI][]protocol.Diagnostic),
		documentRevision:     make(map[protocol.URI]uint64),
		onParsed:             onParsed,
	}
	i.progress.Store(&Progress{})
	return i
}

func (i *Index) Close() {
	i.cancelCompilerDiagnostics()
	// The hosted compiler outlives individual passes, so it is shut down with
	// the index rather than left behind as an orphaned JVM.
	i.compilerHosts.shutdown()
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

func (i *Index) Progress() Progress {
	p := i.progress.Load()
	if p == nil {
		return Progress{}
	}
	return *p
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
	i.workspaceIndex.clear()
	i.completionIndex.clear()
	i.refsByName = make(map[string][]analysis.Reference)
	i.packages = make(map[string][]protocol.URI)
	i.importersByPrefix = make(map[string][]protocol.URI)
	i.compilerDiagnostics = make(map[protocol.URI][]protocol.Diagnostic)
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
