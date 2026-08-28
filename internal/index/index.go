package index

import (
	"context"
	"os"
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

// replaceLocked maintains several secondary indexes per occurrence. Keeping a
// hard per-file ceiling makes every publication critical section finite even
// when a generated source is syntactically valid but adversarially dense.
const maxPublishedFileOccurrences = 32_768

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
	mu                          sync.RWMutex
	interactiveOnce             sync.Once
	interactiveStarted          chan struct{}
	files                       map[protocol.URI]*analysis.ParsedFile
	fileGeneration              map[protocol.URI]uint64
	fileSymbolsByName           map[protocol.URI]map[string][]*analysis.Symbol
	fileSmartCastsByName        map[protocol.URI]map[string][]analysis.SmartCast
	fileAnonymousByName         map[protocol.URI]map[string][]*analysis.Symbol
	fileCursorSpans             map[protocol.URI][]cursorSpan
	docs                        map[protocol.URI]*textdoc.Document
	syntaxStates                map[protocol.URI]*analysis.SyntaxState
	indexedDocs                 map[protocol.URI]*textdoc.Document
	libraryDocs                 map[protocol.URI]*textdoc.Document
	librarySources              map[protocol.URI]LibrarySource
	archiveDigests              map[string][32]byte
	libraryAccess               map[string]map[string]bool
	libraryModules              map[string]libraryJavaModule
	libraryModuleAliases        map[string]string
	libraryStringMu             sync.Mutex
	libraryCommitMu             sync.Mutex
	workspaceCommitMu           sync.Mutex
	semanticProgressMu          sync.Mutex
	semanticProgress            chan struct{}
	libraryStrings              map[string]string
	symbols                     map[string]*analysis.Symbol
	byName                      map[string][]string
	byFQN                       map[string][]string
	bySuper                     map[string][]string
	bySuperID                   map[string][]string
	byContainerName             map[string][]string
	byContainerMember           map[string][]string
	byReceiver                  map[string][]string
	byReceiverMember            map[string][]string
	byGenericReceiverMember     map[string][]string
	byOrigin                    map[string][]string
	byPackage                   map[string][]string
	packageChildren             map[string][]string
	packageCounts               map[string]int
	workspaceIndex              nameIndex[string]
	completionIndex             nameIndex[string]
	refsByName                  map[string][]analysis.Reference
	refsByTarget                map[string][]analysis.Reference
	unresolvedRefsByName        map[string][]analysis.Reference
	packages                    map[string][]protocol.URI
	importersByPrefix           map[string][]protocol.URI
	compilerDiagnostics         map[protocol.URI][]protocol.Diagnostic
	roots                       []string
	classpath                   []string
	modules                     []ModuleInfo
	defaultJavaHome             string
	progress                    atomic.Pointer[Progress]
	closed                      atomic.Bool
	generation                  atomic.Uint64
	compilerRun                 atomic.Uint64
	diagnosticsVersion          atomic.Uint64
	diagnosticStateVersion      atomic.Uint64
	semanticVersion             uint64
	semanticEnvironmentVersion  uint64
	semanticSymbolVersion       map[string]uint64
	semanticNameVersion         map[string]uint64
	semanticCacheMu             sync.RWMutex
	semanticTokenCache          map[protocol.URI]semanticTokenCacheEntry
	documentRevision            map[protocol.URI]uint64
	sourceMirror                librarySourceMirror
	libraryReferenceOrder       []protocol.URI
	nextDocumentRevision        uint64
	compilerMu                  sync.Mutex
	compilerCancelMu            sync.Mutex
	compilerCancel              context.CancelFunc
	lifecycleMu                 sync.Mutex
	scanWG                      sync.WaitGroup
	backgroundWG                sync.WaitGroup
	lifecycleCtx                context.Context
	lifecycleCancel             context.CancelFunc
	cancel                      context.CancelFunc
	onParsed                    func(protocol.URI, []protocol.Diagnostic)
	diagnosticsListenerMu       sync.RWMutex
	compilerHosts               compilerHostPool
	compilerStatus              compilerStatusTracker
	compilerCacheMu             sync.Mutex
	compilerCache               map[string]compilerCacheEntry
	compilerCacheClock          uint64
	compilerCacheRoot           string
	compilerCacheDirectories    map[string]bool
	compilerCacheDirectoryBytes map[string]int64
	compilerCacheBytes          int64
	health                      healthTracker
	compilerTrigger             atomic.Int32
	buildRefreshMu              sync.Mutex
	modelRefreshing             atomic.Bool
	refreshIncomplete           atomic.Bool
	generatedSources            generatedSourceState
	librariesScanned            atomic.Bool
	onDiagnosticsChanged        func()
}

func (i *Index) DiagnosticsVersion() uint64 { return i.diagnosticsVersion.Load() }

// DiagnosticsEpoch is the identity of every input which can change an
// index-backed diagnostic without changing the queried document text.
func (i *Index) DiagnosticsEpoch() [4]uint64 {
	i.mu.RLock()
	epoch := [4]uint64{i.semanticVersion, i.semanticEnvironmentVersion, i.diagnosticsVersion.Load(), i.diagnosticStateVersion.Load()}
	i.mu.RUnlock()
	return epoch
}

func (i *Index) setLibrariesScanned(value bool) {
	if i.librariesScanned.Swap(value) != value {
		i.diagnosticStateVersion.Add(1)
	}
}

func (i *Index) setRefreshIncomplete(value bool) {
	if i.refreshIncomplete.Swap(value) != value {
		i.diagnosticStateVersion.Add(1)
	}
}

func (i *Index) setModelRefreshing(value bool) {
	if i.modelRefreshing.Swap(value) != value {
		i.diagnosticStateVersion.Add(1)
	}
}

// WaitForLibraries blocks until the initial library scan has landed (or ctx
// ends). Until then ClasspathFor answers with module output directories only,
// which is fatally incomplete for run/debug classpaths. An index without any
// workspace scan is complete by construction and never blocks.
func (i *Index) WaitForLibraries(ctx context.Context) bool {
	for {
		if i.closed.Load() {
			return false
		}
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
	if i.closed.Load() {
		return
	}
	i.diagnosticsListenerMu.RLock()
	listener := i.onDiagnosticsChanged
	i.diagnosticsListenerMu.RUnlock()
	if listener != nil {
		listener()
	}
}

func New(onParsed func(protocol.URI, []protocol.Diagnostic)) *Index {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	i := &Index{
		files:                       make(map[protocol.URI]*analysis.ParsedFile),
		fileGeneration:              make(map[protocol.URI]uint64),
		fileSymbolsByName:           make(map[protocol.URI]map[string][]*analysis.Symbol),
		fileSmartCastsByName:        make(map[protocol.URI]map[string][]analysis.SmartCast),
		fileAnonymousByName:         make(map[protocol.URI]map[string][]*analysis.Symbol),
		fileCursorSpans:             make(map[protocol.URI][]cursorSpan),
		interactiveStarted:          make(chan struct{}),
		semanticProgress:            make(chan struct{}),
		docs:                        make(map[protocol.URI]*textdoc.Document),
		syntaxStates:                make(map[protocol.URI]*analysis.SyntaxState),
		indexedDocs:                 make(map[protocol.URI]*textdoc.Document),
		libraryDocs:                 make(map[protocol.URI]*textdoc.Document),
		librarySources:              make(map[protocol.URI]LibrarySource),
		archiveDigests:              make(map[string][32]byte),
		libraryAccess:               make(map[string]map[string]bool),
		libraryModules:              make(map[string]libraryJavaModule),
		libraryModuleAliases:        make(map[string]string),
		libraryStrings:              make(map[string]string),
		symbols:                     make(map[string]*analysis.Symbol),
		byName:                      make(map[string][]string),
		byFQN:                       make(map[string][]string),
		bySuper:                     make(map[string][]string),
		bySuperID:                   make(map[string][]string),
		byContainerName:             make(map[string][]string),
		byContainerMember:           make(map[string][]string),
		byReceiver:                  make(map[string][]string),
		byReceiverMember:            make(map[string][]string),
		byGenericReceiverMember:     make(map[string][]string),
		byOrigin:                    make(map[string][]string),
		byPackage:                   make(map[string][]string),
		packageChildren:             make(map[string][]string),
		packageCounts:               make(map[string]int),
		workspaceIndex:              newNameIndex[string](true),
		completionIndex:             newNameIndex[string](false),
		refsByName:                  make(map[string][]analysis.Reference),
		refsByTarget:                make(map[string][]analysis.Reference),
		unresolvedRefsByName:        make(map[string][]analysis.Reference),
		packages:                    make(map[string][]protocol.URI),
		importersByPrefix:           make(map[string][]protocol.URI),
		compilerDiagnostics:         make(map[protocol.URI][]protocol.Diagnostic),
		compilerCache:               make(map[string]compilerCacheEntry),
		compilerCacheDirectories:    make(map[string]bool),
		compilerCacheDirectoryBytes: make(map[string]int64),
		documentRevision:            make(map[protocol.URI]uint64),
		semanticTokenCache:          make(map[protocol.URI]semanticTokenCacheEntry),
		semanticSymbolVersion:       make(map[string]uint64),
		semanticNameVersion:         make(map[string]uint64),
		onParsed:                    onParsed,
		lifecycleCtx:                lifecycleCtx,
		lifecycleCancel:             lifecycleCancel,
	}
	i.progress.Store(&Progress{})
	return i
}

func (i *Index) Close() {
	if !i.closed.CompareAndSwap(false, true) {
		return
	}
	// Invalidate every workspace publication before waiting for the compiler.
	// A scan does its expensive work outside the index lock and uses this
	// generation as its commit token.
	i.lifecycleMu.Lock()
	i.generation.Add(1)
	cancelScan := i.cancel
	i.cancel = nil
	cancelLifecycle := i.lifecycleCancel
	i.lifecycleCancel = nil
	i.lifecycleMu.Unlock()
	if cancelLifecycle != nil {
		cancelLifecycle()
	}
	if cancelScan != nil {
		cancelScan()
	}
	i.signalSemanticProgress()
	i.scanWG.Wait()
	i.backgroundWG.Wait()
	i.cancelCompilerDiagnostics()
	// Compiler passes are serialized by compilerMu. Waiting here makes the
	// host shutdown and cache removal a lifecycle barrier instead of racing an
	// in-flight javac/K2 invocation which still owns those artifacts.
	i.compilerMu.Lock()
	// The hosted compiler outlives individual passes, so it is shut down with
	// the index rather than left behind as an orphaned JVM.
	i.compilerHosts.shutdown()
	i.compilerCacheMu.Lock()
	compilerCacheRoot := i.compilerCacheRoot
	i.compilerCacheRoot = ""
	i.compilerCache = make(map[string]compilerCacheEntry)
	i.compilerCacheDirectories = make(map[string]bool)
	i.compilerCacheDirectoryBytes = make(map[string]int64)
	i.compilerCacheBytes = 0
	i.compilerCacheMu.Unlock()
	if compilerCacheRoot != "" {
		_ = os.RemoveAll(compilerCacheRoot)
	}
	i.compilerMu.Unlock()
	i.mu.Lock()
	for uri, state := range i.syntaxStates {
		state.Close()
		delete(i.syntaxStates, uri)
	}
	i.mu.Unlock()
}

// signalSemanticProgress wakes foreground requests that arrived just before a
// workspace or archive transaction became visible. A replaceable closed
// channel gives every waiter one broadcast without polling or retaining one
// waiter goroutine per request.
func (i *Index) signalSemanticProgress() {
	i.semanticProgressMu.Lock()
	close(i.semanticProgress)
	i.semanticProgress = make(chan struct{})
	i.semanticProgressMu.Unlock()
}

func (i *Index) semanticProgressSignal() <-chan struct{} {
	i.semanticProgressMu.Lock()
	progress := i.semanticProgress
	i.semanticProgressMu.Unlock()
	return progress
}

// beginBackground joins caller cancellation with the Index lifetime and
// registers one goroutine in the Close barrier. Every Add happens under
// lifecycleMu before Close begins waiting, so no task can appear behind Wait.
func (i *Index) beginBackground(parent context.Context) (context.Context, func(), bool) {
	if parent == nil {
		parent = context.Background()
	}
	i.lifecycleMu.Lock()
	if i.closed.Load() || i.lifecycleCtx == nil {
		i.lifecycleMu.Unlock()
		return nil, func() {}, false
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(i.lifecycleCtx, cancel)
	i.backgroundWG.Add(1)
	i.lifecycleMu.Unlock()
	return ctx, func() {
		stop()
		cancel()
		i.backgroundWG.Done()
	}, true
}

// SetDefaultJavaHome configures the initializationOptions.defaultSdk fallback.
// Build-model-specific toolchains still win for their own modules.
func (i *Index) SetDefaultJavaHome(home string) {
	if i.closed.Load() {
		return
	}
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
	i.fileGeneration = make(map[protocol.URI]uint64)
	i.fileSymbolsByName = make(map[protocol.URI]map[string][]*analysis.Symbol)
	i.fileSmartCastsByName = make(map[protocol.URI]map[string][]analysis.SmartCast)
	i.fileAnonymousByName = make(map[protocol.URI]map[string][]*analysis.Symbol)
	i.fileCursorSpans = make(map[protocol.URI][]cursorSpan)
	i.indexedDocs = make(map[protocol.URI]*textdoc.Document)
	i.libraryDocs = make(map[protocol.URI]*textdoc.Document)
	i.librarySources = make(map[protocol.URI]LibrarySource)
	i.archiveDigests = make(map[string][32]byte)
	i.libraryAccess = make(map[string]map[string]bool)
	i.libraryStringMu.Lock()
	i.libraryStrings = make(map[string]string)
	i.libraryStringMu.Unlock()
	i.symbols = make(map[string]*analysis.Symbol)
	i.byName = make(map[string][]string)
	i.byFQN = make(map[string][]string)
	i.bySuper = make(map[string][]string)
	i.bySuperID = make(map[string][]string)
	i.byContainerName = make(map[string][]string)
	i.byContainerMember = make(map[string][]string)
	i.byReceiver = make(map[string][]string)
	i.byReceiverMember = make(map[string][]string)
	i.byGenericReceiverMember = make(map[string][]string)
	i.byOrigin = make(map[string][]string)
	i.byPackage = make(map[string][]string)
	i.packageChildren = make(map[string][]string)
	i.packageCounts = make(map[string]int)
	i.workspaceIndex.clear()
	i.completionIndex.clear()
	i.refsByName = make(map[string][]analysis.Reference)
	i.refsByTarget = make(map[string][]analysis.Reference)
	i.unresolvedRefsByName = make(map[string][]analysis.Reference)
	i.packages = make(map[string][]protocol.URI)
	i.importersByPrefix = make(map[string][]protocol.URI)
	i.compilerDiagnostics = make(map[protocol.URI][]protocol.Diagnostic)
	i.semanticVersion = 0
	i.semanticEnvironmentVersion = 0
	i.semanticSymbolVersion = make(map[string]uint64)
	i.semanticNameVersion = make(map[string]uint64)
	i.semanticCacheMu.Lock()
	i.semanticTokenCache = make(map[protocol.URI]semanticTokenCacheEntry)
	i.semanticCacheMu.Unlock()
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
