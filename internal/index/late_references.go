package index

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Reference resolution cache.
//
// While the workspace is still being indexed there is nothing to resolve a
// reference against, so most references are stored unresolved, and a
// `references` request resolves every same-named occurrence by type inference.
// For a name used across dozens of files that is slow, and it used to be paid
// again on every request.
//
// Resolving everything ahead of time in the background was tried and rejected:
// it held a core busy for minutes on an idle server. Instead, a request
// remembers what it resolved, so only the first query on a popular symbol pays
// and an idle server does nothing. Results are kept apart from the reference
// buckets so none of their invariants change, and carry what they depend on:
//
//   - the referencing file's content hash, so an edit to it discards its entries;
//   - the declaration version, which moves whenever any file's declarations
//     change shape, so a newly added or removed declaration discards all of them.
type lateReferences struct {
	mu    sync.RWMutex
	byKey map[lateKey]lateEntry

	// declarations moves whenever the set of declarations in the index changes
	// shape. shapes is guarded by Index.mu, like the files it describes.
	declarations atomic.Uint64
	shapes       map[protocol.URI]uint64
}

// lateKey identifies a reference by what its resolution depends on inside its
// file: the text of the declaration around it (scope) and its place within that
// declaration. An edit elsewhere in the file leaves both unchanged, so the
// remembered resolution survives it even though the reference's absolute
// offset moved. What can change meaning across declarations is covered by
// lateEntry's versions instead.
type lateKey struct {
	uri        protocol.URI
	name       string
	scope      uint64
	ordinal    int // among declarations of this file with identical text
	start, end int
}

// lateEntry is what a reference resolved to: one declaration, or the several
// candidates an overloaded name leaves, in the resolver's order. An empty
// result is never remembered: it cannot be told apart from a resolution that
// ran out of budget.
type lateEntry struct {
	targets      []string
	declarations uint64
	environment  uint64
}

type lateResult struct {
	key   lateKey
	entry lateEntry
}

// scopeSpan is one declaration's extent and the hash of its text.
type scopeSpan struct {
	start, end int
	hash       uint64
	ordinal    int
}

type fileScopes struct {
	textHash uint64
	spans    []scopeSpan
}

var scopeCache struct {
	sync.Mutex
	byURI map[protocol.URI]fileScopes
}

// scopesOf returns the file's declaration spans, sorted by start, computed once
// per version of its text. The caller holds Index.mu.
func (i *Index) scopesOf(file *analysis.ParsedFile) []scopeSpan {
	scopeCache.Lock()
	cached, ok := scopeCache.byURI[file.URI]
	scopeCache.Unlock()
	if ok && cached.textHash == file.TextHash {
		return cached.spans
	}
	text := i.documentTextLocked(file.URI)
	spans := make([]scopeSpan, 0, len(file.Symbols))
	for _, symbol := range file.Symbols {
		if isLexicalSymbol(symbol) || symbol.Synthetic || symbol.EndByte <= symbol.StartByte || symbol.EndByte > len(text) {
			continue
		}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(text[symbol.StartByte:symbol.EndByte]))
		spans = append(spans, scopeSpan{start: symbol.StartByte, end: symbol.EndByte, hash: hash.Sum64()})
	}
	sort.Slice(spans, func(a, b int) bool {
		if spans[a].start != spans[b].start {
			return spans[a].start < spans[b].start
		}
		return spans[a].end > spans[b].end
	})
	// Two declarations with the same text (sibling overrides in a sealed
	// hierarchy) can mean different things in their classes; the ordinal tells
	// them apart.
	seen := make(map[uint64]int, len(spans))
	for index := range spans {
		spans[index].ordinal = seen[spans[index].hash]
		seen[spans[index].hash]++
	}
	scopeCache.Lock()
	if scopeCache.byURI == nil || len(scopeCache.byURI) > 4096 {
		scopeCache.byURI = make(map[protocol.URI]fileScopes)
	}
	scopeCache.byURI[file.URI] = fileScopes{textHash: file.TextHash, spans: spans}
	scopeCache.Unlock()
	return spans
}

// lateKeyFor builds the key for a reference of the file. ok is false for a
// reference that cannot be keyed safely (one that is not spelled where it
// claims to be, as inference's synthetic references are not).
func (i *Index) lateKeyFor(file *analysis.ParsedFile, reference analysis.Reference) (lateKey, bool) {
	if file == nil || reference.Synthetic || reference.EndByte <= reference.StartByte {
		return lateKey{}, false
	}
	text := i.documentTextLocked(file.URI)
	if !referenceSpelledAt(text, reference) {
		return lateKey{}, false
	}
	spans := i.scopesOf(file)
	// The innermost declaration containing the reference is the nearest
	// preceding span that still reaches past it.
	at := sort.Search(len(spans), func(index int) bool { return spans[index].start > reference.StartByte }) - 1
	for ; at >= 0; at-- {
		if spans[at].end >= reference.EndByte {
			return lateKey{uri: file.URI, name: reference.Name, scope: spans[at].hash, ordinal: spans[at].ordinal, start: reference.StartByte - spans[at].start, end: reference.EndByte - spans[at].start}, true
		}
	}
	return lateKey{uri: file.URI, name: reference.Name, scope: file.TextHash, start: reference.StartByte, end: reference.EndByte}, true
}

// cachedResolutionLocked returns what the reference was remembered to resolve
// to, if that memory is still valid and every declaration it names still exists.
func (i *Index) cachedResolutionLocked(file *analysis.ParsedFile, reference analysis.Reference) ([]analysis.Symbol, bool) {
	key, ok := i.lateKeyFor(file, reference)
	if !ok {
		return nil, false
	}
	entry, known := i.late.lookup(key)
	if !known || !i.lateEntryValidLocked(entry) {
		return nil, false
	}
	resolved := make([]analysis.Symbol, 0, len(entry.targets))
	for _, target := range entry.targets {
		symbol := i.symbols[target]
		if symbol == nil {
			return nil, false
		}
		resolved = append(resolved, *symbol)
	}
	return resolved, true
}

// rememberResolutionLocked records what a reference resolved to.
func (i *Index) rememberResolutionLocked(file *analysis.ParsedFile, reference analysis.Reference, resolved []analysis.Symbol) {
	if len(resolved) == 0 {
		return
	}
	key, ok := i.lateKeyFor(file, reference)
	if !ok {
		return
	}
	targets := make([]string, len(resolved))
	for index, symbol := range resolved {
		targets[index] = symbol.ID
	}
	i.late.store([]lateResult{{key: key, entry: lateEntry{targets: targets, declarations: i.late.declarations.Load(), environment: i.semanticEnvironmentVersion}}})
}

func (l *lateReferences) store(results []lateResult) {
	if len(results) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byKey == nil || len(l.byKey) > 400_000 {
		// Entries made stale by edits are never revisited, so the table is
		// bounded by starting over rather than by tracking each one.
		l.byKey = make(map[lateKey]lateEntry, len(results))
	}
	for _, result := range results {
		l.byKey[result.key] = result.entry
	}
}

func (l *lateReferences) lookup(key lateKey) (lateEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	entry, ok := l.byKey[key]
	return entry, ok
}

// lateEntryValidLocked reports whether the entry still describes the index:
// no declaration changed shape and the build model is the one it was resolved
// against. The caller holds Index.mu.
func (i *Index) lateEntryValidLocked(entry lateEntry) bool {
	return entry.declarations == i.late.declarations.Load() && entry.environment == i.semanticEnvironmentVersion
}

// noteDeclarationsLocked records the shape of a file's declarations and moves
// the declaration version when it differs from the last one seen. The caller
// holds Index.mu for writing.
func (i *Index) noteDeclarationsLocked(file *analysis.ParsedFile) {
	if i.late.shapes == nil {
		i.late.shapes = make(map[protocol.URI]uint64)
	}
	shape := declarationShape(file, i.documentTextLocked(file.URI))
	if previous, known := i.late.shapes[file.URI]; !known || previous != shape {
		i.late.shapes[file.URI] = shape
		i.late.declarations.Add(1)
	}
}

func (i *Index) forgetDeclarationsLocked(uri protocol.URI) {
	if _, known := i.late.shapes[uri]; known {
		delete(i.late.shapes, uri)
		i.late.declarations.Add(1)
	}
}

// declarationShape hashes everything about a file's declarations that can
// change what a name elsewhere resolves to.
func declarationShape(file *analysis.ParsedFile, text string) uint64 {
	hash := fnv.New64a()
	write := func(value string) {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	write(file.Package)
	for _, symbol := range file.Symbols {
		if isLexicalSymbol(symbol) {
			continue
		}
		write(symbol.Name)
		write(symbol.FQN)
		write(symbol.Type)
		// A declaration whose type is not written takes it from its
		// initializer or expression body, so another file's `x.find()` depends
		// on that text. When the type is declared the body is irrelevant to
		// everyone else, and hashing it would make every edit inside a function
		// invalidate everything.
		if symbol.Type == "" {
			write(symbol.Initializer)
			// An expression body is not kept in Initializer; it is the text.
			if analysis.IsCallableKind(symbol.Kind) && symbol.StartByte >= 0 && symbol.EndByte <= len(text) && symbol.StartByte < symbol.EndByte {
				write(text[symbol.StartByte:symbol.EndByte])
			}
		}
		write(symbol.Signature)
		write(strings.Join(symbol.Modifiers, ","))
		write(string(rune('0' + symbol.Kind%64)))
		write(symbol.ContainerID)
	}
	for _, imported := range file.Imports {
		write(imported.Path)
		if imported.Wildcard {
			write("*")
		}
	}
	return hash.Sum64()
}
