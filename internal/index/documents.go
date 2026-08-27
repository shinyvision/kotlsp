package index

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

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
	i.dropCompilerDiagnosticsLocked(item.URI)
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
	// The next compiler pass is seconds away. Keep the findings it produced for
	// the previous text, moved to follow this edit, so the file stays annotated
	// instead of going blank for the whole wait.
	i.retainCompilerDiagnosticsLocked(old.URI, params.ContentChanges)
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
		i.dropCompilerDiagnosticsLocked(parsed.URI)
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
		i.dropCompilerDiagnosticsLocked(parsed.URI)
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
	//
	// A save validates whatever the trigger policy is: it is the one moment the
	// author has explicitly declared the text finished.
	i.ScheduleCompilerDiagnosticsForSave(ctx)
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

// OpenDocuments returns the URIs the client currently has open. Diagnostics
// that were pushed for them may need recomputing when the index changes.
func (i *Index) OpenDocuments() []protocol.URI {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]protocol.URI, 0, len(i.docs))
	for uri := range i.docs {
		out = append(out, uri)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
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

func (i *Index) documentTextLocked(uri protocol.URI) string {
	if document := i.docs[uri]; document != nil {
		return document.Text
	}
	if document := i.indexedDocs[uri]; document != nil {
		return document.Text
	}
	return ""
}
