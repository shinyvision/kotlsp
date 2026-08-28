package index

import (
	"context"
	"errors"
	"sort"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) Open(ctx context.Context, item protocol.TextDocumentItem) *analysis.ParsedFile {
	if i.IsLibraryMirrorFile(item.URI) {
		// A mirrored archive entry is a read-only library view. Entering it
		// into the workspace document set would compile it as project source
		// and hand the compiler a file no module owns.
		return nil
	}
	operationCtx, finish, started := i.beginBackground(ctx)
	if !started {
		return nil
	}
	defer finish()
	ctx = operationCtx
	i.interactiveOnce.Do(func() { close(i.interactiveStarted) })
	i.cancelCompilerDiagnostics()
	doc := textdoc.NewDocument(item.URI, item.LanguageID, item.Version, item.Text)
	state := analysis.NewSyntaxState()
	parsed := analysis.ParseIncremental(ctx, doc, state, nil)
	if ctx.Err() != nil {
		state.Close()
		return parsed
	}
	i.mu.Lock()
	if previous := i.syntaxStates[item.URI]; previous != nil {
		previous.Close()
	}
	i.syntaxStates[item.URI] = state
	_, libraryDocument := i.librarySources[item.URI]
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
	i.fileGeneration[item.URI] = i.generation.Load()
	i.mu.Unlock()
	if i.onParsed != nil {
		i.onParsed(item.URI, i.Diagnostics(item.URI))
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed
}

func (i *Index) Change(ctx context.Context, params protocol.DidChangeTextDocumentParams) (*analysis.ParsedFile, error) {
	operationCtx, finish, started := i.beginBackground(ctx)
	if !started {
		return nil, errors.New("index is closed")
	}
	defer finish()
	ctx = operationCtx
	i.interactiveOnce.Do(func() { close(i.interactiveStarted) })
	i.cancelCompilerDiagnostics()
	i.mu.RLock()
	old := i.docs[params.TextDocument.URI]
	previousParsed := i.files[params.TextDocument.URI]
	state := i.syntaxStates[params.TextDocument.URI]
	if old != nil {
		old = old.Clone()
	}
	i.mu.RUnlock()
	if old == nil {
		return nil, errors.New("document is not open")
	}
	previousText := old.Text
	edits, err := old.ApplyWithEdits(params.TextDocument.Version, params.ContentChanges)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
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
		i.ScheduleCompilerDiagnostics(ctx)
		return &updated, nil
	}
	if state == nil {
		state = analysis.NewSyntaxState()
	}
	parsed := analysis.ParseIncremental(ctx, old, state, edits)
	if err := ctx.Err(); err != nil {
		return parsed, err
	}
	i.mu.Lock()
	i.syntaxStates[old.URI] = state
	i.docs[old.URI] = old
	// Compiler findings belong to the exact source/configuration transaction
	// which produced them. Even an edit on another line can add an import,
	// change overload resolution, or repair a project-wide declaration, so
	// shifting old ranges is not evidence that the finding remains true.
	i.dropCompilerDiagnosticsLocked(old.URI)
	i.replaceLocked(parsed)
	i.fileGeneration[old.URI] = i.generation.Load()
	i.mu.Unlock()
	if i.onParsed != nil {
		i.onParsed(old.URI, i.Diagnostics(old.URI))
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed, nil
}

func (i *Index) CloseDocument(ctx context.Context, uri protocol.URI) {
	reloadCtx, finish, started := i.beginBackground(ctx)
	if !started {
		return
	}
	// Invalidate any compiler run which captured the discarded unsaved buffer.
	i.compilerRun.Add(1)
	i.mu.Lock()
	delete(i.docs, uri)
	state := i.syntaxStates[uri]
	delete(i.syntaxStates, uri)
	revision := i.documentRevision[uri]
	i.mu.Unlock()
	if state != nil {
		state.Close()
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		finish()
		return
	}
	go func() {
		defer finish()
		if reloadCtx.Err() != nil {
			return
		}
		data, err := readWorkspaceSource(path)
		if err != nil {
			if reloadCtx.Err() != nil || i.closed.Load() {
				return
			}
			i.removeClosedRevision(uri, revision)
			if i.onParsed != nil {
				i.onParsed(uri, nil)
			}
			i.ScheduleCompilerDiagnostics(reloadCtx)
			return
		}
		doc := textdoc.NewDocument(uri, uriutil.LanguageID(path), 0, string(data))
		parsed := analysis.Parse(reloadCtx, doc)
		if reloadCtx.Err() != nil || i.closed.Load() {
			return
		}
		i.mu.Lock()
		if i.closed.Load() || i.docs[uri] != nil || i.documentRevision[uri] != revision {
			i.mu.Unlock()
			return
		}
		i.indexedDocs[uri] = doc
		i.dropCompilerDiagnosticsLocked(parsed.URI)
		i.replaceLocked(parsed)
		i.fileGeneration[parsed.URI] = i.generation.Load()
		i.mu.Unlock()
		if i.onParsed != nil && !i.closed.Load() {
			i.onParsed(uri, i.Diagnostics(uri))
		}
		i.ScheduleCompilerDiagnostics(reloadCtx)
	}()
}

// Reload refreshes a closed workspace document after a file-watcher event.
// Open buffers remain authoritative until didClose. The returned channel is
// closed only after the replacement index is observable, allowing protocol
// high-watermarks to describe completed work rather than queued work.
func (i *Index) Reload(ctx context.Context, uri protocol.URI) <-chan struct{} {
	done := make(chan struct{})
	result := i.ReloadResult(ctx, uri)
	waitCtx, finish, started := i.beginBackground(ctx)
	if !started {
		close(done)
		return done
	}
	go func() {
		defer finish()
		defer close(done)
		select {
		case <-result:
		case <-waitCtx.Done():
		}
	}()
	return done
}

// ReloadResult is Reload with an explicit publication result. A false result
// tells polling watchers to retain their old file stamp and retry: transient
// replace/read failures must preserve both the old semantics and the retry.
func (i *Index) ReloadResult(ctx context.Context, uri protocol.URI) <-chan bool {
	done := make(chan bool, 1)
	reloadCtx, finish, started := i.beginBackground(ctx)
	if !started {
		done <- false
		close(done)
		return done
	}
	i.mu.RLock()
	_, open := i.docs[uri]
	revision := i.documentRevision[uri]
	i.mu.RUnlock()
	if open {
		finish()
		done <- true
		close(done)
		return done
	}
	path, ok := uriutil.Path(uri)
	if !ok || !isSource(path) {
		finish()
		done <- false
		close(done)
		return done
	}
	go func() {
		defer finish()
		defer close(done)
		data, err := readWorkspaceSource(path)
		if err != nil {
			done <- false
			return
		}
		doc := textdoc.NewDocument(uri, uriutil.LanguageID(path), 0, string(data))
		parsed := analysis.Parse(reloadCtx, doc)
		if reloadCtx.Err() != nil || i.closed.Load() {
			done <- false
			return
		}
		i.mu.Lock()
		if i.closed.Load() || i.docs[uri] != nil || i.documentRevision[uri] != revision {
			i.mu.Unlock()
			done <- true
			return
		}
		i.indexedDocs[uri] = doc
		i.dropCompilerDiagnosticsLocked(parsed.URI)
		i.replaceLocked(parsed)
		i.fileGeneration[parsed.URI] = i.generation.Load()
		i.mu.Unlock()
		if i.onParsed != nil && !i.closed.Load() {
			i.onParsed(uri, i.Diagnostics(uri))
		}
		done <- true
	}()
	return done
}

// Remove evicts every declaration and reference belonging to a deleted file.
func (i *Index) Remove(uri protocol.URI) {
	if i.closed.Load() {
		return
	}
	i.mu.Lock()
	i.removeLocked(uri)
	i.mu.Unlock()
}

// RemoveClosed applies a filesystem deletion only when no editor buffer owns
// the URI. A watched delete can race didOpen and must not discard unsaved text.
func (i *Index) RemoveClosed(uri protocol.URI) bool {
	removed, _ := i.RemoveClosedResult(uri)
	return removed
}

// RemoveClosedResult distinguishes an actual removal from an open editor
// buffer which deliberately remains authoritative. Polling watchers may
// advance the absent-on-disk stamp in both cases; an open buffer is not a
// transient failure that should make every later poll repeat the deletion.
func (i *Index) RemoveClosedResult(uri protocol.URI) (removed, handled bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.docs[uri] != nil {
		return false, true
	}
	i.removeLocked(uri)
	return true, true
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
	i.compilerRun.Add(1)
	i.invalidateCompilerDiagnosticsLocked()
	if old := i.files[uri]; old != nil {
		i.removeFileContentsLocked(old)
	}
	delete(i.files, uri)
	delete(i.fileGeneration, uri)
	delete(i.fileCursorSpans, uri)
	delete(i.docs, uri)
	if state := i.syntaxStates[uri]; state != nil {
		state.Close()
		delete(i.syntaxStates, uri)
	}
	delete(i.indexedDocs, uri)
	delete(i.libraryDocs, uri)
	delete(i.librarySources, uri)
}

func (i *Index) dropCompilerDiagnosticsLocked(uri protocol.URI) {
	if _, exists := i.compilerDiagnostics[uri]; !exists {
		return
	}
	delete(i.compilerDiagnostics, uri)
	i.diagnosticsVersion.Add(1)
}

// Compiler output is a workspace transaction, not a per-file decoration. A
// declaration/import/library mutation in one URI can invalidate overload or
// unresolved findings in every other URI, so semantic mutations clear the
// complete prior transaction before publishing their new index state.
func (i *Index) invalidateCompilerDiagnosticsLocked() {
	if len(i.compilerDiagnostics) == 0 {
		return
	}
	i.compilerDiagnostics = make(map[protocol.URI][]protocol.Diagnostic)
	i.diagnosticsVersion.Add(1)
}

func (i *Index) Save(ctx context.Context, uri protocol.URI) {
	if i.closed.Load() {
		return
	}
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
	return i.DocumentContext(context.Background(), uri)
}

func (i *Index) DocumentContext(ctx context.Context, uri protocol.URI) (*textdoc.Document, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil, false
	}
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
		document, err := loadLibraryDocumentContext(ctx, uri, source)
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
	files, _ := i.WorkspaceFilesContext(context.Background(), 0)
	return files
}

// WorkspaceFilesContext copies at most limit immutable pointers while holding
// the index lock. A bounded protocol request must never first allocate a slice
// proportional to an arbitrarily large workspace.
func (i *Index) WorkspaceFilesContext(ctx context.Context, limit int) ([]*analysis.ParsedFile, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	capacity := len(i.files)
	if limit > 0 && capacity > limit {
		capacity = limit
	}
	out := make([]*analysis.ParsedFile, 0, capacity)
	truncated := false
	for uri, file := range i.files {
		if len(out)&255 == 0 && ctx.Err() != nil {
			return out, true
		}
		if _, ok := uriutil.Path(uri); ok {
			if limit > 0 && len(out) >= limit {
				truncated = true
				break
			}
			out = append(out, file)
		}
	}
	return out, truncated
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
