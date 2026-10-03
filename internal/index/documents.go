package index

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) Open(ctx context.Context, item protocol.TextDocumentItem) *analysis.ParsedFile {
	guard := i.lockGuard()
	defer guard.release()
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
	i.preemptDiagnostics()
	doc := textdoc.NewDocument(item.URI, item.LanguageID, item.Version, item.Text)
	state := analysis.NewSyntaxState()
	parsed := analysis.ParseIncremental(ctx, doc, state, nil)
	if ctx.Err() != nil {
		state.Close()
		return parsed
	}
	guard.Lock()
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
	guard.Unlock()
	if i.onParsed != nil {
		i.publishDiagnosticsSoon(item.URI)
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed
}

func (i *Index) Change(ctx context.Context, params protocol.DidChangeTextDocumentParams) (*analysis.ParsedFile, error) {
	guard := i.lockGuard()
	defer guard.release()
	operationCtx, finish, started := i.beginBackground(ctx)
	if !started {
		return nil, errors.New("index is closed")
	}
	defer finish()
	ctx = operationCtx
	i.interactiveOnce.Do(func() { close(i.interactiveStarted) })
	i.cancelCompilerDiagnostics()
	i.preemptDiagnostics()
	guard.RLock()
	old := i.docs[params.TextDocument.URI]
	previousParsed := i.files[params.TextDocument.URI]
	state := i.syntaxStates[params.TextDocument.URI]
	if old != nil {
		old = old.Clone()
	}
	guard.RUnlock()
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
		guard.Lock()
		i.docs[old.URI] = old
		i.files[old.URI] = &updated
		guard.Unlock()
		if i.onParsed != nil {
			i.publishDiagnosticsSoon(old.URI)
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
	guard.Lock()
	i.syntaxStates[old.URI] = state
	i.docs[old.URI] = old
	// The compiler's findings for this file stay until the next pass replaces
	// them -- about a second later -- shifted past the edit; those on the
	// edited lines go. Dropping them all made every compiler-only error
	// vanish on each keystroke and reappear when the pass came back.
	i.shiftCompilerDiagnosticsLocked(old.URI, previousText, old.Text)
	i.replaceLocked(parsed)
	i.fileGeneration[old.URI] = i.generation.Load()
	guard.Unlock()
	if i.onParsed != nil {
		i.publishDiagnosticsSoon(old.URI)
	}
	i.ScheduleCompilerDiagnostics(ctx)
	return parsed, nil
}

func (i *Index) CloseDocument(ctx context.Context, uri protocol.URI) {
	guard := i.lockGuard()
	defer guard.release()
	reloadCtx, finish, started := i.beginBackground(ctx)
	if !started {
		return
	}
	// Invalidate any compiler run which captured the discarded unsaved buffer.
	i.compilerRun.Add(1)
	i.preemptDiagnostics()
	guard.Lock()
	delete(i.docs, uri)
	state := i.syntaxStates[uri]
	delete(i.syntaxStates, uri)
	revision := i.documentRevision[uri]
	guard.Unlock()
	if state != nil {
		state.Close()
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		finish()
		return
	}
	go func() {
		defer i.recoverBackground("CloseDocument")
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
		if !i.closed.Load() {
			i.publishNow(uri)
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
		defer i.recoverBackground("Reload")
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
	guard := i.lockGuard()
	defer guard.release()
	done := make(chan bool, 1)
	reloadCtx, finish, started := i.beginBackground(ctx)
	if !started {
		done <- false
		close(done)
		return done
	}
	guard.RLock()
	_, open := i.docs[uri]
	revision := i.documentRevision[uri]
	guard.RUnlock()
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
		defer i.recoverBackground("ReloadResult")
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
		if !i.closed.Load() {
			i.publishNow(uri)
		}
		done <- true
	}()
	return done
}

// Remove evicts every declaration and reference belonging to a deleted file.
func (i *Index) Remove(uri protocol.URI) {
	guard := i.lockGuard()
	defer guard.release()
	if i.closed.Load() {
		return
	}
	guard.Lock()
	i.removeLocked(uri)
	guard.Unlock()
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
		i.forgetDeclarationsLocked(old.URI)
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
	i.forgetLibrarySourceLocked(uri)
}

// shiftCompilerDiagnosticsLocked moves a file's compiler findings to where
// their lines are after an edit, and drops those on lines the edit changed.
func (i *Index) shiftCompilerDiagnosticsLocked(uri protocol.URI, before, after string) {
	values, exists := i.compilerDiagnostics[uri]
	if !exists {
		return
	}
	start, oldEnd, newEnd := changedLines(before, after)
	delta := newEnd - oldEnd
	kept := make([]protocol.Diagnostic, 0, len(values))
	for _, diagnostic := range values {
		switch {
		case diagnostic.Range.End.Line < start:
			kept = append(kept, diagnostic)
		case diagnostic.Range.Start.Line >= oldEnd:
			diagnostic.Range.Start.Line += delta
			diagnostic.Range.End.Line += delta
			kept = append(kept, diagnostic)
		}
	}
	if len(kept) == 0 {
		delete(i.compilerDiagnostics, uri)
	} else {
		i.compilerDiagnostics[uri] = kept
	}
	i.diagnosticsVersion.Add(1)
}

// changedLines compares two texts line by line: lines [0, start) are equal,
// and so are old lines from oldEnd and new lines from newEnd to the end.
func changedLines(before, after string) (start, oldEnd, newEnd int) {
	oldLines, newLines := strings.Split(before, "\n"), strings.Split(after, "\n")
	for start < len(oldLines) && start < len(newLines) && oldLines[start] == newLines[start] {
		start++
	}
	oldEnd, newEnd = len(oldLines), len(newLines)
	for oldEnd > start && newEnd > start && oldLines[oldEnd-1] == newLines[newEnd-1] {
		oldEnd--
		newEnd--
	}
	return start, oldEnd, newEnd
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
	guard := i.lockGuard()
	defer guard.release()
	if i.closed.Load() {
		return
	}
	guard.RLock()
	_, open := i.docs[uri]
	guard.RUnlock()
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
	guard := i.lockGuard()
	defer guard.release()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil, false
	}
	guard.RLock()
	if d := i.docs[uri]; d != nil {
		clone := d.Clone()
		guard.RUnlock()
		return clone, true
	}
	if d := i.libraryDocs[uri]; d != nil {
		clone := d.Clone()
		i.noteLibraryCacheUse(uri)
		guard.RUnlock()
		return clone, true
	}
	if d := i.indexedDocs[uri]; d != nil {
		clone := d.Clone()
		guard.RUnlock()
		return clone, true
	}
	source, library := i.librarySources[uri]
	guard.RUnlock()
	if library {
		document, err := loadLibraryDocumentContext(ctx, uri, source)
		if err == nil {
			// Filling this cache must never make a foreground request wait. The
			// document is already in hand, so the exclusive lock buys nothing
			// but the memo; while a library-indexing or compiler publication
			// transaction held it, that wait reached 929ms for a read that
			// itself costs 323µs. Take the lock only when it is free. A later
			// call populates the cache instead, and no result ever depended on
			// the write succeeding.
			if i.mu.TryLock() {
				if current, exists := i.librarySources[uri]; exists && current == source {
					i.libraryDocs[uri] = document
				}
				guard.Unlock()
			}
			return document.Clone(), true
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

// SelectionSpans returns, for each offset, the nested byte spans of the syntax
// around it, innermost first; ok is false when the document has no syntax tree.
func (i *Index) SelectionSpans(uri protocol.URI, offsets []int) (spans [][][2]int, ok bool) {
	guard := i.lockGuard()
	defer guard.release()
	guard.RLock()
	state := i.syntaxStates[uri]
	guard.RUnlock()
	if state == nil {
		return nil, false
	}
	spans = make([][][2]int, len(offsets))
	for index, offset := range offsets {
		spans[index] = state.SelectionSpans(offset)
	}
	return spans, true
}
