package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Compiler validation takes seconds, so deleting its findings the moment a
// document changes leaves the editor empty for the whole of that wait: an error
// the author is halfway through fixing vanishes, then reappears unchanged.
// Retaining the previous findings and moving them to follow the edit keeps the
// file annotated continuously, and the next pass replaces them wholesale.
//
// Positions are moved by whole lines only. An edit inside a line can shift
// columns in ways that need the edit applied to know, so any finding on a line
// the edit touched is dropped rather than reported at a position that may no
// longer mean anything. Reporting an error one line out is worse than briefly
// reporting one fewer.
func shiftDiagnosticsForChange(diagnostics []protocol.Diagnostic, change protocol.TextDocumentContentChangeEvent) []protocol.Diagnostic {
	if change.Range == nil {
		// A full-document replacement carries no mapping from old positions to
		// new ones.
		return nil
	}
	first := change.Range.Start.Line
	last := change.Range.End.Line
	delta := strings.Count(change.Text, "\n")
	removed := last - first
	kept := diagnostics[:0]
	for _, diagnostic := range diagnostics {
		start, end := diagnostic.Range.Start.Line, diagnostic.Range.End.Line
		switch {
		case end < first:
			// Entirely above the edit.
			kept = append(kept, diagnostic)
		case start > last:
			// Entirely below it: follow by the number of lines gained or lost.
			diagnostic.Range.Start.Line = start + delta - removed
			diagnostic.Range.End.Line = end + delta - removed
			shiftRelatedInformation(&diagnostic, first, last, delta, removed)
			kept = append(kept, diagnostic)
		default:
			// The edit touched these lines, so the position is no longer known.
		}
	}
	return kept
}

func shiftRelatedInformation(diagnostic *protocol.Diagnostic, first, last, delta, removed int) {
	if len(diagnostic.RelatedInformation) == 0 {
		return
	}
	related := make([]protocol.DiagnosticRelated, 0, len(diagnostic.RelatedInformation))
	for _, entry := range diagnostic.RelatedInformation {
		start, end := entry.Location.Range.Start.Line, entry.Location.Range.End.Line
		switch {
		case end < first:
			related = append(related, entry)
		case start > last:
			entry.Location.Range.Start.Line = start + delta - removed
			entry.Location.Range.End.Line = end + delta - removed
			related = append(related, entry)
		}
	}
	diagnostic.RelatedInformation = related
}

// retainCompilerDiagnosticsLocked moves this document's retained compiler
// findings to follow an edit. Callers hold the write lock.
func (i *Index) retainCompilerDiagnosticsLocked(uri protocol.URI, changes []protocol.TextDocumentContentChangeEvent) {
	existing, ok := i.compilerDiagnostics[uri]
	if !ok {
		return
	}
	for _, change := range changes {
		existing = shiftDiagnosticsForChange(existing, change)
		if len(existing) == 0 {
			break
		}
	}
	if len(existing) == 0 {
		delete(i.compilerDiagnostics, uri)
		return
	}
	i.compilerDiagnostics[uri] = existing
}

// dropCompilerDiagnosticsLocked discards findings for a document whose text
// changed without a mapping from the old positions, such as a reload from disk.
func (i *Index) dropCompilerDiagnosticsLocked(uri protocol.URI) {
	delete(i.compilerDiagnostics, uri)
}
