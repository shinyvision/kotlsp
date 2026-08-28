package index

import (
	"context"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// Library files are indexed without their reference table. Retaining one for
// every entry of the JDK and of every dependency would dominate memory, and a
// library file nobody opens never needs it. Navigation from inside one does:
// without references, only a declaration name resolves, so every type used in
// the body of an archive source file is a dead end.
//
// The table is therefore rebuilt for the few library files actually visited and
// dropped again once the working set is exceeded. Parsing one file costs far
// less than the request budget, and a revisit is a map lookup.
const libraryReferenceWorkingSet = 24

// ensureLibraryReferences rebuilds the reference table for a library file that
// was indexed without one. The parse happens outside the lock; the result is
// published only if the file is still present and still bare.
func (i *Index) ensureLibraryReferences(uri protocol.URI, document *textdoc.Document) {
	i.ensureLibraryReferencesContext(context.Background(), uri, document)
}

func (i *Index) ensureLibraryReferencesContext(ctx context.Context, uri protocol.URI, document *textdoc.Document) {
	if document == nil || !isArchiveURI(uri) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	i.mu.RLock()
	file := i.files[uri]
	bare := file != nil && len(file.References) == 0
	i.mu.RUnlock()
	if !bare {
		return
	}
	parsed := analysis.Parse(ctx, document)
	if ctx.Err() != nil {
		return
	}
	if len(parsed.References) == 0 {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	current := i.files[uri]
	if current == nil || len(current.References) != 0 {
		return
	}
	current.References = parsed.References
	i.fileCursorSpans[uri] = buildCursorSpans(current)
	i.libraryReferenceOrder = append(i.libraryReferenceOrder, uri)
	for len(i.libraryReferenceOrder) > libraryReferenceWorkingSet {
		oldest := i.libraryReferenceOrder[0]
		i.libraryReferenceOrder = i.libraryReferenceOrder[1:]
		if oldest == uri {
			continue
		}
		if evicted := i.files[oldest]; evicted != nil {
			evicted.References = nil
			i.fileCursorSpans[oldest] = buildCursorSpans(evicted)
		}
	}
}
