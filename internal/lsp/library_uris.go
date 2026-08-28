package lsp

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// The index identifies library declarations by jar:// and jrt:// URIs. Those
// schemes are meaningful only inside this process: an editor told to jump to
// one opens an empty buffer and then fails to place the cursor. Navigation
// results are therefore rewritten to the mirrored file:// URI on the way out,
// and request payloads naming a mirrored file are rewritten back to the index
// URI on the way in.
var librarySourceMarker = []byte(index.LibrarySourceMarker)

var librarySourceBaseMarker = []byte(index.LibrarySourceBaseMarker)

// uriFields are the request payload members that carry a document URI in the
// negotiated protocol.
var uriFields = map[string]bool{"uri": true, "targetUri": true, "oldUri": true, "newUri": true}

func (s *Server) externalURI(uri protocol.URI) protocol.URI {
	return s.externalURIContext(context.Background(), uri)
}

func (s *Server) externalURIContext(ctx context.Context, uri protocol.URI) protocol.URI {
	if mirrored, ok := s.index.LibraryFileURIContext(ctx, uri); ok {
		return mirrored
	}
	return uri
}

func (s *Server) externalLocation(location protocol.Location) protocol.Location {
	return s.externalLocationContext(context.Background(), location)
}

func (s *Server) externalLocationContext(ctx context.Context, location protocol.Location) protocol.Location {
	location.URI = s.externalURIContext(ctx, location.URI)
	return location
}

func (s *Server) externalLocations(locations []protocol.Location) []protocol.Location {
	return s.externalLocationsContext(context.Background(), locations)
}

func (s *Server) externalLocationsContext(ctx context.Context, locations []protocol.Location) []protocol.Location {
	for n := range locations {
		if ctx.Err() != nil {
			return locations[:n]
		}
		locations[n].URI = s.externalURIContext(ctx, locations[n].URI)
	}
	return locations
}

// internalParams rewrites mirrored file URIs in a request payload back to the
// library URI the index is keyed by. Payloads that cannot name a mirrored file
// are returned untouched, so the common path costs one scan rather than a
// decode and re-encode.
func (s *Server) internalParams(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !bytes.Contains(raw, librarySourceMarker) {
		return raw
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}
	if !s.internalURIs(payload) {
		return raw
	}
	rewritten, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return rewritten
}

func (s *Server) internalURIs(payload any) bool {
	rewritten := false
	switch value := payload.(type) {
	case map[string]any:
		for key, member := range value {
			if text, ok := member.(string); ok {
				if uriFields[key] {
					if internal, mapped := s.index.LibraryURIForFile(protocol.URI(text)); mapped {
						value[key] = string(internal)
						rewritten = true
					}
				}
				continue
			}
			if s.internalURIs(member) {
				rewritten = true
			}
		}
	case []any:
		for _, member := range value {
			if s.internalURIs(member) {
				rewritten = true
			}
		}
	}
	return rewritten
}

// mirrorsLibraryFile reports whether a document lifecycle notification targets
// a mirrored library file. Those files are read-only views of archive entries:
// opening one must not enter it into the workspace document set, where it would
// be parsed as project source and published diagnostics of its own.
func (s *Server) mirrorsLibraryFile(raw json.RawMessage) bool {
	if len(raw) == 0 || !bytes.Contains(raw, librarySourceBaseMarker) {
		return false
	}
	var payload struct {
		TextDocument protocol.TextDocumentIdentifier `json:"textDocument"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false
	}
	if _, mapped := s.index.LibraryURIForFile(payload.TextDocument.URI); mapped {
		return true
	}
	return s.index.IsLibraryMirrorFile(payload.TextDocument.URI)
}
