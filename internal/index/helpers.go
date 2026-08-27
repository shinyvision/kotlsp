package index

import (
	"errors"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

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

func ReadFile(uri protocol.URI) (string, error) {
	path, ok := uriutil.Path(uri)
	if !ok {
		return "", errors.New("not a file URI")
	}
	data, err := os.ReadFile(path)
	return string(data), err
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

var _ = time.Now
