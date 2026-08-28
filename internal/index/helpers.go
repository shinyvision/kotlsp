package index

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	data, err := readFileBounded(path, 64<<20, "file")
	return string(data), err
}

func readFileBounded(path string, limit int64, description string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %s exceeds its %d-byte safety limit", description, path, limit)
	}
	return data, nil
}

// boundedGlob enumerates a fixed-depth wildcard pattern without allowing a
// single enormous directory to make filepath.Glob allocate an unbounded result
// slice. complete is false when traversal or result limits prevent an
// authoritative answer.
func boundedGlob(pattern string, maxEntries, maxMatches int) (matches []string, complete bool) {
	pattern = filepath.Clean(pattern)
	meta := strings.IndexAny(pattern, "*?[")
	if meta < 0 {
		if info, err := os.Stat(pattern); err == nil && !info.IsDir() {
			return []string{pattern}, true
		}
		return nil, true
	}
	root := filepath.Dir(pattern[:meta])
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, true
		}
		return nil, false
	}
	relativePattern, err := filepath.Rel(root, pattern)
	if err != nil {
		return nil, false
	}
	targetDepth := len(strings.Split(filepath.ToSlash(relativePattern), "/"))
	visited := 0
	complete = true
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			complete = false
			if path == root {
				return filepath.SkipAll
			}
			return nil
		}
		visited++
		if visited > maxEntries {
			complete = false
			return filepath.SkipAll
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil {
			complete = false
			return filepath.SkipAll
		}
		depth := 0
		if relative != "." {
			depth = len(strings.Split(filepath.ToSlash(relative), "/"))
		}
		if entry.IsDir() {
			if depth >= targetDepth {
				return filepath.SkipDir
			}
			return nil
		}
		matched, matchErr := filepath.Match(pattern, path)
		if matchErr != nil {
			complete = false
			return filepath.SkipAll
		}
		if matched {
			if len(matches) >= maxMatches {
				complete = false
				return filepath.SkipAll
			}
			matches = append(matches, path)
		}
		return nil
	})
	if walkErr != nil {
		complete = false
	}
	return matches, complete
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
