package index

import (
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// respellDeclaredTypeLocked rewrites a type that `declaration` spelled in its
// own file so that every simple name still denotes the same declaration when
// the type is read from `file`. A declaring file names its neighbours through
// its own package and imports; the call site rarely shares them (a controller
// imports `UserRepository`, never the `User` its finder returns). A name that
// the call site would resolve to nothing, or to a different declaration, is
// replaced by the fully qualified name of what the declaring file meant.
// Names resolving identically on both sides keep their spelling, so
// same-file and stdlib types are untouched. Type parameters of the
// declaration and of its enclosing declarations are never rewritten, and a
// name whose meaning in the declaring file is not unique is left alone: this
// rewrites only proven bindings, it never guesses.
func (i *Index) respellDeclaredTypeLocked(file *analysis.ParsedFile, declaration analysis.Symbol, typ string) string {
	if typ == "" || file == nil || declaration.URI == "" || declaration.URI == file.URI {
		return typ
	}
	declaringFile := i.files[declaration.URI]
	if declaringFile == nil {
		return typ
	}
	if !strings.ContainsFunc(typ, unicode.IsUpper) {
		return typ
	}
	key := declaration.ID + "\x00" + string(file.URI) + "\x00" + typ
	epoch := [2]uint64{i.semanticVersion, i.semanticEnvironmentVersion}
	if cached, ok := i.respell.lookup(epoch, key); ok {
		return cached
	}
	respelled := i.respellDeclaredTypeUncachedLocked(file, declaringFile, declaration, typ)
	i.respell.store(epoch, key, respelled)
	return respelled
}

// respellMemo caches respelled types for one index epoch. Every entry is a
// pure function of the two files' declarations and imports, all of which
// move the semantic or environment version when they change.
type respellMemo struct {
	mu      sync.Mutex
	epoch   [2]uint64
	entries map[string]string
}

const respellMemoLimit = 8192

func (m *respellMemo) lookup(epoch [2]uint64, key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch != epoch || m.entries == nil {
		return "", false
	}
	value, ok := m.entries[key]
	return value, ok
}

func (m *respellMemo) store(epoch [2]uint64, key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch != epoch || m.entries == nil || len(m.entries) >= respellMemoLimit {
		m.epoch = epoch
		m.entries = make(map[string]string, 256)
	}
	m.entries[key] = value
}

func (i *Index) respellDeclaredTypeUncachedLocked(file, declaringFile *analysis.ParsedFile, declaration analysis.Symbol, typ string) string {
	var declaringAccess, usingAccess *accessibilityMemo
	typeParameters := map[string]bool{}
	for current, hops := declaration, 0; hops < 32; hops++ {
		for _, parameter := range current.TypeParameters {
			typeParameters[parameter] = true
		}
		if current.ContainerID == "" {
			break
		}
		container := i.symbols[current.ContainerID]
		if container == nil {
			break
		}
		current = *container
	}
	var result strings.Builder
	changed := false
	for index := 0; index < len(typ); {
		r, size := utf8.DecodeRuneInString(typ[index:])
		if !isIdentRune(r) {
			result.WriteString(typ[index : index+size])
			index += size
			continue
		}
		end := index + size
		for end < len(typ) {
			r, size = utf8.DecodeRuneInString(typ[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := typ[index:end]
		replacement := ""
		if !typeParameters[word] && !respellKeyword(word) && !adjacentToDot(typ, index, end) {
			first, _ := utf8.DecodeRuneInString(word)
			if unicode.IsUpper(first) {
				if declaringAccess == nil {
					declaringAccess = newAccessibilityMemoLocked(i, declaringFile)
					usingAccess = newAccessibilityMemoLocked(i, file)
				}
				replacement = i.respellNameLocked(file, declaringFile, declaration, word, declaringAccess, usingAccess)
			}
		}
		if replacement != "" {
			result.WriteString(replacement)
			changed = true
		} else {
			result.WriteString(word)
		}
		index = end
	}
	if !changed {
		return typ
	}
	return result.String()
}

// respellNameLocked returns the qualified spelling `file` needs for `word` as
// the declaring file meant it, or "" when the spelling can stay.
func (i *Index) respellNameLocked(file, declaringFile *analysis.ParsedFile, declaration analysis.Symbol, word string, declaringAccess, usingAccess *accessibilityMemo) string {
	meant := i.resolveTypeSymbolsForOwnerMemoLocked(declaringFile, word, declaration, declaringAccess, declaration.StartByte)
	if len(meant) != 1 || meant[0].FQN == "" || meant[0].FQN == word {
		return ""
	}
	read := i.resolveTypeSymbolsForOwnerMemoLocked(file, word, analysis.Symbol{}, usingAccess)
	if len(read) == 1 && read[0].ID == meant[0].ID {
		return ""
	}
	// The qualified name must lead back to exactly the declaration meant,
	// otherwise the rewrite would trade one unresolvable spelling for another.
	for _, id := range i.byFQN[meant[0].FQN] {
		if id == meant[0].ID {
			return meant[0].FQN
		}
	}
	return ""
}

func respellKeyword(word string) bool {
	switch word {
	case "in", "out", "super", "extends", "suspend", "dynamic", "reified", "vararg", "final", "static", "public", "private", "protected":
		return true
	}
	return false
}

// adjacentToDot reports whether the identifier at [start,end) is a segment of
// a dotted name; those are already qualified or nested paths and keep their
// spelling.
func adjacentToDot(value string, start, end int) bool {
	for cursor := start - 1; cursor >= 0; cursor-- {
		if value[cursor] == ' ' {
			continue
		}
		if value[cursor] == '.' {
			return true
		}
		break
	}
	for cursor := end; cursor < len(value); cursor++ {
		if value[cursor] == ' ' {
			continue
		}
		if value[cursor] == '.' {
			return true
		}
		break
	}
	return false
}
