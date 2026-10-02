package index

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

func (i *Index) WorkspaceSymbols(query string, limit int) []analysis.Symbol {
	return i.WorkspaceSymbolsContext(context.Background(), query, limit)
}

func (i *Index) WorkspaceSymbolsContext(ctx context.Context, query string, limit int) []analysis.Symbol {
	values, _ := i.WorkspaceSymbolsBoundedContext(ctx, query, limit)
	return values
}

// WorkspaceSymbolsBoundedContext reports whether candidate work was cut off;
// protocol callers can then return an explicit safety-limit response rather
// than silently presenting a truncated list as complete.
func (i *Index) WorkspaceSymbolsBoundedContext(ctx context.Context, query string, limit int) ([]analysis.Symbol, bool) {
	guard := i.lockGuard()
	defer guard.release()
	if ctx == nil {
		ctx = context.Background()
	}
	if len(query) > 4096 {
		return nil, true
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	limited := limit > 0
	q := strings.ToLower(query)
	type scored struct {
		s     analysis.Symbol
		score int
	}
	var all []scored
	truncated := false
	if q == "" {
		// An empty query means "browse", and every candidate matches it
		// equally. Scoring and ranking the whole workspace to answer it cost
		// 113 ms and 17 MiB per request; a bounded slice answers the same
		// question inside the interaction budget.
		out := make([]analysis.Symbol, 0, limit)
		guard.RLock()
		for _, name := range i.workspaceIndex.allNames() {
			if ctx.Err() != nil {
				guard.RUnlock()
				return nil, true
			}
			for _, id := range i.workspaceIndex.get(name) {
				symbol, ok := i.symbols[id]
				if !ok {
					continue
				}
				out = append(out, *symbol)
				if len(out) >= limit {
					guard.RUnlock()
					sortSymbols(out)
					return out, true
				}
			}
		}
		guard.RUnlock()
		sortSymbols(out)
		return out, false
	}
	guard.RLock()
	names := i.workspaceIndex.allNames()
	if len(q) > 0 && q[0] < 128 {
		// Fuzzy queries may match after the first character (e.g. "NPE" ->
		// NullPointerException), so use the any-position character bucket.
		names = i.workspaceIndex.charBucket(q[0])
	}
	// Score a name before collecting its symbols. Collecting first and scoring
	// afterwards spent the entire candidate budget on names that do not match
	// at all -- every name in one letter's bucket -- so an ordinary query over
	// a Spring dependency graph (here 57k library symbols) was refused as too
	// broad before a single match had been considered.
	matchLimit := limit * 8
	for _, name := range names {
		if ctx.Err() != nil {
			guard.RUnlock()
			return nil, true
		}
		if limited && len(all) >= matchLimit {
			truncated = true
			break
		}
		score := symbolNameScore(name, query)
		if score < 0 {
			continue
		}
		for _, id := range i.workspaceIndex.get(name) {
			symbol, ok := i.symbols[id]
			if !ok {
				continue
			}
			all = append(all, scored{*symbol, score + symbolKindScore(*symbol)})
			if limited && len(all) >= matchLimit {
				truncated = true
				break
			}
		}
	}
	guard.RUnlock()
	sort.SliceStable(all, func(a, b int) bool {
		if all[a].score == all[b].score {
			return all[a].s.FQN < all[b].s.FQN
		}
		return all[a].score > all[b].score
	})
	if limited && len(all) > limit {
		truncated = true
		all = all[:limit]
	}
	out := make([]analysis.Symbol, len(all))
	for n := range all {
		out[n] = all[n].s
	}
	return out, truncated
}

func isWorkspaceSymbol(symbol analysis.Symbol) bool {
	// A primary constructor is its class's header, found as the class.
	if symbol.Synthetic || symbol.Kind == analysis.KindConstructor && containsString(symbol.Modifiers, "primary-constructor") {
		return false
	}
	if symbol.Library && symbol.InteropLanguage == analysis.LanguageJava {
		return false
	}
	switch symbol.Kind {
	case analysis.KindParameter, analysis.KindVariable, analysis.KindTypeParameter:
		return false
	default:
		return true
	}
}

// symbolNameScore ranks a declaration name against a query the way an IDE's
// "go to symbol" does: exact, then prefix (case-sensitive first), then
// camel humps (`CSI` is ColorsServiceImpl), then a plain substring. A loose
// subsequence is no match: it answered `ColorsServ` with test names that
// merely contain those letters somewhere.
func symbolNameScore(name, query string) int {
	if query == "" {
		return 0
	}
	lowerName, lowerQuery := strings.ToLower(name), strings.ToLower(query)
	switch {
	case name == query:
		return 2000
	case lowerName == lowerQuery:
		return 1800
	case strings.HasPrefix(name, query):
		return 1500 - min(len(name), 400)
	case strings.HasPrefix(lowerName, lowerQuery) && !innerUpper(query):
		return 1300 - min(len(name), 400)
	case camelHumpsMatch(name, query):
		return 1000 - min(len(name), 400)
	case strings.HasPrefix(lowerName, lowerQuery):
		// `CSI` written in capitals asks for humps; `csize` only shares
		// the letters.
		return 800 - min(len(name), 400)
	}
	if at := strings.Index(lowerName, lowerQuery); at >= 0 && len(query) >= 3 {
		return 600 - min(at, 100) - min(len(name), 400)
	}
	return -1
}

// camelHumpsMatch reports whether each query character starts a word of name,
// or continues the word the previous one matched: `CoSI`, `CSImpl`.
func camelHumpsMatch(name, query string) bool {
	if query == "" || name == "" || unicode.ToLower(rune(query[0])) != unicode.ToLower(rune(name[0])) {
		return false
	}
	position := 1
	for _, r := range query[1:] {
		matched := false
		// A lowercase letter continues the current word; a capital may also
		// start the next one.
		if position < len(name) && unicode.ToLower(rune(name[position])) == unicode.ToLower(r) && (!unicode.IsUpper(r) || rune(name[position]) == r) {
			position++
			matched = true
		} else if !unicode.IsUpper(r) {
			return false
		} else {
			for next := position; next < len(name); next++ {
				c := rune(name[next])
				wordStart := unicode.IsUpper(c) || next > 0 && (name[next-1] == '_' || name[next-1] == ' ')
				if wordStart && unicode.ToLower(c) == unicode.ToLower(r) {
					position = next + 1
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// symbolKindScore orders equally good names: the project's own declarations
// before a library's, types before functions before properties.
func symbolKindScore(symbol analysis.Symbol) int {
	score := 0
	switch {
	case analysis.IsTypeKind(symbol.Kind):
		score += 60
	case analysis.IsCallableKind(symbol.Kind):
		score += 30
	}
	if !symbol.Library {
		score += 80
	}
	return score
}

func innerUpper(query string) bool {
	for index, r := range query {
		if index > 0 && unicode.IsUpper(r) {
			return true
		}
	}
	return false
}
