package index

import (
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

func (i *Index) WorkspaceSymbols(query string, limit int) []analysis.Symbol {
	limited := limit > 0
	q := strings.ToLower(query)
	type scored struct {
		s     analysis.Symbol
		score int
	}
	var all []scored
	i.mu.RLock()
	if ids := i.workspaceIndex.get(query); len(ids) > 0 {
		exact := make([]analysis.Symbol, 0, len(ids))
		for _, id := range ids {
			if symbol, ok := i.symbols[id]; ok {
				exact = append(exact, *symbol)
			}
		}
		i.mu.RUnlock()
		sortSymbols(exact)
		if limited && len(exact) > limit {
			exact = exact[:limit]
		}
		return exact
	}
	names := i.workspaceIndex.allNames()
	if len(q) > 0 && q[0] < 128 {
		// Fuzzy queries may match after the first character (e.g. "NPE" ->
		// NullPointerException), so use the any-position character bucket.
		names = i.workspaceIndex.charBucket(q[0])
	}
	for _, name := range names {
		if limited && len(all) >= limit*8 {
			break
		}
		if len(i.workspaceIndex.get(name)) == 0 {
			continue
		}
		score := fuzzyScore(strings.ToLower(name), q)
		if score >= 0 {
			ids := i.workspaceIndex.get(name)
			for _, id := range ids {
				if symbol, ok := i.symbols[id]; ok {
					all = append(all, scored{*symbol, score})
				}
				if limited && len(all) >= limit*8 {
					break
				}
			}
		}
	}
	i.mu.RUnlock()
	sort.SliceStable(all, func(a, b int) bool {
		if all[a].score == all[b].score {
			return all[a].s.FQN < all[b].s.FQN
		}
		return all[a].score > all[b].score
	})
	if limited && len(all) > limit {
		all = all[:limit]
	}
	out := make([]analysis.Symbol, len(all))
	for n := range all {
		out[n] = all[n].s
	}
	return out
}

func isWorkspaceSymbol(symbol analysis.Symbol) bool {
	if symbol.Synthetic {
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

func fuzzyScore(candidate, query string) int {
	if query == "" {
		return 0
	}
	if candidate == query {
		return 1000
	}
	if strings.HasPrefix(candidate, query) {
		return 800 - len(candidate)
	}
	score, pos := 0, 0
	for _, r := range query {
		idx := strings.IndexRune(candidate[pos:], r)
		if idx < 0 {
			return -1
		}
		score += 10 - idx
		pos += idx + 1
	}
	return score
}
