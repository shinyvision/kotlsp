package index

import (
	"context"
	"sort"
	"strings"

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
	i.mu.RLock()
	if ids := i.workspaceIndex.get(query); len(ids) > 0 {
		candidateLimit := limit * 8
		if candidateLimit < limit {
			candidateLimit = limit
		}
		exact := make([]analysis.Symbol, 0, min(len(ids), candidateLimit))
		for index, id := range ids {
			if ctx.Err() != nil {
				i.mu.RUnlock()
				return nil, true
			}
			if index >= candidateLimit {
				truncated = true
				break
			}
			if symbol, ok := i.symbols[id]; ok {
				exact = append(exact, *symbol)
			}
		}
		i.mu.RUnlock()
		sortSymbols(exact)
		if limited && len(exact) > limit {
			truncated = true
			exact = exact[:limit]
		}
		return exact, truncated
	}
	names := i.workspaceIndex.allNames()
	if len(q) > 0 && q[0] < 128 {
		// Fuzzy queries may match after the first character (e.g. "NPE" ->
		// NullPointerException), so use the any-position character bucket.
		names = i.workspaceIndex.charBucket(q[0])
	}
	type nameSnapshot struct {
		name    string
		symbols []analysis.Symbol
	}
	snapshots := make([]nameSnapshot, 0, min(len(names), limit*8))
	snapshotCount := 0
	for _, name := range names {
		if ctx.Err() != nil {
			i.mu.RUnlock()
			return nil, true
		}
		if limited && snapshotCount >= limit*8 {
			truncated = true
			break
		}
		ids := i.workspaceIndex.get(name)
		if len(ids) == 0 {
			continue
		}
		snapshot := nameSnapshot{name: name, symbols: make([]analysis.Symbol, 0, len(ids))}
		for _, id := range ids {
			if symbol, ok := i.symbols[id]; ok {
				snapshot.symbols = append(snapshot.symbols, *symbol)
			}
			if limited && snapshotCount+len(snapshot.symbols) >= limit*8 {
				break
			}
		}
		if len(snapshot.symbols) > 0 {
			snapshotCount += len(snapshot.symbols)
			snapshots = append(snapshots, snapshot)
		}
	}
	i.mu.RUnlock()
	for _, snapshot := range snapshots {
		if ctx.Err() != nil {
			return nil, true
		}
		score := fuzzyScore(strings.ToLower(snapshot.name), q)
		if score < 0 {
			continue
		}
		for _, symbol := range snapshot.symbols {
			all = append(all, scored{symbol, score})
			if limited && len(all) >= limit*8 {
				break
			}
		}
		if limited && len(all) >= limit*8 {
			break
		}
	}
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
