package index

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

type cursorSpan struct {
	start, end int
	index      int
	symbol     bool
}

type semanticTokenCacheEntry struct {
	textHash           uint64
	resultID           uint64
	environmentVersion uint64
	tokens             []analysis.Token
	symbolVersions     map[string]uint64
	nameVersions       map[string]uint64
}

func buildCursorSpans(file *analysis.ParsedFile) []cursorSpan {
	if file == nil {
		return nil
	}
	spans := make([]cursorSpan, 0, len(file.Symbols)+len(file.References))
	for index, symbol := range file.Symbols {
		if symbol.NameEndByte > symbol.NameStartByte {
			spans = append(spans, cursorSpan{start: symbol.NameStartByte, end: symbol.NameEndByte, index: index, symbol: true})
		}
	}
	for index, reference := range file.References {
		if reference.EndByte > reference.StartByte {
			spans = append(spans, cursorSpan{start: reference.StartByte, end: reference.EndByte, index: index})
		}
	}
	// cursorSpanLocked walks this slice backwards from the cursor, so the
	// preferred span among equal ranges must sort last: a declaration beats a
	// reference, and among references (several convention references share one
	// operator range) the earlier one in file order wins, as it always has.
	sort.SliceStable(spans, func(left, right int) bool {
		if spans[left].start == spans[right].start {
			if spans[left].end == spans[right].end {
				if spans[left].symbol != spans[right].symbol {
					return spans[right].symbol
				}
				return spans[left].index > spans[right].index
			}
			return spans[left].end < spans[right].end
		}
		return spans[left].start < spans[right].start
	})
	return spans
}

func (i *Index) cursorSpanLocked(ctx context.Context, file *analysis.ParsedFile, offset int, includeEnd bool) (analysis.Symbol, *analysis.Reference, bool) {
	spans := i.fileCursorSpans[file.URI]
	position := sort.Search(len(spans), func(index int) bool { return spans[index].start > offset })
	for index := position - 1; index >= 0; index-- {
		span := spans[index]
		inside := offset >= span.start && (offset < span.end || includeEnd && offset == span.end)
		if !inside {
			if span.end < offset || !includeEnd && span.end == offset {
				break
			}
			continue
		}
		if span.symbol {
			return file.Symbols[span.index], nil, true
		}
		reference := &file.References[span.index]
		resolved := i.resolveContextLocked(ctx, file, *reference)
		if len(resolved) == 1 {
			return resolved[0], reference, true
		}
		if len(resolved) > 1 {
			// Preserve the reference so definition can expose every legitimate
			// target, but do not manufacture one identity for hover or rename.
			return analysis.Symbol{}, reference, true
		}
	}
	return analysis.Symbol{}, nil, false
}

func (i *Index) SymbolAt(uri protocol.URI, pos protocol.Position) (analysis.Symbol, *analysis.Reference, bool) {
	return i.SymbolAtContext(context.Background(), uri, pos)
}

func (i *Index) SymbolAtContext(ctx context.Context, uri protocol.URI, pos protocol.Position) (analysis.Symbol, *analysis.Reference, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return analysis.Symbol{}, nil, false
	}
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return analysis.Symbol{}, nil, false
	}
	i.ensureLibraryReferencesContext(ctx, uri, doc)
	if ctx.Err() != nil {
		return analysis.Symbol{}, nil, false
	}
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return analysis.Symbol{}, nil, false
	}
	if symbol, reference, found := i.cursorSpanLocked(ctx, file, offset, false); found {
		if symbol.ID == "" {
			return analysis.Symbol{}, reference, false
		}
		return symbol, reference, true
	}
	// Editors commonly place the cursor immediately after an identifier. Keep
	// that convenience only as a fallback, after testing the end-exclusive LSP
	// ranges so adjacent punctuation conventions such as box[0] win.
	symbol, reference, found := i.cursorSpanLocked(ctx, file, offset, true)
	if !found || symbol.ID == "" {
		return analysis.Symbol{}, reference, false
	}
	return symbol, reference, true
}

func (i *Index) Definitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	return i.DefinitionsContext(context.Background(), uri, pos)
}

func (i *Index) DefinitionsContext(ctx context.Context, uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	if ctx == nil {
		ctx = context.Background()
	}
	// Dependency archives land transactionally in priority order. A definition
	// request can race the final few milliseconds before the needed archive is
	// published; returning an empty result at that instant makes identical `gd`
	// commands appear random. Retry only on actual publication events and only
	// during cold semantic warm-up. Eight seconds covers central-directory
	// inventory plus the workspace's directly imported archives without tying a
	// request to the complete classpath scan.
	warmup := time.NewTimer(8 * time.Second)
	defer warmup.Stop()
	for {
		progress := i.semanticProgressSignal()
		definitions := i.definitionsOnceContext(ctx, uri, pos)
		if len(definitions) > 0 || ctx.Err() != nil || i.generation.Load() == 0 || i.Progress().Ready || i.closed.Load() {
			return definitions
		}
		// Close may have raced the readiness sample above. Observe it again before
		// sleeping so shutdown is never held for the warm-up allowance.
		if i.closed.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-warmup.C:
			return nil
		case <-progress:
		}
	}
}

func (i *Index) definitionsOnceContext(ctx context.Context, uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil
	}
	i.ensureLibraryReferencesContext(ctx, uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	if resolved, handled := i.springDataDefinitionLocked(file, offset); handled {
		if ctx.Err() != nil {
			return nil
		}
		return resolved
	}
	for _, includeEnd := range []bool{false, true} {
		if symbol, reference, found := i.cursorSpanLocked(ctx, file, offset, includeEnd); found {
			if ctx.Err() != nil {
				return nil
			}
			if reference == nil {
				return []analysis.Symbol{symbol}
			}
			return i.resolveContextLocked(ctx, file, *reference)
		}
	}
	return nil
}

// CallSignatures returns the complete overload family and the best active
// signature at a call site. Constructor navigation intentionally targets the
// class, while signature help exposes all constructors and selects one.
func (i *Index) CallSignatures(uri protocol.URI, pos protocol.Position) ([]analysis.Symbol, int) {
	return i.CallSignaturesContext(context.Background(), uri, pos)
}

func (i *Index) CallSignaturesContext(ctx context.Context, uri protocol.URI, pos protocol.Position) ([]analysis.Symbol, int) {
	if ctx.Err() != nil {
		return nil, 0
	}
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil, 0
	}
	i.ensureLibraryReferencesContext(ctx, uri, doc)
	offset := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil, 0
	}
	access := newAccessibilityMemoLocked(i, file)
	var reference *analysis.Reference
	for index := range file.References {
		if index&255 == 0 && ctx.Err() != nil {
			return nil, 0
		}
		candidate := &file.References[index]
		if candidate.Role == analysis.RoleCall && (candidate.StartByte <= offset && offset <= candidate.EndByte) {
			reference = candidate
			break
		}
	}
	if reference == nil {
		return nil, 0
	}
	resolved := i.resolveContextLocked(ctx, file, *reference)
	candidates := make([]analysis.Symbol, 0, len(resolved)+2)
	seen := make(map[string]bool)
	appendCandidate := func(symbol *analysis.Symbol) {
		if symbol != nil && analysis.IsCallableKind(symbol.Kind) && i.accessibleWithMemoLocked(file, *symbol, access, reference.StartByte) && !seen[symbol.ID] {
			seen[symbol.ID] = true
			candidates = append(candidates, *symbol)
		}
	}
	for _, symbol := range resolved {
		if ctx.Err() != nil {
			return nil, 0
		}
		if analysis.IsTypeKind(symbol.Kind) {
			bucket := i.byContainerMember[memberKey(symbol.ID, symbol.Name)]
			if len(bucket) > maxResolutionCandidates {
				return nil, 0
			}
			for _, id := range bucket {
				constructor := i.symbols[id]
				if constructor != nil && constructor.Kind == analysis.KindConstructor && constructor.ContainerID == symbol.ID {
					appendCandidate(constructor)
				}
			}
			continue
		}
		if !analysis.IsCallableKind(symbol.Kind) {
			continue
		}
		if symbol.ContainerID != "" {
			bucket := i.byContainerMember[memberKey(symbol.ContainerID, symbol.Name)]
			if len(bucket) > maxResolutionCandidates {
				return nil, 0
			}
			for _, id := range bucket {
				candidate := i.symbols[id]
				if candidate != nil && candidate.ContainerID == symbol.ContainerID && candidate.Kind == symbol.Kind {
					appendCandidate(candidate)
				}
			}
		} else if symbol.FQN != "" {
			bucket := i.byFQN[symbol.FQN]
			if len(bucket) > maxResolutionCandidates {
				return nil, 0
			}
			for _, id := range bucket {
				appendCandidate(i.symbols[id])
			}
		} else {
			appendCandidate(i.symbols[symbol.ID])
		}
		if len(candidates) > maxResolutionCandidates {
			return nil, 0
		}
	}
	if len(candidates) == 0 {
		return nil, 0
	}
	sortSymbols(candidates)
	active := 0
	scores := make([]int, len(candidates))
	best, typed := -1<<30, false
	for index, candidate := range candidates {
		if ctx.Err() != nil {
			return nil, 0
		}
		score, hasTypes := i.callCompatibilityLocked(file, *reference, candidate)
		scores[index] = score
		if hasTypes && score > -1<<19 {
			if !typed || score > best {
				typed = true
				best = score
				active = index
			}
		}
	}
	if !typed {
		for index, score := range scores {
			if score <= -1<<19 {
				candidates[index] = analysis.Symbol{}
			}
		}
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if candidate.ID != "" {
				filtered = append(filtered, candidate)
			}
		}
		candidates = filtered
		if len(candidates) == 0 {
			return nil, 0
		}
		if len(candidates) == 1 {
			return candidates, 0
		}
		// All remaining candidates lack type evidence. Preserve the overload
		// family but do not pretend a score proves one active alternative.
		active = 0
	}
	return candidates, active
}

// CallablesNamed is the bounded, by-name fallback for latency-sensitive
// editor features. Unlike WorkspaceSymbols it never performs fuzzy-name
// enumeration: the exact symbol bucket is the complete work set.
func (i *Index) CallablesNamed(uri protocol.URI, pos protocol.Position, name string, limit int) []analysis.Symbol {
	return i.CallablesNamedContext(context.Background(), uri, pos, name, limit)
}

func (i *Index) CallablesNamedContext(ctx context.Context, uri protocol.URI, pos protocol.Position, name string, limit int) []analysis.Symbol {
	if name == "" {
		return nil
	}
	if limit <= 0 || limit > 64 {
		limit = 64
	}
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil
	}
	at := doc.Offset(pos)
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	access := newAccessibilityMemoLocked(i, file)
	bucket := i.byName[name]
	if len(bucket) > maxResolutionCandidates {
		i.recordHealth("signature-help", name, "exact-name callable inventory exceeded its 512-symbol safety limit and was withheld")
		return nil
	}
	out := make([]analysis.Symbol, 0, len(bucket))
	for _, id := range bucket {
		if ctx.Err() != nil {
			return nil
		}
		symbol := i.symbols[id]
		if symbol == nil || !analysis.IsCallableKind(symbol.Kind) || !i.accessibleWithMemoLocked(file, *symbol, access, at) {
			continue
		}
		out = append(out, *symbol)
		if len(out) > limit {
			i.recordHealth("signature-help", name, "applicable callable family exceeded the response limit and was withheld rather than truncated")
			return nil
		}
	}
	sortSymbols(out)
	return out
}

// PackageDefinitions mirrors IntelliJ's Java/Kotlin package providers: a
// package reference navigates to each workspace directory containing files in
// that exact package. Library packages are deliberately excluded.
func (i *Index) PackageDefinitions(uri protocol.URI, pos protocol.Position) []protocol.Location {
	return i.PackageDefinitionsContext(context.Background(), uri, pos)
}

func (i *Index) PackageDefinitionsContext(ctx context.Context, uri protocol.URI, pos protocol.Position) []protocol.Location {
	doc, ok := i.DocumentContext(ctx, uri)
	if !ok {
		return nil
	}
	offset := doc.Offset(pos)
	start := strings.LastIndexByte(doc.Text[:offset], '\n') + 1
	end := len(doc.Text)
	if newline := strings.IndexByte(doc.Text[offset:], '\n'); newline >= 0 {
		end = offset + newline
	}
	line := doc.Text[start:end]
	trimmed := strings.TrimLeft(line, " \t")
	indent := len(line) - len(trimmed)
	keyword := ""
	switch {
	case strings.HasPrefix(trimmed, "package "):
		keyword = "package"
	case strings.HasPrefix(trimmed, "import "):
		keyword = "import"
	default:
		return nil
	}
	qualifiedStart := indent + len(keyword)
	for qualifiedStart < len(line) && (line[qualifiedStart] == ' ' || line[qualifiedStart] == '\t') {
		qualifiedStart++
	}
	if keyword == "import" && strings.HasPrefix(line[qualifiedStart:], "static ") {
		qualifiedStart += len("static ")
	}
	relative := offset - start
	if relative < qualifiedStart || relative > len(line) {
		return nil
	}
	if relative == len(line) || relative > qualifiedStart && !isIdentRune(rune(line[relative])) {
		relative--
	}
	if relative < qualifiedStart || !isIdentRune(rune(line[relative])) {
		return nil
	}
	tokenEnd := relative + 1
	for tokenEnd < len(line) && isIdentRune(rune(line[tokenEnd])) {
		tokenEnd++
	}
	qualified := strings.ReplaceAll(strings.Trim(line[qualifiedStart:tokenEnd], "."), "`", "")
	i.mu.RLock()
	if len(i.packages[qualified]) > maxResolutionCandidates {
		i.mu.RUnlock()
		i.recordHealth("package-definition", qualified, "package directory inventory exceeded its 512-location safety limit and was withheld")
		return nil
	}
	directories := append([]protocol.URI(nil), i.packages[qualified]...)
	i.mu.RUnlock()
	locations := make([]protocol.Location, 0, len(directories))
	for index, directory := range directories {
		if index&31 == 0 && ctx.Err() != nil {
			return nil
		}
		locations = append(locations, protocol.Location{URI: directory, Range: protocol.Range{}})
	}
	return locations
}

func (i *Index) TypeDefinitions(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	return i.TypeDefinitionsContext(context.Background(), uri, pos)
}

func (i *Index) TypeDefinitionsContext(ctx context.Context, uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}
	s, _, ok := i.SymbolAtContext(ctx, uri, pos)
	if !ok {
		return nil
	}
	if analysis.IsTypeKind(s.Kind) {
		return []analysis.Symbol{s}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[s.URI]
	if file == nil {
		return nil
	}
	typ := s.Type
	if typ == "" || typ == "var" || typ == "val" {
		typ = i.inferExpressionTypeLocked(file, s.Initializer, s.StartByte)
	}
	if typ == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	return i.resolveTypeSymbolsForOwnerLocked(file, typ, s)
}

func (i *Index) Implementations(uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	return i.ImplementationsContext(context.Background(), uri, pos)
}

func (i *Index) ImplementationsContext(ctx context.Context, uri protocol.URI, pos protocol.Position) []analysis.Symbol {
	const maxImplementationFamily = 4096
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}
	target, _, ok := i.SymbolAtContext(ctx, uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []analysis.Symbol
	if containsString(target.Modifiers, "expect") || i.containerHasKotlinModifierLocked(target, "expect") {
		for _, counterpart := range i.expectActualFamilyLocked(target) {
			if ctx.Err() != nil {
				return nil
			}
			if counterpart.ID != target.ID && (containsString(counterpart.Modifiers, "actual") || i.containerHasKotlinModifierLocked(counterpart, "actual")) {
				out = append(out, counterpart)
			}
		}
	}
	if analysis.IsTypeKind(target.Kind) {
		queue := []analysis.Symbol{target}
		seen := map[string]bool{}
		for len(queue) > 0 {
			if ctx.Err() != nil {
				return nil
			}
			parent := queue[0]
			queue = queue[1:]
			bucket := i.bySuperID[parent.ID]
			if len(bucket) > maxImplementationFamily-len(seen) {
				return nil
			}
			ids := append([]string(nil), bucket...)
			for _, id := range ids {
				if ctx.Err() != nil {
					return nil
				}
				if seen[id] {
					continue
				}
				if candidate, ok := i.symbols[id]; ok {
					if !i.directSupertypeMatchesLocked(*candidate, parent.ID) {
						continue
					}
					seen[id] = true
					out = append(out, *candidate)
					queue = append(queue, *candidate)
					if len(out) > maxImplementationFamily || len(queue) > maxImplementationFamily {
						return nil
					}
				}
			}
		}
	}
	if analysis.IsCallableKind(target.Kind) {
		bucket := i.byName[target.Name]
		if len(bucket) > maxImplementationFamily {
			return nil
		}
		for _, id := range bucket {
			if ctx.Err() != nil {
				return nil
			}
			candidate, ok := i.symbols[id]
			if ok && analysis.IsCallableKind(candidate.Kind) && sameCallableShape(*candidate, target) && candidate.ContainerID != target.ContainerID && i.containerInheritsLocked(candidate.ContainerID, target.ContainerID) {
				out = append(out, *candidate)
				if len(out) > maxImplementationFamily {
					return nil
				}
			}
		}
	}
	sortSymbols(out)
	return out
}

func (i *Index) References(uri protocol.URI, pos protocol.Position, includeDeclaration bool) []protocol.Location {
	return i.ReferencesContext(context.Background(), uri, pos, includeDeclaration)
}

func (i *Index) ReferencesContext(ctx context.Context, uri protocol.URI, pos protocol.Position, includeDeclaration bool) []protocol.Location {
	const (
		maxUnresolvedReferenceFallback = 4096
		maxReferenceCandidates         = 50_000
	)
	if ctx.Err() != nil {
		return nil
	}
	target, _, ok := i.SymbolAtContext(ctx, uri, pos)
	if !ok {
		return nil
	}
	i.mu.RLock()
	family := i.referenceFamilyLocked(target)
	if len(family) == 0 {
		i.mu.RUnlock()
		i.recordHealth("references", target.Name, "reference identity family exceeded its safety limit and was withheld")
		return nil
	}
	semanticVersion := i.semanticVersion
	environmentVersion := i.semanticEnvironmentVersion
	type referenceWork struct {
		member     analysis.Symbol
		direct     []analysis.Reference
		unresolved []analysis.Reference
	}
	work := make([]referenceWork, 0, len(family))
	referenceFiles := make(map[protocol.URI]*analysis.ParsedFile)
	totalCandidates := 0
	for _, member := range family {
		unresolved := append([]analysis.Reference(nil), i.unresolvedRefsByName[member.Name]...)
		if len(unresolved) > maxUnresolvedReferenceFallback {
			i.mu.RUnlock()
			i.recordHealth("references", member.Name, "unresolved reference fallback exceeded 4096 candidates and was withheld")
			return nil
		}
		direct := append([]analysis.Reference(nil), i.refsByTarget[member.ID]...)
		totalCandidates += len(direct) + len(unresolved)
		if totalCandidates > maxReferenceCandidates {
			i.mu.RUnlock()
			i.recordHealth("references", target.Name, "reference set exceeded its 50000-candidate safety limit and was withheld")
			return nil
		}
		work = append(work, referenceWork{
			member: member, direct: direct,
			unresolved: unresolved,
		})
		for _, reference := range unresolved {
			referenceFiles[reference.URI] = i.files[reference.URI]
		}
	}
	i.mu.RUnlock()
	out := make([]protocol.Location, 0)
	if includeDeclaration {
		for _, member := range family {
			out = append(out, member.Location())
		}
	}
	for _, item := range work {
		member := item.member
		if ctx.Err() != nil {
			return nil
		}
		for _, r := range item.direct {
			out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
		}
		unresolved := item.unresolved
		for start := 0; start < len(unresolved); start += 128 {
			if ctx.Err() != nil {
				return nil
			}
			end := min(start+128, len(unresolved))
			i.mu.RLock()
			if i.semanticVersion != semanticVersion || i.semanticEnvironmentVersion != environmentVersion {
				i.mu.RUnlock()
				return nil
			}
			for _, r := range unresolved[start:end] {
				file := referenceFiles[r.URI]
				if i.files[r.URI] != file {
					i.mu.RUnlock()
					return nil
				}
				if file == nil {
					continue
				}
				resolved := i.resolveContextLocked(ctx, file, r)
				for _, s := range resolved {
					if s.ID == member.ID {
						out = append(out, protocol.Location{URI: r.URI, Range: r.Range})
						break
					}
				}
			}
			i.mu.RUnlock()
		}
	}
	return uniqueLocations(out)
}

func (i *Index) referenceFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	const maxReferenceFamily = 4096
	origin := target
	if target.OriginID != "" {
		if value, ok := i.symbols[target.OriginID]; ok {
			origin = *value
		}
	}
	family := []analysis.Symbol{origin}
	if len(i.byOrigin[origin.ID]) > maxReferenceFamily {
		return nil
	}
	for _, id := range i.byOrigin[origin.ID] {
		if symbol, ok := i.symbols[id]; ok {
			family = append(family, *symbol)
		}
	}
	if len(family) > maxReferenceFamily || origin.FQN != "" && len(i.byFQN[origin.FQN]) > maxReferenceFamily {
		return nil
	}
	for _, counterpart := range i.expectActualFamilyLocked(origin) {
		if counterpart.ID != origin.ID {
			family = append(family, counterpart)
			if len(i.byOrigin[counterpart.ID]) > maxReferenceFamily {
				return nil
			}
			for _, id := range i.byOrigin[counterpart.ID] {
				if symbol, ok := i.symbols[id]; ok {
					family = append(family, *symbol)
				}
			}
			if len(family) > maxReferenceFamily {
				return nil
			}
		}
	}
	if analysis.IsCallableKind(origin.Kind) && origin.ContainerID != "" {
		if len(i.byName[origin.Name]) > 50_000 {
			return nil
		}
		for _, id := range i.byName[origin.Name] {
			candidate, ok := i.symbols[id]
			if !ok || candidate.ID == origin.ID || candidate.ContainerID == "" || !analysis.IsCallableKind(candidate.Kind) || !sameCallableShape(*candidate, origin) {
				continue
			}
			if i.containerInheritsLocked(candidate.ContainerID, origin.ContainerID) || i.containerInheritsLocked(origin.ContainerID, candidate.ContainerID) {
				family = append(family, *candidate)
				if len(family) > maxReferenceFamily {
					return nil
				}
			}
		}
	}
	property, bean := beanPropertyName(origin.Name)
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		property, bean = origin.Name, true
	}
	if bean && origin.ContainerID != "" {
		propertyType := strings.TrimSpace(origin.Type)
		if strings.HasPrefix(origin.Name, "set") && len(origin.Parameters) == 1 {
			propertyType = strings.TrimSpace(origin.Parameters[0].Type)
		}
		originStatic := containsString(origin.Modifiers, "static")
		stem := property
		if stem != "" && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		beanCandidates := make([]analysis.Symbol, 0, 4)
		compatibleSetters := 0
		for _, name := range []string{property, "get" + stem, "is" + stem, "set" + stem} {
			ids := i.byContainerMember[memberKey(origin.ContainerID, name)]
			if len(ids) > maxReferenceFamily {
				return nil
			}
			for _, id := range ids {
				candidate := i.symbols[id]
				if candidate == nil || candidate.ContainerID != origin.ContainerID || containsString(candidate.Modifiers, "static") != originStatic {
					continue
				}
				candidateType, compatible := strings.TrimSpace(candidate.Type), false
				switch {
				case candidate.Kind == analysis.KindProperty:
					compatible = candidateType == propertyType
				case strings.HasPrefix(candidate.Name, "set") && len(candidate.Parameters) == 1:
					compatible = strings.TrimSpace(candidate.Parameters[0].Type) == propertyType
					if compatible {
						compatibleSetters++
					}
				case (strings.HasPrefix(candidate.Name, "get") || strings.HasPrefix(candidate.Name, "is")) && len(candidate.Parameters) == 0:
					compatible = candidateType == propertyType
				}
				if compatible {
					beanCandidates = append(beanCandidates, *candidate)
				}
			}
		}
		if compatibleSetters <= 1 {
			family = append(family, beanCandidates...)
			if len(family) > maxReferenceFamily {
				return nil
			}
		}
	}
	return uniqueSymbols(family)
}

func (i *Index) expectActualFamilyLocked(target analysis.Symbol) []analysis.Symbol {
	if target.Language != analysis.LanguageKotlin || target.FQN == "" {
		return nil
	}
	targetMarked := containsString(target.Modifiers, "expect") || containsString(target.Modifiers, "actual")
	if !targetMarked && target.ContainerID != "" {
		targetMarked = i.containerHasKotlinModifierLocked(target, "expect") || i.containerHasKotlinModifierLocked(target, "actual")
	}
	if !targetMarked {
		return nil
	}
	targetExpect := containsString(target.Modifiers, "expect") || i.containerHasKotlinModifierLocked(target, "expect")
	targetActual := containsString(target.Modifiers, "actual") || i.containerHasKotlinModifierLocked(target, "actual")
	targetModule := i.moduleForURILocked(target.URI)
	result := []analysis.Symbol{target}
	if len(i.byFQN[target.FQN]) > 4096 {
		return nil
	}
	for _, id := range i.byFQN[target.FQN] {
		candidate, ok := i.symbols[id]
		if !ok || candidate.ID == target.ID || candidate.Language != analysis.LanguageKotlin || !expectActualKindCompatible(target, *candidate) {
			continue
		}
		candidateExpect := containsString(candidate.Modifiers, "expect") || i.containerHasKotlinModifierLocked(*candidate, "expect")
		candidateActual := containsString(candidate.Modifiers, "actual") || i.containerHasKotlinModifierLocked(*candidate, "actual")
		if targetExpect == candidateExpect || targetActual == candidateActual || !(targetExpect && candidateActual || targetActual && candidateExpect) {
			continue
		}
		expect, actual := target, *candidate
		if targetActual {
			expect, actual = *candidate, target
		}
		if !sameExpectActualShape(expect, actual) || !i.expectActualTypeSurfaceCompatibleLocked(expect, actual) {
			continue
		}
		candidateModule := i.moduleForURILocked(candidate.URI)
		if targetModule == nil || candidateModule == nil || !targetModule.BuildModelAuthoritative || !candidateModule.BuildModelAuthoritative {
			continue
		}
		if targetModule.Name != candidateModule.Name || targetModule.Dir != candidateModule.Dir {
			continue
		}
		targetSet := i.sourceSetForURILocked(target.URI, targetModule)
		candidateSet := i.sourceSetForURILocked(candidate.URI, candidateModule)
		expectSet, actualSet := targetSet, candidateSet
		if targetActual {
			expectSet, actualSet = candidateSet, targetSet
		}
		if !sourceSetsConnected(targetModule, expectSet, actualSet) {
			continue
		}
		result = append(result, *candidate)
		if len(result) > 4096 {
			return nil
		}
	}
	return uniqueSymbols(result)
}

func expectActualKindCompatible(left, right analysis.Symbol) bool {
	if left.Kind == right.Kind {
		return true
	}
	return (left.Kind == analysis.KindTypeAlias && analysis.IsTypeKind(right.Kind)) ||
		(right.Kind == analysis.KindTypeAlias && analysis.IsTypeKind(left.Kind))
}

func sameExpectActualShape(left, right analysis.Symbol) bool {
	if kotlinVisibility(left) != kotlinVisibility(right) || kotlinModality(left) != kotlinModality(right) || len(left.TypeParameters) != len(right.TypeParameters) {
		return false
	}
	bindings := make(map[string]string, len(right.TypeParameters))
	for index := range right.TypeParameters {
		bindings[right.TypeParameters[index]] = left.TypeParameters[index]
		if !equalStringSets(normalizedKotlinTypes(left.TypeParameterBounds[left.TypeParameters[index]], nil), normalizedKotlinTypes(right.TypeParameterBounds[right.TypeParameters[index]], bindings)) {
			return false
		}
	}
	if analysis.IsCallableKind(left.Kind) || analysis.IsCallableKind(right.Kind) {
		if !analysis.IsCallableKind(left.Kind) || !analysis.IsCallableKind(right.Kind) || len(left.Parameters) != len(right.Parameters) || normalizeKotlinType(left.Type, nil) != normalizeKotlinType(right.Type, bindings) || normalizeKotlinType(left.ReceiverType, nil) != normalizeKotlinType(right.ReceiverType, bindings) {
			return false
		}
		for index := range left.Parameters {
			if left.Parameters[index].Name != right.Parameters[index].Name || left.Parameters[index].Variadic != right.Parameters[index].Variadic || normalizeKotlinType(left.Parameters[index].Type, nil) != normalizeKotlinType(right.Parameters[index].Type, bindings) {
				return false
			}
		}
		return true
	}
	if left.Kind == analysis.KindProperty || left.Kind == analysis.KindField || left.Kind == analysis.KindVariable {
		return normalizeKotlinType(left.Type, nil) == normalizeKotlinType(right.Type, bindings) && containsString(left.Modifiers, "var") == containsString(right.Modifiers, "var")
	}
	if analysis.IsTypeKind(left.Kind) && analysis.IsTypeKind(right.Kind) {
		return true
	}
	return left.Kind == right.Kind
}

func sourceSetsConnected(module *ModuleInfo, expectSet, actualSet string) bool {
	if module == nil || !module.BuildModelAuthoritative || expectSet == "" || actualSet == "" || expectSet == actualSet {
		return false
	}
	seen := make(map[string]bool)
	queue := []string{actualSet}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == expectSet {
			return true
		}
		if seen[current] {
			continue
		}
		if len(seen) >= 100_000 {
			return false
		}
		seen[current] = true
		next := module.SourceSetDependsOn[current]
		if len(queue)+len(seen)+len(next) > 100_000 {
			return false
		}
		queue = append(queue, next...)
	}
	return false
}

func kotlinVisibility(symbol analysis.Symbol) string {
	for _, modifier := range []string{"private", "protected", "internal", "public"} {
		if containsString(symbol.Modifiers, modifier) {
			return modifier
		}
	}
	return "public"
}

func kotlinModality(symbol analysis.Symbol) string {
	for _, modifier := range []string{"sealed", "abstract", "open"} {
		if containsString(symbol.Modifiers, modifier) {
			return modifier
		}
	}
	if symbol.Kind == analysis.KindInterface {
		return "abstract"
	}
	return "final"
}

func normalizeKotlinType(value string, bindings map[string]string) string {
	value = substituteTypeBindings(strings.TrimSpace(value), bindings)
	return strings.Join(strings.Fields(value), "")
}

func normalizedKotlinTypes(values []string, bindings map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, normalizeKotlinType(value, bindings))
	}
	sort.Strings(out)
	return out
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (i *Index) expectActualTypeSurfaceCompatibleLocked(expect, actual analysis.Symbol) bool {
	if !analysis.IsTypeKind(expect.Kind) || !analysis.IsTypeKind(actual.Kind) || expect.Kind == analysis.KindTypeAlias || actual.Kind == analysis.KindTypeAlias {
		return true
	}
	actualMembers := make(map[string][]analysis.Symbol)
	for _, id := range i.byContainerName[actual.ID] {
		member := i.symbols[id]
		if member != nil && member.ContainerID == actual.ID && !member.Synthetic {
			actualMembers[member.Name] = append(actualMembers[member.Name], *member)
		}
	}
	for _, id := range i.byContainerName[expect.ID] {
		member := i.symbols[id]
		if member == nil || member.ContainerID != expect.ID || member.Synthetic || kotlinVisibility(*member) == "private" {
			continue
		}
		matched := false
		for _, candidate := range actualMembers[member.Name] {
			if expectActualKindCompatible(*member, candidate) && sameExpectActualShape(*member, candidate) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (i *Index) containerHasKotlinModifierLocked(symbol analysis.Symbol, modifier string) bool {
	for containerID := symbol.ContainerID; containerID != ""; {
		container, ok := i.symbols[containerID]
		if !ok {
			return false
		}
		if containsString(container.Modifiers, modifier) {
			return true
		}
		containerID = container.ContainerID
	}
	return false
}

func (i *Index) SymbolsInFile(uri protocol.URI) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	f := i.files[uri]
	if f == nil {
		return nil
	}
	out := make([]analysis.Symbol, 0, len(f.Symbols))
	for _, symbol := range f.Symbols {
		if !symbol.Synthetic {
			out = append(out, symbol)
		}
	}
	return out
}

// InferredType resolves a declaration initializer using the same constructor,
// factory, literal, and collection inference used by member completion.
func (i *Index) InferredType(uri protocol.URI, symbolID string) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	symbol, ok := i.symbols[symbolID]
	if file == nil || !ok || symbol.URI != uri {
		return ""
	}
	if symbol.Type != "" && symbol.Type != "var" {
		return simpleType(symbol.Type)
	}
	return simpleType(i.inferExpressionTypeLocked(file, symbol.Initializer, symbol.StartByte))
}

func (i *Index) FunctionalParameterTypes(uri protocol.URI, typeName string) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return nil
	}
	return i.functionalParameterTypesLocked(file, typeName)
}

func (i *Index) functionalParameterTypesLocked(file *analysis.ParsedFile, typeName string) []string {
	base, arguments := splitInstantiatedType(typeName)
	owners := i.resolveTypeSymbolsLocked(file, base)
	if len(owners) != 1 || owners[0].Kind != analysis.KindInterface {
		return nil
	}
	owner := owners[0]
	var methods []analysis.Symbol
	for _, id := range i.byContainerName[owner.ID] {
		method := i.symbols[id]
		if method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
			continue
		}
		methods = append(methods, *method)
	}
	if len(methods) == 1 {
		out := make([]string, len(methods[0].Parameters))
		for index, parameter := range methods[0].Parameters {
			out[index] = substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments)
		}
		return out
	}
	return nil
}

func (i *Index) Supertypes(item analysis.Symbol) []analysis.Symbol {
	return i.SupertypesContext(context.Background(), item)
}

func (i *Index) SupertypesContext(ctx context.Context, item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[item.URI]
	if file == nil {
		return nil
	}
	var out []analysis.Symbol
	for _, name := range item.Supertypes {
		if ctx.Err() != nil {
			return nil
		}
		out = append(out, i.resolveTypeSymbolsForOwnerLocked(file, name, item)...)
	}
	return uniqueSymbols(out)
}

func (i *Index) Subtypes(item analysis.Symbol) []analysis.Symbol {
	return i.SubtypesContext(context.Background(), item)
}

func (i *Index) SubtypesContext(ctx context.Context, item analysis.Symbol) []analysis.Symbol {
	i.mu.RLock()
	defer i.mu.RUnlock()
	ids := append([]string(nil), i.bySuperID[item.ID]...)
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			return nil
		}
		if symbol, ok := i.symbols[id]; ok {
			if i.directSupertypeMatchesLocked(*symbol, item.ID) {
				out = append(out, *symbol)
			}
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) CallsFrom(item analysis.Symbol) map[string][]analysis.Reference {
	return i.CallsFromContext(context.Background(), item)
}

func (i *Index) CallsFromContext(ctx context.Context, item analysis.Symbol) map[string][]analysis.Reference {
	const maxCallHierarchyCandidates = 50_000
	if document, ok := i.DocumentContext(ctx, item.URI); ok {
		i.ensureLibraryReferencesContext(ctx, item.URI, document)
	}
	empty := map[string][]analysis.Reference{}
	if ctx.Err() != nil {
		return empty
	}
	i.mu.RLock()
	f := i.files[item.URI]
	if f == nil {
		i.mu.RUnlock()
		return empty
	}
	semanticVersion := i.semanticVersion
	environmentVersion := i.semanticEnvironmentVersion
	candidates := make([]analysis.Reference, 0)
	for _, r := range f.References {
		if r.ContainerID == item.ID && r.Role == analysis.RoleCall {
			candidates = append(candidates, r)
			if len(candidates) > maxCallHierarchyCandidates {
				break
			}
		}
	}
	i.mu.RUnlock()
	if len(candidates) > maxCallHierarchyCandidates {
		i.recordHealth("call-hierarchy", item.Name, "outgoing call set exceeded its 50000-candidate safety limit and was withheld")
		return empty
	}
	out := map[string][]analysis.Reference{}
	for start := 0; start < len(candidates); start += 128 {
		if ctx.Err() != nil {
			return empty
		}
		end := min(start+128, len(candidates))
		i.mu.RLock()
		if i.semanticVersion != semanticVersion || i.semanticEnvironmentVersion != environmentVersion || i.files[item.URI] != f {
			i.mu.RUnlock()
			return empty
		}
		for _, reference := range candidates[start:end] {
			for _, symbol := range i.resolveContextLocked(ctx, f, reference) {
				out[symbol.ID] = append(out[symbol.ID], reference)
			}
		}
		i.mu.RUnlock()
	}
	return out
}

func (i *Index) CallsTo(item analysis.Symbol) map[string][]analysis.Reference {
	return i.CallsToContext(context.Background(), item)
}

func (i *Index) CallsToContext(ctx context.Context, item analysis.Symbol) map[string][]analysis.Reference {
	const (
		maxUnresolvedCallFallback  = 4096
		maxCallHierarchyCandidates = 50_000
	)
	empty := map[string][]analysis.Reference{}
	if ctx.Err() != nil {
		return empty
	}
	i.mu.RLock()
	semanticVersion := i.semanticVersion
	environmentVersion := i.semanticEnvironmentVersion
	type callWork struct {
		member     analysis.Symbol
		direct     []analysis.Reference
		unresolved []analysis.Reference
	}
	work := make([]callWork, 0)
	referenceFiles := make(map[protocol.URI]*analysis.ParsedFile)
	totalCandidates := 0
	for _, member := range i.referenceFamilyLocked(item) {
		direct := append([]analysis.Reference(nil), i.refsByTarget[member.ID]...)
		unresolved := append([]analysis.Reference(nil), i.unresolvedRefsByName[member.Name]...)
		if len(unresolved) > maxUnresolvedCallFallback {
			i.recordHealth("call-hierarchy", member.Name, "unresolved call fallback exceeded 4096 candidates and was withheld")
			unresolved = nil
		}
		work = append(work, callWork{member: member, direct: direct, unresolved: unresolved})
		totalCandidates += len(direct) + len(unresolved)
		for _, reference := range unresolved {
			referenceFiles[reference.URI] = i.files[reference.URI]
		}
	}
	i.mu.RUnlock()
	if totalCandidates > maxCallHierarchyCandidates {
		i.recordHealth("call-hierarchy", item.Name, "incoming call set exceeded its 50000-candidate safety limit and was withheld")
		return empty
	}
	out := map[string][]analysis.Reference{}
	for _, entry := range work {
		for _, reference := range entry.direct {
			if reference.Role == analysis.RoleCall {
				out[reference.ContainerID] = append(out[reference.ContainerID], reference)
			}
		}
		for start := 0; start < len(entry.unresolved); start += 128 {
			if ctx.Err() != nil {
				return empty
			}
			end := min(start+128, len(entry.unresolved))
			i.mu.RLock()
			if i.semanticVersion != semanticVersion || i.semanticEnvironmentVersion != environmentVersion {
				i.mu.RUnlock()
				return empty
			}
			for _, reference := range entry.unresolved[start:end] {
				file := referenceFiles[reference.URI]
				if i.files[reference.URI] != file {
					i.mu.RUnlock()
					return empty
				}
				if file == nil || reference.Role != analysis.RoleCall {
					continue
				}
				for _, resolved := range i.resolveContextLocked(ctx, file, reference) {
					if resolved.ID == entry.member.ID {
						out[reference.ContainerID] = append(out[reference.ContainerID], reference)
						break
					}
				}
			}
			i.mu.RUnlock()
		}
	}
	return out
}

func (i *Index) Rename(uri protocol.URI, pos protocol.Position, newName string) protocol.WorkspaceEdit {
	return i.RenameContext(context.Background(), uri, pos, newName)
}

type renameReferenceWork struct {
	member     analysis.Symbol
	references []analysis.Reference
}

type renameAnalysisSnapshot struct {
	origin             analysis.Symbol
	work               []renameReferenceWork
	files              map[protocol.URI]*analysis.ParsedFile
	texts              map[protocol.URI]string
	failure            string
	semanticVersion    uint64
	environmentVersion uint64
}

func (i *Index) renameAnalysisSnapshotLocked(target analysis.Symbol, limit int) (renameAnalysisSnapshot, bool) {
	origin := target
	if target.OriginID != "" {
		if value, exists := i.symbols[target.OriginID]; exists {
			origin = *value
		}
	}
	family := i.referenceFamilyLocked(origin)
	if len(family) == 0 {
		return renameAnalysisSnapshot{origin: origin, failure: "rename family exceeded its identity/candidate safety limit"}, false
	}
	candidateCount := 0
	for _, member := range family {
		if member.Library {
			return renameAnalysisSnapshot{origin: origin, failure: "rename family crosses a read-only library declaration"}, false
		}
		candidateCount += len(i.refsByName[member.Name])
		if candidateCount > limit {
			return renameAnalysisSnapshot{origin: origin, failure: "rename candidate set exceeded its 10000-reference safety limit"}, false
		}
	}
	snapshot := renameAnalysisSnapshot{
		origin: origin, work: make([]renameReferenceWork, 0, len(family)),
		files: make(map[protocol.URI]*analysis.ParsedFile), texts: make(map[protocol.URI]string),
		semanticVersion: i.semanticVersion, environmentVersion: i.semanticEnvironmentVersion,
	}
	for _, member := range family {
		references := append([]analysis.Reference(nil), i.refsByName[member.Name]...)
		snapshot.work = append(snapshot.work, renameReferenceWork{member: member, references: references})
		snapshot.files[member.URI] = i.files[member.URI]
		for _, reference := range references {
			snapshot.files[reference.URI] = i.files[reference.URI]
			if _, exists := snapshot.texts[reference.URI]; !exists {
				snapshot.texts[reference.URI] = i.documentTextLocked(reference.URI)
			}
		}
	}
	return snapshot, true
}

func (i *Index) renameSnapshotCurrentLocked(snapshot renameAnalysisSnapshot) bool {
	if i.semanticVersion != snapshot.semanticVersion || i.semanticEnvironmentVersion != snapshot.environmentVersion {
		return false
	}
	for uri, file := range snapshot.files {
		if i.files[uri] != file {
			return false
		}
	}
	return true
}

func (i *Index) resolveRenameReferencesContext(ctx context.Context, snapshot renameAnalysisSnapshot, work renameReferenceWork) ([]bool, bool) {
	matches := make([]bool, len(work.references))
	for start := 0; start < len(work.references); start += 128 {
		if ctx.Err() != nil {
			return nil, false
		}
		end := min(start+128, len(work.references))
		i.mu.RLock()
		if i.semanticVersion != snapshot.semanticVersion || i.semanticEnvironmentVersion != snapshot.environmentVersion {
			i.mu.RUnlock()
			return nil, false
		}
		for offset, reference := range work.references[start:end] {
			file := snapshot.files[reference.URI]
			if i.files[reference.URI] != file {
				i.mu.RUnlock()
				return nil, false
			}
			if file == nil {
				continue
			}
			for _, resolved := range i.resolveContextLocked(ctx, file, reference) {
				if resolved.ID == work.member.ID {
					matches[start+offset] = true
					break
				}
			}
		}
		i.mu.RUnlock()
	}
	return matches, true
}

func (i *Index) RenameContext(ctx context.Context, uri protocol.URI, pos protocol.Position, newName string) protocol.WorkspaceEdit {
	const maxRenameCandidates = 10000
	if ctx == nil {
		ctx = context.Background()
	}
	empty := protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{}}
	if ctx.Err() != nil {
		return empty
	}
	target, _, ok := i.SymbolAtContext(ctx, uri, pos)
	if !ok || target.Library {
		return empty
	}
	changes := make(map[protocol.URI][]protocol.TextEdit)
	i.mu.RLock()
	snapshot, complete := i.renameAnalysisSnapshotLocked(target, maxRenameCandidates)
	i.mu.RUnlock()
	if !complete {
		i.recordHealth("rename", snapshot.origin.Name, snapshot.failure)
		return empty
	}
	propertyName, interopFamily := interopRenamePropertyName(target, snapshot.origin, newName)
	seen := make(map[string]bool)
	add := func(location protocol.Location, replacement string) {
		key := string(location.URI) + "|" + itoa(location.Range.Start.Line) + ":" + itoa(location.Range.Start.Character) + "-" + itoa(location.Range.End.Line) + ":" + itoa(location.Range.End.Character)
		if !seen[key] {
			seen[key] = true
			changes[location.URI] = append(changes[location.URI], protocol.TextEdit{Range: location.Range, NewText: replacement})
		}
	}
	for _, work := range snapshot.work {
		if ctx.Err() != nil {
			return empty
		}
		member := work.member
		replacement := newName
		if interopFamily {
			replacement = interopRenameMemberName(member, propertyName)
		}
		add(member.Location(), replacement)
		matches, current := i.resolveRenameReferencesContext(ctx, snapshot, work)
		if !current {
			return empty
		}
		for index, reference := range work.references {
			if !matches[index] {
				continue
			}
			text := snapshot.texts[reference.URI]
			if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != member.Name {
				// Kotlin operator/convention references are structural
				// syntax, not identifier tokens. IntelliJ leaves them
				// untouched and removes `operator` when necessary.
				continue
			}
			add(protocol.Location{URI: reference.URI, Range: reference.Range}, replacement)
		}
	}
	i.mu.RLock()
	snapshotCurrent := i.renameSnapshotCurrentLocked(snapshot)
	i.mu.RUnlock()
	if !snapshotCurrent {
		return empty
	}
	return protocol.WorkspaceEdit{Changes: changes}
}

// Renameable reports whether every resolved use can be changed by replacing
// an identifier token. Kotlin convention calls such as `left + right`,
// destructuring, indexing, and delegation are semantic references whose
// source range is punctuation or another structural form. Replacing those
// ranges with the requested identifier would produce invalid source, while
// omitting them would silently break the program, so the LSP rejects that
// rename until it has a full structural refactoring for the convention.
func (i *Index) Renameable(uri protocol.URI, pos protocol.Position) bool {
	return i.RenameableContext(context.Background(), uri, pos)
}

func (i *Index) RenameableContext(ctx context.Context, uri protocol.URI, pos protocol.Position) bool {
	const maxRenameCandidates = 10000
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	target, _, ok := i.SymbolAtContext(ctx, uri, pos)
	if !ok || target.Library {
		return false
	}
	i.mu.RLock()
	snapshot, complete := i.renameAnalysisSnapshotLocked(target, maxRenameCandidates)
	i.mu.RUnlock()
	if !complete {
		i.recordHealth("rename", snapshot.origin.Name, snapshot.failure)
		return false
	}
	for _, work := range snapshot.work {
		if ctx.Err() != nil {
			return false
		}
		matches, current := i.resolveRenameReferencesContext(ctx, snapshot, work)
		if !current {
			return false
		}
		for index, reference := range work.references {
			if !matches[index] {
				continue
			}
			text := snapshot.texts[reference.URI]
			if reference.StartByte < 0 || reference.EndByte > len(text) || reference.StartByte >= reference.EndByte || strings.Trim(text[reference.StartByte:reference.EndByte], "`") != work.member.Name {
				return false
			}
		}
	}
	i.mu.RLock()
	current := i.renameSnapshotCurrentLocked(snapshot)
	i.mu.RUnlock()
	return current
}

func interopRenamePropertyName(target, origin analysis.Symbol, requested string) (string, bool) {
	if origin.Language == analysis.LanguageKotlin && origin.Kind == analysis.KindProperty {
		if target.Synthetic && target.InteropLanguage == analysis.LanguageJava {
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
		return strings.Trim(requested, "`"), true
	}
	if origin.Language == analysis.LanguageJava {
		if _, bean := beanPropertyName(origin.Name); bean {
			if target.Synthetic && target.InteropLanguage == analysis.LanguageKotlin {
				return strings.Trim(requested, "`"), true
			}
			if property, ok := beanPropertyName(requested); ok {
				return property, true
			}
		}
	}
	return "", false
}

func interopRenameMemberName(member analysis.Symbol, propertyName string) string {
	if member.InteropLanguage == analysis.LanguageKotlin || member.Language == analysis.LanguageKotlin && member.Kind == analysis.KindProperty && !member.Synthetic {
		return propertyName
	}
	if _, ok := beanPropertyName(member.Name); ok {
		stem := propertyName
		if len(stem) > 0 && stem[0] >= 'a' && stem[0] <= 'z' {
			stem = strings.ToUpper(stem[:1]) + stem[1:]
		}
		switch {
		case strings.HasPrefix(member.Name, "set"):
			return "set" + stem
		case strings.HasPrefix(member.Name, "is"):
			return "is" + stem
		default:
			return "get" + stem
		}
	}
	return propertyName
}

func beanPropertyName(accessor string) (string, bool) {
	for _, prefix := range []string{"get", "set", "is"} {
		if strings.HasPrefix(accessor, prefix) {
			return decapitalizeBean(accessor[len(prefix):])
		}
	}
	return "", false
}

// SemanticTokens returns lexical/declaration tokens plus references classified
// from the symbol each reference actually resolves to. The parser's role-based
// token remains as a fallback for temporarily unresolved code.
func (i *Index) SemanticTokens(uri protocol.URI) ([]analysis.Token, uint64, bool) {
	return i.SemanticTokensContext(context.Background(), uri)
}

func (i *Index) SemanticTokensContext(ctx context.Context, uri protocol.URI) ([]analysis.Token, uint64, bool) {
	if ctx.Err() != nil {
		return nil, 0, false
	}
	i.semanticCacheMu.RLock()
	cached, cachedOK := i.semanticTokenCache[uri]
	i.semanticCacheMu.RUnlock()
	if cachedOK {
		i.mu.RLock()
		file := i.files[uri]
		valid := file != nil && file.TextHash == cached.textHash && i.semanticEnvironmentVersion == cached.environmentVersion
		checked := 0
		for id, version := range cached.symbolVersions {
			if !valid {
				break
			}
			checked++
			valid = valid && i.semanticSymbolVersion[id] == version
			if checked&1023 == 0 {
				i.mu.RUnlock()
				if ctx.Err() != nil {
					return nil, 0, false
				}
				i.mu.RLock()
				valid = valid && i.files[uri] == file && i.semanticEnvironmentVersion == cached.environmentVersion
			}
		}
		if valid {
			for name, version := range cached.nameVersions {
				checked++
				valid = valid && i.semanticNameVersion[name] == version
				if checked&1023 == 0 {
					i.mu.RUnlock()
					if ctx.Err() != nil {
						return nil, 0, false
					}
					i.mu.RLock()
					valid = valid && i.files[uri] == file && i.semanticEnvironmentVersion == cached.environmentVersion
				}
				if !valid {
					break
				}
			}
		}
		i.mu.RUnlock()
		if valid {
			return append([]analysis.Token(nil), cached.tokens...), cached.resultID, true
		}
	}
	i.mu.RLock()
	file := i.files[uri]
	if file == nil {
		i.mu.RUnlock()
		return nil, 0, false
	}
	if len(file.Tokens) > 250_000 || len(file.Symbols) > 250_000 || len(file.References) > 250_000 {
		i.mu.RUnlock()
		i.recordHealth("semantic-tokens", string(uri), "document semantic inventory exceeds its 250000-item-per-kind safety limit")
		return nil, 0, false
	}
	tokens := append([]analysis.Token(nil), file.Tokens...)
	symbols := append([]analysis.Symbol(nil), file.Symbols...)
	references := append([]analysis.Reference(nil), file.References...)
	textHash := file.TextHash
	semanticVersion := i.semanticVersion
	environmentVersion := i.semanticEnvironmentVersion
	i.mu.RUnlock()
	type semanticClassification struct {
		typ       uint32
		modifiers uint32
	}
	classifications := make(map[[2]int]semanticClassification, len(symbols)+len(references))
	declarationSpans := make(map[[2]int]bool, len(symbols))
	declarationSymbols := make(map[[2]int]analysis.Symbol, len(symbols))
	symbolVersions := make(map[string]uint64)
	nameVersions := make(map[string]uint64)
	for _, symbol := range symbols {
		if ctx.Err() != nil {
			return nil, 0, false
		}
		key := [2]int{symbol.NameStartByte, symbol.NameEndByte}
		declarationSpans[key] = true
		if previous, exists := declarationSymbols[key]; !exists || previous.Synthetic && !symbol.Synthetic {
			declarationSymbols[key] = symbol
		}
	}
	for key, symbol := range declarationSymbols {
		classifications[key] = semanticClassification{
			typ: symbol.Kind.SemanticToken(), modifiers: semanticModifiersForSymbol(symbol, true, analysis.RoleRead),
		}
	}
	// Resolution remains a coherent generation but yields the read lock after
	// bounded batches. A writer can proceed between batches; if it changes any
	// semantic input, this result is discarded instead of mixing generations.
	const semanticResolutionBatch = 128
	for start := 0; start < len(references); start += semanticResolutionBatch {
		if ctx.Err() != nil {
			return nil, 0, false
		}
		end := min(start+semanticResolutionBatch, len(references))
		i.mu.RLock()
		if i.files[uri] != file || i.semanticVersion != semanticVersion || i.semanticEnvironmentVersion != environmentVersion {
			i.mu.RUnlock()
			return nil, 0, false
		}
		for _, reference := range references[start:end] {
			key := [2]int{reference.StartByte, reference.EndByte}
			nameVersions[reference.Name] = i.semanticNameVersion[reference.Name]
			if declarationSpans[key] {
				continue
			}
			resolved := i.resolveContextLocked(ctx, file, reference)
			for _, symbol := range resolved {
				symbolVersions[symbol.ID] = i.semanticSymbolVersion[symbol.ID]
			}
			if typ, modifiers, unambiguous := semanticClassificationForResolution(resolved, reference.Role); unambiguous {
				classifications[key] = semanticClassification{typ: typ, modifiers: modifiers}
			}
		}
		i.mu.RUnlock()
	}
	for n := range tokens {
		if n&1023 == 0 && ctx.Err() != nil {
			return nil, 0, false
		}
		if classification, ok := classifications[[2]int{tokens[n].StartByte, tokens[n].EndByte}]; ok {
			tokens[n].Type = classification.typ
			tokens[n].Modifiers = classification.modifiers
		}
	}
	i.mu.RLock()
	coherent := i.files[uri] == file && i.semanticVersion == semanticVersion && i.semanticEnvironmentVersion == environmentVersion
	i.mu.RUnlock()
	if !coherent {
		return nil, 0, false
	}
	hash := sha256.New()
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], uint64(len(uri)))
	_, _ = hash.Write(word[:])
	_, _ = hash.Write([]byte(uri))
	binary.LittleEndian.PutUint64(word[:], textHash)
	_, _ = hash.Write(word[:])
	for _, token := range tokens {
		for _, value := range []uint64{uint64(token.StartByte), uint64(token.EndByte), uint64(token.Type), uint64(token.Modifiers)} {
			binary.LittleEndian.PutUint64(word[:], value)
			_, _ = hash.Write(word[:])
		}
	}
	digest := hash.Sum(nil)
	resultID := binary.LittleEndian.Uint64(digest[:8])
	i.semanticCacheMu.Lock()
	if _, exists := i.semanticTokenCache[uri]; !exists && len(i.semanticTokenCache) >= 256 {
		for victim := range i.semanticTokenCache {
			delete(i.semanticTokenCache, victim)
			break
		}
	}
	i.semanticTokenCache[uri] = semanticTokenCacheEntry{
		textHash: textHash, resultID: resultID, tokens: append([]analysis.Token(nil), tokens...),
		environmentVersion: environmentVersion, symbolVersions: symbolVersions, nameVersions: nameVersions,
	}
	i.semanticCacheMu.Unlock()
	return tokens, resultID, true
}

func semanticClassificationForResolution(resolved []analysis.Symbol, role analysis.ReferenceRole) (uint32, uint32, bool) {
	if len(resolved) == 0 {
		return 0, 0, false
	}
	typ := resolved[0].Kind.SemanticToken()
	modifiers := semanticModifiersForSymbol(resolved[0], false, role)
	for _, symbol := range resolved[1:] {
		if symbol.Kind.SemanticToken() != typ || semanticModifiersForSymbol(symbol, false, role) != modifiers {
			return 0, 0, false
		}
	}
	return typ, modifiers, true
}

func semanticModifiersForSymbol(symbol analysis.Symbol, declaration bool, role analysis.ReferenceRole) uint32 {
	var modifiers uint32
	if declaration {
		modifiers |= analysis.SemanticModifierDeclaration
	}
	if containsString(symbol.Modifiers, "final") || containsString(symbol.Modifiers, "const") || containsString(symbol.Modifiers, "val") {
		modifiers |= analysis.SemanticModifierReadonly
	}
	static := containsString(symbol.Modifiers, "static") || containsString(symbol.Modifiers, "JvmStatic") || containsString(symbol.Modifiers, "companion")
	if symbol.Language == analysis.LanguageKotlin && symbol.ContainerID == "" && (symbol.Kind == analysis.KindProperty || analysis.IsCallableKind(symbol.Kind)) {
		static = true
	}
	if static {
		modifiers |= analysis.SemanticModifierStatic
	}
	if symbol.Deprecated || containsString(symbol.Modifiers, "deprecated") || containsString(symbol.Modifiers, "Deprecated") {
		modifiers |= analysis.SemanticModifierDeprecated
	}
	if containsString(symbol.Modifiers, "abstract") {
		modifiers |= analysis.SemanticModifierAbstract
	}
	if containsString(symbol.Modifiers, "suspend") {
		modifiers |= analysis.SemanticModifierAsync
	}
	variable := symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || symbol.Kind == analysis.KindVariable
	readonly := modifiers&analysis.SemanticModifierReadonly != 0
	if variable && !readonly || !declaration && role == analysis.RoleWrite {
		modifiers |= analysis.SemanticModifierModification
	}
	if symbol.Library && (symbol.Package == "kotlin" || strings.HasPrefix(symbol.Package, "kotlin.")) {
		modifiers |= analysis.SemanticModifierDefaultLibrary
	}
	return modifiers
}

// FilesImportingPrefix returns only workspace files whose import path is equal
// to prefix or starts with prefix plus a dot. Import prefixes are maintained as
// files enter the index, avoiding a whole-workspace scan on package moves.
func (i *Index) FilesImportingPrefix(prefix string) []*analysis.ParsedFile {
	files, _ := i.FilesImportingPrefixContext(context.Background(), prefix, 0)
	return files
}

func (i *Index) FilesImportingPrefixContext(ctx context.Context, prefix string, limit int) ([]*analysis.ParsedFile, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if limit > 0 && len(i.importersByPrefix[prefix]) > limit {
		return nil, true
	}
	seen := make(map[protocol.URI]bool)
	out := make([]*analysis.ParsedFile, 0, len(i.importersByPrefix[prefix]))
	for index, uri := range i.importersByPrefix[prefix] {
		if index&255 == 0 && ctx.Err() != nil {
			return nil, true
		}
		if seen[uri] {
			continue
		}
		file := i.files[uri]
		if file == nil {
			continue
		}
		if _, ok := uriutil.Path(uri); !ok {
			continue
		}
		seen[uri] = true
		if limit > 0 && len(out) >= limit {
			return nil, true
		}
		out = append(out, file)
	}
	return out, false
}

// UsedImports reports imports that contribute an unqualified semantic
// reference. Comments, strings, and fully-qualified expressions never enter
// the parser's reference stream and therefore cannot keep an import alive.
func (i *Index) UsedImports(uri protocol.URI) map[string]bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return map[string]bool{}
	}
	return i.usedImportsLocked(file)
}

// usedImportsLocked is the single confidence policy for both unused-import
// diagnostics and organize-import edits. A warning that offers removal is
// already destructive in practice, so it must obey the same abstention rules
// as the explicit source action.
func (i *Index) usedImportsLocked(file *analysis.ParsedFile) map[string]bool {
	used := make(map[string]bool)
	// Import removal is destructive. Broken syntax or an unbound reference
	// means the fast semantic model is incomplete, so preserve every import and
	// restrict organize-imports to stable sorting/deduplication.
	incomplete := len(file.Diagnostics) > 0 || file.ParseMode == "large"
	if !incomplete {
		for _, reference := range file.References {
			if languageIntrinsicReference(reference, file.Language) {
				continue
			}
			if reference.Role != analysis.RoleImport && reference.Qualifier == "" && len(i.resolveLocked(file, reference)) == 0 {
				incomplete = true
				break
			}
		}
	}
	for _, imported := range file.Imports {
		if incomplete || imported.Wildcard {
			used[imported.Path] = true
			continue
		}
		// Kotlin extension/convention call sites need not contain the imported
		// callable's source name (operators are the common case). Keep callable
		// imports unless an authoritative compiler-use model becomes available.
		for _, id := range i.byFQN[imported.Path] {
			if symbol := i.symbols[id]; symbol != nil && analysis.IsCallableKind(symbol.Kind) {
				used[imported.Path] = true
				break
			}
		}
		for _, reference := range file.References {
			if reference.Role == analysis.RoleImport || reference.Qualifier != "" {
				continue
			}
			if !imported.Wildcard && reference.Name == imported.LocalName() {
				used[imported.Path] = true
				break
			}
			if imported.Wildcard {
				for _, symbol := range i.resolveLocked(file, reference) {
					if symbol.Package == imported.Path || strings.HasPrefix(symbol.FQN, imported.Path+".") {
						used[imported.Path] = true
						break
					}
				}
			}
			if used[imported.Path] {
				break
			}
		}
	}
	return used
}

func importPrefixes(path string) []string {
	parts := strings.Split(strings.TrimSpace(path), ".")
	out := make([]string, 0, len(parts))
	for n, part := range parts {
		if part == "" {
			break
		}
		out = append(out, strings.Join(parts[:n+1], "."))
	}
	return out
}
