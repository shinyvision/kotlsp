package index

import (
	"context"
	"math/big"
	"sort"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

const maxResolutionCandidates = 512

// maxResolutionNesting bounds how deeply resolution may re-enter itself through
// expression inference: resolving a qualified name needs its receiver's type,
// and typing a receiver call needs that callee resolved. Each step consumes
// syntax, so real Kotlin/Java chains nest a handful of levels and a bound with
// this much headroom cannot cost a real answer. An unbounded cycle costs the
// whole process, because Go cannot recover from a stack overflow.
const maxResolutionNesting = 48

type resolutionDepthKey struct{}

// resolutionNesting is what a resolution chain carries down through its
// context: how deep it is, and a flag shared by the whole chain that records
// whether any step was cut off by the bound. A cut-off step answers "unknown",
// which is right for the request but must not be remembered as the answer.
type resolutionNesting struct {
	depth     int
	truncated *atomic.Bool
	active    *resolutionFrame
}

// resolutionFrame is one reference being resolved somewhere up the chain. A
// reference whose answer depends on itself -- an incomplete edit can parse
// as a call whose own lambda needs that call's receiver -- has no answer, and
// asking again would only repeat the question until the depth bound.
type resolutionFrame struct {
	uri        protocol.URI
	start, end int
	name       string
	role       analysis.ReferenceRole
	outer      *resolutionFrame
}

// enterResolution returns ctx with r recorded as being resolved, or false
// when r is already being resolved further up the same chain.
func enterResolution(ctx context.Context, file *analysis.ParsedFile, r analysis.Reference) (context.Context, bool) {
	nesting, _ := ctx.Value(resolutionDepthKey{}).(resolutionNesting)
	for frame := nesting.active; frame != nil; frame = frame.outer {
		if frame.start == r.StartByte && frame.end == r.EndByte && frame.name == r.Name && frame.role == r.Role && frame.uri == file.URI {
			if nesting.truncated != nil {
				nesting.truncated.Store(true)
			}
			return ctx, false
		}
	}
	if nesting.truncated == nil {
		nesting.truncated = new(atomic.Bool)
	}
	nesting.depth++
	nesting.active = &resolutionFrame{uri: file.URI, start: r.StartByte, end: r.EndByte, name: r.Name, role: r.Role, outer: nesting.active}
	return context.WithValue(withReceiverSpellingsMemo(ctx), resolutionDepthKey{}, nesting), true
}

func resolutionDepth(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	nesting, _ := ctx.Value(resolutionDepthKey{}).(resolutionNesting)
	return nesting.depth
}

func withResolutionDepth(ctx context.Context, depth int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	nesting, _ := ctx.Value(resolutionDepthKey{}).(resolutionNesting)
	if nesting.truncated == nil {
		nesting.truncated = new(atomic.Bool)
	}
	nesting.depth = depth
	return context.WithValue(ctx, resolutionDepthKey{}, nesting)
}

// resolutionNestingExceeded reports whether ctx is at the bound, and marks the
// chain as truncated when it is.
func resolutionNestingExceeded(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	nesting, _ := ctx.Value(resolutionDepthKey{}).(resolutionNesting)
	if nesting.depth < maxResolutionNesting {
		return false
	}
	if nesting.truncated != nil {
		nesting.truncated.Store(true)
	}
	return true
}

// resolutionTruncated reports whether some step of ctx's chain hit the bound,
// so its answers are incomplete and must not be cached.
func resolutionTruncated(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	nesting, _ := ctx.Value(resolutionDepthKey{}).(resolutionNesting)
	return nesting.truncated != nil && nesting.truncated.Load()
}

func (i *Index) resolveLocked(ctx context.Context, file *analysis.ParsedFile, r analysis.Reference) []analysis.Symbol {
	return i.resolveContextLocked(ctx, file, r)
}

// resolveContextLocked is always called with i.mu held. It bounds the total
// candidate inventory before ranking so an exact-name collision in a large
// dependency graph cannot turn a cursor request into unbounded lock-held work.
// Exhaustion deliberately means ambiguity/abstention, never a partial answer.
func (i *Index) resolveContextLocked(ctx context.Context, file *analysis.ParsedFile, r analysis.Reference) []analysis.Symbol {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || file == nil {
		return nil
	}
	// A reference that resolved to exactly one declaration is remembered, keyed
	// on the declaration around it (see lateKey), so an edit elsewhere in the
	// file -- or a request that comes round again -- does not repeat inference.
	// Everything that resolves references shares this: diagnostics, hints,
	// highlighting, references, rename and call hierarchy.
	if r.ResolvedID == "" && !r.Synthetic {
		if cached, ok := i.cachedResolutionLocked(file, r); ok {
			return cached
		}
		ctx = withResolutionDepth(ctx, resolutionDepth(ctx))
		resolved := i.resolveUncachedLocked(ctx, file, r)
		if ctx.Err() == nil && !resolutionTruncated(ctx) {
			i.rememberResolutionLocked(file, r, resolved)
		}
		return resolved
	}
	return i.resolveUncachedLocked(ctx, file, r)
}

func (i *Index) resolveUncachedLocked(ctx context.Context, file *analysis.ParsedFile, r analysis.Reference) []analysis.Symbol {
	if resolutionNestingExceeded(ctx) {
		return nil
	}
	// Every resolution below this one -- a qualifier's type, the callee whose
	// lambda this reference sits in, an initializer -- counts one level deeper,
	// so a cycle through any of them ends at the bound instead of the stack,
	// and the same reference asked again inside its own chain ends at once.
	ctx, fresh := enterResolution(ctx, file, r)
	if !fresh {
		return nil
	}
	access := newAccessibilityMemoLocked(i, file)
	if r.ResolvedID != "" {
		if symbol, ok := i.symbols[r.ResolvedID]; ok {
			return []analysis.Symbol{*symbol}
		}
	}
	if r.ArgumentLabel {
		if file.Language == analysis.LanguageJava {
			if symbols := i.resolveAnnotationAttributeLabelLocked(file, r); len(symbols) > 0 {
				return symbols
			}
		}
		return i.resolveArgumentLabelContextLocked(ctx, file, r)
	}
	ids := make([]string, 0)
	exhausted, exhaustedBy := false, ""
	appendIDs := func(bucket []string) {
		if exhausted || !access.consumeWork(len(bucket)) || len(bucket) > maxResolutionCandidates-len(ids) {
			exhausted, exhaustedBy = true, "#1 if exhausted  access.consumeWork(len(bucket))  len(bucket) >"
			return
		}
		ids = append(ids, bucket...)
	}
	appendID := func(id string) {
		if exhausted || !access.consumeWork(1) || len(ids) >= maxResolutionCandidates {
			exhausted, exhaustedBy = true, "#2 if exhausted  access.consumeWork(1)  len(ids) > maxResolutio"
			return
		}
		ids = append(ids, id)
	}
	finishExhausted := func() []analysis.Symbol {
		i.recordHealth("resolution", r.Name, "candidate inventory exceeded its 512-symbol safety limit and was withheld ("+exhaustedBy+")")
		return nil
	}
	if !i.prepareResolutionImportsLocked(file, access) {
		return finishExhausted()
	}
	explicitImports := make(map[string]bool)
	for _, imported := range access.importsByLocal[r.Name] {
		if !imported.Wildcard {
			explicitImports[imported.Path] = true
		}
	}
	relevantImports := make([]analysis.Import, 0, len(access.importsByLocal[r.Name])+len(access.wildcardImports))
	relevantImports = append(relevantImports, access.importsByLocal[r.Name]...)
	relevantImports = append(relevantImports, access.wildcardImports...)
	if !access.consumeWork(len(relevantImports) - access.implicitWildcards) {
		return finishExhausted()
	}
	qualifier := r.Qualifier
	implicitReceiverTypes := make([]string, 0, 4)
	if text := i.documentTextLocked(file.URI); text != "" {
		// Tree-sitter's qualifier field commonly contains only the final token
		// (`value` in wrap(x).value.member), and is empty altogether for a
		// call qualified by a call with a trailing lambda (`Foo(false).apply {`).
		// Prefer the complete balanced source expression before the dot so
		// generic return arguments survive through longer chains and a dotted
		// call never falls back to unqualified name lookup. Synthetic references
		// built by type inference borrow an outer reference's position while
		// naming a callee elsewhere, so they say so and are never re-qualified
		// from the text: spelling alone cannot tell them apart, because the name
		// at the borrowed position can be the same one (`x.param(a).param(b)`),
		// and resolution would then analyse that expression forever.
		if !r.Synthetic && referenceSpelledAt(text, r) {
			if textual := expressionQualifierBefore(text, r.StartByte); textual != "" {
				qualifier = textual
			}
		}
	}
	if qualifier == "" {
		if qualifier == "" && file.Language == analysis.LanguageKotlin {
			implicitReceiverTypes = append(implicitReceiverTypes, i.contextualLambdaReceiverTypeLocked(ctx, file, r.StartByte), i.enclosingExtensionReceiverTypeLocked(file, r.StartByte))
			implicitReceiverTypes = append(implicitReceiverTypes, i.thisSmartCastTypesLocked(file, r.StartByte)...)
			implicitReceiverTypes = append(implicitReceiverTypes, i.enclosingContextReceiverTypesLocked(file, r.StartByte)...)
			if enclosing := i.enclosingTypeLocked(file, r.StartByte); enclosing.ID != "" {
				implicitReceiverTypes = append(implicitReceiverTypes, enclosing.Name)
			}
			implicitReceiverTypes = append(implicitReceiverTypes, gradleScriptReceiverTypes(file)...)
		} else if file.Language == analysis.LanguageJava {
			implicitReceiverTypes = append(implicitReceiverTypes, i.javaSwitchLabelReceiverTypeLocked(ctx, file, r.StartByte))
		}
	}
	typeQualifierSymbols := i.resolveTypeSymbolsForOwnerMemoLocked(file, qualifier, analysis.Symbol{}, access)
	typeQualifier := qualifier != "" && !strings.ContainsAny(qualifier, "()[]{} ") && !strings.Contains(qualifier, "::") && len(typeQualifierSymbols) > 0
	typeQualifierValue := i.typeQualifierActsAsValueLocked(file, typeQualifierSymbols)
	callableReference := callableReferenceOperatorBefore(i.documentTextLocked(file.URI), r.StartByte)
	unboundCallableReference := typeQualifier && callableReference
	if r.Role == analysis.RoleImport && r.Qualifier != "" {
		appendIDs(i.byFQN[r.Qualifier+"."+r.Name])
	}
	qualifierType := ""
	if qualifier != "" {
		anonymous, complete := i.anonymousObjectMemberIDsBoundedLocked(ctx, file, qualifier, r.Name, r.StartByte, maxResolutionCandidates-len(ids))
		if !complete {
			exhausted, exhaustedBy = true, "#3 if complete "
		} else {
			appendIDs(anonymous)
		}
		typ := i.inferExpressionResultContextLocked(ctx, file, qualifier, r.StartByte).Type
		if explicit := explicitReceiverType(qualifier); explicit != "" {
			typ = explicit
		}
		// `Outer.Nested(1)`: a class is no value, so nothing infers a type
		// for it, but its nested types, statics and companion members are
		// what follows the dot. The filters below keep them to exactly those.
		if typ == "" && typeQualifier && len(typeQualifierSymbols) == 1 && analysis.IsTypeKind(typeQualifierSymbols[0].Kind) && typeQualifierSymbols[0].FQN != "" {
			typ = typeQualifierSymbols[0].FQN
		}
		qualifierType = typ
		if typ != "" {
			nullableReceiver := file.Language == analysis.LanguageKotlin && strings.HasSuffix(strings.TrimSpace(typ), "?")
			memberAccessAllowed := !nullableReceiver || kotlinNullableMemberAccessAllowed(i.documentTextLocked(file.URI), r.StartByte)
			dot := qualifiedAccess{
				receiverType: typ, typeQualifier: typeQualifier, typeQualifierValue: typeQualifierValue, typeQualifierSymbols: typeQualifierSymbols,
				unboundCallableReference: unboundCallableReference, memberAccessAllowed: memberAccessAllowed, at: r.StartByte,
			}
			validContainers, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, typ, maxIntAtLeastOne(maxResolutionCandidates-len(ids)), access)
			if !complete {
				exhausted, exhaustedBy = true, "#4 if complete "
			}
			for _, instantiated := range validContainers {
				if ctx.Err() != nil {
					return nil
				}
				owner := instantiated.symbol
				if memberAccessAllowed {
					bucket := i.byContainerMember[memberKey(owner.ID, r.Name)]
					if len(bucket) > maxResolutionCandidates-len(ids) {
						exhausted, exhaustedBy = true, "#5 if len(bucket) > maxResolutionCandidates-len(ids) "
						break
					}
					for _, id := range bucket {
						if symbol := i.symbols[id]; i.qualifiedMemberViableLocked(file, access, dot, *symbol) {
							appendID(id)
						}
					}
				}
				if typeQualifier {
					for _, id := range i.binaryNestedTypeIDsLocked(owner, r.Name) {
						if i.accessibleWithMemoLocked(file, *i.symbols[id], access, r.StartByte) {
							appendID(id)
						}
					}
				}
				extensions, complete := i.extensionMemberCandidatesBoundedLocked(owner, r.Name, maxResolutionCandidates-len(ids))
				if !complete {
					exhausted, exhaustedBy = true, "#6 if complete "
					break
				}
				for _, id := range extensions {
					if symbol := i.symbols[id]; i.qualifiedExtensionViableLocked(ctx, file, access, dot, *symbol) {
						appendID(id)
					}
				}
				if qualifiedCompanionMembersViable(file, dot) {
					companionMembers, complete := i.companionMembersForOwnerBoundedLocked(ctx, owner, nil, maxResolutionCandidates-len(ids))
					if !complete {
						exhausted, exhaustedBy = true, "#7 if complete "
						break
					}
					for _, member := range companionMembers {
						if member.Name == r.Name && i.accessibleWithMemoLocked(file, member, access, r.StartByte) {
							appendID(member.ID)
						}
					}
				}
			}
			if complete && len(validContainers) == 0 && file.Language == analysis.LanguageKotlin {
				for _, owner := range spellingReceiverOwners(typ) {
					extensions, complete := i.extensionMemberCandidatesBoundedLocked(owner, r.Name, maxResolutionCandidates-len(ids))
					if !complete {
						exhausted, exhaustedBy = true, "#8 if complete "
						break
					}
					for _, id := range extensions {
						if symbol := i.symbols[id]; i.qualifiedExtensionViableLocked(ctx, file, access, dot, *symbol) {
							appendID(id)
						}
					}
				}
			}
		} else {
			appendIDs(i.byFQN[qualifier+"."+r.Name])
		}
	}
	if exhausted {
		return finishExhausted()
	}
	for _, implicitReceiverType := range implicitReceiverTypes {
		if ctx.Err() != nil {
			return nil
		}
		if implicitReceiverType == "" {
			continue
		}
		hierarchy, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, implicitReceiverType, maxIntAtLeastOne(maxResolutionCandidates-len(ids)), access)
		if !complete {
			exhausted, exhaustedBy = true, "#9 if complete "
			break
		}
		for _, instantiated := range hierarchy {
			owner := instantiated.symbol
			bucket := i.byContainerMember[memberKey(owner.ID, r.Name)]
			if len(bucket) > maxResolutionCandidates-len(ids) {
				exhausted, exhaustedBy = true, "#10 if len(bucket) > maxResolutionCandidates-len(ids) "
				break
			}
			for _, id := range bucket {
				if symbol := i.symbols[id]; i.memberInheritedForReceiverLocked(file, *symbol, implicitReceiverType) && i.accessibleWithMemoLocked(file, *symbol, access, r.StartByte) {
					appendID(id)
				}
			}
			extensions, complete := i.extensionMemberCandidatesBoundedLocked(owner, r.Name, maxResolutionCandidates-len(ids))
			if !complete {
				exhausted, exhaustedBy = true, "#11 if complete "
				break
			}
			for _, id := range extensions {
				if symbol := i.symbols[id]; i.extensionReceiverApplicableLocked(ctx, file, *symbol, implicitReceiverType) && i.accessibleWithMemoLocked(file, *symbol, access, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
					appendID(id)
				}
			}
		}
		if len(hierarchy) == 0 && file.Language == analysis.LanguageKotlin {
			for _, owner := range spellingReceiverOwners(implicitReceiverType) {
				extensions, complete := i.extensionMemberCandidatesBoundedLocked(owner, r.Name, maxResolutionCandidates-len(ids))
				if !complete {
					exhausted, exhaustedBy = true, "#12 if complete "
					break
				}
				for _, id := range extensions {
					if symbol := i.symbols[id]; i.extensionReceiverApplicableLocked(ctx, file, *symbol, implicitReceiverType) && i.accessibleWithMemoLocked(file, *symbol, access, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) {
						appendID(id)
					}
				}
			}
		}
	}
	if exhausted {
		return finishExhausted()
	}
	for _, imp := range relevantImports {
		if imp.Static && file.Language == analysis.LanguageJava {
			if imp.Wildcard || imp.LocalName() == r.Name {
				members, complete := i.staticImportMemberIDsBoundedWithMemoLocked(ctx, file, imp, r.Name, r.StartByte, maxResolutionCandidates-len(ids), access)
				if !complete {
					exhausted, exhaustedBy = true, "#13 if complete "
					break
				}
				appendIDs(members)
			}
			continue
		}
		if !imp.Wildcard && imp.LocalName() == r.Name {
			if qualifier == "" || imp.Alias == "" {
				appendIDs(i.byFQN[imp.Path])
				continue
			}
			// `}.listAsFlow()` through `import ...asFlow as listAsFlow`: a
			// qualified call can only be one of the aliased extensions, and
			// only one whose receiver takes the qualifier.
			for _, id := range i.byFQN[imp.Path] {
				symbol := i.symbols[id]
				if symbol == nil || symbol.ReceiverType == "" {
					continue
				}
				if qualifierType == "" || i.extensionReceiverApplicableLocked(ctx, file, *symbol, qualifierType) {
					appendID(id)
				}
			}
			continue
		}
		if imp.Wildcard {
			appendIDs(i.byFQN[imp.Path+"."+r.Name])
		}
	}
	if file.Package != "" {
		appendIDs(i.byFQN[file.Package+"."+r.Name])
	}
	if r.ContainerID != "" && qualifier == "" {
		instanceReceiver := !i.staticLikeContextLocked(file, r.StartByte)
		for containerID := r.ContainerID; containerID != ""; {
			if ctx.Err() != nil {
				return nil
			}
			c, ok := i.symbols[containerID]
			if !ok {
				break
			}
			bucket := i.byContainerMember[memberKey(c.ID, r.Name)]
			if len(bucket) > maxResolutionCandidates-len(ids) {
				exhausted, exhaustedBy = true, "#14 if len(bucket) > maxResolutionCandidates-len(ids) "
				break
			}
			for _, id := range bucket {
				s := i.symbols[id]
				if (s.ContainerID == c.ID || s.ContainerName == c.Name) && (instanceReceiver || i.staticOrNestedMemberLocked(*s)) {
					appendID(id)
				}
			}
			// A class sees its companion's members as bare names, the
			// companion's private `logger` included.
			if file.Language == analysis.LanguageKotlin && analysis.IsTypeKind(c.Kind) {
				companionMembers, complete := i.companionMembersForOwnerBoundedLocked(ctx, *c, nil, maxResolutionCandidates-len(ids))
				if !complete {
					exhausted, exhaustedBy = true, "companion members of an enclosing class"
					break
				}
				for _, member := range companionMembers {
					if member.Name == r.Name {
						appendID(member.ID)
					}
				}
			}
			nextID := c.ContainerID
			if next, exists := i.symbols[nextID]; exists && analysis.IsTypeKind(c.Kind) && analysis.IsTypeKind(next.Kind) && !nestedTypeCapturesOuter(*c, *next) {
				instanceReceiver = false
			}
			containerID = nextID
		}
	}
	if len(ids) == 0 && qualifier == "" {
		bucket := i.byName[r.Name]
		if len(bucket) > maxResolutionCandidates {
			exhausted, exhaustedBy = true, "#15 if len(bucket) > maxResolutionCandidates "
		}
		for _, id := range bucket {
			if exhausted || ctx.Err() != nil {
				break
			}
			symbol := i.symbols[id]
			if i.accessibleWithMemoLocked(file, *symbol, access, r.StartByte) && i.extensionVisibleLocked(file, *symbol, r.StartByte) && (analysis.IsTypeKind(symbol.Kind) || symbol.ContainerID == "") && i.simpleNameInScopeLocked(file, *symbol) {
				appendID(id)
			}
		}
	}
	if exhausted {
		return finishExhausted()
	}
	if r.Role == analysis.RoleCall {
		for _, id := range append([]string(nil), ids...) {
			if ctx.Err() != nil {
				return nil
			}
			owner := i.symbols[id]
			if !analysis.IsTypeKind(owner.Kind) {
				continue
			}
			constructors := i.byContainerMember[memberKey(owner.ID, owner.Name)]
			if len(constructors) > maxResolutionCandidates-len(ids) {
				return finishExhausted()
			}
			for _, constructorID := range constructors {
				constructor := i.symbols[constructorID]
				if constructor.Kind == analysis.KindConstructor && constructor.ContainerID == owner.ID {
					appendID(constructorID)
				}
			}
		}
	}
	if exhausted || ctx.Err() != nil {
		if exhausted {
			return finishExhausted()
		}
		return nil
	}
	candidates := i.symbolsForIDsLocked(ids, func(s analysis.Symbol) bool {
		if !i.accessibleWithMemoLocked(file, s, access, r.StartByte) || !i.extensionVisibleLocked(file, s, r.StartByte) {
			return false
		}
		if typeQualifier && !unboundCallableReference {
			// `Outer.Nested(1)` calls Nested's constructor: whether the type
			// qualifier reaches it is whether it reaches Nested.
			reached := s
			if s.Kind == analysis.KindConstructor {
				if owner := i.symbols[s.ContainerID]; owner != nil {
					reached = *owner
				}
			}
			if !i.memberAvailableThroughTypeQualifierLocked(file, reached, typeQualifierSymbols) {
				return false
			}
		}
		if !i.protectedReceiverAccessibleLocked(ctx, file, s, r) {
			return false
		}
		if isLexicalSymbol(s) && s.URI == file.URI {
			if s.StartByte > r.StartByte || !symbolInScopeAt(s, r.StartByte) {
				return false
			}
		}
		if r.Role == analysis.RoleCall {
			// `JsonSubTypes.Type(value = X::class, name = "x")` instantiates an
			// annotation inside another's arguments: its "parameters" are its
			// methods, which no declared parameter list records.
			if s.Kind == analysis.KindAnnotation && file.Language == analysis.LanguageKotlin {
				return true
			}
			return (analysis.IsCallableKind(s.Kind) || analysis.IsTypeKind(s.Kind)) && (r.Arity < 0 || matchesArityForLanguage(s, r.Arity, file.Language))
		}
		if r.Role == analysis.RoleType {
			return analysis.IsTypeKind(s.Kind)
		}
		return true
	})
	fromModule := access.fromModule
	sourceSetRank := func(symbol analysis.Symbol) int {
		targetModule, targetSet, _ := i.accessibilityTargetLocked(access, symbol.URI)
		if fromModule == nil || targetModule == nil || fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir {
			return 0
		}
		if distance := i.sourceSetDistanceWithMemoLocked(access, targetModule, targetSet); distance >= 0 {
			return 40 - distance
		}
		return 0
	}
	receiverRanks := map[string]int{}
	if r.Qualifier != "" || len(implicitReceiverTypes) > 0 {
		receiverTypes := implicitReceiverTypes
		if r.Qualifier != "" {
			receiverTypes = []string{i.typeOfExpressionLocked(ctx, file, r.Qualifier, r.StartByte)}
		}
		for _, receiverType := range receiverTypes {
			if receiverType != "" {
				hierarchy, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, receiverType, maxResolutionCandidates, access)
				if !complete {
					return nil
				}
				for _, owner := range hierarchy {
					rank := 1000 - owner.distance
					for _, container := range []string{owner.symbol.Name, owner.symbol.FQN} {
						if container == "" {
							continue
						}
						if previous, exists := receiverRanks[container]; !exists || rank > previous {
							receiverRanks[container] = rank
						}
					}
				}
			}
		}
	}
	resolutionRank := func(candidate analysis.Symbol) int {
		score := sourceSetRank(candidate)
		if explicitImports[candidate.FQN] {
			score += 30
		}
		score += receiverRanks[candidate.ContainerName]
		if owner, ok := i.symbols[candidate.ContainerID]; ok {
			score += receiverRanks[owner.FQN]
		}
		if candidate.ContainerID == r.ContainerID {
			score += 100
		}
		if candidate.URI == file.URI && candidate.StartByte <= r.StartByte && candidate.EndByte >= r.StartByte {
			score += 50
		}
		if candidate.URI == file.URI {
			score += 20
		}
		if candidate.Package == file.Package {
			score += 10
		}
		// Declared before the reference: only meaningful within one file. A
		// library declaration's offset is a position in another document, and
		// comparing it with this one ranked jOOQ's first `mapping` overloads
		// above the rest by where in Records.class they happen to sit.
		if candidate.URI == file.URI && candidate.StartByte <= r.StartByte {
			score += 2
		}
		return score
	}
	// A call candidate that provably cannot take these arguments is out
	// before ranking, not after: ranking keeps only the best-placed group,
	// and when that group was a member the call cannot use -- Gradle's
	// `dependencies(Closure)` before the Kotlin DSL's extension -- nothing
	// was left.
	type compatibility struct {
		score int
		typed bool
	}
	compatibilityOf := make(map[string]compatibility, len(candidates))
	callCompatibility := func(candidate analysis.Symbol) (int, bool) {
		if known, ok := compatibilityOf[candidate.ID]; ok {
			return known.score, known.typed
		}
		score, typed := i.callCompatibilityLocked(ctx, file, r, candidate)
		compatibilityOf[candidate.ID] = compatibility{score, typed}
		return score, typed
	}
	if r.Role == analysis.RoleCall && file.Language == analysis.LanguageKotlin && len(candidates) > 1 {
		viable := make([]analysis.Symbol, 0, len(candidates))
		for _, candidate := range candidates {
			if score, typed := callCompatibility(candidate); typed && score <= -1<<19 {
				continue
			}
			viable = append(viable, candidate)
		}
		if len(viable) > 0 {
			candidates = viable
		}
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		as, bs := resolutionRank(candidates[a]), resolutionRank(candidates[b])
		if as == bs {
			aLexical, bLexical := isLexicalSymbol(candidates[a]), isLexicalSymbol(candidates[b])
			if aLexical && bLexical && candidates[a].URI == file.URI && candidates[b].URI == file.URI {
				if candidates[a].ScopeEndByte != candidates[b].ScopeEndByte {
					// The innermost containing block wins; an inner declaration
					// must stop shadowing as soon as that block ends.
					return candidates[a].ScopeEndByte < candidates[b].ScopeEndByte
				}
				if candidates[a].StartByte != candidates[b].StartByte {
					return candidates[a].StartByte > candidates[b].StartByte
				}
			}
			return candidates[a].FQN < candidates[b].FQN
		}
		return as > bs
	})
	if len(candidates) > 1 {
		best := resolutionRank(candidates[0])
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if resolutionRank(candidate) == best {
				filtered = append(filtered, candidate)
			}
		}
		candidates = preferInnermostLexicalCandidates(filtered, file.URI)
	}
	if callableReference && len(candidates) > 1 {
		if expected, ok := i.callableReferenceExpectedParametersLocked(file, r.StartByte); ok {
			filtered := make([]analysis.Symbol, 0, len(candidates))
			for _, candidate := range candidates {
				if !analysis.IsCallableKind(candidate.Kind) || len(candidate.Parameters) != len(expected) {
					continue
				}
				matches := true
				for index, parameter := range candidate.Parameters {
					left, right := simpleType(parameter.Type), simpleType(expected[index])
					if file.Language == analysis.LanguageJava {
						matches = javaInvocationType(left) == javaInvocationType(right)
					} else {
						matches = sameJvmType(left, right)
					}
					if !matches {
						break
					}
				}
				if matches {
					filtered = append(filtered, candidate)
				}
			}
			candidates = filtered
		}
	}
	if r.Role == analysis.RoleCall && len(candidates) > 0 {
		scores := make([]int, len(candidates))
		typedScores := make([]bool, len(candidates))
		for n, candidate := range candidates {
			if n&31 == 0 && ctx.Err() != nil {
				return nil
			}
			score, typed := callCompatibility(candidate)
			scores[n] = score
			typedScores[n] = typed
		}
		if file.Language == analysis.LanguageKotlin && (qualifier != "" || len(implicitReceiverTypes) > 0) {
			memberApplicable := false
			for n, candidate := range candidates {
				if candidate.ReceiverType == "" && (!typedScores[n] || scores[n] > -1<<19) {
					memberApplicable = true
					break
				}
			}
			if memberApplicable {
				memberCandidates := make([]analysis.Symbol, 0, len(candidates))
				memberScores := make([]int, 0, len(candidates))
				memberTyped := make([]bool, 0, len(candidates))
				for n, candidate := range candidates {
					if candidate.ReceiverType == "" {
						memberCandidates = append(memberCandidates, candidate)
						memberScores = append(memberScores, scores[n])
						memberTyped = append(memberTyped, typedScores[n])
					}
				}
				candidates, scores, typedScores = memberCandidates, memberScores, memberTyped
			}
		}
		bestScore, anyTyped, anyApplicableTyped := -1<<30, false, false
		for n, score := range scores {
			if typedScores[n] {
				anyTyped = true
				if score > -1<<19 && score > bestScore {
					anyApplicableTyped = true
					bestScore = score
				}
			}
		}
		if anyTyped && !anyApplicableTyped {
			return nil
		}
		if anyApplicableTyped {
			filtered := candidates[:0]
			for n, candidate := range candidates {
				if typedScores[n] && scores[n] == bestScore {
					filtered = append(filtered, candidate)
				}
			}
			candidates = i.preferMostSpecificCallCandidatesLocked(ctx, file, filtered)
		}
	}
	return candidates
}

func (i *Index) preferMostSpecificCallCandidatesLocked(ctx context.Context, file *analysis.ParsedFile, candidates []analysis.Symbol) []analysis.Symbol {
	if len(candidates) < 2 {
		return candidates
	}
	moreSpecific := func(left, right analysis.Symbol) bool {
		if len(left.Parameters) != len(right.Parameters) {
			return false
		}
		strict := false
		for index := range left.Parameters {
			leftType := variadicElementType(left.Parameters[index].Type)
			rightType := variadicElementType(right.Parameters[index].Type)
			if sameJvmType(leftType, rightType) {
				continue
			}
			if typeContainsAnyParameter(leftType, left.TypeParameters) && !typeContainsAnyParameter(rightType, right.TypeParameters) {
				return false
			}
			if !i.isSubtypeLocked(ctx, file, leftType, rightType) {
				return false
			}
			strict = true
		}
		if len(left.TypeParameters) < len(right.TypeParameters) {
			strict = true
		}
		leftVariadic, rightVariadic := false, false
		for _, parameter := range left.Parameters {
			leftVariadic = leftVariadic || parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
		}
		for _, parameter := range right.Parameters {
			rightVariadic = rightVariadic || parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
		}
		if !leftVariadic && rightVariadic {
			strict = true
		}
		return strict
	}
	maximal := make([]analysis.Symbol, 0, len(candidates))
	for index, candidate := range candidates {
		dominated := false
		for otherIndex, other := range candidates {
			if index != otherIndex && moreSpecific(other, candidate) {
				dominated = true
				break
			}
		}
		if !dominated {
			maximal = append(maximal, candidate)
		}
	}
	return maximal
}

func preferInnermostLexicalCandidates(candidates []analysis.Symbol, uri protocol.URI) []analysis.Symbol {
	bestEnd, bestStart := 0, 0
	found := false
	for _, candidate := range candidates {
		if candidate.URI != uri || !isLexicalSymbol(candidate) {
			continue
		}
		if !found || candidate.ScopeEndByte < bestEnd || candidate.ScopeEndByte == bestEnd && candidate.StartByte > bestStart {
			bestEnd, bestStart, found = candidate.ScopeEndByte, candidate.StartByte, true
		}
	}
	if !found {
		return candidates
	}
	out := candidates[:0]
	for _, candidate := range candidates {
		if candidate.URI == uri && isLexicalSymbol(candidate) && candidate.ScopeEndByte == bestEnd && candidate.StartByte == bestStart {
			out = append(out, candidate)
		}
	}
	return out
}

func (i *Index) callableReferenceExpectedParametersLocked(file *analysis.ParsedFile, at int) ([]string, bool) {
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	equals := strings.LastIndexByte(source[:at], '=')
	if equals < 0 {
		return nil, false
	}
	start := strings.LastIndexAny(source[:equals], "\n;{}") + 1
	left := strings.TrimSpace(source[start:equals])
	if file.Language == analysis.LanguageKotlin {
		colon := strings.LastIndexByte(left, ':')
		if colon < 0 {
			return nil, false
		}
		target := strings.TrimSpace(left[colon+1:])
		arrow := strings.Index(target, "->")
		if arrow < 0 {
			return nil, false
		}
		parameters := strings.TrimSpace(target[:arrow])
		parameters = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(parameters, "("), ")"))
		if parameters == "" {
			return []string{}, true
		}
		return splitTopLevelTypeArguments(parameters), true
	}
	fields := strings.Fields(left)
	if len(fields) < 2 {
		return nil, false
	}
	target := strings.Join(fields[:len(fields)-1], " ")
	for _, modifier := range []string{"public ", "protected ", "private ", "static ", "final ", "volatile ", "transient "} {
		target = strings.TrimSpace(strings.ReplaceAll(" "+target+" ", " "+modifier, " "))
	}
	base, arguments := splitInstantiatedType(target)
	switch simpleType(base) {
	case "Consumer", "Predicate", "Function", "UnaryOperator":
		if len(arguments) >= 1 {
			return arguments[:1], true
		}
	case "BiConsumer", "BiPredicate", "BiFunction", "BinaryOperator":
		if len(arguments) >= 2 {
			return arguments[:2], true
		}
	case "Supplier", "Runnable":
		return []string{}, true
	}
	if parameters := i.functionalParameterTypesLocked(file, instantiatedTypeName(base, arguments)); parameters != nil {
		return parameters, true
	}
	return nil, false
}

func (i *Index) anonymousObjectMemberIDsBoundedLocked(ctx context.Context, file *analysis.ParsedFile, qualifier, name string, at, limit int) ([]string, bool) {
	qualifier = strings.TrimSpace(qualifier)
	if limit < 0 || strings.ContainsAny(qualifier, ".()[]{} 	\r\n") {
		return nil, limit >= 0
	}
	var owner analysis.Symbol
	candidates := i.fileAnonymousByName[file.URI][qualifier]
	if len(candidates) > maxResolutionCandidates {
		return nil, false
	}
	before := sort.Search(len(candidates), func(index int) bool { return candidates[index].StartByte > at })
	for index := before - 1; index >= 0; index-- {
		if ctx.Err() != nil {
			return nil, false
		}
		symbol := candidates[index]
		if !symbol.InScopeAt(at) {
			continue
		}
		owner = *symbol
		break
	}
	if owner.ID == "" {
		return nil, true
	}
	bucket := i.byContainerName[owner.ID]
	if len(bucket) > limit || len(bucket) > maxResolutionCandidates {
		return nil, false
	}
	ids := make([]string, 0, len(bucket))
	for index, id := range bucket {
		if index&31 == 0 && ctx.Err() != nil {
			return nil, false
		}
		symbol := i.symbols[id]
		if symbol == nil || symbol.ContainerID != owner.ID || name != "" && symbol.Name != name {
			continue
		}
		if analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty || symbol.Kind == analysis.KindField || analysis.IsTypeKind(symbol.Kind) {
			if len(ids) >= limit {
				return nil, false
			}
			ids = append(ids, id)
		}
	}
	return ids, true
}

func (i *Index) resolveAnnotationAttributeLabelLocked(file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	ownerName := AnnotationAttributeOwner(i.documentTextLocked(file.URI), label.StartByte)
	if ownerName == "" {
		return nil
	}
	var ids []string
	for _, owner := range i.resolveTypeSymbolsAtLocked(file, ownerName, label.StartByte) {
		if owner.Kind != analysis.KindAnnotation {
			continue
		}
		for _, id := range i.byContainerMember[memberKey(owner.ID, label.Name)] {
			if symbol := i.symbols[id]; symbol.ContainerID == owner.ID && i.accessibleLocked(file, *symbol, label.StartByte) {
				ids = append(ids, id)
			}
		}
	}
	return i.symbolsForIDsLocked(ids, nil)
}

func (i *Index) memberInheritedForReceiverLocked(file *analysis.ParsedFile, symbol analysis.Symbol, receiverType string) bool {
	if file.Language != analysis.LanguageJava || !containsString(symbol.Modifiers, "static") || symbol.ContainerID == "" {
		return true
	}
	owner, ok := i.symbols[symbol.ContainerID]
	if !ok || owner.Kind != analysis.KindInterface && owner.Kind != analysis.KindAnnotation {
		return true
	}
	for _, receiver := range i.resolveTypeSymbolsLocked(file, receiverType) {
		if receiver.ID == owner.ID {
			return true
		}
	}
	return false
}

func (i *Index) staticImportMemberIDsBoundedWithMemoLocked(ctx context.Context, file *analysis.ParsedFile, imported analysis.Import, name string, at, limit int, access *accessibilityMemo) ([]string, bool) {
	if limit < 0 {
		return nil, false
	}
	ownerName := imported.Path
	if !imported.Wildcard {
		if dot := strings.LastIndexByte(ownerName, '.'); dot >= 0 {
			ownerName = ownerName[:dot]
		}
	}
	var ids []string
	owners := i.resolveTypeSymbolsForOwnerMemoLocked(file, ownerName, analysis.Symbol{}, access)
	if len(owners) > limit {
		return nil, false
	}
	for _, owner := range owners {
		if limit-len(ids) < 1 {
			return nil, false
		}
		hierarchy, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, owner.FQN, limit-len(ids), access)
		if !complete {
			return nil, false
		}
		for _, instantiated := range hierarchy {
			bucket := i.byContainerName[instantiated.symbol.ID]
			if len(bucket) > maxResolutionCandidates {
				return nil, false
			}
			for index, id := range bucket {
				if index&31 == 0 && ctx.Err() != nil {
					return nil, false
				}
				symbol := i.symbols[id]
				if symbol != nil && symbol.Name == name && i.staticOrNestedMemberLocked(*symbol) && i.memberInheritedForReceiverLocked(file, *symbol, owner.FQN) && i.accessibleWithMemoLocked(file, *symbol, access, at) {
					if len(ids) >= limit {
						return nil, false
					}
					ids = append(ids, id)
				}
			}
		}
	}
	return ids, true
}

func maxIntAtLeastOne(value int) int {
	if value < 1 {
		return 1
	}
	return value
}

func (i *Index) javaSwitchLabelReceiverTypeLocked(ctx context.Context, file *analysis.ParsedFile, at int) string {
	if file.Language != analysis.LanguageJava {
		return ""
	}
	source := i.documentTextLocked(file.URI)
	if at > len(source) {
		at = len(source)
	}
	caseAt := strings.LastIndex(source[:at], "case")
	if caseAt < 0 || caseAt > 0 && isIdentRune(rune(source[caseAt-1])) || caseAt+4 < len(source) && isIdentRune(rune(source[caseAt+4])) {
		return ""
	}
	labelPrefix := source[caseAt+4 : at]
	if strings.Contains(labelPrefix, "->") || strings.Contains(labelPrefix, ":") {
		return ""
	}
	switchAt := strings.LastIndex(source[:caseAt], "switch")
	if switchAt < 0 {
		return ""
	}
	openRelative := strings.IndexByte(source[switchAt:caseAt], '(')
	if openRelative < 0 {
		return ""
	}
	open := switchAt + openRelative
	close := matchingDelimiter(source, open, '(', ')')
	if close < 0 || close >= caseAt {
		return ""
	}
	return i.typeOfExpressionLocked(ctx, file, strings.TrimSpace(source[open+1:close]), at)
}

func matchingDelimiter(source string, open int, opening, closing byte) int {
	return lexical.MatchingDelimiter(source, open, string(opening), string(closing), true)
}

func callableReferenceOperatorBefore(source string, start int) bool {
	if start > len(source) {
		start = len(source)
	}
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(source[:start])
		if !unicode.IsSpace(r) {
			break
		}
		start -= size
	}
	return start >= 2 && source[start-2:start] == "::"
}

func (i *Index) resolveArgumentLabelContextLocked(ctx context.Context, file *analysis.ParsedFile, label analysis.Reference) []analysis.Symbol {
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		if document = i.libraryDocs[file.URI]; document != nil {
			i.noteLibraryCacheUse(file.URI)
		}
	}
	if document == nil {
		return nil
	}
	var call *analysis.Reference
	bestSpan := int(^uint(0) >> 1)
	for index := range file.References {
		if index&255 == 0 && ctx.Err() != nil {
			return nil
		}
		candidate := &file.References[index]
		if candidate.Role != analysis.RoleCall || candidate.ArgumentLabel || candidate.StartByte >= label.StartByte {
			continue
		}
		for _, argumentRange := range candidate.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start <= label.StartByte && label.EndByte <= end && end-start < bestSpan {
				call, bestSpan = candidate, end-start
			}
		}
	}
	if call == nil {
		// An annotation argument has no enclosing call reference: the
		// annotation name is recorded as a type, not a call. Its attributes
		// still resolve, against the annotation's own members.
		return i.resolveAnnotationAttributeLocked(file, document, label)
	}
	var out []analysis.Symbol
	for _, callable := range i.resolveContextLocked(ctx, file, *call) {
		if ctx.Err() != nil {
			return nil
		}
		if !analysis.IsCallableKind(callable.Kind) {
			continue
		}
		before := len(out)
		if declaration := i.files[callable.URI]; declaration != nil {
			for _, symbol := range declaration.Symbols {
				if symbol.Kind == analysis.KindParameter && symbol.ContainerID == callable.ID && symbol.Name == label.Name {
					out = append(out, symbol)
				}
			}
		}
		if len(out) > before {
			continue
		}
		for _, parameter := range callable.Parameters {
			if parameter.Name == label.Name {
				out = append(out, analysis.Symbol{
					ID: callable.ID + "#parameter:" + label.Name, Name: label.Name, FQN: callable.FQN + "." + label.Name,
					Kind: analysis.KindParameter, Language: callable.Language, URI: callable.URI,
					Range: parameter.Range, SelectionRange: parameter.Range, ContainerID: callable.ID,
					ContainerName: callable.Name, Package: callable.Package, Type: parameter.Type,
					Signature: label.Name + ": " + parameter.Type, Library: callable.Library,
				})
			}
		}
	}
	return uniqueSymbols(out)
}

// resolveAnnotationAttributeLocked resolves `name` in `@Ann(name = value)` to
// the attribute declared by the annotation type. Java annotations declare them
// as methods and Kotlin ones as constructor parameters, so both member shapes
// are accepted.
func (i *Index) resolveAnnotationAttributeLocked(file *analysis.ParsedFile, document *textdoc.Document, label analysis.Reference) []analysis.Symbol {
	owner := AnnotationAttributeOwner(document.Text, label.StartByte)
	if owner == "" {
		return nil
	}
	var out []analysis.Symbol
	for _, annotation := range i.resolveTypeSymbolsAtLocked(file, owner, label.StartByte) {
		if !analysis.IsTypeKind(annotation.Kind) {
			continue
		}
		for _, memberID := range i.byContainerName[annotation.ID] {
			member := i.symbols[memberID]
			if member == nil || member.ContainerID != annotation.ID || member.Name != label.Name {
				continue
			}
			if analysis.IsCallableKind(member.Kind) || member.Kind == analysis.KindParameter || member.Kind == analysis.KindProperty || member.Kind == analysis.KindField {
				out = append(out, *member)
			}
		}
	}
	return uniqueSymbols(out)
}

func (i *Index) companionMembersForOwnerBoundedLocked(ctx context.Context, owner analysis.Symbol, seen map[string]bool, limit int) ([]analysis.Symbol, bool) {
	if limit < 0 {
		return nil, false
	}
	if seen == nil {
		seen = make(map[string]bool)
	}
	var members []analysis.Symbol
	// Only Kotlin declares companions. The owner's member list is scanned to
	// find them, and its size is no bound on the answer: jOOQ's DSLContext
	// has over 512 methods and no companion, and bounding the scan withheld
	// every call on a DSLContext.
	if owner.Language != analysis.LanguageKotlin {
		return nil, true
	}
	companions := i.byContainerName[owner.ID]
	for index, companionID := range companions {
		if index&31 == 0 && ctx.Err() != nil {
			return nil, false
		}
		companion, ok := i.symbols[companionID]
		if !ok || companion.ContainerID != owner.ID || companion.Kind != analysis.KindObject || !containsString(companion.Modifiers, "companion") {
			continue
		}
		bucket := i.byContainerName[companion.ID]
		if len(bucket) > limit-len(members) || len(bucket) > maxResolutionCandidates {
			return nil, false
		}
		for memberIndex, memberID := range bucket {
			if memberIndex&31 == 0 && ctx.Err() != nil {
				return nil, false
			}
			member, exists := i.symbols[memberID]
			if !exists || member.ContainerID != companion.ID || seen[member.ID] {
				continue
			}
			if len(members) >= limit {
				return nil, false
			}
			seen[member.ID] = true
			members = append(members, *member)
		}
	}
	return members, true
}

// Extension declarations are indexed by their source spelling because their
// receiver can contain generic patterns. These buckets are candidate-only:
// callers must prove applicability against the resolved owner identity before
// returning a symbol.
func (i *Index) extensionMemberCandidatesLocked(owner analysis.Symbol, name string) []string {
	ids, complete := i.extensionMemberCandidatesBoundedLocked(owner, name, maxResolutionCandidates)
	if !complete {
		return nil
	}
	return ids
}

func (i *Index) extensionMemberCandidatesBoundedLocked(owner analysis.Symbol, name string, limit int) ([]string, bool) {
	if limit < 0 {
		return nil, false
	}
	seen := make(map[string]bool)
	var ids []string
	for _, key := range []string{owner.ID, owner.Name, owner.FQN} {
		if key == "" {
			continue
		}
		for _, id := range i.byReceiverMember[memberKey(key, name)] {
			if !seen[id] {
				if len(ids) >= limit {
					return nil, false
				}
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	for _, id := range i.byGenericReceiverMember[name] {
		if !seen[id] {
			if len(ids) >= limit {
				return nil, false
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, true
}

// genericExtensionCandidatesLocked lists extensions whose declared receiver is
// a type parameter, so they apply to any receiver: `let`, `takeIf`, `also` and
// the rest of the standard library's scope functions. They are filed by member
// name rather than by receiver, so completion reaches them through the prefix
// the author has typed; the caller still proves applicability against the
// actual receiver type. An empty prefix is the common case, not an edge:
// editors ask once, right after the dot, and filter what they got as the user
// types, so leaving these out there hid them for good.
func (i *Index) genericExtensionCandidatesLocked(prefix string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	lower := strings.ToLower(prefix)
	ids := make([]string, 0, 8)
	for name, candidates := range i.byGenericReceiverMember {
		if !strings.HasPrefix(strings.ToLower(name), lower) {
			continue
		}
		for _, id := range candidates {
			ids = append(ids, id)
			if len(ids) >= limit {
				return ids
			}
		}
	}
	return ids
}

func (i *Index) extensionCandidatesLocked(owner analysis.Symbol) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, key := range []string{owner.ID, owner.Name, owner.FQN} {
		if key == "" {
			continue
		}
		for _, id := range i.byReceiver[key] {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func sameCallableShape(left, right analysis.Symbol) bool {
	if left.Name != right.Name || len(left.Parameters) != len(right.Parameters) {
		return false
	}
	if left.JVMName != right.JVMName || left.ReceiverType != "" || right.ReceiverType != "" {
		if left.JVMName != right.JVMName || !sameJvmType(left.ReceiverType, right.ReceiverType) {
			return false
		}
	}
	// Alpha-equivalent generic override signatures require substitution through
	// both owners. Until that identity is available, omitting a dispatch-family
	// edge is safer than merging unrelated generic overloads.
	if len(left.TypeParameters) > 0 || len(right.TypeParameters) > 0 {
		return false
	}
	if left.JVMDescriptor != "" && right.JVMDescriptor != "" {
		leftClose, rightClose := strings.IndexByte(left.JVMDescriptor, ')'), strings.IndexByte(right.JVMDescriptor, ')')
		if leftClose < 0 || rightClose < 0 || left.JVMDescriptor[:leftClose+1] != right.JVMDescriptor[:rightClose+1] {
			return false
		}
		// JVM dispatch identity is the erased name and parameter descriptor.
		// Return types may be covariant and therefore are not part of the
		// override-family key.
		return true
	}
	for index := range left.Parameters {
		if left.Parameters[index].Variadic != right.Parameters[index].Variadic || !sameJvmType(left.Parameters[index].Type, right.Parameters[index].Type) {
			return false
		}
	}
	// Return types are covariant (and often omitted in Kotlin source), so they
	// are not part of the override-family key here either.
	return true
}

func (i *Index) protectedReceiverAccessibleLocked(ctx context.Context, file *analysis.ParsedFile, symbol analysis.Symbol, reference analysis.Reference) bool {
	if symbol.Language != analysis.LanguageJava || symbol.Package == file.Package || !containsString(symbol.Modifiers, "protected") {
		return true
	}
	if symbol.ContainerID == "" {
		return false
	}
	current := i.enclosingTypeLocked(file, reference.StartByte)
	if current.ID == "" || !i.containerInheritsLocked(current.ID, symbol.ContainerID) {
		return false
	}
	qualifier := strings.TrimSpace(reference.Qualifier)
	if qualifier == "" || qualifier == "this" || qualifier == "super" {
		return true
	}
	receiverType := i.typeOfExpressionLocked(ctx, file, qualifier, reference.StartByte)
	for _, receiver := range i.resolveTypeSymbolsAtLocked(file, receiverType, reference.StartByte) {
		if receiver.ID == current.ID || i.containerInheritsLocked(receiver.ID, current.ID) {
			return true
		}
	}
	return false
}

func lexicalBinding(file *analysis.ParsedFile, reference analysis.Reference, candidates []analysis.Symbol) string {
	if reference.Qualifier != "" || reference.Role == analysis.RoleImport {
		return ""
	}
	bestID := ""
	bestContainer, bestScope, bestStart := -1, int(^uint(0)>>1), -1
	for _, symbol := range candidates {
		if symbol.URI != file.URI || symbol.Name != reference.Name || !isLexicalSymbol(symbol) || !lexicalCandidateMatches(reference, symbol) {
			continue
		}
		containerScore := 0
		if symbol.ContainerID != "" && symbol.ContainerID == reference.ContainerID {
			containerScore = 1
		}
		scopeSize := symbol.ScopeEndByte - symbol.ScopeStartByte
		if scopeSize <= 0 {
			scopeSize = int(^uint(0) >> 1)
		}
		if containerScore > bestContainer || containerScore == bestContainer && (scopeSize < bestScope || scopeSize == bestScope && symbol.StartByte > bestStart) {
			bestID, bestContainer, bestScope, bestStart = symbol.ID, containerScore, scopeSize, symbol.StartByte
		}
	}
	return bestID
}

func lexicalCandidateMatches(reference analysis.Reference, symbol analysis.Symbol) bool {
	if symbol.NameEndByte > reference.StartByte {
		return false
	}
	if reference.Role == analysis.RoleType && symbol.Kind != analysis.KindTypeParameter || reference.Role != analysis.RoleType && symbol.Kind == analysis.KindTypeParameter {
		return false
	}
	if reference.Role == analysis.RoleLabel && symbol.Kind != analysis.KindLabel || reference.Role != analysis.RoleLabel && symbol.Kind == analysis.KindLabel {
		return false
	}
	return symbolInScopeAt(symbol, reference.StartByte)
}

func symbolInScopeAt(symbol analysis.Symbol, at int) bool {
	return symbol.InScopeAt(at)
}

func expressionQualifierBefore(source string, start int) string {
	if start <= 0 || start > len(source) || source[start-1] != '.' {
		return ""
	}
	if explicit := explicitReceiverSourceBefore(source, start); explicit != "" {
		return explicit
	}
	end, index := start-1, start-2
	parenDepth, bracketDepth, braceDepth, angleDepth := 0, 0, 0, 0
	allowLambdaGap := false
	for index >= 0 {
		value := source[index]
		// A string or character literal is one atom: its closing quote is
		// not an identifier character, so without this a literal receiver
		// ("abc".) had no qualifier at all and completion fell back to every
		// name in scope.
		if (value == '"' || value == '\'') && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 {
			if open := literalStartBefore(source, index); open >= 0 {
				return normalizeQualifier(source[open:end])
			}
		}
		// A fluent chain continues on the next line:
		//
		//	items
		//	    .filter { ... }
		//	    .
		//
		// Whitespace next to a dot belongs to the expression.
		if (value == ' ' || value == '\t' || value == '\r' || value == '\n') && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 && whitespaceContinuesChain(source, index, end) {
			index--
			continue
		}
		switch value {
		case ')':
			parenDepth++
		case '(':
			if parenDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			parenDepth--
		case ']':
			bracketDepth++
		case '[':
			if bracketDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			bracketDepth--
		case '}':
			braceDepth++
		case '{':
			if braceDepth == 0 {
				return strings.TrimSpace(source[index+1 : end])
			}
			braceDepth--
			if braceDepth == 0 {
				allowLambdaGap = true
			}
		case '>':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				angleDepth++
			}
		case '<':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth > 0 {
				angleDepth--
			}
		default:
			lambdaGap := allowLambdaGap && braceDepth == 0 && (value == ' ' || value == '\t' || value == '\r' || value == '\n')
			if !lambdaGap {
				allowLambdaGap = false
			}
			if !lambdaGap && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 && !(isIdentRune(rune(value)) || value == '.' || value == ':' || value == '?' || value == '!' || value == '`') {
				return normalizeQualifier(strings.Trim(strings.TrimSpace(source[index+1:end]), ".?!"))
			}
		}
		index--
	}
	return normalizeQualifier(strings.Trim(strings.TrimSpace(source[:end]), ".?!"))
}

// whitespaceContinuesChain reports whether the whitespace at index sits
// beside a member-access dot (`.` or `?.`) that joins two pieces of one
// expression: either the text to its right (up to end) starts with a dot, or
// the text to its left ends with one.
func whitespaceContinuesChain(source string, index, end int) bool {
	right := index + 1
	for right < end && strings.IndexByte(" \t\r\n", source[right]) >= 0 {
		right++
	}
	if right >= end {
		// The whitespace runs up to the dot being completed. A line break
		// before it means the dot opens a new line of a chain.
		runStart := index
		for runStart > 0 && strings.IndexByte(" \t\r\n", source[runStart-1]) >= 0 {
			runStart--
		}
		return strings.ContainsAny(source[runStart:end], "\r\n")
	}
	if right < end && (source[right] == '.' || source[right] == '?' && right+1 < end && source[right+1] == '.') {
		return true
	}
	left := index
	for left >= 0 && strings.IndexByte(" \t\r\n", source[left]) >= 0 {
		left--
	}
	return left >= 0 && source[left] == '.' && right < end
}

// literalStartBefore returns the offset of the opening quote of the string or
// character literal whose closing quote is at closing, or -1 when the quote is
// not the end of a literal. Raw (""") and escaped quotes are understood;
// templates are skipped as text, which only matters for nesting.
func literalStartBefore(source string, closing int) int {
	quote := source[closing]
	if quote == '"' && closing >= 2 && source[closing-1] == '"' && source[closing-2] == '"' {
		// raw string """..."""
		if open := strings.LastIndex(source[:closing-2], `"""`); open >= 0 {
			return open
		}
		return -1
	}
	for index := closing - 1; index >= 0; index-- {
		if source[index] == '\n' {
			return -1
		}
		if source[index] != quote {
			continue
		}
		backslashes := 0
		for before := index - 1; before >= 0 && source[before] == '\\'; before-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return index
		}
	}
	return -1
}

// normalizeQualifier removes the line breaks and indentation that sit before a
// continuing dot, so a chain written over several lines reads as one expression.
func normalizeQualifier(expression string) string {
	if !strings.ContainsAny(expression, "\r\n") {
		return expression
	}
	var out strings.Builder
	runes := []rune(expression)
	for index := 0; index < len(runes); index++ {
		if runes[index] == '\n' || runes[index] == '\r' {
			next := index
			for next < len(runes) && unicode.IsSpace(runes[next]) {
				next++
			}
			if next < len(runes) && (runes[next] == '.' || runes[next] == '?' && next+1 < len(runes) && runes[next+1] == '.') {
				index = next - 1
				continue
			}
		}
		out.WriteRune(runes[index])
	}
	return strings.TrimSpace(out.String())
}

func explicitReceiverSourceBefore(source string, start int) string {
	end := start - 1
	for end > 0 && unicode.IsSpace(rune(source[end-1])) {
		end--
	}
	prefix := source[:end]
	for _, marker := range []string{"super<", "this@"} {
		if at := strings.LastIndex(prefix, marker); at >= 0 {
			candidate := strings.TrimSpace(prefix[at:])
			if marker == "super<" && strings.HasSuffix(candidate, ">") || marker == "this@" && len(candidate) > len(marker) && !strings.ContainsAny(candidate[len(marker):], " \t\r\n.(){}[]") {
				return candidate
			}
		}
	}
	return ""
}

func explicitReceiverType(qualifier string) string {
	qualifier = strings.TrimSpace(qualifier)
	if strings.HasPrefix(qualifier, "super<") && strings.HasSuffix(qualifier, ">") {
		return strings.TrimSpace(qualifier[len("super<") : len(qualifier)-1])
	}
	if strings.HasPrefix(qualifier, "this@") {
		return strings.TrimSpace(strings.TrimPrefix(qualifier, "this@"))
	}
	if strings.HasSuffix(qualifier, ".super") {
		return strings.TrimSuffix(qualifier, ".super")
	}
	if strings.HasSuffix(qualifier, ".this") {
		return strings.TrimSuffix(qualifier, ".this")
	}
	return ""
}

func isLexicalSymbol(symbol analysis.Symbol) bool {
	return symbol.Kind == analysis.KindVariable || symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindTypeParameter || symbol.Kind == analysis.KindLabel ||
		symbol.Kind == analysis.KindProperty && symbol.ScopeEndByte > symbol.EndByte
}

func (i *Index) callCompatibilityLocked(ctx context.Context, file *analysis.ParsedFile, ref analysis.Reference, candidate analysis.Symbol) (int, bool) {
	doc := i.docs[file.URI]
	if doc == nil {
		doc = i.indexedDocs[file.URI]
	}
	if doc == nil {
		return 0, false
	}
	if len(ref.Arguments) == 0 && ref.Arity > 0 {
		// Synthetic references built by type inference carry the argument
		// count but no argument ranges. Arity still rules out candidates, yet
		// there is no argument text to type, so this is not type evidence.
		if !matchesArityForLanguage(candidate, ref.Arity, file.Language) {
			return -1 << 20, true
		}
		return 0, false
	}
	if len(candidate.Parameters) == 0 {
		return 16, len(ref.Arguments) == 0
	}
	required, variadicCallable := 0, false
	for _, parameter := range candidate.Parameters {
		variadic := parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
		variadicCallable = variadicCallable || variadic
		if !variadic && parameter.Default == "" {
			required++
		}
	}
	if len(ref.Arguments) < required || !variadicCallable && len(ref.Arguments) > len(candidate.Parameters) {
		return -1 << 20, true
	}
	score, typed := 0, true
	ownerBindings, ownerBindingsKnown := i.receiverOwnerTypeBindingsLocked(ctx, file, ref, candidate)
	provided := make(map[int]bool, len(ref.Arguments))
	inferredTypeParameters := make(map[string]string, len(candidate.TypeParameters))
	for n, argumentRange := range ref.Arguments {
		parameterIndex := n
		expression := doc.Slice(argumentRange)
		if name, value, named := namedArgument(expression); named {
			parameterIndex = -1
			for index, parameter := range candidate.Parameters {
				if parameter.Name == name {
					parameterIndex = index
					break
				}
			}
			if parameterIndex < 0 {
				// A named argument makes a candidate without that parameter
				// inapplicable even when its positional types happen to match.
				return -1 << 20, true
			}
			expression = value
		}
		if parameterIndex >= len(candidate.Parameters) {
			parameterIndex = len(candidate.Parameters) - 1
		}
		provided[parameterIndex] = true
		parameter := candidate.Parameters[parameterIndex]
		// Spelled as the declaring file spelled it: `UUID` in ColorDto.kt is an
		// import the call site need not share.
		expectedType := strings.TrimSpace(substituteTypeBindings(i.respellDeclaredTypeLocked(file, candidate, parameter.Type), ownerBindings))
		if parameter.Variadic || strings.Contains(expectedType, "...") || strings.Contains(expectedType, "vararg") {
			expectedType = variadicElementType(expectedType)
		}
		if lambdaTypes, explicitLambda := explicitLambdaParameterTypes(expression, file.Language); explicitLambda {
			expectedParameters := kotlinFunctionParameterTypes(expectedType)
			if file.Language == analysis.LanguageJava {
				expectedParameters = i.functionalParameterTypesLocked(file, expectedType)
			}
			if len(expectedParameters) != len(lambdaTypes) {
				return -1 << 20, true
			}
			for index := range lambdaTypes {
				matches, known := i.typesIdenticalAtLocked(file, lambdaTypes[index], expectedParameters[index], ref.StartByte)
				if !known {
					typed = false
					continue
				}
				if !matches {
					return -1 << 20, true
				}
			}
			score += 48
			continue
		}
		// `mapping(Product::create)`: a callable reference fits a function
		// type only with as many parameters as the referenced function takes.
		// jOOQ overloads `mapping` for Function1 to Function22 and nothing
		// else tells them apart.
		if file.Language == analysis.LanguageKotlin {
			if reference := callableReferenceArgument.FindStringSubmatch(strings.TrimSpace(expression)); reference != nil && reference[2] != "class" {
				expectedParameters := kotlinFunctionParameterTypes(expectedType)
				functional := expectedParameters != nil || strings.Contains(expectedType, "->")
				if !functional {
					if sam := i.samFunctionTypeLocked(candidate, expectedType); sam != "" {
						expectedParameters, functional = kotlinFunctionParameterTypes(sam), true
					}
				}
				if functional {
					arities := i.callableReferenceAritiesLocked(ctx, file, reference[1], reference[2], ref.StartByte)
					if len(arities) > 0 {
						if !arities[len(expectedParameters)] {
							return -1 << 20, true
						}
						score += 40
						continue
					}
				}
			}
		}
		// `dependencies { implementation(...) }` has no arrow, but braces make
		// it a lambda all the same, and a lambda never converts to a class:
		// Gradle's `dependencies(Closure)` is not the Kotlin DSL's call.
		if trimmed := strings.TrimSpace(expression); file.Language == analysis.LanguageKotlin && strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") &&
			len(kotlinFunctionParameterTypes(expectedType)) == 0 && !strings.Contains(expectedType, "->") && i.samFunctionTypeLocked(candidate, expectedType) == "" && i.provablyNotFunctionalLocked(candidate, expectedType) {
			return -1 << 20, true
		}
		if lambdaArity, lambda := untypedLambdaArity(expression); lambda {
			expectedParameters := kotlinFunctionParameterTypes(expectedType)
			if file.Language == analysis.LanguageJava {
				expectedParameters = i.functionalParameterTypesLocked(file, expectedType)
			}
			if expectedParameters == nil && file.Language == analysis.LanguageKotlin {
				if sam := i.samFunctionTypeLocked(candidate, expectedType); sam != "" {
					expectedParameters = kotlinFunctionParameterTypes(sam)
				} else if i.provablyNotFunctionalLocked(candidate, expectedType) {
					// `dependencies(Closure)` from Kotlin: a lambda is no
					// Groovy Closure, so the Kotlin DSL's extension is the call.
					return -1 << 20, true
				}
			}
			if expectedParameters == nil {
				typed = false
				continue
			}
			if len(expectedParameters) != lambdaArity {
				return -1 << 20, true
			}
			score += 40
			continue
		}
		if file.Language == analysis.LanguageKotlin && strings.TrimSpace(expression) == "null" {
			if strings.HasSuffix(expectedType, "?") {
				score += 40
				continue
			}
			return -1 << 20, true
		}
		if file.Language == analysis.LanguageJava && strings.TrimSpace(expression) == "null" {
			if javaPrimitiveType(expectedType) {
				return -1 << 20, true
			}
			score += 28
			continue
		}
		inferred := i.inferExpressionResultLocked(ctx, file, expression, ref.StartByte)
		actualType := strings.TrimSpace(inferred.Type)
		if inferred.Expression.Kind == expressionUnknown || inferred.Expression.Kind == expressionBlock {
			typed = false
		}
		if file.Language == analysis.LanguageKotlin && strings.HasSuffix(actualType, "?") && !strings.HasSuffix(expectedType, "?") {
			return -1 << 20, true
		}
		actual := simpleType(actualType)
		expected := simpleType(expectedType)
		if actual == "" || expected == "" {
			typed = false
			continue
		}
		if inferred.Confidence == inferenceExact {
			score += 2
		}
		if typeContainsAnyParameter(expectedType, candidate.TypeParameters) {
			if !i.inferTypeParameterBindingsLocked(ctx, file, expectedType, actualType, candidate.TypeParameters, inferredTypeParameters) {
				typed = false
				continue
			}
			if substituted := substituteTypeBindings(expectedType, inferredTypeParameters); substituted != expectedType && !i.typePatternApplicableLocked(ctx, file, substituted, actualType) {
				return -1 << 20, true
			}
			// A solved type variable is applicable evidence but is less specific
			// than an otherwise equal concrete parameter.
			score += 28
			continue
		}
		// `Field<T>.eq(T)` on a receiver whose binding of T was not worked out:
		// the expected type is still the owner's type variable, which says
		// nothing about this argument -- it is not a mismatch.
		if owner := i.symbols[candidate.ContainerID]; owner != nil && typeContainsAnyParameter(expectedType, owner.TypeParameters) {
			typed = false
			continue
		}
		identity, identityKnown := i.typesIdenticalAtLocked(file, actualType, expectedType, ref.StartByte)
		if identity {
			score += 32
		} else if file.Language == analysis.LanguageKotlin {
			if conversion, ok := kotlinIntegerLiteralConversionScore(expression, expected); ok {
				score += conversion
			} else if subtype, known := i.subtypeRelationAtLocked(ctx, file, actualType, expectedType, ref.StartByte); subtype {
				score += 24
			} else if !known || !identityKnown {
				typed = false
				continue
			} else {
				return -1 << 20, true
			}
		} else if subtype, known := i.subtypeRelationAtLocked(ctx, file, actualType, expectedType, ref.StartByte); subtype {
			score += 24
		} else if file.Language == analysis.LanguageJava {
			if conversion, ok := javaConstantInvocationConversionScore(expression, expected); ok {
				score += conversion
			} else if conversion, ok := javaInvocationConversionScore(actual, expected); ok {
				score += conversion
			} else if !known || !identityKnown {
				typed = false
				continue
			} else {
				return -1 << 20, true
			}
		}
	}
	for _, parameter := range candidate.TypeParameters {
		inferred := inferredTypeParameters[parameter]
		if inferred == "" {
			typed = false
			continue
		}
		bounds := candidate.TypeParameterBounds[parameter]
		if len(ownerBindings) > 0 {
			bounds = append([]string(nil), bounds...)
			for index := range bounds {
				bounds[index] = substituteTypeBindings(bounds[index], ownerBindings)
			}
		}
		owner := i.symbols[candidate.ContainerID]
		unresolvedOwnerBound := false
		if owner != nil {
			for _, bound := range bounds {
				if typeContainsAnyParameter(bound, owner.TypeParameters) {
					unresolvedOwnerBound = true
					break
				}
			}
		}
		if unresolvedOwnerBound {
			typed = false
			continue
		}
		if !i.typeArgumentSatisfiesBoundsLocked(ctx, file, inferred, bounds) {
			return -1 << 20, true
		}
	}
	if owner := i.symbols[candidate.ContainerID]; owner != nil && len(owner.TypeParameters) > 0 {
		for _, parameter := range owner.TypeParameters {
			if ownerBindingsKnown && ownerBindings[parameter] != "" {
				continue
			}
			for _, value := range candidate.Parameters {
				if typeContainsAnyParameter(value.Type, []string{parameter}) {
					typed = false
				}
			}
			if typeContainsAnyParameter(candidate.Type, []string{parameter}) {
				typed = false
			}
		}
	}
	defaultsUsed, variadic := 0, false
	for index, parameter := range candidate.Parameters {
		if !provided[index] && parameter.Default != "" {
			defaultsUsed++
		}
		variadic = variadic || parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
	}
	if len(ref.Arguments) == len(candidate.Parameters) {
		score += 16
	}
	score -= defaultsUsed * 4
	if variadic {
		score -= 2
	}
	// Preserve an earlier unknown-expression result. Arity/default ranking can
	// order otherwise applicable candidates, but it is not type evidence and
	// must not turn an untyped overload tie into a unique semantic answer.
	return score, typed
}

// receiverOwnerTypeBindingsLocked recovers the concrete arguments of the
// declaration owner reached through the call receiver. A method can introduce
// its own type parameter bounded by an owner parameter (CrudRepository's
// `<S extends T> S save(S)` is the common example); checking `S` against the
// literal spelling `T` incorrectly rejects an otherwise proven call.
func (i *Index) receiverOwnerTypeBindingsLocked(ctx context.Context, file *analysis.ParsedFile, ref analysis.Reference, candidate analysis.Symbol) (map[string]string, bool) {
	owner := i.symbols[candidate.ContainerID]
	if owner == nil || len(owner.TypeParameters) == 0 {
		return nil, true
	}
	qualifier := strings.TrimSpace(ref.Qualifier)
	if qualifier != "" {
		if text := i.documentTextLocked(file.URI); text != "" {
			if textual := expressionQualifierBefore(text, ref.StartByte); textual != "" {
				qualifier = textual
			}
		}
	}
	if qualifier == "" {
		return nil, false
	}
	receiverType := i.inferExpressionTypeLocked(ctx, file, qualifier, ref.StartByte)
	if receiverType == "" {
		return nil, false
	}
	var found map[string]string
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(ctx, file, receiverType) {
		if instantiated.symbol.ID != owner.ID || len(instantiated.arguments) != len(owner.TypeParameters) {
			continue
		}
		bindings := make(map[string]string, len(owner.TypeParameters))
		for index, parameter := range owner.TypeParameters {
			bindings[parameter] = instantiated.arguments[index]
		}
		if found == nil {
			found = bindings
			continue
		}
		for parameter, value := range bindings {
			if found[parameter] != value {
				return nil, false
			}
		}
	}
	return found, found != nil
}

func typeContainsAnyParameter(value string, parameters []string) bool {
	for index := 0; index < len(value); {
		if !isIdentRune(rune(value[index])) {
			index++
			continue
		}
		end := index + 1
		for end < len(value) && isIdentRune(rune(value[end])) {
			end++
		}
		for _, parameter := range parameters {
			if value[index:end] == parameter {
				return true
			}
		}
		index = end
	}
	return false
}

func (i *Index) typePatternApplicableLocked(ctx context.Context, file *analysis.ParsedFile, expected, actual string) bool {
	if sameJvmType(expected, actual) || i.isSubtypeLocked(ctx, file, actual, expected) {
		return true
	}
	expectedBase, expectedArguments := splitInstantiatedType(expected)
	for _, owner := range i.instantiatedTypeHierarchyLocked(ctx, file, actual) {
		if !sameJvmType(owner.symbol.Name, expectedBase) && !sameJvmType(owner.symbol.FQN, expectedBase) || len(owner.arguments) != len(expectedArguments) {
			continue
		}
		matches := true
		for index := range expectedArguments {
			if !sameJvmType(owner.arguments[index], expectedArguments[index]) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func variadicElementType(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "vararg "))
	if strings.HasSuffix(value, "...") {
		return strings.TrimSpace(strings.TrimSuffix(value, "..."))
	}
	if strings.HasSuffix(value, "[]") {
		return strings.TrimSpace(strings.TrimSuffix(value, "[]"))
	}
	return value
}

func untypedLambdaArity(expression string) (int, bool) {
	arrow := topLevelExpressionOperator(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expression), "{")), "->")
	if arrow < 0 {
		return 0, false
	}
	prefix := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expression), "{"))
	prefix = strings.TrimSpace(prefix[:arrow])
	if strings.HasPrefix(prefix, "(") && strings.HasSuffix(prefix, ")") {
		prefix = strings.TrimSpace(prefix[1 : len(prefix)-1])
	}
	if prefix == "" {
		return 0, true
	}
	parameters := splitTopLevelCallArguments(prefix)
	for _, parameter := range parameters {
		if strings.Contains(parameter, ":") || len(strings.Fields(parameter)) > 1 {
			return 0, false
		}
	}
	return len(parameters), true
}

func javaPrimitiveType(value string) bool {
	switch javaInvocationType(value) {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return true
	default:
		return false
	}
}

func javaConstantInvocationConversionScore(expression, expected string) (int, bool) {
	expected = javaInvocationType(expected)
	if expected != "byte" && expected != "short" && expected != "char" {
		return 0, false
	}
	value, ok := javaIntLiteralValue(strings.TrimSpace(expression))
	if !ok {
		return 0, false
	}
	low, high := int64(-128), int64(127)
	if expected == "short" {
		low, high = -32768, 32767
	} else if expected == "char" {
		low, high = 0, 65535
	}
	if value < low || value > high {
		return 0, false
	}
	return 22, true
}

func explicitLambdaParameterTypes(expression string, language analysis.Language) ([]string, bool) {
	expression = strings.TrimSpace(expression)
	arrow := strings.Index(expression, "->")
	if arrow < 0 {
		return nil, false
	}
	prefix := strings.TrimSpace(expression[:arrow])
	prefix = strings.TrimSpace(strings.TrimPrefix(prefix, "{"))
	if strings.HasPrefix(prefix, "(") && strings.HasSuffix(prefix, ")") {
		prefix = strings.TrimSpace(prefix[1 : len(prefix)-1])
	}
	if prefix == "" {
		return []string{}, true
	}
	parameters := splitTopLevelCallArguments(prefix)
	types := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		parameter = strings.TrimSpace(parameter)
		if language == analysis.LanguageKotlin {
			colon := topLevelExpressionOperator(parameter, ":")
			if colon < 0 {
				return nil, false
			}
			typ := strings.TrimSpace(parameter[colon+1:])
			if typ == "" {
				return nil, false
			}
			types = append(types, typ)
			continue
		}
		fields := strings.Fields(parameter)
		filtered := fields[:0]
		for _, field := range fields {
			if field != "final" && !strings.HasPrefix(field, "@") {
				filtered = append(filtered, field)
			}
		}
		if len(filtered) < 2 {
			return nil, false
		}
		types = append(types, strings.Join(filtered[:len(filtered)-1], " "))
	}
	return types, true
}

func (i *Index) typeArgumentSatisfiesBoundsLocked(ctx context.Context, file *analysis.ParsedFile, actual string, bounds []string) bool {
	memo, _ := ctx.Value(receiverSpellingsKey{}).(*receiverSpellingsMemo)
	for _, bound := range bounds {
		if sameJvmType(actual, bound) {
			continue
		}
		key := string(file.URI) + "\x00" + actual + "\x00" + bound
		if memo != nil {
			memo.mu.Lock()
			known, ok := memo.subtypes[key]
			memo.mu.Unlock()
			if ok {
				if !known {
					return false
				}
				continue
			}
		}
		subtype := i.isSubtypeLocked(ctx, file, actual, bound)
		if memo != nil && ctx.Err() == nil {
			memo.mu.Lock()
			if len(memo.subtypes) < 4096 {
				memo.subtypes[key] = subtype
			}
			memo.mu.Unlock()
		}
		if !subtype {
			return false
		}
	}
	return true
}

func kotlinIntegerLiteralConversionScore(expression, expected string) (int, bool) {
	expression = strings.ReplaceAll(strings.TrimSpace(expression), "_", "")
	if expression == "" || strings.ContainsAny(expression, ".eEfF") {
		return 0, false
	}
	lower := strings.ToLower(expression)
	if strings.HasSuffix(lower, "l") || strings.HasSuffix(lower, "u") || strings.HasSuffix(lower, "ul") || strings.HasSuffix(lower, "lu") {
		return 0, false
	}
	value, ok := new(big.Int).SetString(expression, 0)
	if !ok {
		return 0, false
	}
	bits, signed := 0, true
	switch simpleType(expected) {
	case "Byte":
		bits = 8
	case "Short":
		bits = 16
	case "Int":
		bits = 32
	case "Long":
		bits = 64
	case "UByte":
		bits, signed = 8, false
	case "UShort":
		bits, signed = 16, false
	case "UInt":
		bits, signed = 32, false
	case "ULong":
		bits, signed = 64, false
	default:
		return 0, false
	}
	if !signed {
		return 28, value.Sign() >= 0 && value.BitLen() <= bits
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	minimum := new(big.Int).Neg(new(big.Int).Set(limit))
	maximum := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
	return 28, value.Cmp(minimum) >= 0 && value.Cmp(maximum) <= 0
}

func namedArgument(expression string) (name, value string, ok bool) {
	expression = strings.TrimSpace(expression)
	for index := 0; index < len(expression); index++ {
		if expression[index] != '=' || index+1 < len(expression) && expression[index+1] == '=' || index > 0 && strings.ContainsRune("=!<>", rune(expression[index-1])) {
			continue
		}
		candidate := strings.TrimSpace(expression[:index])
		if candidate == "" {
			return "", "", false
		}
		for offset, char := range candidate {
			if !(char == '_' || char == '`' || unicode.IsLetter(char) || offset > 0 && unicode.IsDigit(char)) {
				return "", "", false
			}
		}
		return strings.Trim(candidate, "`"), strings.TrimSpace(expression[index+1:]), true
	}
	return "", "", false
}

func sameJvmType(a, b string) bool {
	return canonicalJvmType(a) == canonicalJvmType(b)
}

func (i *Index) typesIdenticalAtLocked(file *analysis.ParsedFile, left, right string, at int) (bool, bool) {
	leftID, leftKnown := i.exactTypeIdentityAtLocked(file, left, at, 0)
	rightID, rightKnown := i.exactTypeIdentityAtLocked(file, right, at, 0)
	if !leftKnown || !rightKnown {
		return false, false
	}
	return leftID == rightID, true
}

// exactTypeIdentityAtLocked resolves user types to stable symbol identities.
// Textual simple names are never equality evidence: two imports can expose the
// same spelling from unrelated packages. Builtins are used only as a fallback
// after scoped symbol lookup has found no declaration.
func (i *Index) exactTypeIdentityAtLocked(file *analysis.ParsedFile, value string, at, depth int) (string, bool) {
	if file == nil || depth > 16 {
		return "", false
	}
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"out ", "in ", "? extends ", "? super "} {
		value = strings.TrimPrefix(value, prefix)
	}
	nullable := strings.HasSuffix(value, "?")
	value = strings.TrimSuffix(value, "?")
	arrays := 0
	for strings.HasSuffix(value, "[]") {
		arrays++
		value = strings.TrimSpace(strings.TrimSuffix(value, "[]"))
	}
	base, arguments := splitInstantiatedType(value)
	base = strings.TrimSpace(base)
	if base == "" {
		return "", false
	}
	var symbols []analysis.Symbol
	if at >= 0 {
		symbols = i.resolveTypeSymbolsAtLocked(file, base, at)
	} else {
		symbols = i.resolveTypeSymbolsLocked(file, base)
	}
	identity := ""
	if len(symbols) == 1 {
		identity = "symbol:" + symbols[0].ID
		if platform, ok := jvmPlatformIdentity(symbols[0].FQN); ok {
			identity = "jvm:" + platform
		}
	} else if len(symbols) > 1 {
		return "", false
	} else if builtin, ok := builtinTypeIdentity(file.Language, base); ok {
		identity = "builtin:" + builtin
		if platform, ok := jvmPlatformIdentity(builtin); ok {
			identity = "jvm:" + platform
		}
	} else {
		return "", false
	}
	for _, argument := range arguments {
		argument = strings.TrimSpace(argument)
		if argument == "*" || argument == "?" {
			identity += "<*>"
			continue
		}
		argumentID, ok := i.exactTypeIdentityAtLocked(file, argument, at, depth+1)
		if !ok {
			return "", false
		}
		identity += "<" + argumentID + ">"
	}
	if nullable {
		identity += "?"
	}
	return strings.Repeat("[]", arrays) + identity, true
}

// jvmPlatformIdentity maps a resolved type name to the JVM class it denotes
// when Kotlin and Java spell the same class differently: kotlin.String and
// java.lang.String are one class, kotlin.collections.List is java.util.List,
// Int is int (or its box). Only names in the platform mapping qualify; every
// other resolved declaration keeps its symbol identity.
func jvmPlatformIdentity(name string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "java.lang.integer":
		return "int", true
	case "java.lang.long":
		return "long", true
	case "java.lang.short":
		return "short", true
	case "java.lang.byte":
		return "byte", true
	case "java.lang.float":
		return "float", true
	case "java.lang.double":
		return "double", true
	case "java.lang.character":
		return "char", true
	case "java.lang.boolean":
		return "boolean", true
	}
	switch canonical := canonicalJvmType(name); canonical {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return canonical, true
	}
	if alias, ok := jvmTypeAliases[lower]; ok {
		return alias, true
	}
	if jvmPlatformClasses[lower] {
		return lower, true
	}
	return "", false
}

// jvmPlatformClasses is the set of JVM classes the alias table maps onto, so
// a declaration spelled by that class itself (java.lang.CharSequence from the
// JDK) shares the identity of the Kotlin names mapped to it.
var jvmPlatformClasses = func() map[string]bool {
	classes := make(map[string]bool, len(jvmTypeAliases))
	for _, alias := range jvmTypeAliases {
		classes[alias] = true
	}
	return classes
}()

// jvmSameClass reports whether two resolved type symbols denote one JVM
// class, by identity or through the Kotlin/Java platform mapping.
func jvmSameClass(left, right analysis.Symbol) bool {
	if left.ID == right.ID {
		return true
	}
	leftPlatform, leftOK := jvmPlatformIdentity(left.FQN)
	rightPlatform, rightOK := jvmPlatformIdentity(right.FQN)
	return leftOK && rightOK && leftPlatform == rightPlatform
}

// referenceSpelledAt reports whether the document spells the reference's own
// name at its byte range, which distinguishes a parsed reference from a
// synthetic one that reuses another reference's position.
func referenceSpelledAt(text string, r analysis.Reference) bool {
	return r.StartByte >= 0 && r.EndByte <= len(text) && r.StartByte < r.EndByte && text[r.StartByte:r.EndByte] == r.Name
}

func builtinTypeIdentity(language analysis.Language, base string) (string, bool) {
	if language == analysis.LanguageJava {
		switch base {
		case "byte", "short", "int", "long", "float", "double", "char", "boolean", "void":
			return base, true
		}
		// java.lang is implicitly imported by every compilation unit. Scoped
		// lookup runs first, so a declaration shadowing one of these names
		// still wins; the fallback only names the class the JLS guarantees.
		simple := strings.TrimPrefix(base, "java.lang.")
		switch simple {
		case "Object", "String", "CharSequence", "Number", "Integer", "Long", "Short", "Byte", "Float", "Double", "Character", "Boolean", "Void", "Class", "Iterable", "Comparable", "Runnable", "Throwable", "Exception", "RuntimeException", "Error", "StringBuilder", "Enum", "Record", "Thread", "Math", "System":
			return "java.lang." + simple, true
		}
	} else if language == analysis.LanguageKotlin {
		switch base {
		case "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double", "UByte", "UShort", "UInt", "ULong", "String", "Any", "Unit", "Nothing":
			return "kotlin." + base, true
		}
		if strings.HasPrefix(base, "kotlin.") {
			switch strings.TrimPrefix(base, "kotlin.") {
			case "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double", "UByte", "UShort", "UInt", "ULong", "String", "Any", "Unit", "Nothing":
				return base, true
			}
		}
	}
	return "", false
}

func canonicalJvmType(value string) string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"out ", "in ", "? extends ", "? super "} {
		value = strings.TrimPrefix(value, prefix)
	}
	value = strings.TrimSuffix(value, "?")
	arrays := 0
	for strings.HasSuffix(value, "[]") {
		arrays++
		value = strings.TrimSpace(strings.TrimSuffix(value, "[]"))
	}
	if open := strings.IndexByte(value, '<'); open >= 0 {
		value = strings.TrimSpace(value[:open])
	}
	base := value
	lower := strings.ToLower(value)
	switch lower {
	case "byte", "kotlin.byte":
		base = "byte"
	case "short", "kotlin.short":
		base = "short"
	case "int", "kotlin.int":
		base = "int"
	case "long", "kotlin.long":
		base = "long"
	case "float", "kotlin.float":
		base = "float"
	case "double", "kotlin.double":
		base = "double"
	case "char", "kotlin.char":
		base = "char"
	case "boolean", "kotlin.boolean":
		base = "boolean"
	default:
		// Only known language aliases are case-folded. JVM package and class
		// identifiers themselves are case-sensitive.
		if alias := jvmTypeAliases[lower]; alias != "" {
			base = alias
		}
	}
	if alias := jvmTypeAliases[strings.ToLower(base)]; alias != "" {
		base = alias
	}
	return base + strings.Repeat("[]", arrays)
}

var jvmTypeAliases = map[string]string{
	"java.lang.string":                     "java.lang.string",
	"string":                               "java.lang.string",
	"kotlin.string":                        "java.lang.string",
	"any":                                  "java.lang.object",
	"kotlin.any":                           "java.lang.object",
	"object":                               "java.lang.object",
	"charsequence":                         "java.lang.charsequence",
	"kotlin.charsequence":                  "java.lang.charsequence",
	"number":                               "java.lang.number",
	"kotlin.number":                        "java.lang.number",
	"throwable":                            "java.lang.throwable",
	"kotlin.throwable":                     "java.lang.throwable",
	"iterable":                             "java.lang.iterable",
	"java.lang.iterable":                   "java.lang.iterable",
	"kotlin.collections.iterable":          "java.lang.iterable",
	"collection":                           "java.util.collection",
	"java.util.collection":                 "java.util.collection",
	"kotlin.collections.collection":        "java.util.collection",
	"kotlin.collections.mutablecollection": "java.util.collection",
	"list":                                 "java.util.list",
	"java.util.list":                       "java.util.list",
	"kotlin.collections.list":              "java.util.list",
	"kotlin.collections.mutablelist":       "java.util.list",
	"set":                                  "java.util.set",
	"java.util.set":                        "java.util.set",
	"kotlin.collections.set":               "java.util.set",
	"kotlin.collections.mutableset":        "java.util.set",
	"map":                                  "java.util.map",
	"java.util.map":                        "java.util.map",
	"kotlin.collections.map":               "java.util.map",
	"kotlin.collections.mutablemap":        "java.util.map",
}

func javaInvocationConversionScore(actual, expected string) (int, bool) {
	actual, expected = javaInvocationType(actual), javaInvocationType(expected)
	primitiveWidening := map[string][]string{
		"byte":  {"short", "int", "long", "float", "double"},
		"short": {"int", "long", "float", "double"},
		"char":  {"int", "long", "float", "double"},
		"int":   {"long", "float", "double"},
		"long":  {"float", "double"},
		"float": {"double"},
	}
	for distance, candidate := range primitiveWidening[actual] {
		if candidate == expected {
			return 20 - distance, true
		}
	}
	boxed := map[string]string{
		"byte": "java.lang.byte", "short": "java.lang.short", "int": "java.lang.integer", "long": "java.lang.long",
		"float": "java.lang.float", "double": "java.lang.double", "char": "java.lang.character", "boolean": "java.lang.boolean",
	}
	if wrapper := boxed[actual]; wrapper != "" {
		if expected == wrapper {
			return 12, true
		}
		if expected == "java.lang.object" || expected == "java.lang.number" && actual != "char" && actual != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			return 8, true
		}
	}
	unboxed := map[string]string{}
	for primitive, wrapper := range boxed {
		unboxed[wrapper] = primitive
	}
	if primitive := unboxed[actual]; primitive != "" {
		if expected == "java.lang.object" || expected == "java.lang.number" && primitive != "char" && primitive != "boolean" || expected == "java.io.serializable" || expected == "java.lang.comparable" {
			// Widening reference conversion is a strict-invocation candidate and
			// therefore wins before loose unboxing/widening is considered.
			return 24, true
		}
		if primitive == expected {
			return 12, true
		}
		for distance, candidate := range primitiveWidening[primitive] {
			if candidate == expected {
				return 10 - distance, true
			}
		}
	}
	if actual == "java.lang.string" && (expected == "java.lang.object" || expected == "java.lang.charsequence" || expected == "java.io.serializable" || expected == "java.lang.comparable") {
		return 16, true
	}
	return 0, false
}

func javaInvocationType(value string) string {
	value = simpleType(value)
	switch value {
	case "byte", "short", "int", "long", "float", "double", "char", "boolean":
		return value
	case "Byte", "Short", "Integer", "Long", "Float", "Double", "Character", "Boolean":
		return "java.lang." + strings.ToLower(value)
	case "integer":
		return "java.lang.integer"
	case "character":
		return "java.lang.character"
	case "String", "string":
		return "java.lang.string"
	case "Object", "Number", "Comparable", "CharSequence":
		return "java.lang." + strings.ToLower(value)
	case "Serializable":
		return "java.io.serializable"
	default:
		return strings.ToLower(value)
	}
}

func (i *Index) isSubtypeLocked(ctx context.Context, file *analysis.ParsedFile, actual, expected string) bool {
	matched, _ := i.subtypeRelationAtLocked(ctx, file, actual, expected, -1)
	return matched
}

func (i *Index) subtypeRelationAtLocked(ctx context.Context, file *analysis.ParsedFile, actual, expected string, at int) (bool, bool) {
	if file == nil || strings.TrimSpace(actual) == "" || strings.TrimSpace(expected) == "" {
		return false, false
	}
	if identical, known := i.typesIdenticalAtLocked(file, actual, expected, at); known && identical {
		return true, true
	}
	expectedBase, _ := splitInstantiatedType(strings.TrimSuffix(strings.TrimSpace(expected), "?"))
	// kotlin.Any and java.lang.Object are the top of both hierarchies; every
	// non-null reference is a subtype without consulting the index.
	if topType := expectedBase == "Any" || expectedBase == "kotlin.Any" || expectedBase == "Object" || expectedBase == "java.lang.Object"; topType {
		if file.Language == analysis.LanguageKotlin && !strings.HasSuffix(strings.TrimSpace(actual), "?") {
			return true, true
		}
		if file.Language == analysis.LanguageJava && !javaPrimitiveType(strings.TrimSpace(actual)) {
			return true, true
		}
	}
	var expectedSymbols []analysis.Symbol
	if at >= 0 {
		expectedSymbols = i.resolveTypeSymbolsAtLocked(file, expectedBase, at)
	} else {
		expectedSymbols = i.resolveTypeSymbolsLocked(file, expectedBase)
	}
	if len(expectedSymbols) != 1 {
		return false, false
	}
	access := newAccessibilityMemoLocked(i, file)
	hierarchy, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, actual, maxResolutionCandidates, access)
	if !complete || access.workExhausted || len(hierarchy) == 0 {
		return false, false
	}
	for _, owner := range hierarchy {
		if jvmSameClass(owner.symbol, expectedSymbols[0]) {
			return true, true
		}
	}
	return false, true
}

func memberKey(container, name string) string { return container + "\x00" + name }

func matchesArityForLanguage(symbol analysis.Symbol, count int, language analysis.Language) bool {
	if len(symbol.Parameters) == count {
		return true
	}
	if !analysis.IsCallableKind(symbol.Kind) {
		return count == 0
	}
	required := 0
	variadic := false
	for _, parameter := range symbol.Parameters {
		variadicParameter := parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg")
		if !variadicParameter && (parameter.Default == "" || language == analysis.LanguageJava) {
			required++
		}
		if variadicParameter {
			variadic = true
		}
	}
	return count >= required && (variadic || count <= len(symbol.Parameters))
}

// takesArityWithoutVararg reports whether a call with count arguments fits
// symbol without spreading any of them into a vararg.
func takesArityWithoutVararg(symbol analysis.Symbol, count int, language analysis.Language) bool {
	for _, parameter := range symbol.Parameters {
		if parameter.Variadic || strings.Contains(parameter.Type, "...") || strings.Contains(parameter.Type, "vararg") {
			return false
		}
	}
	return matchesArityForLanguage(symbol, count, language)
}

// simpleNameInScopeLocked reports whether a declaration can be named by its
// simple name from this file. A name is in scope when it is declared here, sits
// in the same package, is imported, or comes from a package the language
// imports by default. Anything else needs an import first, and resolving it
// regardless made go-to-definition jump to a declaration the file cannot name
// and the compiler will not accept.
func (i *Index) simpleNameInScopeLocked(file *analysis.ParsedFile, symbol analysis.Symbol) bool {
	if symbol.URI == file.URI {
		return true
	}
	if symbol.Package == file.Package {
		return true
	}
	for _, imported := range file.Imports {
		if imported.Wildcard {
			if imported.Path == symbol.Package {
				return true
			}
			continue
		}
		if imported.Path == symbol.FQN || imported.LocalName() == symbol.Name && strings.HasSuffix(imported.Path, "."+symbol.Name) {
			return true
		}
		// A member imported by name brings only that member into scope, but its
		// owner is named by the import path itself.
		if strings.HasPrefix(imported.Path, symbol.Package+".") {
			if remainder := imported.Path[len(symbol.Package)+1:]; remainder == symbol.Name || strings.HasPrefix(remainder, symbol.Name+".") {
				return true
			}
		}
	}
	if symbol.Package == "java.lang" {
		return true
	}
	if file.Language == analysis.LanguageKotlin {
		switch symbol.Package {
		case "kotlin", "kotlin.annotation", "kotlin.collections", "kotlin.comparisons", "kotlin.io", "kotlin.ranges", "kotlin.sequences", "kotlin.text", "kotlin.jvm":
			return true
		}
	}
	// A declaration the index recorded without a package cannot be placed, so
	// it is accepted rather than hidden.
	return symbol.Package == ""
}

// thisSmartCastTypesLocked lists the types the implicit receiver is refined to
// at offset: inside `when (this) { is A -> ... }` the receiver is an A, and A's
// members are bare names there.
func (i *Index) thisSmartCastTypesLocked(file *analysis.ParsedFile, at int) []string {
	if file == nil {
		return nil
	}
	var types []string
	for _, cast := range i.fileSmartCastsByName[file.URI]["this"] {
		if cast.StartByte <= at && at <= cast.EndByte {
			types = append(types, cast.Type)
		}
	}
	return types
}
