package index

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func (i *Index) resolveTypeSymbolsLocked(file *analysis.ParsedFile, typeName string) []analysis.Symbol {
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, analysis.Symbol{}, newAccessibilityMemoLocked(i, file))
}

func (i *Index) resolveTypeSymbolsAtLocked(file *analysis.ParsedFile, typeName string, at int) []analysis.Symbol {
	var owner analysis.Symbol
	if ownerID := i.containerIDAtLocked(file, at); ownerID != "" {
		if candidate := i.symbols[ownerID]; candidate != nil {
			owner = *candidate
		}
	}
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, owner, newAccessibilityMemoLocked(i, file), at)
}

// resolveTypeSymbolsForOwnerLocked applies the same import/package precedence
// as ordinary type lookup, but can also prove which nested declaration is in
// lexical scope for an owning declaration. Equal-precedence collisions are
// ambiguity, never an invitation to select map or source order.
func (i *Index) resolveTypeSymbolsForOwnerLocked(file *analysis.ParsedFile, typeName string, lexicalOwner analysis.Symbol) []analysis.Symbol {
	return i.resolveTypeSymbolsForOwnerMemoLocked(file, typeName, lexicalOwner, newAccessibilityMemoLocked(i, file), lexicalOwner.StartByte)
}

func (i *Index) resolveTypeSymbolsForOwnerMemoLocked(file *analysis.ParsedFile, typeName string, lexicalOwner analysis.Symbol, access *accessibilityMemo, positions ...int) []analysis.Symbol {
	base, _ := splitInstantiatedType(typeName)
	base = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(base, "out "), "in "))
	base = strings.TrimPrefix(base, "? extends ")
	base = strings.TrimPrefix(base, "? super ")
	base = strings.TrimSuffix(base, "?")
	for strings.HasSuffix(base, "[]") {
		base = strings.TrimSuffix(base, "[]")
	}
	if base == "" {
		return nil
	}
	// Import inspection and every symbol bucket share one work budget. Capping
	// buckets separately still allowed a file with thousands of repeated star
	// imports to allocate an equally large aggregate candidate slice while the
	// foreground index lock was held.
	filter := func(ids []string) []analysis.Symbol {
		if access.workExhausted || !access.consumeWork(len(ids)) {
			return nil
		}
		return i.symbolsForIDsLocked(ids, func(symbol analysis.Symbol) bool {
			return analysis.IsTypeKind(symbol.Kind) && i.accessibleWithMemoLocked(file, symbol, access, positions...)
		})
	}
	if strings.Contains(base, ".") {
		if values := preferSourceDeclarations(filter(i.byFQN[base])); len(values) > 0 {
			return values
		}
		// `CatalogRestriction.Restricted`: a type in scope, then nested types
		// by name. Only a qualified name that is not itself a fully qualified
		// one gets here.
		segments := strings.Split(base, ".")
		owners := i.resolveTypeSymbolsForOwnerMemoLocked(file, segments[0], lexicalOwner, access, positions...)
		for _, segment := range segments[1:] {
			var nested []analysis.Symbol
			for _, owner := range owners {
				nested = append(nested, filter(i.byContainerMember[memberKey(owner.ID, segment)])...)
			}
			owners = uniqueTypeResolution(nested)
			if len(owners) == 0 {
				return nil
			}
		}
		return owners
	}
	if !i.prepareResolutionImportsLocked(file, access) {
		i.recordHealth("type-resolution", base, "import inventory exceeded the query-wide type-resolution work limit and was withheld")
		return nil
	}
	// Lexically declared type parameters and nested/local types have priority.
	var local []string
	localSymbols := i.fileSymbolsByName[file.URI][base]
	if len(localSymbols) > maxResolutionCandidates || !access.consumeWork(len(localSymbols)) {
		i.recordHealth("type-resolution", base, "same-file type inventory exceeded its 512-symbol safety limit and was withheld")
		return nil
	}
	for _, symbol := range localSymbols {
		if analysis.IsTypeKind(symbol.Kind) && (len(positions) == 0 || i.typeDeclarationVisibleAtLocked(*symbol, positions[0])) {
			local = append(local, symbol.ID)
		}
	}
	if values := filter(local); len(values) > 0 {
		if lexicalOwner.ID != "" {
			values = nearestLexicalTypesLocked(values, lexicalOwner, i.symbols)
		} else {
			// Without a lexical owner (a type spelled by an inferred result such
			// as `Box<T>` returned from a nested declaration) a same-file nested
			// type is still the only declaration that name can mean, provided it
			// is unique. A top-level declaration outranks a nested homonym; two
			// nested homonyms remain an ambiguity rather than a guess.
			values = preferTopLevelTypes(values)
		}
		return uniqueTypeResolution(values)
	} else if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	var explicit []analysis.Symbol
	explicitImports := access.importsByLocal[base]
	if !access.consumeWork(len(explicitImports)) {
		return nil
	}
	for _, imported := range explicitImports {
		if !imported.Wildcard && imported.LocalName() == base {
			explicit = append(explicit, filter(i.byFQN[imported.Path])...)
		}
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(explicit); len(values) > 0 {
		return values
	} else if len(explicit) > 0 {
		return nil
	}
	if file.Package != "" {
		if values := filter(i.byFQN[file.Package+"."+base]); len(values) > 0 {
			return uniqueTypeResolution(values)
		}
	} else if values := filter(i.byFQN[base]); len(values) > 0 {
		// A file with no package declaration sits in the root package, where a
		// top-level declaration's qualified name is its simple name. Skipping
		// this left such files resolving nothing by scope at all.
		return uniqueTypeResolution(values)
	}
	// Every explicit star import has equal precedence. Preserve ambiguity across
	// them instead of returning whichever import happened to occur first.
	var wildcard []analysis.Symbol
	if !access.consumeWork(len(access.wildcardImports) - access.implicitWildcards) {
		return nil
	}
	for _, imported := range access.wildcardImports {
		if imported.Wildcard {
			wildcard = append(wildcard, filter(i.byFQN[imported.Path+"."+base])...)
		}
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(wildcard); len(values) > 0 {
		return values
	} else if len(wildcard) > 0 {
		return nil
	}
	// In a Kotlin file `String` is kotlin.String, never java.lang.String,
	// however both are on the classpath: Kotlin's own default imports shadow
	// the Java ones. Java files see only java.lang.
	defaults := []string{"java.lang." + base}
	if file.Language == analysis.LanguageKotlin {
		defaults = defaults[:0]
		for _, prefix := range []string{"kotlin.", "kotlin.annotation.", "kotlin.collections.", "kotlin.comparisons.", "kotlin.io.", "kotlin.ranges.", "kotlin.sequences.", "kotlin.text.", "kotlin.jvm."} {
			defaults = append(defaults, prefix+base)
		}
	}
	var defaultCandidates []analysis.Symbol
	for _, fqn := range defaults {
		defaultCandidates = append(defaultCandidates, filter(i.byFQN[fqn])...)
	}
	if access.workExhausted {
		i.recordHealth("type-resolution", base, "candidate inventory exceeded the 512-work type-resolution safety limit and was withheld")
		return nil
	}
	if values := uniqueTypeResolution(defaultCandidates); len(values) > 0 {
		return values
	} else if len(defaultCandidates) > 0 {
		return nil
	}
	if file.Language == analysis.LanguageKotlin {
		return uniqueTypeResolution(filter(i.byFQN["java.lang."+base]))
	}
	// No global by-name fallback. A simple name that is not declared here, not
	// imported, not in this package and not default-imported is not in scope,
	// and Kotlin will not compile it. Resolving it anyway made navigation jump
	// to a type the file cannot actually name.
	return nil
}

func (i *Index) typeDeclarationVisibleAtLocked(symbol analysis.Symbol, at int) bool {
	if symbol.Kind == analysis.KindTypeParameter {
		return symbolInScopeAt(symbol, at)
	}
	if symbol.ContainerID == "" {
		return true
	}
	container := i.symbols[symbol.ContainerID]
	if container == nil || !analysis.IsCallableKind(container.Kind) {
		// Member/nested types are in scope throughout their owning type.
		return true
	}
	// Java and Kotlin local classes enter scope at their declaration and never
	// leak to an earlier reference in the same callable.
	return symbol.NameEndByte <= at && symbolInScopeAt(symbol, at)
}

func preferTopLevelTypes(values []analysis.Symbol) []analysis.Symbol {
	var topLevel []analysis.Symbol
	for _, value := range values {
		if value.ContainerID == "" {
			topLevel = append(topLevel, value)
		}
	}
	if len(topLevel) > 0 {
		return topLevel
	}
	return values
}

func uniqueTypeResolution(values []analysis.Symbol) []analysis.Symbol {
	if len(values) == 0 {
		return nil
	}
	values = preferSourceDeclarations(values)
	var resolved analysis.Symbol
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		identity := value.ID
		if identity == "" {
			identity = string(value.URI) + "\x00" + value.FQN + "\x00" + value.Signature
		}
		if seen[identity] {
			continue
		}
		seen[identity] = true
		if resolved.ID != "" || resolved.FQN != "" {
			return nil
		}
		resolved = value
	}
	if resolved.ID == "" && resolved.FQN == "" {
		return nil
	}
	return []analysis.Symbol{resolved}
}

func nearestLexicalTypesLocked(values []analysis.Symbol, owner analysis.Symbol, symbols map[string]*analysis.Symbol) []analysis.Symbol {
	distance := make(map[string]int)
	for current, depth := owner, 0; current.ID != ""; depth++ {
		distance[current.ID] = depth
		if current.ContainerID == "" {
			break
		}
		parent := symbols[current.ContainerID]
		if parent == nil {
			break
		}
		current = *parent
	}
	best := int(^uint(0) >> 1)
	var nearest []analysis.Symbol
	for _, value := range values {
		depth, nested := distance[value.ContainerID]
		if value.ContainerID == "" {
			depth, nested = len(distance)+1, true
		}
		if !nested || depth > best {
			continue
		}
		if depth < best {
			best, nearest = depth, nearest[:0]
		}
		nearest = append(nearest, value)
	}
	return nearest
}

func splitInstantiatedType(value string) (string, []string) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
	if len(value) > 1<<20 {
		return "", nil
	}
	open := strings.IndexByte(value, '<')
	if open < 0 {
		return value, nil
	}
	// Type spellings repeat endlessly (every extension's receiver pattern is
	// matched against every supertype of the receiver), and splitting one runs
	// the lexer. The split is a pure function of the string, so it is
	// remembered; callers get their own copy of the arguments to edit.
	if cached, ok := splitTypeCache.Load(value); ok {
		split := cached.(splitTypeResult)
		return split.base, append([]string(nil), split.arguments...)
	}
	base, arguments := splitInstantiatedTypeUncached(value, open)
	if splitTypeCacheSize.Add(1) > splitTypeCacheLimit {
		splitTypeCache.Clear()
		splitTypeCacheSize.Store(0)
	}
	splitTypeCache.Store(value, splitTypeResult{base: base, arguments: arguments})
	return base, append([]string(nil), arguments...)
}

type splitTypeResult struct {
	base      string
	arguments []string
}

const splitTypeCacheLimit = 1 << 16

var (
	splitTypeCache     sync.Map
	splitTypeCacheSize atomic.Int64
)

func splitInstantiatedTypeUncached(value string, open int) (string, []string) {
	close := matchingTypeArgumentEnd(value, open)
	if close < 0 {
		return strings.TrimSpace(value[:open]), nil
	}
	return strings.TrimSpace(value[:open]), splitTopLevelTypeArguments(value[open+1 : close])
}

func matchingTypeArgumentEnd(value string, open int) int {
	return lexical.MatchingDelimiter(value, open, "<", ">", true)
}

func splitTopLevelTypeArguments(value string) []string {
	return lexical.SplitTopLevelTypes(value, ",", true)
}

func substituteTypeParameters(value string, parameters, arguments []string) string {
	if value == "" || len(parameters) == 0 || len(arguments) == 0 {
		return value
	}
	replacements := make(map[string]string, len(parameters))
	for index, parameter := range parameters {
		if index < len(arguments) {
			replacements[parameter] = arguments[index]
		}
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if !isIdentRune(r) {
			if result.Len()+size > 1<<20 {
				return ""
			}
			result.WriteString(value[index : index+size])
			index += size
			continue
		}
		end := index + size
		for end < len(value) {
			r, size = utf8.DecodeRuneInString(value[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := value[index:end]
		if replacement := replacements[word]; replacement != "" {
			if result.Len()+len(replacement) > 1<<20 {
				return ""
			}
			result.WriteString(replacement)
		} else {
			if result.Len()+len(word) > 1<<20 {
				return ""
			}
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) directSupertypeMatchesLocked(candidate analysis.Symbol, targetID string) bool {
	file := i.files[candidate.URI]
	if file == nil {
		return false
	}
	for _, declared := range candidate.Supertypes {
		for _, resolved := range i.resolveTypeSymbolsForOwnerLocked(file, declared, candidate) {
			if resolved.ID == targetID {
				return true
			}
		}
	}
	return false
}

func (i *Index) contextualLambdaParameterTypeLocked(ctx context.Context, file *analysis.ParsedFile, parameter analysis.Symbol) string {
	if file.Language != analysis.LanguageKotlin || parameter.ScopeEndByte <= parameter.ScopeStartByte {
		return ""
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return ""
	}
	parameterIndex := 0
	if parameter.Name != "it" {
		peers := make([]analysis.Symbol, 0, 2)
		for _, symbol := range file.Symbols {
			if (symbol.Kind == analysis.KindParameter || symbol.Kind == analysis.KindVariable) && symbol.ScopeStartByte == parameter.ScopeStartByte && symbol.ScopeEndByte == parameter.ScopeEndByte {
				peers = append(peers, symbol)
			}
		}
		sort.Slice(peers, func(left, right int) bool { return peers[left].NameStartByte < peers[right].NameStartByte })
		for index, peer := range peers {
			if peer.ID == parameter.ID {
				parameterIndex = index
				break
			}
		}
	}
	// The lambda the parameter belongs to is the innermost call argument
	// around it. Taking the first one found answered `{ record -> }` inside
	// `transactional { trx -> ... }` with the outer lambda's parameter type.
	bestCall, bestArgument, bestSpan := -1, -1, int(^uint(0)>>1)
	for callIndex, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
			if start > parameter.StartByte || parameter.EndByte > end || end-start >= bestSpan {
				continue
			}
			bestCall, bestArgument, bestSpan = callIndex, argumentIndex, end-start
		}
	}
	if bestCall >= 0 {
		call, argumentIndex := file.References[bestCall], bestArgument
		for _, callable := range i.resolveLocked(ctx, file, call) {
			if len(callable.Parameters) == 0 {
				continue
			}
			callableParameter := argumentIndex
			if callableParameter >= len(callable.Parameters) {
				callableParameter = len(callable.Parameters) - 1
			}
			parameterType := i.contextualCallableParameterTypeLocked(ctx, file, call, callable, callableParameter, document)
			types := kotlinFunctionParameterTypes(parameterType)
			if len(types) == 0 {
				// A Java functional interface: the lambda's parameters
				// are its single abstract method's.
				types = kotlinFunctionParameterTypes(i.samFunctionTypeLocked(callable, parameterType))
			}
			if parameterIndex < len(types) {
				// Spelled as the callee's file spelled it: `Configuration`
				// there is an import the call site need not have.
				return i.respellDeclaredTypeLocked(file, callable, withoutVariance(types[parameterIndex]))
			}
		}
	}
	return ""
}

func (i *Index) contextualLambdaReceiverTypeLocked(ctx context.Context, file *analysis.ParsedFile, at int) string {
	receiver, _ := i.contextualLambdaReceiverLocked(ctx, file, at)
	return receiver
}

// contextualLambdaReceiverLocked is the receiver of the innermost lambda with
// a receiver around at, and where that lambda's argument starts.
func (i *Index) contextualLambdaReceiverLocked(ctx context.Context, file *analysis.ParsedFile, at int) (string, int) {
	if file.Language != analysis.LanguageKotlin {
		return "", -1
	}
	document := i.docs[file.URI]
	if document == nil {
		document = i.indexedDocs[file.URI]
	}
	if document == nil {
		return "", -1
	}
	best, bestSpan, bestStart := "", int(^uint(0)>>1), -1
	for _, span := range i.callArgumentSpans(file, document) {
		start, end := span.start, span.end
		if at < start || end < at || end-start >= bestSpan {
			continue
		}
		// Only a lambda argument has a receiver. Resolving the call for any
		// other argument around the position -- `batch(xs.map { ... })` --
		// typed that whole argument for nothing.
		if !lambdaArgumentAt(document.Text, start, end) {
			continue
		}
		if receiver := i.lambdaReceiverOfArgumentLocked(ctx, file, document, span); receiver != "" {
			best, bestSpan, bestStart = receiver, end-start, start
		}
	}
	return best, bestStart
}

// lambdaReceiverOfArgumentLocked is the receiver type of the lambda written as
// the span's argument -- `apply { }` runs its block on the receiver -- or "".
// Every reference inside that argument asks the same question, and answering
// it resolves the enclosing call and reads its parameter type from source, so
// the answer is kept for the file's text and the current declarations.
func (i *Index) lambdaReceiverOfArgumentLocked(ctx context.Context, file *analysis.ParsedFile, document *textdoc.Document, span callArgumentSpan) string {
	key := lambdaReceiverKey{owner: i, uri: file.URI, textHash: file.TextHash, call: span.call, argument: span.argument, declarations: i.late.declarations.Load(), environment: i.semanticEnvironmentVersion}
	lambdaReceiverCache.Lock()
	cached, ok := lambdaReceiverCache.values[key]
	lambdaReceiverCache.Unlock()
	if ok {
		return cached
	}
	ctx = withResolutionDepth(ctx, resolutionDepth(ctx))
	call, argumentIndex := file.References[span.call], span.argument
	receiver := ""
	for _, callable := range i.resolveLocked(ctx, file, call) {
		if len(callable.Parameters) == 0 {
			continue
		}
		callableParameter := argumentIndex
		if callableParameter >= len(callable.Parameters) {
			callableParameter = len(callable.Parameters) - 1
		}
		parameterType := i.contextualCallableParameterTypeLocked(ctx, file, call, callable, callableParameter, document)
		if found := kotlinFunctionReceiverType(parameterType); found != "" {
			receiver = i.respellDeclaredTypeLocked(file, callable, found)
			break
		}
	}
	if ctx.Err() != nil || resolutionTruncated(ctx) {
		return receiver
	}
	lambdaReceiverCache.Lock()
	if lambdaReceiverCache.values == nil || len(lambdaReceiverCache.values) > 100_000 {
		lambdaReceiverCache.values = make(map[lambdaReceiverKey]string)
	}
	lambdaReceiverCache.values[key] = receiver
	lambdaReceiverCache.Unlock()
	return receiver
}

type lambdaReceiverKey struct {
	owner          *Index // the counters below are per index
	uri            protocol.URI
	textHash       uint64
	call, argument int
	declarations   uint64
	environment    uint64
}

var lambdaReceiverCache struct {
	sync.Mutex
	values map[lambdaReceiverKey]string
}

// callArgumentSpan is one call argument as a byte range, with the call it
// belongs to as an index into the file's references.
type callArgumentSpan struct{ start, end, call, argument int }

type callArgumentSpans struct {
	textHash uint64
	spans    []callArgumentSpan
}

var callArgumentSpanCache struct {
	sync.Mutex
	byURI map[protocol.URI]callArgumentSpans
}

// callArgumentSpans returns the byte span of every call argument in the file.
// Finding the lambda an offset sits in used to convert every argument range of
// every call in the file, once per reference being resolved: quadratic in the
// file's size. The spans depend only on the file's text, so they are computed
// once per version of it.
func (i *Index) callArgumentSpans(file *analysis.ParsedFile, document *textdoc.Document) []callArgumentSpan {
	callArgumentSpanCache.Lock()
	cached, ok := callArgumentSpanCache.byURI[file.URI]
	callArgumentSpanCache.Unlock()
	if ok && cached.textHash == file.TextHash {
		return cached.spans
	}
	var spans []callArgumentSpan
	for callIndex, call := range file.References {
		if call.Role != analysis.RoleCall {
			continue
		}
		for argumentIndex, argumentRange := range call.Arguments {
			spans = append(spans, callArgumentSpan{
				start: document.Offset(argumentRange.Start), end: document.Offset(argumentRange.End),
				call: callIndex, argument: argumentIndex,
			})
		}
	}
	callArgumentSpanCache.Lock()
	if callArgumentSpanCache.byURI == nil || len(callArgumentSpanCache.byURI) > 4096 {
		callArgumentSpanCache.byURI = make(map[protocol.URI]callArgumentSpans)
	}
	callArgumentSpanCache.byURI[file.URI] = callArgumentSpans{textHash: file.TextHash, spans: spans}
	callArgumentSpanCache.Unlock()
	return spans
}

func (i *Index) enclosingExtensionReceiverTypeLocked(file *analysis.ParsedFile, at int) string {
	receiver, _ := i.enclosingExtensionReceiverLocked(file, at)
	return receiver
}

// enclosingExtensionReceiverLocked is the receiver of the innermost extension
// function around at, and where that function starts.
func (i *Index) enclosingExtensionReceiverLocked(file *analysis.ParsedFile, at int) (string, int) {
	bestStart, bestEnd, receiver := -1, len(i.documentTextLocked(file.URI))+1, ""
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.ReceiverType == "" || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if symbol.StartByte > bestStart || symbol.StartByte == bestStart && symbol.EndByte < bestEnd {
			bestStart, bestEnd, receiver = symbol.StartByte, symbol.EndByte, symbol.ReceiverType
		}
	}
	return receiver, bestStart
}

func (i *Index) enclosingContextReceiverTypesLocked(file *analysis.ParsedFile, at int) []string {
	if file.Language != analysis.LanguageKotlin {
		return nil
	}
	text := i.documentTextLocked(file.URI)
	if text == "" {
		return nil
	}
	var callable analysis.Symbol
	for _, symbol := range file.Symbols {
		if !analysis.IsCallableKind(symbol.Kind) || symbol.StartByte > at || at > symbol.EndByte {
			continue
		}
		if callable.ID == "" || symbol.StartByte >= callable.StartByte && symbol.EndByte <= callable.EndByte {
			callable = symbol
		}
	}
	if callable.ID == "" || callable.StartByte <= 0 || callable.StartByte > len(text) {
		return nil
	}
	end := callable.StartByte
	for end > 0 && unicode.IsSpace(rune(text[end-1])) {
		end--
	}
	if end == 0 || text[end-1] != ')' {
		return nil
	}
	closeAt := end - 1
	depth, openAt := 0, -1
	for index := closeAt; index >= 0; index-- {
		switch text[index] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				openAt = index
				index = -1
			}
		}
	}
	if openAt < 0 {
		return nil
	}
	wordEnd := openAt
	for wordEnd > 0 && unicode.IsSpace(rune(text[wordEnd-1])) {
		wordEnd--
	}
	wordStart := wordEnd
	for wordStart > 0 && isIdentRune(rune(text[wordStart-1])) {
		wordStart--
	}
	if text[wordStart:wordEnd] != "context" {
		return nil
	}
	items := splitTopLevelCallArguments(text[openAt+1 : closeAt])
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if colon := strings.IndexByte(item, ':'); colon >= 0 {
			item = strings.TrimSpace(item[colon+1:])
		}
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (i *Index) contextualCallableParameterTypeLocked(ctx context.Context, file *analysis.ParsedFile, call analysis.Reference, callable analysis.Symbol, parameterIndex int, document *textdoc.Document) string {
	if parameterIndex < 0 || parameterIndex >= len(callable.Parameters) {
		return ""
	}
	parameterType := callable.Parameters[parameterIndex].Type
	if len(callable.TypeParameters) == 0 || len(call.Arguments) == 0 {
		return parameterType
	}
	inferred := make(map[string]string, len(callable.TypeParameters))
	// `tasks.withType<Jar> { archiveBaseName }`: type arguments written at the
	// call bind the callee's type parameters in order, before anything is
	// inferred.
	if explicit := explicitTypeArgumentsAfter(document.Text, call.EndByte); len(explicit) == len(callable.TypeParameters) {
		for index, parameter := range callable.TypeParameters {
			inferred[parameter] = explicit[index]
		}
	}
	// An extension's type parameters are bound by its receiver, not only by its
	// value arguments. `h.name?.let { it.length }` passes exactly one argument
	// -- the lambda whose parameter type is being asked about -- and the loop
	// below skips that one, so nothing ever bound T and `it` read as the bare
	// type parameter in every scope function.
	if typeMentionsParameter(callable.ReceiverType, callable.TypeParameters) {
		receiver := call.Qualifier
		text := i.documentTextLocked(file.URI)
		if receiver == "" && !call.Synthetic {
			// A synthetic reference carries the position of the expression being
			// analysed, never its own spelling, so its qualifier must not be
			// re-derived from the text at that position.
			receiver = expressionQualifierBefore(text, call.StartByte)
		}
		if receiver != "" {
			if actual := i.inferExpressionTypeLocked(ctx, file, receiver, call.StartByte); actual != "" {
				if isSafeCallBefore(text, call.StartByte) {
					// `?.` unwraps: `String?` receiver binds T to String, or the
					// lambda's `it` is nullable and every member access on it
					// looks unresolved.
					actual = strings.TrimSuffix(strings.TrimSpace(actual), "?")
				}
				i.inferTypeParameterBindingsLocked(ctx, file, callable.ReceiverType, actual, callable.TypeParameters, inferred)
			}
		}
	}
	for argumentIndex, argumentRange := range call.Arguments {
		callableIndex := argumentIndex
		if callableIndex >= len(callable.Parameters) {
			callableIndex = len(callable.Parameters) - 1
		}
		if callableIndex < 0 || callableIndex == parameterIndex {
			continue
		}
		start, end := document.Offset(argumentRange.Start), document.Offset(argumentRange.End)
		if start < 0 || end < start || end > len(document.Text) {
			continue
		}
		expression := strings.TrimSpace(document.Text[start:end])
		if equals := topLevelNamedArgumentEquals(expression); equals >= 0 {
			expression = strings.TrimSpace(expression[equals+1:])
		}
		actual := i.inferExpressionTypeLocked(ctx, file, expression, call.StartByte)
		if actual != "" {
			i.inferTypeParameterBindingsLocked(ctx, file, callable.Parameters[callableIndex].Type, actual, callable.TypeParameters, inferred)
		}
	}
	arguments := make([]string, len(callable.TypeParameters))
	for index, parameter := range callable.TypeParameters {
		arguments[index] = inferred[parameter]
	}
	return substituteTypeParameters(parameterType, callable.TypeParameters, arguments)
}

// typeMentionsParameter reports whether a declared type names one of the
// callable's own type parameters, so a receiver that can never bind one --
// `fun String.trim()` and every other ordinary extension -- skips the receiver
// inference entirely instead of typing an expression whose result is discarded.
// Matching is on identifier boundaries: a receiver spelled `Transformer` does
// not mention the parameter `T`.
func typeMentionsParameter(value string, parameters []string) bool {
	if value == "" || len(parameters) == 0 {
		return false
	}
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if !isIdentRune(r) {
			index += size
			continue
		}
		end := index + size
		for end < len(value) {
			r, size = utf8.DecodeRuneInString(value[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := value[index:end]
		for _, parameter := range parameters {
			if word == parameter {
				return true
			}
		}
		index = end
	}
	return false
}

// isSafeCallBefore reports whether the call at start is reached through `?.`
// rather than `.`, which decides whether the receiver's nullability carries
// into the callee's type parameters.
func isSafeCallBefore(text string, start int) bool {
	at := start - 1
	for at >= 0 && (text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r') {
		at--
	}
	if at < 0 || text[at] != '.' {
		return false
	}
	at--
	for at >= 0 && (text[at] == ' ' || text[at] == '\t' || text[at] == '\n' || text[at] == '\r') {
		at--
	}
	return at >= 0 && text[at] == '?'
}

func topLevelNamedArgumentEquals(expression string) int {
	if index := lexical.TopLevelTokenIndex(expression, "=", true); index >= 0 {
		return index
	}
	angles, parens, brackets, braces := 0, 0, 0, 0
	for index, r := range expression {
		switch r {
		case '<':
			angles++
		case '>':
			if angles > 0 {
				angles--
			}
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '{':
			braces++
		case '}':
			if braces > 0 {
				braces--
			}
		case '=':
			if angles == 0 && parens == 0 && brackets == 0 && braces == 0 {
				return index
			}
		}
	}
	return -1
}

func kotlinFunctionParameterTypes(functionType string) []string {
	_, parameters, _, _ := parseKotlinFunctionType(functionType)
	return parameters
}

func kotlinFunctionReceiverType(functionType string) string {
	receiver, _, _, _ := parseKotlinFunctionType(functionType)
	return receiver
}

// parseKotlinFunctionType reads a Kotlin function type -- `(A, B) -> R`,
// `suspend (configuration: Configuration) -> T`, `Receiver.(A) -> R`,
// `(suspend () -> Unit)?`, or the binary spelling `Function2<A, B, R>` with
// `@ExtensionFunctionType` -- into its receiver, parameter types and result.
// ok is false for anything that is not a function type.
func parseKotlinFunctionType(functionType string) (receiver string, parameters []string, result string, ok bool) {
	text := strings.TrimSpace(functionType)
	// `(suspend () -> Unit)?`: a function type parenthesised whole (to make
	// it nullable) is that function type.
	for {
		trimmed := strings.TrimSpace(strings.TrimSuffix(text, "?"))
		if len(trimmed) < 2 || trimmed[0] != '(' || lexical.MatchingDelimiter(trimmed, 0, "(", ")", true) != len(trimmed)-1 {
			break
		}
		text = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	extensionAnnotated := false
	for strings.HasPrefix(text, "@") {
		end := 1
		for end < len(text) && (isIdentifierByteFast(text[end]) || text[end] == '.') {
			end++
		}
		if strings.HasSuffix(text[1:end], "ExtensionFunctionType") {
			extensionAnnotated = true
		}
		text = strings.TrimSpace(text[end:])
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "suspend "))
	if base, arguments := splitInstantiatedType(text); len(arguments) > 0 && !strings.Contains(text, "->") {
		simple := base[strings.LastIndexByte(base, '.')+1:]
		if strings.HasPrefix(simple, "Function") || strings.HasPrefix(simple, "SuspendFunction") {
			if _, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(simple, "Suspend"), "Function")); err == nil {
				parameters, result = arguments[:len(arguments)-1], arguments[len(arguments)-1]
				if extensionAnnotated && len(parameters) > 0 {
					receiver, parameters = parameters[0], parameters[1:]
				}
				return receiver, parameters, result, true
			}
		}
		return "", nil, "", false
	}
	// Find the parameter list: the first top-level `(`, preceded by
	// `Receiver.` when there is a receiver.
	open := -1
	depth := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '<':
			depth++
		case '>':
			if index == 0 || text[index-1] != '-' {
				depth--
			}
		case '(':
			if depth == 0 {
				open = index
			}
		}
		if open >= 0 {
			break
		}
	}
	if open < 0 {
		return "", nil, "", false
	}
	close := lexical.MatchingDelimiter(text, open, "(", ")", true)
	if close < 0 || !arrowFollows(text, close) {
		return "", nil, "", false
	}
	if head := strings.TrimSpace(text[:open]); head != "" {
		if !strings.HasSuffix(head, ".") {
			return "", nil, "", false
		}
		receiver = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(head, "."), "suspend "))
	}
	for _, parameter := range splitTopLevelCallArguments(text[open+1 : close]) {
		parameter = strings.TrimSpace(parameter)
		// `configuration: Configuration` names the parameter; the type follows.
		if colon := topLevelNameColon(parameter); colon >= 0 {
			parameter = strings.TrimSpace(parameter[colon+1:])
		}
		if parameter != "" {
			parameters = append(parameters, parameter)
		}
	}
	rest := strings.TrimSpace(text[close+1:])
	result = strings.TrimSpace(strings.TrimPrefix(rest, "->"))
	return receiver, parameters, result, true
}

func arrowFollows(text string, close int) bool {
	return strings.HasPrefix(strings.TrimSpace(text[close+1:]), "->")
}

// topLevelNameColon finds the colon of `name: Type` in a function type's
// parameter, or -1 when the parameter is a bare type.
func topLevelNameColon(parameter string) int {
	end := 0
	for end < len(parameter) && isIdentifierByteFast(parameter[end]) {
		end++
	}
	rest := strings.TrimLeft(parameter[end:], " \t")
	if end == 0 || !strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "::") {
		return -1
	}
	return len(parameter) - len(rest)
}

type typeInferenceConstraint struct {
	parameter  string
	lowerBound string
}

type typeInferenceConstraints struct {
	values      []typeInferenceConstraint
	unsupported bool
}

// inferTypeParameterBindingsLocked is the measured fast constraint solver.
// It records lower-bound constraints explicitly, merges repeated constraints
// through the structured type graph's LUB, and reports false for projections,
// captures, intersections, or incompatible shapes. Callers must treat false as
// unknown rather than selecting an overload from a fabricated binding.
func (i *Index) inferTypeParameterBindingsLocked(ctx context.Context, file *analysis.ParsedFile, pattern, actual string, parameters []string, inferred map[string]string) bool {
	if pattern == "" || actual == "" {
		return false
	}
	constraints := typeInferenceConstraints{}
	matched := collectTypeParameterConstraints(pattern, actual, parameters, &constraints, 0)
	if constraints.unsupported {
		return false
	}
	// A declared parameter such as Iterable<T> also constrains T when the
	// actual argument is List<String>. Walk the instantiated supertype graph and
	// bind against the first matching generic owner instead of requiring equal
	// raw spellings at the call site.
	if !matched {
		patternBase, _ := splitInstantiatedType(pattern)
		for _, owner := range i.instantiatedTypeHierarchyLocked(ctx, file, actual) {
			if !sameJvmType(owner.symbol.Name, patternBase) && !sameJvmType(owner.symbol.FQN, patternBase) {
				continue
			}
			instantiated := instantiatedTypeName(owner.symbol.FQN, owner.arguments)
			matched = collectTypeParameterConstraints(pattern, instantiated, parameters, &constraints, 0)
			break
		}
	}
	if !matched || constraints.unsupported || len(constraints.values) == 0 {
		return false
	}
	solved := make(map[string]string, len(inferred)+len(constraints.values))
	for parameter, value := range inferred {
		solved[parameter] = value
	}
	for _, constraint := range constraints.values {
		previous := solved[constraint.parameter]
		if previous == "" {
			solved[constraint.parameter] = constraint.lowerBound
			continue
		}
		merged := i.commonExpressionTypeLocked(ctx, file, previous, constraint.lowerBound)
		if merged == "" {
			return false
		}
		solved[constraint.parameter] = merged
	}
	for parameter, value := range solved {
		inferred[parameter] = value
	}
	return true
}

func collectTypeParameterConstraints(pattern, actual string, parameters []string, constraints *typeInferenceConstraints, depth int) bool {
	pattern, actual = strings.TrimSpace(pattern), strings.TrimSpace(actual)
	if depth > 256 {
		constraints.unsupported = true
		return false
	}
	if strings.ContainsAny(pattern, "*&") || strings.ContainsAny(actual, "*&") || strings.Contains(pattern, "? extends ") || strings.Contains(pattern, "? super ") || strings.Contains(actual, "? extends ") || strings.Contains(actual, "? super ") || strings.Contains(pattern, "->") || strings.Contains(actual, "->") {
		constraints.unsupported = true
		return false
	}
	// `Array<out T>` accepts an Array<Color> and binds T to Color: a covariant
	// projection constrains the parameter the same way the bare type does. The
	// stdlib spells most of its extension receivers this way (first, map,
	// toList, ...), and treating it as unsupported made them not apply.
	if strings.HasPrefix(pattern, "out ") {
		return collectTypeParameterConstraints(strings.TrimPrefix(pattern, "out "), strings.TrimPrefix(actual, "out "), parameters, constraints, depth+1)
	}
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	for _, parameter := range parameters {
		base := strings.TrimSpace(patternBase)
		if strings.HasPrefix(base, "out ") || strings.HasPrefix(base, "in ") {
			constraints.unsupported = true
			return false
		}
		if simpleType(base) == parameter && actual != "" {
			constraints.values = append(constraints.values, typeInferenceConstraint{parameter: parameter, lowerBound: actual})
			return true
		}
	}
	if !sameJvmType(patternBase, actualBase) || len(patternArguments) != len(actualArguments) {
		return false
	}
	matched := true
	for index := range patternArguments {
		if !collectTypeParameterConstraints(patternArguments[index], actualArguments[index], parameters, constraints, depth+1) {
			matched = false
		}
	}
	return matched
}

func matchTypePattern(pattern, actual string, parameters map[string]bool, inferred map[string]string) bool {
	return matchTypePatternDepth(pattern, actual, parameters, inferred, 0)
}

func matchTypePatternDepth(pattern, actual string, parameters map[string]bool, inferred map[string]string, depth int) bool {
	if depth > 256 {
		return false
	}
	pattern = withoutVariance(strings.TrimSpace(pattern))
	actual = withoutVariance(strings.TrimSpace(actual))
	// A star projection accepts any argument: `Iterable<*>.filterIsInstance`
	// applies to a List of anything.
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(actual, "?") && !strings.HasSuffix(pattern, "?") {
		return false
	}
	pattern = strings.TrimSuffix(pattern, "?")
	actual = strings.TrimSuffix(actual, "?")
	patternBase, patternArguments := splitInstantiatedType(pattern)
	actualBase, actualArguments := splitInstantiatedType(actual)
	patternSimple := simpleType(strings.TrimPrefix(strings.TrimPrefix(patternBase, "out "), "in "))
	if parameters[patternSimple] {
		if previous := inferred[patternSimple]; previous != "" {
			return sameJvmType(previous, actual)
		}
		inferred[patternSimple] = actual
		return true
	}
	if simpleType(patternBase) != simpleType(actualBase) || len(patternArguments) != len(actualArguments) {
		return false
	}
	for index := range patternArguments {
		if !matchTypePatternDepth(patternArguments[index], actualArguments[index], parameters, inferred, depth+1) {
			return false
		}
	}
	return true
}

func instantiatedTypeName(name string, arguments []string) string {
	if len(arguments) == 0 {
		return name
	}
	total := len(name) + 2
	for _, argument := range arguments {
		total += len(argument) + 2
		if total > 1<<20 {
			return ""
		}
	}
	return name + "<" + strings.Join(arguments, ", ") + ">"
}

func substituteTypeBindings(value string, bindings map[string]string) string {
	if value == "" || len(bindings) == 0 {
		return value
	}
	var result strings.Builder
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if !isIdentRune(r) {
			if result.Len()+size > 1<<20 {
				return ""
			}
			result.WriteString(value[index : index+size])
			index += size
			continue
		}
		end := index + size
		for end < len(value) {
			r, size = utf8.DecodeRuneInString(value[end:])
			if !isIdentRune(r) {
				break
			}
			end += size
		}
		word := value[index:end]
		if replacement := bindings[word]; replacement != "" {
			if result.Len()+len(replacement) > 1<<20 {
				return ""
			}
			result.WriteString(replacement)
		} else {
			if result.Len()+len(word) > 1<<20 {
				return ""
			}
			result.WriteString(word)
		}
		index = end
	}
	return result.String()
}

func (i *Index) extensionReceiverBindingsLocked(ctx context.Context, file *analysis.ParsedFile, extension analysis.Symbol, actualType string) (map[string]string, bool) {
	if extension.ReceiverType == "" || actualType == "" {
		return nil, false
	}
	parameters := make(map[string]bool, len(extension.TypeParameters))
	for _, parameter := range extension.TypeParameters {
		parameters[parameter] = true
	}
	for _, actual := range i.receiverTypeSpellingsLocked(ctx, file, actualType) {
		bindings := make(map[string]string, len(parameters))
		if !matchTypePattern(extension.ReceiverType, actual, parameters, bindings) {
			continue
		}
		valid := true
		for parameter, actualType := range bindings {
			if !i.typeArgumentSatisfiesBoundsLocked(ctx, file, actualType, extension.TypeParameterBounds[parameter]) {
				valid = false
				break
			}
		}
		if valid {
			return bindings, true
		}
	}
	return nil, false
}

// receiverTypeSpellingsLocked is actualType followed by each of its
// supertypes, instantiated, by simple and by qualified name: everything an
// extension receiver pattern may match. One completion tests hundreds of
// extensions against the same receiver, and each used to walk the whole
// hierarchy again -- for a jOOQ table, past the request deadline.
func (i *Index) receiverTypeSpellingsLocked(ctx context.Context, file *analysis.ParsedFile, actualType string) []string {
	memo, _ := ctx.Value(receiverSpellingsKey{}).(*receiverSpellingsMemo)
	key := string(file.URI) + "\x00" + actualType
	if memo != nil {
		memo.mu.Lock()
		cached, ok := memo.values[key]
		memo.mu.Unlock()
		if ok {
			return cached
		}
	}
	spellings := []string{actualType}
	for _, instantiated := range i.instantiatedTypeHierarchyLocked(ctx, file, actualType) {
		spellings = append(spellings, instantiatedTypeName(instantiated.symbol.Name, instantiated.arguments))
		if instantiated.symbol.FQN != "" && instantiated.symbol.FQN != instantiated.symbol.Name {
			spellings = append(spellings, instantiatedTypeName(instantiated.symbol.FQN, instantiated.arguments))
		}
	}
	if memo != nil && ctx.Err() == nil {
		memo.mu.Lock()
		if len(memo.values) < 4096 {
			memo.values[key] = spellings
		}
		memo.mu.Unlock()
	}
	return spellings
}

type receiverSpellingsKey struct{}

// receiverSpellingsMemo holds what one request learns about types and may
// ask again: a receiver's supertype spellings and bound checks.
type receiverSpellingsMemo struct {
	mu       sync.Mutex
	values   map[string][]string
	subtypes map[string]bool
}

// withReceiverSpellingsMemo scopes receiverTypeSpellingsLocked's memo to one
// request, which holds the index lock throughout, so the hierarchy it
// remembers cannot change underneath it.
func withReceiverSpellingsMemo(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(receiverSpellingsKey{}).(*receiverSpellingsMemo); ok {
		return ctx
	}
	return context.WithValue(ctx, receiverSpellingsKey{}, &receiverSpellingsMemo{values: make(map[string][]string), subtypes: make(map[string]bool)})
}

// spellingReceiverOwners names the extension buckets a receiver type can reach
// when it resolves to no indexed declaration (kotlin.String without a stdlib
// index, an unresolved library type). Extension buckets are keyed by the
// receiver's simple spelling, so the spelling is the only owner identity such
// a receiver has. Callers still prove applicability against each extension's
// receiver pattern; this is candidate discovery, never a resolution answer.
func spellingReceiverOwners(typeName string) []analysis.Symbol {
	var owners []analysis.Symbol
	for _, root := range splitIntersectionTypes(strings.TrimSpace(typeName)) {
		base, _ := splitInstantiatedType(strings.TrimSuffix(strings.TrimSpace(root), "?"))
		if name := simpleType(strings.TrimSpace(base)); name != "" {
			owners = append(owners, analysis.Symbol{Name: name, Kind: analysis.KindClass})
		}
	}
	return owners
}

func (i *Index) extensionReceiverApplicableLocked(ctx context.Context, file *analysis.ParsedFile, extension analysis.Symbol, actualType string) bool {
	_, applicable := i.extensionReceiverBindingsLocked(ctx, file, extension, actualType)
	return applicable
}

type instantiatedTypeOwner struct {
	symbol    analysis.Symbol
	arguments []string
	distance  int
}

func (i *Index) instantiatedTypeHierarchyLocked(ctx context.Context, file *analysis.ParsedFile, typeName string) []instantiatedTypeOwner {
	result, complete := i.instantiatedTypeHierarchyBoundedWithMemoLocked(ctx, file, typeName, 4096, newAccessibilityMemoLocked(i, file))
	if !complete {
		return nil
	}
	return result
}

func (i *Index) instantiatedTypeHierarchyBoundedWithMemoLocked(ctx context.Context, file *analysis.ParsedFile, typeName string, limit int, access *accessibilityMemo) ([]instantiatedTypeOwner, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit < 1 || limit > 4096 {
		return nil, false
	}
	type pendingOwner struct {
		name           string
		distance       int
		resolutionFile *analysis.ParsedFile
		lexicalOwner   analysis.Symbol
	}
	current := make([]pendingOwner, 0)
	for _, root := range splitIntersectionTypes(typeName) {
		current = append(current, pendingOwner{name: root, resolutionFile: file})
	}
	seen := make(map[string]bool)
	result := make([]instantiatedTypeOwner, 0, 4)
	for len(current) > 0 {
		next := make([]pendingOwner, 0)
		for cursor := 0; cursor < len(current); cursor++ {
			if ctx.Err() != nil {
				return nil, false
			}
			if len(seen) >= limit || len(current)+len(next) > limit*4 {
				return nil, false
			}
			pending := current[cursor]
			instantiated := pending.name
			base, arguments := splitInstantiatedType(instantiated)
			resolutionFile := pending.resolutionFile
			if resolutionFile == nil {
				resolutionFile = file
			}
			// A source declaration may spell its supertype through an import which
			// does not exist at the eventual call site. Resolve every hierarchy edge
			// in the declaring file's lexical/import context. Keep one shared work
			// allowance by transferring the remaining budget into and out of the
			// edge-local memo.
			resolutionAccess := access
			if resolutionFile.URI != file.URI || pending.lexicalOwner.ID != "" {
				edgeAccess := *access
				edgeAccess.importsReady = false
				edgeAccess.importsComplete = false
				edgeAccess.importsByLocal = nil
				edgeAccess.wildcardImports = nil
				resolutionAccess = &edgeAccess
			}
			resolvedTypes := i.resolveTypeSymbolsForOwnerMemoLocked(resolutionFile, base, pending.lexicalOwner, resolutionAccess)
			if resolutionAccess != access {
				access.remainingWork = resolutionAccess.remainingWork
				access.workExhausted = access.workExhausted || resolutionAccess.workExhausted
			}
			if access.workExhausted {
				return nil, false
			}
			for _, symbol := range resolvedTypes {
				key := symbol.ID + "\x00" + strings.Join(arguments, "\x00")
				if seen[key] {
					continue
				}
				if len(result) >= limit {
					return nil, false
				}
				seen[key] = true
				result = append(result, instantiatedTypeOwner{symbol: symbol, arguments: arguments, distance: pending.distance})
				declarationFile := i.files[symbol.URI]
				if declarationFile == nil {
					declarationFile = resolutionFile
				}
				if symbol.Kind == analysis.KindTypeAlias && symbol.Type != "" {
					// Typealiases are zero-cost edges. Append them to the active
					// level so every zero-cost closure is exhausted before any
					// superclass edge at distance+1 is observed.
					current = append(current, pendingOwner{name: substituteTypeParameters(symbol.Type, symbol.TypeParameters, arguments), distance: pending.distance, resolutionFile: declarationFile, lexicalOwner: symbol})
				}
				for _, supertype := range symbol.Supertypes {
					// Type arguments the supertype spells (`JpaRepository<User, Long>`)
					// are read later from the call site; spell them for it.
					next = append(next, pendingOwner{name: substituteTypeParameters(i.respellDeclaredTypeLocked(file, symbol, supertype), symbol.TypeParameters, arguments), distance: pending.distance + 1, resolutionFile: declarationFile, lexicalOwner: symbol})
				}
				// Every class has supertypes nobody writes: `toString`, `equals`
				// and `hashCode` come from Any/Object, and an enum's `name` and
				// `ordinal` from Enum. Without them they were absent from
				// completion and could not be resolved or typed.
				for _, implicit := range implicitSupertypes(symbol) {
					next = append(next, pendingOwner{name: implicit, distance: pending.distance + 1, resolutionFile: declarationFile, lexicalOwner: symbol})
				}
			}
		}
		current = next
	}
	return result, true
}

func (i *Index) enclosingTypeLocked(file *analysis.ParsedFile, at int) analysis.Symbol {
	var found analysis.Symbol
	for _, symbol := range file.Symbols {
		// A Kotlin file's JVM facade (`URIExtKt`) is Java's view of its
		// top-level declarations; code in the file is never inside it, and
		// taking it for the enclosing class made `this` in a top-level
		// extension function the facade.
		if symbol.Synthetic && symbol.InteropLanguage == analysis.LanguageJava && file.Language == analysis.LanguageKotlin {
			continue
		}
		if analysis.IsTypeKind(symbol.Kind) && symbol.StartByte <= at && at <= symbol.EndByte && (found.ID == "" || symbol.StartByte >= found.StartByte && symbol.EndByte <= found.EndByte) {
			found = symbol
		}
	}
	return found
}

func (i *Index) symbolWithinCallableScopeLocked(file *analysis.ParsedFile, symbol analysis.Symbol, at int) bool {
	container, ok := i.symbols[symbol.ContainerID]
	return ok && analysis.IsCallableKind(container.Kind) && container.URI == file.URI && container.StartByte <= at && at <= container.EndByte
}

func splitIntersectionTypes(typeName string) []string {
	if len(typeName) > 1<<20 {
		return nil
	}
	angles, start := 0, 0
	var result []string
	for index := 0; index <= len(typeName); index++ {
		if index == len(typeName) || typeName[index] == '&' && angles == 0 {
			if value := strings.TrimSpace(typeName[start:index]); value != "" {
				if len(result) >= 256 {
					return nil
				}
				result = append(result, value)
			}
			start = index + 1
			continue
		}
		if typeName[index] == '<' {
			angles++
		} else if typeName[index] == '>' && angles > 0 {
			angles--
		}
	}
	if len(result) == 0 {
		return []string{typeName}
	}
	return result
}

func (i *Index) accessibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	return i.accessibleWithMemoLocked(file, symbol, newAccessibilityMemoLocked(i, file), positions...)
}

type accessibilityMemo struct {
	fromModule        *ModuleInfo
	fromSourceSet     string
	ownershipComplete bool
	targetModules     map[protocol.URI]*ModuleInfo
	targetSourceSets  map[protocol.URI]string
	targetComplete    map[protocol.URI]bool
	moduleAccess      map[string]bool
	moduleComplete    bool
	moduleReady       bool
	javaAccess        map[string]bool
	libraryJava       map[string]bool
	javaReadable      map[string]bool
	javaReadComplete  bool
	javaReadReady     bool
	sourceSetDistance map[string]int
	remainingWork     int
	workExhausted     bool
	importsReady      bool
	importsComplete   bool
	importsByLocal    map[string][]analysis.Import
	wildcardImports   []analysis.Import
	// implicitWildcards counts the wildcard imports a file has without writing
	// them (a Gradle script's two hundred defaults). They are a fixed table,
	// not work the file asks for, so they are not charged to its budget.
	implicitWildcards int
}

// A non-module key keeps a newly indexed archive inaccessible until the build
// model which introduced it commits. Real access identities always begin with
// an absolute module directory and therefore cannot collide with this marker.
const pendingLibraryAccessKey = "\x00pending-build-refresh"

func (memo *accessibilityMemo) consumeWork(count int) bool {
	if memo == nil || memo.workExhausted || count < 0 || count > memo.remainingWork {
		if memo != nil {
			memo.workExhausted = true
		}
		return false
	}
	memo.remainingWork -= count
	return true
}

func (i *Index) prepareResolutionImportsLocked(file *analysis.ParsedFile, memo *accessibilityMemo) bool {
	if memo.importsReady {
		return memo.importsComplete
	}
	memo.importsReady = true
	if !memo.consumeWork(len(file.Imports)) {
		return false
	}
	// The tables depend only on the file's imports, so they are built once per
	// version of its text rather than for every reference resolved in it.
	importTableCache.Lock()
	cached, known := importTableCache.values[file.URI]
	importTableCache.Unlock()
	if known && cached.textHash == file.TextHash {
		memo.importsByLocal, memo.wildcardImports, memo.implicitWildcards = cached.byLocal, cached.wildcard, cached.implicitWildcards
		memo.importsComplete = true
		return true
	}
	byLocal := make(map[string][]analysis.Import)
	var wildcard []analysis.Import
	effective := i.effectiveImportsLocked(file)
	implicitWildcards := 0
	for index, imported := range effective {
		if index >= len(file.Imports) && imported.Wildcard {
			implicitWildcards++
		}
	}
	for _, imported := range effective {
		if imported.Wildcard {
			wildcard = append(wildcard, imported)
			continue
		}
		name := imported.LocalName()
		byLocal[name] = append(byLocal[name], imported)
	}
	importTableCache.Lock()
	if importTableCache.values == nil || len(importTableCache.values) > 4096 {
		importTableCache.values = make(map[protocol.URI]importTables)
	}
	importTableCache.values[file.URI] = importTables{textHash: file.TextHash, byLocal: byLocal, wildcard: wildcard, implicitWildcards: implicitWildcards}
	importTableCache.Unlock()
	memo.importsByLocal, memo.wildcardImports, memo.implicitWildcards = byLocal, wildcard, implicitWildcards
	memo.importsComplete = true
	return true
}

type moduleAccessKey struct {
	owner                      *Index // the environment version is per index
	root, name, dir, sourceSet string
	environment                uint64
}

type moduleAccessResult struct {
	access   map[string]bool
	complete bool
}

var moduleAccessCache struct {
	sync.Mutex
	values map[moduleAccessKey]moduleAccessResult
}

type importTables struct {
	textHash          uint64
	byLocal           map[string][]analysis.Import
	wildcard          []analysis.Import
	implicitWildcards int
}

var importTableCache struct {
	sync.Mutex
	values map[protocol.URI]importTables
}

func (i *Index) javaReadableWithMemoLocked(memo *accessibilityMemo, moduleName string) bool {
	if memo.fromModule == nil || memo.fromModule.JavaModuleName == "" || moduleName == "" || memo.fromModule.JavaModuleName == moduleName {
		return true
	}
	if !memo.javaReadReady {
		memo.javaReadable, memo.javaReadComplete = i.javaReadableSetLocked(memo.fromModule)
		memo.javaReadReady = true
	}
	return memo.javaReadComplete && memo.javaReadable[moduleName]
}

func newAccessibilityMemoLocked(i *Index, file *analysis.ParsedFile) *accessibilityMemo {
	from, complete := moduleForURIInModules(file.URI, i.modules)
	fromSourceSet := ""
	if complete {
		fromSourceSet, complete = sourceSetForURIInModule(file.URI, from)
	}
	if i.generation.Load() == 0 {
		complete = true
	}
	if _, library := i.librarySources[file.URI]; library {
		// Library files (jar:/jrt:) belong to no workspace module; their
		// ownership is fully known, and their supertypes and members must be
		// resolvable from the library's own context.
		from, fromSourceSet, complete = nil, "", true
	}
	return &accessibilityMemo{
		fromModule:        from,
		fromSourceSet:     fromSourceSet,
		ownershipComplete: complete,
		targetModules:     make(map[protocol.URI]*ModuleInfo),
		targetSourceSets:  make(map[protocol.URI]string),
		targetComplete:    make(map[protocol.URI]bool),
		javaAccess:        make(map[string]bool),
		libraryJava:       make(map[string]bool),
		sourceSetDistance: make(map[string]int),
		remainingWork:     maxResolutionCandidates,
	}
}

func (i *Index) sourceSetDistanceWithMemoLocked(memo *accessibilityMemo, target *ModuleInfo, targetSet string) int {
	if memo.fromModule == nil || target == nil || memo.fromModule.Name != target.Name || memo.fromModule.Dir != target.Dir {
		return -1
	}
	key := targetSet
	if distance, known := memo.sourceSetDistance[key]; known {
		return distance
	}
	distance := sourceSetAccessDistance(memo.fromModule, memo.fromSourceSet, targetSet)
	memo.sourceSetDistance[key] = distance
	return distance
}

func (i *Index) accessibilityTargetLocked(memo *accessibilityMemo, uri protocol.URI) (*ModuleInfo, string, bool) {
	target, known := memo.targetModules[uri]
	if !known {
		var complete bool
		target, complete = moduleForURIInModules(uri, i.modules)
		memo.targetModules[uri] = target
		if complete {
			memo.targetSourceSets[uri], complete = sourceSetForURIInModule(uri, target)
		}
		if i.generation.Load() == 0 {
			complete = true
		}
		memo.targetComplete[uri] = complete
	}
	return target, memo.targetSourceSets[uri], memo.targetComplete[uri]
}

func (i *Index) moduleCanAccessWithMemoLocked(memo *accessibilityMemo, target *ModuleInfo, targetSourceSet string) bool {
	if !memo.ownershipComplete {
		return false
	}
	from := memo.fromModule
	if from == nil || target == nil {
		return true
	}
	if from.Name == target.Name && from.Dir == target.Dir {
		return sourceSetCanAccess(from, memo.fromSourceSet, targetSourceSet)
	}
	if targetSourceSet != "main" && targetSourceSet != "commonMain" {
		return false
	}
	if !memo.moduleReady {
		// The set of modules a module can see changes only with the build
		// model, whose every mutation moves the environment version, yet it was
		// rebuilt -- walking the dependency graph -- for every single reference
		// resolved.
		key := moduleAccessKey{owner: i, root: from.Root, name: from.Name, dir: from.Dir, sourceSet: memo.fromSourceSet, environment: i.semanticEnvironmentVersion}
		moduleAccessCache.Lock()
		cached, known := moduleAccessCache.values[key]
		moduleAccessCache.Unlock()
		if known {
			memo.moduleAccess, memo.moduleComplete = cached.access, cached.complete
		} else {
			byName := make(map[string][]*ModuleInfo, len(i.modules))
			for index := range i.modules {
				module := &i.modules[index]
				name := module.Root + "\x00" + module.Name
				byName[name] = append(byName[name], module)
			}
			memo.moduleAccess, memo.moduleComplete = moduleAccessSet(from, memo.fromSourceSet, byName)
			moduleAccessCache.Lock()
			if moduleAccessCache.values == nil || len(moduleAccessCache.values) > 1024 {
				moduleAccessCache.values = make(map[moduleAccessKey]moduleAccessResult)
			}
			moduleAccessCache.values[key] = moduleAccessResult{access: memo.moduleAccess, complete: memo.moduleComplete}
			moduleAccessCache.Unlock()
		}
		memo.moduleReady = true
	}
	return memo.moduleComplete && memo.moduleAccess[moduleAccessIdentity(target)]
}

func (i *Index) accessibleWithMemoLocked(file *analysis.ParsedFile, symbol analysis.Symbol, memo *accessibilityMemo, positions ...int) bool {
	if symbol.InteropLanguage != analysis.LanguageUnknown && symbol.InteropLanguage != file.Language {
		return false
	}
	if file.Language == analysis.LanguageJava && containsString(symbol.Modifiers, "JvmSynthetic") {
		return false
	}
	if file.Language == analysis.LanguageJava && symbol.Language == analysis.LanguageKotlin && !symbol.Synthetic {
		if symbol.JVMName != "" || symbol.ContainerID == "" && (analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindProperty) {
			return false
		}
	}
	fromModule := memo.fromModule
	fromSourceSet := memo.fromSourceSet
	targetModule, targetSourceSet, targetComplete := i.accessibilityTargetLocked(memo, symbol.URI)
	if !memo.ownershipComplete && symbol.URI != file.URI || !symbol.Library && !targetComplete && symbol.URI != file.URI {
		return false
	}
	if symbol.Library && fromModule != nil {
		if source, exists := i.librarySources[symbol.URI]; exists {
			if access := i.libraryAccess[filepath.Clean(source.Archive)]; len(access) > 0 && !access[fromModule.Dir] && !access[libraryAccessKey(fromModule.Dir, fromSourceSet)] {
				return false
			}
			if file.Language == analysis.LanguageJava {
				archive := filepath.Clean(source.Archive)
				if module, modular := i.libraryModules[archive]; modular {
					key := archive + "\x00" + symbol.Package
					allowed, known := memo.libraryJava[key]
					if !known {
						allowed = i.javaReadableWithMemoLocked(memo, module.Name)
						if allowed && !module.Automatic && fromModule != nil && fromModule.JavaModuleName != "" && fromModule.JavaModuleName != module.Name {
							targets, exported := module.Exports[symbol.Package]
							allowed = exported && (containsString(targets, "*") || containsString(targets, fromModule.JavaModuleName))
						}
						memo.libraryJava[key] = allowed
					}
					if !allowed {
						return false
					}
				}
			}
		}
	}
	if targetModule != nil && !i.moduleCanAccessWithMemoLocked(memo, targetModule, targetSourceSet) {
		return false
	}
	if file.Language == analysis.LanguageJava && symbol.Language == analysis.LanguageJava {
		key := moduleAccessIdentity(targetModule) + "\x00" + symbol.Package
		allowed, known := memo.javaAccess[key]
		if !known {
			allowed = targetModule == nil || i.javaReadableWithMemoLocked(memo, targetModule.JavaModuleName)
			if allowed && fromModule != nil && targetModule != nil && fromModule.JavaModuleName != "" && targetModule.JavaModuleName != "" && fromModule.JavaModuleName != targetModule.JavaModuleName {
				targets, exported := targetModule.JavaExports[symbol.Package]
				allowed = exported && (containsString(targets, "*") || containsString(targets, fromModule.JavaModuleName))
			}
			memo.javaAccess[key] = allowed
		}
		if !allowed {
			return false
		}
	}
	visibility := ""
	for _, modifier := range symbol.Modifiers {
		if modifier == "private" || modifier == "protected" || modifier == "public" || modifier == "internal" {
			visibility = modifier
		}
	}
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok {
			if IsLocalDeclarationOwner(*owner) {
				if owner.URI != file.URI || len(positions) == 0 || !symbol.InScopeAt(positions[0]) {
					return false
				}
			}
			if analysis.IsTypeKind(owner.Kind) && !i.accessibleWithMemoLocked(file, *i.realBinaryContainerLocked(owner), memo, positions...) {
				return false
			}
		}
	}
	if visibility == "protected" && symbol.Language == analysis.LanguageKotlin {
		if symbol.ContainerID == "" || len(positions) == 0 {
			return false
		}
		owner := i.symbols[symbol.ContainerID]
		for owner != nil && !analysis.IsTypeKind(owner.Kind) && owner.ContainerID != "" {
			owner = i.symbols[owner.ContainerID]
		}
		current := i.enclosingTypeLocked(file, positions[0])
		if owner == nil || current.ID == "" || current.ID != owner.ID && !i.containerInheritsLocked(current.ID, owner.ID) {
			return false
		}
	}
	if symbol.URI == file.URI {
		if visibility != "private" || symbol.ContainerID == "" {
			return true
		}
		if len(positions) == 0 {
			// No position to check against: the name came from code in this
			// file (an inferred type, a hierarchy root), which is where a
			// private declaration is visible. Refusing it emptied the member
			// list of every private nested class, `copy` included.
			return true
		}
		owner, ok := i.symbols[symbol.ContainerID]
		if !ok {
			return false
		}
		if symbol.Language == analysis.LanguageJava {
			for owner.ContainerID != "" {
				parent, exists := i.symbols[owner.ContainerID]
				if !exists || !analysis.IsTypeKind(parent.Kind) {
					break
				}
				owner = parent
			}
		} else if owner.Kind == analysis.KindObject && containsString(owner.Modifiers, "companion") {
			// A companion's private members are visible throughout the class
			// that contains it: `private val logger` in the companion is the
			// class's logger.
			if outer, exists := i.symbols[owner.ContainerID]; exists && analysis.IsTypeKind(outer.Kind) {
				owner = outer
			}
		}
		return owner.StartByte <= positions[0] && positions[0] <= owner.EndByte
	}
	if visibility == "private" {
		return false
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && (owner.Kind == analysis.KindInterface || owner.Kind == analysis.KindAnnotation) {
			visibility = "public"
		}
	}
	if symbol.Language == analysis.LanguageJava && visibility == "" && symbol.Package != file.Package {
		return false // Java package-private declaration.
	}
	if visibility == "protected" && symbol.Package != file.Package {
		if symbol.ContainerID == "" {
			return false
		}
		for _, candidate := range file.Symbols {
			if analysis.IsTypeKind(candidate.Kind) && i.containerInheritsLocked(candidate.ID, symbol.ContainerID) {
				return true
			}
		}
		return false
	}
	if visibility == "internal" && file.Language == analysis.LanguageKotlin && fromModule != nil && targetModule != nil && (fromModule.Name != targetModule.Name || fromModule.Dir != targetModule.Dir) {
		return false
	}
	return true
}

func IsLocalDeclarationOwner(symbol analysis.Symbol) bool {
	return analysis.IsCallableKind(symbol.Kind)
}

func (i *Index) typeQualifierActsAsValueLocked(file *analysis.ParsedFile, types []analysis.Symbol) bool {
	if file.Language != analysis.LanguageKotlin {
		return false
	}
	for _, symbol := range types {
		if symbol.Kind == analysis.KindObject {
			return true
		}
	}
	return false
}

func (i *Index) memberAvailableThroughTypeQualifierLocked(file *analysis.ParsedFile, symbol analysis.Symbol, types []analysis.Symbol) bool {
	if i.staticOrNestedMemberLocked(symbol) {
		return true
	}
	if file.Language == analysis.LanguageKotlin && symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && owner.Kind == analysis.KindObject && containsString(owner.Modifiers, "companion") {
			return true
		}
	}
	return i.typeQualifierActsAsValueLocked(file, types) && !symbol.Synthetic
}

func (i *Index) staticOrNestedMemberLocked(symbol analysis.Symbol) bool {
	return analysis.IsTypeKind(symbol.Kind) || containsString(symbol.Modifiers, "static") || symbol.Kind == analysis.KindEnumMember
}

func (i *Index) staticLikeContextLocked(file *analysis.ParsedFile, at int) bool {
	for _, symbol := range file.Symbols {
		if symbol.StartByte <= at && at <= symbol.EndByte {
			if symbol.Language == analysis.LanguageJava && !analysis.IsTypeKind(symbol.Kind) && containsString(symbol.Modifiers, "static") {
				return true
			}
		}
	}
	return false
}

func nestedTypeCapturesOuter(nested, outer analysis.Symbol) bool {
	if nested.Language == analysis.LanguageKotlin {
		return containsString(nested.Modifiers, "inner")
	}
	if nested.Language == analysis.LanguageJava {
		return nested.Kind == analysis.KindClass && outer.Kind != analysis.KindInterface && outer.Kind != analysis.KindAnnotation && !containsString(nested.Modifiers, "static")
	}
	return false
}

func (i *Index) extensionVisibleLocked(file *analysis.ParsedFile, symbol analysis.Symbol, positions ...int) bool {
	if symbol.ContainerID != "" {
		if owner, ok := i.symbols[symbol.ContainerID]; ok && analysis.IsCallableKind(owner.Kind) {
			if symbol.URI != file.URI || len(positions) == 0 || !symbol.InScopeAt(positions[0]) {
				return false
			}
		}
	}
	if symbol.ReceiverType == "" || symbol.URI == file.URI || symbol.Package == file.Package {
		return true
	}
	// Top-level extensions obey exactly the same package/import rules as other
	// top-level declarations. In particular, Kotlin's default imports include
	// the generic extensions in package kotlin (apply, let, run, also, takeIf,
	// and friends). Requiring a textual import here made those declarations
	// discoverable in the index but permanently invisible to resolution.
	if symbol.ContainerID == "" {
		return i.topLevelVisibleLocked(file, symbol)
	}
	for _, imp := range i.effectiveImportsLocked(file) {
		if imp.Path == symbol.FQN || imp.Wildcard && imp.Path == symbol.Package {
			return true
		}
	}
	return false
}

func (i *Index) containerInheritsLocked(containerID, targetContainerID string) bool {
	target, ok := i.symbols[targetContainerID]
	if !ok {
		return false
	}
	queue := []string{containerID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		container, exists := i.symbols[id]
		if !exists {
			continue
		}
		file := i.files[container.URI]
		if file == nil {
			continue
		}
		for _, supertype := range container.Supertypes {
			for _, parent := range i.resolveTypeSymbolsForOwnerLocked(file, supertype, *container) {
				if parent.ID == target.ID {
					return true
				}
				queue = append(queue, parent.ID)
			}
		}
	}
	return false
}

func (i *Index) symbolsForIDsLocked(ids []string, accept func(analysis.Symbol) bool) []analysis.Symbol {
	seen := map[string]bool{}
	out := make([]analysis.Symbol, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		s, ok := i.symbols[id]
		if ok && (accept == nil || accept(*s)) {
			seen[id] = true
			out = append(out, *s)
		}
	}
	return out
}

// implicitSupertypes lists the supertypes a declaration has without spelling
// them, fully qualified so they resolve from any file.
func implicitSupertypes(symbol analysis.Symbol) []string {
	switch symbol.Kind {
	case analysis.KindClass, analysis.KindInterface, analysis.KindObject, analysis.KindEnum, analysis.KindRecord, analysis.KindAnnotation:
	default:
		return nil
	}
	switch symbol.Language {
	case analysis.LanguageKotlin:
		if symbol.FQN == "kotlin.Any" {
			return nil
		}
		out := []string{"kotlin.Any"}
		if symbol.Kind == analysis.KindEnum {
			out = append(out, "kotlin.Enum<"+symbol.Name+">")
		}
		return out
	case analysis.LanguageJava:
		if symbol.FQN == "java.lang.Object" {
			return nil
		}
		out := []string{"java.lang.Object"}
		switch symbol.Kind {
		case analysis.KindEnum:
			out = append(out, "java.lang.Enum<"+symbol.Name+">")
		case analysis.KindRecord:
			out = append(out, "java.lang.Record")
		}
		return out
	}
	return nil
}

// preferSourceDeclarations drops a library copy of a type whose source
// declaration is also indexed. The same class reaches the index twice when a
// module's build output is on a classpath next to its sources; the source is
// the one to navigate to and the copy only makes the name ambiguous.
func preferSourceDeclarations(values []analysis.Symbol) []analysis.Symbol {
	if len(values) < 2 {
		return values
	}
	source := make(map[string]bool, len(values))
	for _, value := range values {
		if !value.Library && value.FQN != "" {
			source[value.FQN] = true
		}
	}
	if len(source) == 0 {
		return values
	}
	kept := make([]analysis.Symbol, 0, len(values))
	for _, value := range values {
		if value.Library && source[value.FQN] {
			continue
		}
		kept = append(kept, value)
	}
	return kept
}

// withoutVariance drops a use-site variance projection: a lambda for a
// `Consumer<in T>` parameter receives a T, not an `in T`.
func withoutVariance(typ string) string {
	typ = strings.TrimSpace(typ)
	for _, projection := range []string{"in ", "out ", "? extends ", "? super "} {
		if strings.HasPrefix(typ, projection) {
			return strings.TrimSpace(typ[len(projection):])
		}
	}
	return typ
}

// realBinaryContainerLocked is the declaration a nested class file's outer
// stub stands for. `JsonSubTypes$Type.class` renders a bare `JsonSubTypes`
// around its class only to nest it; the stub has no modifiers of its own, so
// judging access by it made every nested library type package-private.
func (i *Index) realBinaryContainerLocked(owner *analysis.Symbol) *analysis.Symbol {
	if owner == nil || !owner.Synthetic || !owner.Library || owner.FQN == "" || !analysis.IsTypeKind(owner.Kind) {
		return owner
	}
	for _, id := range i.byFQN[owner.FQN] {
		if real := i.symbols[id]; real != nil && !real.Synthetic && analysis.IsTypeKind(real.Kind) {
			return real
		}
	}
	return owner
}

// binaryNestedTypeIDsLocked lists the nested types of owner that were read
// from class files of their own, whose container is that file's outer stub
// rather than owner itself, so owner's member buckets never list them.
func (i *Index) binaryNestedTypeIDsLocked(owner analysis.Symbol, name string) []string {
	if owner.FQN == "" || owner.Name == "" {
		return nil
	}
	bucket := i.byContainerName[owner.Name]
	if name != "" {
		bucket = i.byContainerMember[memberKey(owner.Name, name)]
	}
	var ids []string
	for _, id := range bucket {
		nested := i.symbols[id]
		if nested == nil || nested.ContainerID == owner.ID || !analysis.IsTypeKind(nested.Kind) || nested.Synthetic || nested.FQN != owner.FQN+"."+nested.Name {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// lambdaArgumentAt reports whether the argument spanning [start, end) is a
// lambda literal, possibly labelled (`loop@{ ... }`) or named (`block = { }`).
func lambdaArgumentAt(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	argument := strings.TrimSpace(text[start:end])
	if name, value, named := namedArgument(argument); named && name != "" {
		argument = strings.TrimSpace(value)
	}
	if at := strings.IndexByte(argument, '@'); at > 0 && at+1 < len(argument) && argument[at+1] == '{' && isSimpleIdentifier(argument[:at]) {
		argument = argument[at+1:]
	}
	return strings.HasPrefix(argument, "{")
}

// explicitTypeArgumentsAfter reads the type argument list written right after
// a callee's name (`withType<Jar>`, `mockk<Repo>`), or nil when there is none.
func explicitTypeArgumentsAfter(text string, end int) []string {
	if end < 0 || end >= len(text) || text[end] != '<' {
		return nil
	}
	close := matchingTypeArgumentEnd(text, end)
	if close < 0 || close-end > 512 {
		return nil
	}
	arguments := splitTopLevelTypeArguments(text[end+1 : close])
	for index := range arguments {
		arguments[index] = strings.TrimSpace(arguments[index])
		if arguments[index] == "" {
			return nil
		}
	}
	return arguments
}
