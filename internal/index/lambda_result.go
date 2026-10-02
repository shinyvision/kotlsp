package index

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// lambdaParameterList is what may stand before a lambda's arrow: names,
// destructuring parentheses and type annotations, never an expression.
var lambdaParameterList = regexp.MustCompile(`^[\s\w,():<>?.@*]*$`)

// lambdaResultExpression is the expression a lambda literal evaluates to --
// its last statement -- and that expression's offset within the literal.
// ok is false for a lambda whose last statement produces no value (a
// declaration or an assignment) or whose shape is not understood.
func lambdaResultExpression(lambda string) (string, int, bool) {
	if len(lambda) < 2 || lambda[0] != '{' || lexical.MatchingDelimiter(lambda, 0, "{", "}", true) != len(lambda)-1 {
		return "", 0, false
	}
	start, end := 1, len(lambda)-1
	type piece struct{ start, end int }
	var pieces []piece
	depth, pieceStart, arrowSeen := 0, start, false
	for index := start; index < end; index++ {
		switch c := lambda[index]; c {
		case '"', '\'':
			index = skipQuotedLiteral(lambda, index, end)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '-':
			if depth == 0 && !arrowSeen && index+1 < end && lambda[index+1] == '>' {
				arrowSeen = true
				if lambdaParameterList.MatchString(lambda[start:index]) {
					pieceStart = index + 2
					pieces = pieces[:0]
				}
				index++
			}
		case '\n', ';':
			if depth == 0 {
				pieces = append(pieces, piece{pieceStart, index})
				pieceStart = index + 1
			}
		}
		if depth < 0 {
			return "", 0, false
		}
	}
	pieces = append(pieces, piece{pieceStart, end})
	// Lines continue a statement when either side of the break says so:
	// `.map { }` on its own line, or a line ending in an operator.
	var statements []piece
	for _, current := range pieces {
		text := strings.TrimSpace(lambda[current.start:current.end])
		if text == "" {
			continue
		}
		if len(statements) > 0 {
			previous := strings.TrimSpace(lambda[statements[len(statements)-1].start:statements[len(statements)-1].end])
			if continuesStatement(previous, text) {
				statements[len(statements)-1].end = current.end
				continue
			}
		}
		statements = append(statements, current)
	}
	if len(statements) == 0 {
		return "", 0, false
	}
	last := statements[len(statements)-1]
	raw := lambda[last.start:last.end]
	offset := last.start + len(raw) - len(strings.TrimLeft(raw, " \t\r\n"))
	expression := strings.TrimSpace(raw)
	if strings.HasPrefix(expression, "return@") {
		label := strings.IndexAny(expression, " \t")
		if label < 0 {
			return "", 0, false
		}
		trimmed := strings.TrimLeft(expression[label:], " \t")
		offset += len(expression) - len(trimmed)
		expression = trimmed
	}
	for _, keyword := range []string{"val ", "var ", "fun ", "class ", "object ", "return ", "return", "throw ", "for ", "while ", "do "} {
		if strings.HasPrefix(expression, keyword) || expression == strings.TrimSpace(keyword) {
			return "", 0, false
		}
	}
	if topLevelAssignment(expression) {
		return "", 0, false
	}
	return expression, offset, true
}

func skipQuotedLiteral(text string, open, end int) int {
	quote := text[open]
	if quote == '"' && strings.HasPrefix(text[open:], `"""`) {
		if close := strings.Index(text[open+3:end], `"""`); close >= 0 {
			return open + 3 + close + 2
		}
		return end
	}
	for index := open + 1; index < end; index++ {
		switch text[index] {
		case '\\':
			index++
		case quote:
			return index
		case '$':
			if quote == '"' && index+1 < end && text[index+1] == '{' {
				if close := lexical.MatchingDelimiter(text, index+1, "{", "}", true); close > index && close < end {
					index = close
				}
			}
		}
	}
	return end
}

var statementContinuationPrefixes = []string{".", "?.", "?:", "&&", "||", "as ", "as?", "+", "*", "/", "%", "==", "!=", "->", "else", "catch", "finally"}
var statementContinuationSuffixes = []string{"=", "(", ",", ".", "+", "-", "*", "/", "&&", "||", "?:", "->", "?."}

func continuesStatement(previous, next string) bool {
	for _, prefix := range statementContinuationPrefixes {
		if strings.HasPrefix(next, prefix) {
			return true
		}
	}
	for _, suffix := range statementContinuationSuffixes {
		if strings.HasSuffix(previous, suffix) {
			return true
		}
	}
	return false
}

// topLevelAssignment reports whether expression is `target = value` (or a
// compound assignment), which is a statement without a value.
func topLevelAssignment(expression string) bool {
	depth := 0
	for index := 0; index < len(expression); index++ {
		switch c := expression[index]; c {
		case '"', '\'':
			index = skipQuotedLiteral(expression, index, len(expression))
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if depth != 0 {
				continue
			}
			before := byte(0)
			if index > 0 {
				before = expression[index-1]
			}
			after := byte(0)
			if index+1 < len(expression) {
				after = expression[index+1]
			}
			if after == '=' || before == '=' || before == '!' || before == '<' || before == '>' {
				continue
			}
			return true
		}
	}
	return false
}

// locateExpressionNearLocked finds where text occurs in the document closest
// to at. Inference works on expression text, but a lambda's parameters exist
// only at the lambda's place in the file, so its body has to be typed there.
// The text may have been normalised the way chains are (`?.` read as `.`,
// `!!` dropped), so the document is normalised the same way to compare.
func (i *Index) locateExpressionNearLocked(file *analysis.ParsedFile, text string, at int) int {
	document := i.documentTextLocked(file.URI)
	if document == "" || text == "" || at < 0 || at > len(document) {
		return -1
	}
	const window = 1 << 16
	low, high := max(0, at-window), min(len(document), at+window+len(text))
	normalized, offsets := normalizedChainText(document[low:high])
	best, bestDistance := -1, int(^uint(0)>>1)
	for from := 0; from <= len(normalized); {
		found := strings.Index(normalized[from:], text)
		if found < 0 {
			break
		}
		position := low + offsets[from+found]
		distance := position - at
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			best, bestDistance = position, distance
		}
		from += found + 1
	}
	return best
}

// normalizedChainText applies typeOfExpressionLocked's rewriting (`?.` to
// `.`, `!!` removed) and maps each byte of the result back to the input.
func normalizedChainText(text string) (string, []int) {
	var out strings.Builder
	offsets := make([]int, 0, len(text)+1)
	for index := 0; index < len(text); index++ {
		if text[index] == '?' && index+1 < len(text) && text[index+1] == '.' {
			continue
		}
		if text[index] == '!' && index+1 < len(text) && text[index+1] == '!' {
			index++
			continue
		}
		out.WriteByte(text[index])
		offsets = append(offsets, index)
	}
	offsets = append(offsets, len(text))
	return out.String(), offsets
}

// lambdaResultTypeLocked types what a lambda argument evaluates to, at its
// place in the file, so `it` and named parameters mean what they mean there.
func (i *Index) lambdaResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, lambda string, at int) string {
	// A lambda's result is wanted from inside other inference -- every
	// reference in a `transactional { }` body asks about that call -- and
	// typing a body nests inference again. Past a few levels it only
	// multiplies the work: the answer is then unknown.
	if file.Language != analysis.LanguageKotlin || resolutionDepth(ctx) > maxLambdaResultDepth || resolutionNestingExceeded(ctx) {
		return ""
	}
	lambda = strings.TrimSpace(lambda)
	expression, offset, ok := lambdaResultExpression(lambda)
	if !ok {
		return ""
	}
	position := i.locateExpressionNearLocked(file, lambda, at)
	if position < 0 {
		return ""
	}
	key := lambdaResultKey{owner: i, uri: file.URI, textHash: file.TextHash, position: position, declarations: i.late.declarations.Load(), environment: i.semanticEnvironmentVersion}
	lambdaResultCache.Lock()
	cached, hit := lambdaResultCache.values[key]
	lambdaResultCache.Unlock()
	if hit {
		return cached
	}
	result := i.inferExpressionTypeLocked(ctx, file, expression, position+offset)
	if ctx.Err() != nil || resolutionTruncated(ctx) {
		return result
	}
	lambdaResultCache.Lock()
	if lambdaResultCache.values == nil || len(lambdaResultCache.values) > 100_000 {
		lambdaResultCache.values = make(map[lambdaResultKey]string)
	}
	lambdaResultCache.values[key] = result
	lambdaResultCache.Unlock()
	return result
}

const maxLambdaResultDepth = 12

type lambdaResultKey struct {
	owner        *Index
	uri          protocol.URI
	textHash     uint64
	position     int
	declarations uint64
	environment  uint64
}

var lambdaResultCache struct {
	sync.Mutex
	values map[lambdaResultKey]string
}

// bindLambdaResultsLocked binds the type parameters a callee's function-typed
// parameters return from the lambdas passed for them: `map { it.name }`
// makes R a String. Without it every `map`, `associate` and `flatMap` result
// was the bare parameter R, and whatever followed the call had no type.
func (i *Index) bindLambdaResultsLocked(ctx context.Context, file *analysis.ParsedFile, callee analysis.Symbol, callArguments []string, typeParameters map[string]bool, bindings map[string]string, at int) map[string]string {
	for index, argument := range callArguments {
		if index >= len(callee.Parameters) {
			break
		}
		argument = strings.TrimSpace(argument)
		if !strings.HasPrefix(argument, "{") {
			continue
		}
		parameterType := strings.TrimPrefix(strings.TrimSpace(callee.Parameters[index].Type), "vararg ")
		_, _, result, ok := parseKotlinFunctionType(parameterType)
		if !ok {
			// A Java functional interface takes a Kotlin lambda by SAM
			// conversion: `Function<? super T, ? extends V>` is `(T) -> V`.
			_, _, result, ok = parseKotlinFunctionType(i.samFunctionTypeLocked(callee, parameterType))
		}
		if !ok || !typeContainsAnyParameter(result, callee.TypeParameters) {
			continue
		}
		unbound := false
		for parameter := range typeParameters {
			if bindings[parameter] == "" && typeContainsAnyParameter(result, []string{parameter}) {
				unbound = true
				break
			}
		}
		if !unbound {
			continue
		}
		bodyType := i.lambdaResultTypeLocked(ctx, file, argument, at)
		if bodyType == "" {
			continue
		}
		if bindings == nil {
			bindings = make(map[string]string)
		}
		// The body's type may be a subtype of what the parameter returns
		// (`flatMap`'s Iterable<R> from a List), so its supertypes are tried.
		for _, spelling := range i.receiverTypeSpellingsLocked(ctx, file, bodyType) {
			trial := make(map[string]string, len(bindings))
			for key, value := range bindings {
				trial[key] = value
			}
			if matchTypePattern(strings.TrimSuffix(strings.TrimSpace(result), "?"), strings.TrimSuffix(strings.TrimSpace(spelling), "?"), typeParameters, trial) {
				bindings = trial
				break
			}
		}
	}
	return bindings
}

// samFunctionTypeLocked spells a functional interface type as the Kotlin
// function type its single abstract method gives a lambda: Java's
// `Function<? super T, ? extends V>` is `(T) -> V`. It is "" for any other
// type, or an interface with more than one abstract method.
func (i *Index) samFunctionTypeLocked(callee analysis.Symbol, typeName string) string {
	base, arguments := splitInstantiatedType(kotlinizeBinaryType(typeName))
	// Library declarations spell types qualified, and their class files are
	// not kept parsed; a source declaration resolves in its own file.
	var owners []analysis.Symbol
	for _, id := range i.byFQN[base] {
		if symbol := i.symbols[id]; symbol != nil && analysis.IsTypeKind(symbol.Kind) && !symbol.Synthetic {
			owners = append(owners, *symbol)
		}
	}
	if len(owners) == 0 {
		if declaring := i.files[callee.URI]; declaring != nil {
			owners = i.resolveTypeSymbolsLocked(declaring, base)
		}
	}
	owners = uniqueSymbolsByFQN(owners)
	if len(owners) != 1 || owners[0].Kind != analysis.KindInterface {
		return ""
	}
	owner := owners[0]
	for index := range arguments {
		arguments[index] = withoutVariance(arguments[index])
	}
	var abstract []*analysis.Symbol
	for _, id := range i.byContainerName[owner.ID] {
		method := i.symbols[id]
		if method == nil || method.ContainerID != owner.ID || !analysis.IsCallableKind(method.Kind) || method.Kind == analysis.KindConstructor ||
			containsString(method.Modifiers, "static") || containsString(method.Modifiers, "default") || containsString(method.Modifiers, "private") {
			continue
		}
		// Object's methods redeclared in an interface (`equals` in
		// Comparator) are not its abstract method.
		if method.Name == "equals" && len(method.Parameters) == 1 || (method.Name == "hashCode" || method.Name == "toString") && len(method.Parameters) == 0 {
			continue
		}
		// A Kotlin interface member with a body is not abstract either.
		if method.Language == analysis.LanguageKotlin && kotlinMemberHasBody(i.documentTextLocked(method.URI), *method) {
			continue
		}
		abstract = append(abstract, method)
	}
	// Read from a class file, an interface's abstract methods say so and its
	// default methods say nothing; in Java source it is the other way round.
	var declaredAbstract []*analysis.Symbol
	for _, method := range abstract {
		if containsString(method.Modifiers, "abstract") {
			declaredAbstract = append(declaredAbstract, method)
		}
	}
	if len(declaredAbstract) > 0 {
		abstract = declaredAbstract
	}
	if len(abstract) != 1 {
		return ""
	}
	method := abstract[0]
	parameters := make([]string, len(method.Parameters))
	for index, parameter := range method.Parameters {
		parameters[index] = kotlinViewOfJavaType(substituteTypeParameters(parameter.Type, owner.TypeParameters, arguments))
	}
	result := kotlinViewOfJavaType(substituteTypeParameters(method.Type, owner.TypeParameters, arguments))
	if result == "" || result == "void" {
		result = "Unit"
	}
	return "(" + strings.Join(parameters, ", ") + ") -> " + result
}

// kotlinMemberHasBody reports whether a Kotlin source member is implemented:
// a block or an expression body after its signature.
func kotlinMemberHasBody(text string, member analysis.Symbol) bool {
	start, end := member.NameEndByte, member.EndByte
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	signature := text[start:end]
	depth := 0
	for index := 0; index < len(signature); index++ {
		if signature[index] == '-' && index+1 < len(signature) && signature[index+1] == '>' {
			index++
			continue
		}
		switch signature[index] {
		case '(', '<':
			depth++
		case ')', '>':
			depth--
		case '{', '=':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// instantiateCallResultLocked is a generic callee's result type at one call:
// its own type parameters bound from the arguments' types (`Mono.just(key)`)
// and from the lambdas passed for functional parameters (`flux.map { }`),
// and whatever stays unbound read as unknown (`List<*>`) instead of naming a
// type that does not exist. ownerParameters/ownerArguments instantiate the
// declaring class first.
func (i *Index) instantiateCallResultLocked(ctx context.Context, file *analysis.ParsedFile, callee analysis.Symbol, result string, ownerParameters, ownerArguments, callArguments []string, at int) string {
	// Binding costs inference of arguments and lambda bodies; a result that
	// names none of the callee's type parameters needs none of it.
	if len(callee.TypeParameters) == 0 || file.Language != analysis.LanguageKotlin || !typeContainsAnyParameter(result, callee.TypeParameters) {
		return result
	}
	instantiated := callee
	instantiated.Parameters = append([]analysis.Parameter(nil), callee.Parameters...)
	for index := range instantiated.Parameters {
		instantiated.Parameters[index].Type = substituteTypeParameters(instantiated.Parameters[index].Type, ownerParameters, ownerArguments)
	}
	parameters := make(map[string]bool, len(callee.TypeParameters))
	for _, parameter := range callee.TypeParameters {
		parameters[parameter] = true
	}
	bindings := map[string]string{}
	for index, argument := range callArguments {
		if index >= len(instantiated.Parameters) || strings.HasPrefix(strings.TrimSpace(argument), "{") {
			continue
		}
		if _, _, named := namedArgument(argument); named {
			continue
		}
		actual := i.inferExpressionTypeLocked(ctx, file, argument, at)
		if actual == "" {
			continue
		}
		expected := strings.TrimPrefix(strings.TrimSpace(instantiated.Parameters[index].Type), "vararg ")
		if !typeContainsAnyParameter(expected, callee.TypeParameters) {
			continue
		}
		if callee.Language == analysis.LanguageJava {
			expected = kotlinViewOfJavaType(expected)
		}
		trial := make(map[string]string, len(bindings))
		for key, value := range bindings {
			trial[key] = value
		}
		if matchTypePattern(strings.TrimSuffix(withoutVariance(expected), "?"), strings.TrimSuffix(actual, "?"), parameters, trial) {
			bindings = trial
			continue
		}
		// The argument may be a subtype: jOOQ's generated `ProductTypes` is a
		// `TableImpl<Record>`, which binds R of `insertInto(Table<R>)` through
		// its supertypes.
		if i.inferTypeParameterBindingsLocked(ctx, file, strings.TrimSuffix(withoutVariance(expected), "?"), strings.TrimSuffix(actual, "?"), callee.TypeParameters, trial) {
			bindings = trial
		}
	}
	bindings = i.bindCallableReferenceResultsLocked(ctx, file, instantiated, callArguments, parameters, bindings, at)
	bindings = i.bindLambdaResultsLocked(ctx, file, instantiated, callArguments, parameters, bindings, at)
	return starUnboundTypeArguments(substituteTypeBindings(result, bindings), callee.TypeParameters, bindings)
}

// callableReferenceArgument matches `Owner::function` (not `::class`).
var callableReferenceArgument = regexp.MustCompile(`^([A-Za-z_][\w.]*)::([A-Za-z_]\w*)$`)

// bindCallableReferenceResultsLocked binds what a function-typed parameter
// returns from a callable reference passed for it: `mapping(Product::create)`
// makes R the result of `Product.create`.
func (i *Index) bindCallableReferenceResultsLocked(ctx context.Context, file *analysis.ParsedFile, callee analysis.Symbol, callArguments []string, typeParameters map[string]bool, bindings map[string]string, at int) map[string]string {
	for index, argument := range callArguments {
		if index >= len(callee.Parameters) {
			break
		}
		match := callableReferenceArgument.FindStringSubmatch(strings.TrimSpace(argument))
		if match == nil || match[2] == "class" {
			continue
		}
		parameterType := strings.TrimPrefix(strings.TrimSpace(callee.Parameters[index].Type), "vararg ")
		_, _, result, ok := parseKotlinFunctionType(parameterType)
		if !ok {
			_, _, result, ok = parseKotlinFunctionType(i.samFunctionTypeLocked(callee, parameterType))
		}
		if !ok || !typeContainsAnyParameter(result, callee.TypeParameters) {
			continue
		}
		referenced := i.callableReferenceResultTypeLocked(ctx, file, match[1], match[2], at)
		if referenced == "" {
			continue
		}
		if bindings == nil {
			bindings = make(map[string]string)
		}
		for _, spelling := range i.receiverTypeSpellingsLocked(ctx, file, referenced) {
			trial := make(map[string]string, len(bindings))
			for key, value := range bindings {
				trial[key] = value
			}
			if matchTypePattern(strings.TrimSuffix(withoutVariance(strings.TrimSpace(result)), "?"), strings.TrimSuffix(strings.TrimSpace(spelling), "?"), typeParameters, trial) {
				bindings = trial
				break
			}
		}
	}
	return bindings
}

// callableReferenceResultTypeLocked is the result type of `Owner::name`: the
// functions named name in Owner, its companion, or as extensions on it, when
// they all answer the same type.
func (i *Index) callableReferenceResultTypeLocked(ctx context.Context, file *analysis.ParsedFile, owner, name string, at int) string {
	owners := i.resolveTypeSymbolsAtLocked(file, owner, at)
	if len(owners) != 1 {
		return ""
	}
	var candidates []analysis.Symbol
	for _, id := range i.byContainerMember[memberKey(owners[0].ID, name)] {
		if symbol := i.symbols[id]; symbol != nil && analysis.IsCallableKind(symbol.Kind) {
			candidates = append(candidates, *symbol)
		}
	}
	if companions, complete := i.companionMembersForOwnerBoundedLocked(ctx, owners[0], nil, maxResolutionCandidates); complete {
		for _, member := range companions {
			if member.Name == name && analysis.IsCallableKind(member.Kind) {
				candidates = append(candidates, member)
			}
		}
	}
	result := ""
	for _, candidate := range candidates {
		typ := i.declaredOrInferredMemberTypeLocked(ctx, candidate)
		if typ == "" {
			return ""
		}
		typ = i.respellDeclaredTypeLocked(file, candidate, typ)
		if result != "" && typ != result {
			return ""
		}
		result = typ
	}
	return result
}

// uniqueSymbolsByFQN keeps one declaration per qualified name: a library type
// is indexed from its class file and again from its sources.
func uniqueSymbolsByFQN(symbols []analysis.Symbol) []analysis.Symbol {
	seen := make(map[string]bool, len(symbols))
	out := symbols[:0:0]
	for _, symbol := range symbols {
		key := symbol.FQN
		if key == "" {
			key = symbol.ID
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, symbol)
		}
	}
	return out
}

// provablyNotFunctionalLocked reports whether a parameter type is a class the
// index knows that no lambda converts to: a class (not an interface), or an
// interface with no single abstract method. A type it cannot find, a type
// parameter or `Any` may still take a lambda.
func (i *Index) provablyNotFunctionalLocked(callee analysis.Symbol, typeName string) bool {
	base, _ := splitInstantiatedType(kotlinizeBinaryType(strings.TrimSuffix(strings.TrimSpace(typeName), "?")))
	if base == "" || containsString(callee.TypeParameters, base) || strings.Contains(base, "->") {
		return false
	}
	switch simpleType(base) {
	case "Any", "Object", "Function", "KFunction", "Unit":
		return false
	}
	// Gradle's Groovy-facing overloads take a Closure, an abstract class
	// whose jar build scripts do not index.
	if base == "groovy.lang.Closure" {
		return true
	}
	var owners []analysis.Symbol
	for _, id := range i.byFQN[base] {
		if symbol := i.symbols[id]; symbol != nil && analysis.IsTypeKind(symbol.Kind) && !symbol.Synthetic {
			owners = append(owners, *symbol)
		}
	}
	owners = uniqueSymbolsByFQN(owners)
	if len(owners) != 1 {
		return false
	}
	switch owners[0].Kind {
	case analysis.KindClass, analysis.KindEnum, analysis.KindRecord, analysis.KindAnnotation:
		return !containsString(owners[0].Modifiers, "fun")
	}
	return false
}

// callableReferenceAritiesLocked lists how many parameters `Owner::name`
// takes as a function value: an instance member takes its receiver first, a
// companion, object or static function does not.
func (i *Index) callableReferenceAritiesLocked(ctx context.Context, file *analysis.ParsedFile, owner, name string, at int) map[int]bool {
	owners := i.resolveTypeSymbolsAtLocked(file, owner, at)
	if len(owners) != 1 {
		return nil
	}
	arities := make(map[int]bool)
	for _, id := range i.byContainerMember[memberKey(owners[0].ID, name)] {
		symbol := i.symbols[id]
		if symbol == nil || !analysis.IsCallableKind(symbol.Kind) || symbol.Kind == analysis.KindConstructor {
			continue
		}
		receiver := 1
		if containsString(symbol.Modifiers, "static") || owners[0].Kind == analysis.KindObject {
			receiver = 0
		}
		arities[len(symbol.Parameters)+receiver] = true
	}
	if companions, complete := i.companionMembersForOwnerBoundedLocked(ctx, owners[0], nil, maxResolutionCandidates); complete {
		for _, member := range companions {
			if member.Name == name && analysis.IsCallableKind(member.Kind) {
				arities[len(member.Parameters)] = true
			}
		}
	}
	return arities
}

// filterByCallableReferenceArityLocked keeps the overloads whose
// function-typed parameters take as many parameters as the callable
// references passed for them, when that settles anything.
func (i *Index) filterByCallableReferenceArityLocked(ctx context.Context, file *analysis.ParsedFile, candidates []analysis.Symbol, arguments []string, at int) []analysis.Symbol {
	if len(candidates) < 2 || file.Language != analysis.LanguageKotlin {
		return candidates
	}
	kept := candidates[:0:0]
	for _, candidate := range candidates {
		fits := true
		for index, argument := range arguments {
			match := callableReferenceArgument.FindStringSubmatch(strings.TrimSpace(argument))
			if match == nil || match[2] == "class" || index >= len(candidate.Parameters) {
				continue
			}
			parameterType := strings.TrimPrefix(strings.TrimSpace(candidate.Parameters[index].Type), "vararg ")
			parameters := kotlinFunctionParameterTypes(parameterType)
			functional := parameters != nil || strings.Contains(parameterType, "->")
			if !functional {
				if sam := i.samFunctionTypeLocked(candidate, parameterType); sam != "" {
					parameters, functional = kotlinFunctionParameterTypes(sam), true
				}
			}
			if !functional {
				continue
			}
			if arities := i.callableReferenceAritiesLocked(ctx, file, match[1], match[2], at); len(arities) > 0 && !arities[len(parameters)] {
				fits = false
				break
			}
		}
		if fits {
			kept = append(kept, candidate)
		}
	}
	if len(kept) == 0 {
		return candidates
	}
	return kept
}
