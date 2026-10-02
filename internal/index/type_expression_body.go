package index

import (
	"context"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// Kotlin lets a function omit its return type when the body is an expression,
// and idiomatic code does so constantly: `private fun validUser(token: String)
// = users.find(token)`. Without typing that body the call has no result type,
// which costs far more than a hover: the value it produces has no members, so
// completion after it is empty, definition on those members finds nothing, and
// rename misses the call sites it cannot see.
//
// The body is typed exactly like any other expression, which means the same
// conservative rules and the same abstention when the syntax is not understood.
// Cycles (`fun a() = b()` with `fun b() = a()`) are bounded by the resolution
// nesting limit, and each answer is memoised for the index epoch that produced
// it.
func (i *Index) kotlinExpressionBodyResultTypeLocked(ctx context.Context, candidate analysis.Symbol) string {
	if candidate.Type != "" || candidate.Language != analysis.LanguageKotlin || !analysis.IsCallableKind(candidate.Kind) {
		return ""
	}
	file := i.files[candidate.URI]
	if file == nil {
		return ""
	}
	body, at := kotlinExpressionBody(i.documentTextLocked(candidate.URI), candidate)
	if body == "" {
		return ""
	}
	epoch := [2]uint64{i.semanticVersion, i.semanticEnvironmentVersion}
	// The index version moves when declarations are added or removed, not when
	// a body is edited, so the body itself is part of what the answer is for.
	bodyHash := fnv.New64a()
	_, _ = bodyHash.Write([]byte(body))
	memoKey := candidate.ID + "\x00" + strconv.FormatUint(bodyHash.Sum64(), 16)
	if cached, ok := i.expressionBodyTypes.lookup(epoch, memoKey); ok {
		return cached
	}
	// Typed at the body's own position so the function's parameters and
	// receiver are in scope, and one nesting level deeper so a mutually
	// recursive pair of expression bodies terminates.
	ctx = withResolutionDepth(ctx, resolutionDepth(ctx)+1)
	result := i.inferExpressionResultContextLocked(ctx, file, body, at).Type
	if ctx.Err() == nil && !resolutionTruncated(ctx) {
		i.expressionBodyTypes.store(epoch, memoKey, result)
	}
	return result
}

// InferredDisplayTypeContext reports the type of a declaration that states none
// of its own: `val user = validUser(token)`, `private fun make() = Account()`,
// or a lambda's `it`. The index proves these types for completion and
// navigation, so hover showing a bare name while go-to-definition resolves the
// same value is the display lagging behind what is known.
func (i *Index) InferredDisplayTypeContext(ctx context.Context, symbol analysis.Symbol) string {
	if symbol.Type != "" || symbol.URI == "" {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[symbol.URI]
	if file == nil {
		return ""
	}
	if analysis.IsCallableKind(symbol.Kind) {
		return i.kotlinExpressionBodyResultTypeLocked(ctx, symbol)
	}
	switch symbol.Kind {
	case analysis.KindVariable, analysis.KindProperty, analysis.KindField, analysis.KindParameter:
	default:
		return ""
	}
	if symbol.Initializer != "" {
		// Typed at the end of the declaration, where everything the
		// initializer names is in scope.
		if typ := i.inferExpressionResultContextLocked(ctx, file, symbol.Initializer, symbol.EndByte).Type; typ != "" {
			return typ
		}
	}
	return i.typeOfNameLocked(ctx, file, symbol.Name, symbol.EndByte)
}

// kotlinExpressionBody returns the source of a declaration's expression body
// and the offset it starts at, or "" when the declaration has a block body, a
// declared type, or no body at all. It walks the parameter list rather than
// searching for the first `=`, which would find a default argument value.
func kotlinExpressionBody(text string, symbol analysis.Symbol) (string, int) {
	start, end := symbol.NameEndByte, symbol.EndByte
	if text == "" || start <= 0 || end > len(text) || start >= end {
		return "", 0
	}
	for start < end && isDeclarationSpace(text[start]) {
		start++
	}
	if start < end && text[start] == '(' {
		depth := 0
		for start < end {
			switch text[start] {
			case '(':
				depth++
			case ')':
				depth--
			}
			start++
			if depth == 0 {
				break
			}
		}
	}
	for start < end && isDeclarationSpace(text[start]) {
		start++
	}
	// A declared return type means the symbol already carries it; a block body
	// needs control-flow analysis this does not attempt.
	if start >= end || text[start] != '=' || start+1 < end && text[start+1] == '=' {
		return "", 0
	}
	start++
	for start < end && isDeclarationSpace(text[start]) {
		start++
	}
	body := strings.TrimSpace(text[start:end])
	if body == "" || strings.HasPrefix(body, "{") {
		return "", 0
	}
	return body, start
}

func isDeclarationSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

// declaredOrInferredMemberTypeLocked is a member's type as written, or -- for
// `fun make() = Outer()` and `val name = compute()`, which write none -- the
// type of the body or initializer, typed in the member's own file. Member
// lookups skipped every such member, so a value reached through one had no
// type at all.
func (i *Index) declaredOrInferredMemberTypeLocked(ctx context.Context, member analysis.Symbol) string {
	if member.Type != "" && member.Type != "val" && member.Type != "var" {
		return member.Type
	}
	if member.Language != analysis.LanguageKotlin || resolutionNestingExceeded(ctx) {
		return ""
	}
	if analysis.IsCallableKind(member.Kind) {
		return i.kotlinExpressionBodyResultTypeLocked(ctx, member)
	}
	if member.Kind != analysis.KindProperty || member.Initializer == "" {
		return ""
	}
	declaring := i.files[member.URI]
	if declaring == nil {
		return ""
	}
	return i.inferExpressionResultContextLocked(withResolutionDepth(ctx, resolutionDepth(ctx)+1), declaring, member.Initializer, member.EndByte).Type
}
