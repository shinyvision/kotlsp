package index

import (
	"context"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
)

// qualifiedAccess describes a member access `qualifier.name`: what the
// qualifier is, so completion and resolution decide the same way which
// declarations follow its dot. They used to decide separately, and drifted:
// completion hid Kotlin statics and constructors behind a value, resolution
// did not; resolution offered companion members through a value, completion
// did not.
type qualifiedAccess struct {
	// receiverType is the qualifier's type, as inferred.
	receiverType string
	// typeQualifier: the qualifier names a type (`Color.`, `DSL.`).
	typeQualifier bool
	// typeQualifierValue: that type is also a value (an object).
	typeQualifierValue   bool
	typeQualifierSymbols []analysis.Symbol
	// unboundCallableReference: `Type::member`, which names instance members
	// through the type.
	unboundCallableReference bool
	// memberAccessAllowed is false behind a nullable receiver without `?.`;
	// only extensions on a nullable receiver apply there.
	memberAccessAllowed bool
	at                  int
}

// qualifiedMemberViableLocked reports whether a declared member of the
// qualifier's type hierarchy follows its dot.
func (i *Index) qualifiedMemberViableLocked(file *analysis.ParsedFile, access *accessibilityMemo, q qualifiedAccess, symbol analysis.Symbol) bool {
	// A constructor is never reached through a dot: neither a value nor a
	// type qualifier names it.
	if symbol.Kind == analysis.KindConstructor || !q.memberAccessAllowed || !i.memberInheritedForReceiverLocked(file, symbol, q.receiverType) {
		return false
	}
	if q.typeQualifier && !q.unboundCallableReference && !i.memberAvailableThroughTypeQualifierLocked(file, symbol, q.typeQualifierSymbols) {
		return false
	}
	// Kotlin has no statics: an enum entry, a static member or a companion
	// object is reached through the type, never through a value of it.
	if !q.typeQualifier && file.Language == analysis.LanguageKotlin && (symbol.Kind == analysis.KindEnumMember || containsString(symbol.Modifiers, "static") || symbol.Kind == analysis.KindObject && containsString(symbol.Modifiers, "companion")) {
		return false
	}
	return i.accessibleWithMemoLocked(file, symbol, access, q.at)
}

// qualifiedExtensionViableLocked reports whether an extension applies after
// the qualifier's dot.
func (i *Index) qualifiedExtensionViableLocked(ctx context.Context, file *analysis.ParsedFile, access *accessibilityMemo, q qualifiedAccess, symbol analysis.Symbol) bool {
	if q.typeQualifier && !q.typeQualifierValue && !q.unboundCallableReference {
		return false
	}
	if !q.memberAccessAllowed && !strings.HasSuffix(strings.TrimSpace(symbol.ReceiverType), "?") {
		return false
	}
	return i.extensionReceiverApplicableLocked(ctx, file, symbol, q.receiverType) && i.accessibleWithMemoLocked(file, symbol, access, q.at) && i.extensionVisibleLocked(file, symbol, q.at)
}

// qualifiedCompanionMembersViable reports whether companion members follow the
// dot: through the type that owns the companion, never through a value.
func qualifiedCompanionMembersViable(file *analysis.ParsedFile, q qualifiedAccess) bool {
	return file.Language == analysis.LanguageKotlin && q.typeQualifier
}
