package analysis

import (
	"fmt"
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

type Language uint8

const (
	LanguageUnknown Language = iota
	LanguageKotlin
	LanguageJava
)

func (l Language) String() string {
	switch l {
	case LanguageKotlin:
		return "kotlin"
	case LanguageJava:
		return "java"
	default:
		return "unknown"
	}
}

type SymbolKind uint8

const (
	KindUnknown SymbolKind = iota
	KindPackage
	KindClass
	KindInterface
	KindEnum
	KindObject
	KindAnnotation
	KindRecord
	KindConstructor
	KindFunction
	KindMethod
	KindProperty
	KindField
	KindVariable
	KindParameter
	KindEnumMember
	KindTypeAlias
	KindTypeParameter
	KindLabel
)

// SemanticToken returns the token type index in the server's advertised LSP
// legend. Keeping this mapping on SymbolKind lets references be classified by
// their resolved target instead of by the syntactic shape of the use site.
func (k SymbolKind) SemanticToken() uint32 {
	switch k {
	case KindPackage:
		return 0
	case KindClass, KindObject, KindRecord, KindConstructor:
		return 1
	case KindEnum:
		return 2
	case KindInterface:
		return 3
	case KindTypeParameter, KindTypeAlias:
		return 5
	case KindParameter:
		return 7
	case KindVariable:
		return 8
	case KindProperty, KindField:
		return 9
	case KindEnumMember:
		return 10
	case KindFunction:
		return 12
	case KindMethod:
		return 13
	case KindAnnotation:
		return 22
	default:
		return 8
	}
}

func (k SymbolKind) LSP() int {
	switch k {
	case KindPackage:
		return protocol.SymbolPackage
	case KindClass, KindAnnotation:
		return protocol.SymbolClass
	case KindInterface:
		return protocol.SymbolInterface
	case KindEnum:
		return protocol.SymbolEnum
	case KindObject:
		return protocol.SymbolObject
	case KindRecord:
		return protocol.SymbolStruct
	case KindConstructor:
		return protocol.SymbolConstructor
	case KindFunction:
		return protocol.SymbolFunction
	case KindMethod:
		return protocol.SymbolMethod
	case KindProperty:
		return protocol.SymbolProperty
	case KindField:
		return protocol.SymbolField
	case KindVariable, KindParameter, KindLabel:
		return protocol.SymbolVariable
	case KindEnumMember:
		return protocol.SymbolEnumMember
	case KindTypeAlias, KindTypeParameter:
		return protocol.SymbolTypeParameter
	default:
		return protocol.SymbolVariable
	}
}

func (k SymbolKind) Completion() int {
	switch k {
	case KindPackage:
		return protocol.CompletionModule
	case KindClass, KindAnnotation:
		return protocol.CompletionClass
	case KindInterface:
		return protocol.CompletionInterface
	case KindEnum:
		return protocol.CompletionEnum
	case KindObject:
		return protocol.CompletionModule
	case KindRecord:
		return protocol.CompletionStruct
	case KindConstructor:
		return protocol.CompletionConstructor
	case KindFunction:
		return protocol.CompletionFunction
	case KindMethod:
		return protocol.CompletionMethod
	case KindProperty:
		return protocol.CompletionProperty
	case KindField:
		return protocol.CompletionField
	case KindVariable, KindParameter:
		return protocol.CompletionVariable
	case KindLabel:
		return protocol.CompletionReference
	case KindEnumMember:
		return protocol.CompletionEnumMember
	case KindTypeAlias, KindTypeParameter:
		return protocol.CompletionTypeParameter
	default:
		return protocol.CompletionText
	}
}

type Parameter struct {
	Name     string
	Type     string
	Default  string
	Variadic bool
	Range    protocol.Range
}

type ByteScope struct {
	StartByte int
	EndByte   int
}

type Symbol struct {
	ID             string
	Name           string
	FQN            string
	Kind           SymbolKind
	Language       Language
	URI            protocol.URI
	Range          protocol.Range
	SelectionRange protocol.Range
	StartByte      int
	EndByte        int
	NameStartByte  int
	NameEndByte    int
	ScopeStartByte int
	ScopeEndByte   int
	// AdditionalScopes models disconnected flow scopes such as Java's
	// `!(x instanceof T t) || t.use()` RHS plus the post-guard block.
	AdditionalScopes []ByteScope
	ContainerID      string
	ContainerName    string
	Package          string
	Type             string
	Initializer      string
	ReceiverType     string
	Signature        string
	Parameters       []Parameter
	TypeParameters   []string
	// TypeParameterBounds preserves source constraints without changing the
	// parameter names used by substitution and inference.
	TypeParameterBounds map[string][]string
	Supertypes          []string
	Modifiers           []string
	// JVMName is the bytecode-level callable/accessor name supplied by a
	// Kotlin @JvmName annotation. The source declaration keeps Name so Kotlin
	// navigation and rename continue to use the spelling in the document.
	JVMName string
	// JVMDescriptor is the exact erased field/method descriptor when the
	// declaration originates in bytecode. Source declarations leave it empty;
	// consumers may derive one only when every source type resolves uniquely.
	JVMDescriptor string
	Documentation string
	Deprecated    bool
	Library       bool
	Synthetic     bool
	// Provisional marks a declaration retained from the last syntax snapshot
	// after error recovery could no longer rediscover it. The declaration name
	// and byte span have still been validated against the edited source; fields
	// touched by an edit are cleared before the symbol is published.
	Provisional bool
	// InteropLanguage restricts a synthetic JVM view to the language which can
	// spell it. LanguageUnknown means visible to both languages.
	InteropLanguage Language
	OriginID        string
	SourceURI       protocol.URI
	SourceRange     protocol.Range
}

func (s Symbol) DisplaySignature() string {
	if s.Signature != "" {
		return s.Signature
	}
	if s.Type != "" {
		return s.Name + ": " + s.Type
	}
	return s.Name
}

func (s Symbol) Location() protocol.Location {
	uri, r := s.URI, s.SelectionRange
	if s.SourceURI != "" {
		uri, r = s.SourceURI, s.SourceRange
	}
	return protocol.Location{URI: uri, Range: r}
}

type ReferenceRole uint8

const (
	RoleRead ReferenceRole = iota
	RoleWrite
	RoleCall
	RoleType
	RoleImport
	RoleLabel
)

type Reference struct {
	Name          string
	Qualifier     string
	URI           protocol.URI
	Range         protocol.Range
	StartByte     int
	EndByte       int
	ContainerID   string
	Role          ReferenceRole
	ResolvedID    string
	Arguments     []protocol.Range
	Arity         int
	ArgumentLabel bool
	// ContextualBranch is set only when the syntax tree places this occurrence
	// in the label/condition side of a Kotlin when entry or Java switch label.
	// It lets conservative fast diagnostics delegate contextual enum/sealed
	// binding without scanning unrelated source text.
	ContextualBranch bool
}

type Import struct {
	Path     string
	Alias    string
	Wildcard bool
	Static   bool
	Range    protocol.Range
}

func (i Import) LocalName() string {
	if i.Alias != "" {
		return i.Alias
	}
	if at := strings.LastIndexByte(i.Path, '.'); at >= 0 {
		return i.Path[at+1:]
	}
	return i.Path
}

type Token struct {
	Range     protocol.Range
	StartByte int
	EndByte   int
	Type      uint32
	Modifiers uint32
}

// SmartCast records a type refinement whose validity is restricted to one
// control-flow branch. Resolution uses these facts before a lexical variable's
// declared type.
type SmartCast struct {
	Name      string
	Type      string
	StartByte int
	EndByte   int
}

type ParsedFile struct {
	URI          protocol.URI
	Language     Language
	Package      string
	PackageRange protocol.Range
	// JVMFacadeName is the class name selected by @file:JvmName. Empty means
	// the conventional capitalized <filename>Kt facade.
	JVMFacadeName string
	JVMMultifile  bool
	Imports       []Import
	Symbols       []Symbol
	References    []Reference
	SmartCasts    []SmartCast
	Tokens        []Token
	Diagnostics   []protocol.Diagnostic
	Folds         []protocol.FoldingRange
	Version       int
	TextHash      uint64
	// ParseMode is an instrumentation contract used by performance tests and
	// status/debug tooling: "full", "incremental", "snapshot", or "large".
	ParseMode string
	// InteropPrepared records that the JVM-view symbols have already been
	// merged into Symbols, so the index does not derive them again under its
	// lock. Library loading does this on a worker before insertion.
	InteropPrepared bool
}

func SymbolID(uri protocol.URI, start int, kind SymbolKind, name string) string {
	return fmt.Sprintf("%s#%d:%d:%s", uri, start, kind, name)
}

func IsTypeKind(k SymbolKind) bool {
	switch k {
	case KindClass, KindInterface, KindEnum, KindObject, KindAnnotation, KindRecord, KindTypeAlias, KindTypeParameter:
		return true
	default:
		return false
	}
}

func IsCallableKind(k SymbolKind) bool {
	switch k {
	case KindConstructor, KindFunction, KindMethod:
		return true
	default:
		return false
	}
}
