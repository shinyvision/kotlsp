package protocol

import "encoding/json"

type URI string

type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

type Location struct {
	URI   URI   `json:"uri"`
	Range Range `json:"range"`
}

type LocationLink struct {
	OriginSelectionRange *Range `json:"originSelectionRange,omitempty"`
	TargetURI            URI    `json:"targetUri"`
	TargetRange          Range  `json:"targetRange"`
	TargetSelectionRange Range  `json:"targetSelectionRange"`
}

type TextDocumentIdentifier struct {
	URI URI `json:"uri"`
}

type VersionedTextDocumentIdentifier struct {
	URI     URI `json:"uri"`
	Version int `json:"version"`
}

type TextDocumentItem struct {
	URI        URI    `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type TextDocumentPositionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
	Snippet string `json:"snippet,omitempty"`
}

type AnnotatedTextEdit struct {
	Range        Range  `json:"range"`
	NewText      string `json:"newText"`
	AnnotationID string `json:"annotationId"`
}

type OptionalVersionedTextDocumentIdentifier struct {
	URI     URI  `json:"uri"`
	Version *int `json:"version"`
}

type TextDocumentEdit struct {
	TextDocument OptionalVersionedTextDocumentIdentifier `json:"textDocument"`
	Edits        []TextEdit                              `json:"edits"`
}

type RenameFile struct {
	Kind       string          `json:"kind"`
	OldURI     URI             `json:"oldUri"`
	NewURI     URI             `json:"newUri"`
	Options    map[string]bool `json:"options,omitempty"`
	Annotation string          `json:"annotationId,omitempty"`
}

type WorkspaceEdit struct {
	Changes         map[URI][]TextEdit `json:"changes,omitempty"`
	DocumentChanges []any              `json:"documentChanges,omitempty"`
}

type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

type CompletionList struct {
	IsIncomplete bool             `json:"isIncomplete"`
	Items        []CompletionItem `json:"items"`
}

type CompletionItem struct {
	Label               string         `json:"label"`
	LabelDetails        map[string]any `json:"labelDetails,omitempty"`
	Kind                int            `json:"kind,omitempty"`
	Tags                []int          `json:"tags,omitempty"`
	Detail              string         `json:"detail,omitempty"`
	Documentation       any            `json:"documentation,omitempty"`
	Deprecated          bool           `json:"deprecated,omitempty"`
	Preselect           bool           `json:"preselect,omitempty"`
	SortText            string         `json:"sortText,omitempty"`
	FilterText          string         `json:"filterText,omitempty"`
	InsertText          string         `json:"insertText,omitempty"`
	InsertTextFormat    int            `json:"insertTextFormat,omitempty"`
	TextEdit            *TextEdit      `json:"textEdit,omitempty"`
	AdditionalTextEdits []TextEdit     `json:"additionalTextEdits,omitempty"`
	CommitCharacters    []string       `json:"commitCharacters,omitempty"`
	Command             *Command       `json:"command,omitempty"`
	Data                any            `json:"data,omitempty"`
}

type Command struct {
	Title     string `json:"title"`
	Command   string `json:"command"`
	Arguments []any  `json:"arguments,omitempty"`
}

type ParameterInformation struct {
	Label         any `json:"label"`
	Documentation any `json:"documentation,omitempty"`
}

type SignatureInformation struct {
	Label         string                 `json:"label"`
	Documentation any                    `json:"documentation,omitempty"`
	Parameters    []ParameterInformation `json:"parameters,omitempty"`
	ActiveParam   *int                   `json:"activeParameter,omitempty"`
}

type SignatureHelp struct {
	Signatures      []SignatureInformation `json:"signatures"`
	ActiveSignature int                    `json:"activeSignature,omitempty"`
	ActiveParameter any                    `json:"activeParameter,omitempty"`
}

type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           int              `json:"kind"`
	Tags           []int            `json:"tags,omitempty"`
	Deprecated     bool             `json:"deprecated,omitempty"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

type SymbolInformation struct {
	Name          string   `json:"name"`
	Kind          int      `json:"kind"`
	Tags          []int    `json:"tags,omitempty"`
	Deprecated    bool     `json:"deprecated,omitempty"`
	Location      Location `json:"location"`
	ContainerName string   `json:"containerName,omitempty"`
}

type Diagnostic struct {
	Range              Range               `json:"range"`
	Severity           int                 `json:"severity,omitempty"`
	Code               any                 `json:"code,omitempty"`
	CodeDescription    map[string]string   `json:"codeDescription,omitempty"`
	Source             string              `json:"source,omitempty"`
	Message            string              `json:"message"`
	Tags               []int               `json:"tags,omitempty"`
	RelatedInformation []DiagnosticRelated `json:"relatedInformation,omitempty"`
	Data               any                 `json:"data,omitempty"`
}

type DiagnosticRelated struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

type FullDocumentDiagnosticReport struct {
	Kind     string       `json:"kind"`
	ResultID string       `json:"resultId,omitempty"`
	Items    []Diagnostic `json:"items"`
}

type WorkspaceDocumentDiagnosticReport struct {
	URI      URI          `json:"uri"`
	Version  *int         `json:"version,omitempty"`
	Kind     string       `json:"kind"`
	ResultID string       `json:"resultId,omitempty"`
	Items    []Diagnostic `json:"items,omitempty"`
}

// MarshalJSON keeps the report's shape aligned with its kind: a full report
// always carries an "items" array (an empty one for a clean document; clients
// index it unconditionally), while an unchanged report carries none.
func (r WorkspaceDocumentDiagnosticReport) MarshalJSON() ([]byte, error) {
	type plain WorkspaceDocumentDiagnosticReport
	if r.Kind == "full" {
		items := r.Items
		if items == nil {
			items = []Diagnostic{}
		}
		return json.Marshal(struct {
			plain
			Items []Diagnostic `json:"items"`
		}{plain(r), items})
	}
	r.Items = nil
	return json.Marshal(plain(r))
}

type WorkspaceDiagnosticReport struct {
	Items []WorkspaceDocumentDiagnosticReport `json:"items"`
}

type CodeAction struct {
	Title       string         `json:"title"`
	Kind        string         `json:"kind,omitempty"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
	IsPreferred bool           `json:"isPreferred,omitempty"`
	Disabled    any            `json:"disabled,omitempty"`
	Edit        *WorkspaceEdit `json:"edit,omitempty"`
	Command     *Command       `json:"command,omitempty"`
	Data        any            `json:"data,omitempty"`
}

type CodeLens struct {
	Range   Range    `json:"range"`
	Command *Command `json:"command,omitempty"`
	Data    any      `json:"data,omitempty"`
}

type FoldingRange struct {
	StartLine      int    `json:"startLine"`
	StartCharacter *int   `json:"startCharacter,omitempty"`
	EndLine        int    `json:"endLine"`
	EndCharacter   *int   `json:"endCharacter,omitempty"`
	Kind           string `json:"kind,omitempty"`
	CollapsedText  string `json:"collapsedText,omitempty"`
}

type SemanticTokens struct {
	ResultID string   `json:"resultId,omitempty"`
	Data     []uint32 `json:"data"`
}

type SemanticTokensEdit struct {
	Start       int      `json:"start"`
	DeleteCount int      `json:"deleteCount"`
	Data        []uint32 `json:"data,omitempty"`
}

type SemanticTokensDelta struct {
	ResultID string               `json:"resultId,omitempty"`
	Edits    []SemanticTokensEdit `json:"edits"`
}

type InlayHintLabelPart struct {
	Value    string    `json:"value"`
	Tooltip  any       `json:"tooltip,omitempty"`
	Location *Location `json:"location,omitempty"`
	Command  *Command  `json:"command,omitempty"`
}

type InlayHint struct {
	Position     Position   `json:"position"`
	Label        any        `json:"label"`
	Kind         int        `json:"kind,omitempty"`
	TextEdits    []TextEdit `json:"textEdits,omitempty"`
	Tooltip      any        `json:"tooltip,omitempty"`
	PaddingLeft  bool       `json:"paddingLeft,omitempty"`
	PaddingRight bool       `json:"paddingRight,omitempty"`
	Data         any        `json:"data,omitempty"`
}

type CallHierarchyItem struct {
	Name           string `json:"name"`
	Kind           int    `json:"kind"`
	Tags           []int  `json:"tags,omitempty"`
	Detail         string `json:"detail,omitempty"`
	URI            URI    `json:"uri"`
	Range          Range  `json:"range"`
	SelectionRange Range  `json:"selectionRange"`
	Data           any    `json:"data,omitempty"`
}

type CallHierarchyIncomingCall struct {
	From       CallHierarchyItem `json:"from"`
	FromRanges []Range           `json:"fromRanges"`
}

type CallHierarchyOutgoingCall struct {
	To         CallHierarchyItem `json:"to"`
	FromRanges []Range           `json:"fromRanges"`
}

type TypeHierarchyItem = CallHierarchyItem

type TypeHierarchySupertypes struct{}

type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

type TextDocumentContentChangeEvent struct {
	Range       *Range `json:"range,omitempty"`
	RangeLength *int   `json:"rangeLength,omitempty"`
	Text        string `json:"text"`
}

type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Text         *string                `json:"text,omitempty"`
}

type FormattingOptions struct {
	TabSize                int            `json:"tabSize"`
	InsertSpaces           bool           `json:"insertSpaces"`
	TrimTrailingWhitespace bool           `json:"trimTrailingWhitespace,omitempty"`
	InsertFinalNewline     bool           `json:"insertFinalNewline,omitempty"`
	TrimFinalNewlines      bool           `json:"trimFinalNewlines,omitempty"`
	Extra                  map[string]any `json:"-"`
}

type ExecuteCommandParams struct {
	Command   string            `json:"command"`
	Arguments []json.RawMessage `json:"arguments,omitempty"`
}

type FileRename struct {
	OldURI URI `json:"oldUri"`
	NewURI URI `json:"newUri"`
}

const (
	SymbolFile          = 1
	SymbolModule        = 2
	SymbolNamespace     = 3
	SymbolPackage       = 4
	SymbolClass         = 5
	SymbolMethod        = 6
	SymbolProperty      = 7
	SymbolField         = 8
	SymbolConstructor   = 9
	SymbolEnum          = 10
	SymbolInterface     = 11
	SymbolFunction      = 12
	SymbolVariable      = 13
	SymbolConstant      = 14
	SymbolString        = 15
	SymbolNumber        = 16
	SymbolBoolean       = 17
	SymbolArray         = 18
	SymbolObject        = 19
	SymbolKey           = 20
	SymbolNull          = 21
	SymbolEnumMember    = 22
	SymbolStruct        = 23
	SymbolEvent         = 24
	SymbolOperator      = 25
	SymbolTypeParameter = 26
)

const (
	CompletionText          = 1
	CompletionMethod        = 2
	CompletionFunction      = 3
	CompletionConstructor   = 4
	CompletionField         = 5
	CompletionVariable      = 6
	CompletionClass         = 7
	CompletionInterface     = 8
	CompletionModule        = 9
	CompletionProperty      = 10
	CompletionUnit          = 11
	CompletionValue         = 12
	CompletionEnum          = 13
	CompletionKeyword       = 14
	CompletionSnippet       = 15
	CompletionColor         = 16
	CompletionFile          = 17
	CompletionReference     = 18
	CompletionFolder        = 19
	CompletionEnumMember    = 20
	CompletionConstant      = 21
	CompletionStruct        = 22
	CompletionEvent         = 23
	CompletionOperator      = 24
	CompletionTypeParameter = 25
)

// DocumentHighlightKind values from the negotiated protocol: 1 text, 2 read,
// 3 write.
type DocumentHighlight struct {
	Range Range `json:"range"`
	Kind  int   `json:"kind,omitempty"`
}
