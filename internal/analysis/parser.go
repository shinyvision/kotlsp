package analysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	kotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"
	sitter "github.com/tree-sitter/go-tree-sitter"
	java "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

var (
	javaLanguage   = sitter.NewLanguage(java.Language())
	kotlinLanguage = sitter.NewLanguage(kotlin.Language())
	javaFieldIDs   = parserFieldIDs(javaLanguage)
	kotlinFieldIDs = parserFieldIDs(kotlinLanguage)
)

func parserFieldIDs(language *sitter.Language) map[string]uint16 {
	fields := []string{"arguments", "condition", "left", "name", "object", "parameters", "receiver", "receiver_type", "return_type", "right", "type", "value", "value_parameters"}
	ids := make(map[string]uint16, len(fields))
	for _, field := range fields {
		ids[field] = language.FieldIdForName(field)
	}
	return ids
}

type declarationSpec struct {
	kind      SymbolKind
	nameField string
}

var kotlinDeclarations = map[string]declarationSpec{
	"class_declaration":     {KindClass, "name"},
	"object_declaration":    {KindObject, "name"},
	"companion_object":      {KindObject, "name"},
	"function_declaration":  {KindFunction, "name"},
	"property_declaration":  {KindProperty, ""},
	"variable_declaration":  {KindVariable, "name"},
	"catch_block":           {KindParameter, ""},
	"type_alias":            {KindTypeAlias, "name"},
	"primary_constructor":   {KindConstructor, ""},
	"secondary_constructor": {KindConstructor, ""},
	"class_parameter":       {KindProperty, "name"},
	"parameter":             {KindParameter, "name"},
	"enum_entry":            {KindEnumMember, "name"},
	"type_parameter":        {KindTypeParameter, "name"},
}

var javaDeclarations = map[string]declarationSpec{
	"class_declaration":                   {KindClass, "name"},
	"interface_declaration":               {KindInterface, "name"},
	"enum_declaration":                    {KindEnum, "name"},
	"record_declaration":                  {KindRecord, "name"},
	"annotation_type_declaration":         {KindAnnotation, "name"},
	"method_declaration":                  {KindMethod, "name"},
	"constructor_declaration":             {KindConstructor, "name"},
	"enhanced_for_statement":              {KindVariable, "name"},
	"resource":                            {KindVariable, "name"},
	"variable_declarator":                 {KindVariable, "name"},
	"formal_parameter":                    {KindParameter, "name"},
	"spread_parameter":                    {KindParameter, "name"},
	"catch_formal_parameter":              {KindParameter, "name"},
	"type_pattern":                        {KindVariable, ""},
	"record_pattern_component":            {KindVariable, ""},
	"instanceof_expression":               {KindVariable, "name"},
	"type_parameter":                      {KindTypeParameter, "name"},
	"enum_constant":                       {KindEnumMember, "name"},
	"annotation_type_element_declaration": {KindMethod, "name"},
}

var kotlinKeywords = map[string]bool{
	"as": true, "break": true, "class": true, "context": true, "continue": true, "do": true, "else": true, "false": true, "for": true, "fun": true, "if": true, "in": true, "interface": true, "is": true, "null": true, "object": true, "package": true, "return": true, "super": true, "this": true, "throw": true, "true": true, "try": true, "typealias": true, "typeof": true, "val": true, "var": true, "when": true, "while": true, "by": true, "catch": true, "constructor": true, "delegate": true, "dynamic": true, "field": true, "file": true, "finally": true, "get": true, "import": true, "init": true, "param": true, "property": true, "receiver": true, "set": true, "setparam": true, "where": true, "actual": true, "abstract": true, "annotation": true, "companion": true, "const": true, "crossinline": true, "data": true, "enum": true, "expect": true, "external": true, "final": true, "infix": true, "inline": true, "inner": true, "internal": true, "lateinit": true, "noinline": true, "open": true, "operator": true, "out": true, "override": true, "private": true, "protected": true, "public": true, "reified": true, "sealed": true, "suspend": true, "tailrec": true, "vararg": true, "value": true,
}

var javaKeywords = map[string]bool{
	"abstract": true, "assert": true, "boolean": true, "break": true, "byte": true, "case": true, "catch": true, "char": true, "class": true, "const": true, "continue": true, "default": true, "do": true, "double": true, "else": true, "enum": true, "extends": true, "final": true, "finally": true, "float": true, "for": true, "goto": true, "if": true, "implements": true, "import": true, "instanceof": true, "int": true, "interface": true, "long": true, "native": true, "new": true, "package": true, "private": true, "protected": true, "public": true, "return": true, "short": true, "static": true, "strictfp": true, "super": true, "switch": true, "synchronized": true, "this": true, "throw": true, "throws": true, "transient": true, "try": true, "void": true, "volatile": true, "while": true, "true": true, "false": true, "null": true, "record": true, "sealed": true, "permits": true, "var": true, "yield": true,
}

func LanguageFor(uri protocol.URI, languageID string) Language {
	lang := strings.ToLower(languageID)
	switch {
	case lang == "kotlin" || strings.HasSuffix(strings.ToLower(string(uri)), ".kt") || strings.HasSuffix(strings.ToLower(string(uri)), ".kts"):
		return LanguageKotlin
	case lang == "java" || strings.HasSuffix(strings.ToLower(string(uri)), ".java"):
		return LanguageJava
	default:
		return LanguageUnknown
	}
}

// SyntaxFingerprint hashes the complete concrete syntax tree while ignoring
// trivia positions. Formatters may change whitespace, but every token, literal,
// comment, error node, and parent/child shape must remain identical. Returning
// ok=false makes callers withhold an edit rather than trust a lexical rewrite.
func SyntaxFingerprint(ctx context.Context, source string, language Language) (fingerprint uint64, ok bool) {
	parserLanguage := javaLanguage
	if language == LanguageKotlin {
		parserLanguage = kotlinLanguage
	} else if language != LanguageJava {
		return 0, false
	}
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(parserLanguage); err != nil {
		return 0, false
	}
	tree := parseTreeContext(ctx, parser, []byte(source), nil)
	if tree == nil || ctx.Err() != nil {
		return 0, false
	}
	defer tree.Close()
	hash := sha256.New()
	type syntaxFrame struct {
		node        sitter.Node
		next, count uint
		entered     bool
	}
	root := tree.RootNode()
	if root == nil {
		return 0, false
	}
	stack := []syntaxFrame{{node: *root}}
	visited := 0
	for len(stack) > 0 {
		if visited&255 == 0 && ctx.Err() != nil || visited >= 4_000_000 || len(stack) > 65_536 {
			return 0, false
		}
		frame := &stack[len(stack)-1]
		if !frame.entered {
			frame.entered = true
			frame.count = frame.node.ChildCount()
			visited++
			_, _ = hash.Write([]byte(frame.node.Kind()))
			_, _ = hash.Write([]byte{0})
			if frame.count != 0 {
				continue
			}
			start, end := int(frame.node.StartByte()), int(frame.node.EndByte())
			if start < 0 || end < start || end > len(source) {
				return 0, false
			}
			_, _ = hash.Write([]byte(source[start:end]))
			_, _ = hash.Write([]byte{0xff})
			stack = stack[:len(stack)-1]
			continue
		}
		if frame.next < frame.count {
			child := frame.node.Child(frame.next)
			frame.next++
			if child == nil {
				return 0, false
			}
			stack = append(stack, syntaxFrame{node: *child})
			continue
		}
		_, _ = hash.Write([]byte{0xfe})
		stack = stack[:len(stack)-1]
	}
	return binary.LittleEndian.Uint64(hash.Sum(nil)[:8]), true
}

// parseTreeContext keeps cancellation synchronous with the lifetime of parser.
//
// go-tree-sitter's deprecated ParseCtx starts a goroutine which writes through
// the parser's native cancellation pointer. ParseCtx returns before proving
// that goroutine has exited, so a context cancellation racing Parser.Close can
// dereference an already deleted TSParser and terminate the whole process. A
// panic in that detached goroutine is not recoverable by an LSP request guard.
//
// ParseWithOptions avoids that goroutine, but v0.25.0 retains the Go callback
// payload for every options-bearing parse. A bounded input callback gives us
// prompt cancellation without either lifetime defect. Returning an empty chunk
// may let tree-sitter construct a prefix tree; the post-parse context check
// closes and rejects it, so canceled syntax is never published.
func parseTreeContext(ctx context.Context, parser *sitter.Parser, source []byte, oldTree *sitter.Tree) *sitter.Tree {
	if parser == nil {
		return nil
	}
	if ctx == nil || ctx.Done() == nil {
		return parser.Parse(source, oldTree)
	}
	if ctx.Err() != nil {
		return nil
	}
	const inputChunkBytes = 32 << 10
	tree := parser.ParseWith(func(offset int, _ sitter.Point) []byte {
		if ctx.Err() != nil || offset < 0 || offset >= len(source) {
			return nil
		}
		end := offset + inputChunkBytes
		if end > len(source) {
			end = len(source)
		}
		return source[offset:end]
	}, oldTree)
	if ctx.Err() != nil {
		if tree != nil {
			tree.Close()
		}
		return nil
	}
	return tree
}

// SyntaxState owns the native syntax tree for one open document. Index edits
// are serialized per document, while the mutex also makes shutdown safe.
type SyntaxState struct {
	mu                sync.Mutex
	tree              *sitter.Tree
	language          Language
	incrementalParses uint64
}

func NewSyntaxState() *SyntaxState { return &SyntaxState{} }

func (s *SyntaxState) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.tree != nil {
		s.tree.Close()
		s.tree = nil
	}
	s.mu.Unlock()
}

func (s *SyntaxState) IncrementalParses() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incrementalParses
}

func Parse(ctx context.Context, doc *textdoc.Document) *ParsedFile {
	return parseDocument(ctx, doc, nil, nil)
}

func ParseIncremental(ctx context.Context, doc *textdoc.Document, state *SyntaxState, edits []textdoc.TextEdit) *ParsedFile {
	return parseDocument(ctx, doc, state, edits)
}

func parseDocument(ctx context.Context, doc *textdoc.Document, state *SyntaxState, edits []textdoc.TextEdit) *ParsedFile {
	if ctx == nil {
		ctx = context.Background()
	}
	language := LanguageFor(doc.URI, doc.LanguageID)
	parsed := &ParsedFile{URI: doc.URI, Language: language, Version: doc.Version, ParseMode: "full"}
	h := sha256.New()
	_, _ = h.Write([]byte(doc.Text))
	parsed.TextHash = binary.LittleEndian.Uint64(h.Sum(nil)[:8])
	if ctx.Err() != nil {
		return parsed
	}
	if language == LanguageUnknown {
		return parsed
	}
	if language == LanguageKotlin {
		parsed.JVMFacadeName = kotlinFileAnnotationString(doc.Text, "JvmName")
		parsed.JVMMultifile = hasKotlinFileAnnotation(doc.Text, "JvmMultifileClass")
	}
	if len(doc.Text) >= 8<<20 {
		if state != nil {
			state.Close()
		}
		parsed.ParseMode = "large"
		parseLargeDeclarations(ctx, doc, parsed)
		return parsed
	}
	if len(doc.Text) >= 512*1024 {
		// Register before parser/tree Close defers so native nodes are destroyed
		// before the allocator is asked to return its now-free pages.
		defer releaseLargeParseMemory()
	}
	parserLanguage := javaLanguage
	if language == LanguageKotlin {
		parserLanguage = kotlinLanguage
	}
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(parserLanguage); err != nil {
		parsed.Diagnostics = append(parsed.Diagnostics, protocol.Diagnostic{Range: protocol.Range{}, Severity: 1, Source: "kotlsp", Message: "failed to initialize parser: " + err.Error()})
		return parsed
	}
	b := &parseBuilder{ctx: ctx, doc: doc, parsed: parsed, source: []byte(doc.Text), declarations: javaDeclarations, keywords: javaKeywords, fieldIDs: javaFieldIDs, selectionBytes: make(map[[2]int]bool)}
	b.allowParallel = true
	if language == LanguageKotlin {
		b.declarations = kotlinDeclarations
		b.keywords = kotlinKeywords
		b.fieldIDs = kotlinFieldIDs
	}
	// Lexical tokens depend only on immutable source text. Compute them while
	// tree-sitter parses on another core, then subtract semantic spans in a
	// linear merge after the syntax walk.
	lexicalDone := make(chan []Token, 1)
	go func() {
		lexicalBuilder := *b
		lexicalParsed := &ParsedFile{}
		lexicalBuilder.parsed = lexicalParsed
		lexicalBuilder.addLexicalTokens()
		lexicalDone <- lexicalParsed.Tokens
	}()
	parserSource := b.source
	var oldTree, previousTree *sitter.Tree
	fullFallback := false
	if state == nil {
		parserSource = compressFullLineComments(parserSource)
	} else {
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.tree != nil && state.language == language {
			previousTree = state.tree
			oldTree = state.tree.Clone()
			for _, edit := range edits {
				oldTree.Edit(&sitter.InputEdit{
					StartByte: uint(edit.StartByte), OldEndByte: uint(edit.OldEndByte), NewEndByte: uint(edit.NewEndByte),
					StartPosition:  sitter.Point{Row: uint(edit.StartLine), Column: uint(edit.StartColumn)},
					OldEndPosition: sitter.Point{Row: uint(edit.OldEndLine), Column: uint(edit.OldEndColumn)},
					NewEndPosition: sitter.Point{Row: uint(edit.NewEndLine), Column: uint(edit.NewEndColumn)},
				})
			}
		} else if state.tree != nil {
			state.tree.Close()
			state.tree = nil
		}
	}
	tree := parseTreeContext(ctx, p, parserSource, oldTree)
	if oldTree != nil {
		oldTree.Close()
	}
	if tree == nil && ctx.Err() == nil {
		// Incremental failure is not a reason to discard the last usable tree.
		// Retry once from source while the unedited previous state remains owned
		// by SyntaxState; only a successful replacement closes it.
		tree = parseTreeContext(ctx, p, parserSource, nil)
		fullFallback = tree != nil
	}
	b.lexicalTokens = <-lexicalDone
	if tree == nil {
		parsed.Diagnostics = append(parsed.Diagnostics, protocol.Diagnostic{Range: protocol.Range{}, Severity: 1, Source: "kotlsp", Message: "parser did not produce a syntax tree"})
		return parsed
	}
	if ctx.Err() != nil {
		tree.Close()
		return parsed
	}
	stateTree := tree
	// Normalized recovery is one retry, never a cascade of two complete
	// reparses. The real-source tree remains the incremental state even when a
	// recovered tree supplies the semantic walk for this snapshot.
	if language == LanguageKotlin && tree.RootNode().HasError() {
		recovered := kotlinEmptyCollectionDefaultRecovery(parserSource)
		recovered = kotlinBraceLineRecovery(recovered)
		if !bytes.Equal(recovered, parserSource) {
			if candidate := parseTreeContext(ctx, p, recovered, nil); candidate != nil {
				if syntaxErrorScore(candidate.RootNode()) < syntaxErrorScore(tree.RootNode()) {
					tree = candidate
				} else {
					candidate.Close()
				}
			}
		}
	}
	keepStateTree := false
	defer func() {
		if tree != stateTree {
			tree.Close()
		}
		if !keepStateTree {
			stateTree.Close()
		}
	}()
	root := tree.RootNode()
	if len(doc.Text) >= 256<<10 {
		b.syntax = newSyntaxSnapshot(ctx, root, language)
		parsed.ParseMode = "snapshot"
	}
	if fullFallback {
		parsed.ParseMode = "full-fallback"
	} else if previousTree != nil {
		parsed.ParseMode = "incremental"
	}
	b.checkSyntaxErrors = root.HasError()
	b.walk(root, "")
	if ctx.Err() != nil {
		return parsed
	}
	b.finish()
	if state != nil && ctx.Err() == nil {
		if previousTree != nil {
			previousTree.Close()
		}
		state.tree = stateTree
		state.language = language
		if previousTree != nil && !fullFallback {
			state.incrementalParses++
		}
		keepStateTree = true
	}
	return parsed
}

// compressFullLineComments keeps byte/line offsets identical but represents a
// consecutive run as one block-comment node. This avoids quadratic sibling
// traversal in grammars and keeps the original source available for KDoc,
// semantic tokens, and region/line-comment folds.
func compressFullLineComments(source []byte) []byte {
	var compressed []byte
	const (
		commentNormal = iota
		commentBlock
		commentDouble
		commentSingle
		commentTriple
	)
	state, blockDepth, escaped := commentNormal, 0, false
	for lineStart := 0; lineStart < len(source); {
		lineEnd := lineContentEnd(source, lineStart)
		if state != commentNormal {
			scanCommentCompressionLine(source[lineStart:lineEnd], &state, &blockDepth, &escaped)
			lineStart = nextLineStart(source, lineStart)
			continue
		}
		commentStart := lineStart
		for commentStart < len(source) && (source[commentStart] == ' ' || source[commentStart] == '\t') {
			commentStart++
		}
		if commentStart+1 >= len(source) || source[commentStart] != '/' || source[commentStart+1] != '/' {
			scanCommentCompressionLine(source[lineStart:lineEnd], &state, &blockDepth, &escaped)
			lineStart = nextLineStart(source, lineStart)
			continue
		}
		runStart, runEnd := commentStart, lineContentEnd(source, lineStart)
		next := nextLineStart(source, lineStart)
		for next < len(source) {
			candidate := next
			for candidate < len(source) && (source[candidate] == ' ' || source[candidate] == '\t') {
				candidate++
			}
			if candidate+1 >= len(source) || source[candidate] != '/' || source[candidate+1] != '/' {
				break
			}
			runEnd = lineContentEnd(source, next)
			next = nextLineStart(source, next)
		}
		if runEnd-runStart >= 4 {
			if compressed == nil {
				compressed = append([]byte(nil), source...)
			}
			for index := runStart; index < runEnd; index++ {
				if compressed[index] != '\n' && compressed[index] != '\r' {
					compressed[index] = ' '
				}
			}
			compressed[runStart], compressed[runStart+1] = '/', '*'
			compressed[runEnd-2], compressed[runEnd-1] = '*', '/'
		}
		lineStart = next
	}
	if compressed != nil {
		return compressed
	}
	return source
}

func scanCommentCompressionLine(line []byte, state, blockDepth *int, escaped *bool) {
	const (
		commentNormal = iota
		commentBlock
		commentDouble
		commentSingle
		commentTriple
	)
	for index := 0; index < len(line); index++ {
		value := line[index]
		switch *state {
		case commentBlock:
			if value == '/' && index+1 < len(line) && line[index+1] == '*' {
				*blockDepth++
				index++
			} else if value == '*' && index+1 < len(line) && line[index+1] == '/' {
				*blockDepth--
				index++
				if *blockDepth == 0 {
					*state = commentNormal
				}
			}
			continue
		case commentDouble, commentSingle:
			quote := byte('"')
			if *state == commentSingle {
				quote = '\''
			}
			if *escaped {
				*escaped = false
			} else if value == '\\' {
				*escaped = true
			} else if value == quote {
				*state = commentNormal
			}
			continue
		case commentTriple:
			if value == '"' && index+2 < len(line) && line[index+1] == '"' && line[index+2] == '"' {
				*state = commentNormal
				index += 2
			}
			continue
		}
		if value == '/' && index+1 < len(line) && line[index+1] == '/' {
			return
		}
		if value == '/' && index+1 < len(line) && line[index+1] == '*' {
			*state, *blockDepth = commentBlock, 1
			index++
		} else if value == '"' && index+2 < len(line) && line[index+1] == '"' && line[index+2] == '"' {
			*state = commentTriple
			index += 2
		} else if value == '"' {
			*state = commentDouble
		} else if value == '\'' {
			*state = commentSingle
		}
	}
	if *state == commentDouble || *state == commentSingle {
		// Ordinary Java/Kotlin string and char literals cannot continue across
		// an unescaped physical newline; leave recovery to the parser.
		*state, *escaped = commentNormal, false
	}
}

func lineContentEnd(source []byte, start int) int {
	for start < len(source) && source[start] != '\n' && source[start] != '\r' {
		start++
	}
	return start
}

func nextLineStart(source []byte, start int) int {
	start = lineContentEnd(source, start)
	if start < len(source) && source[start] == '\r' {
		start++
	}
	if start < len(source) && source[start] == '\n' {
		start++
	}
	return start
}

func syntaxErrorScore(root *sitter.Node) int64 {
	if root == nil {
		return 1 << 60
	}
	const maxScoredSyntaxNodes = 2_000_000
	var score int64
	stack := []*sitter.Node{root}
	for visited := 0; len(stack) > 0; visited++ {
		if visited >= maxScoredSyntaxNodes {
			// Recovery scoring is only a choice between two parse attempts. An
			// adversarially large tree must not turn that choice into unbounded
			// stack or heap growth.
			return 1 << 60
		}
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.IsError() || node.IsMissing() {
			span := int64(node.EndByte() - node.StartByte())
			score += 1 + span
		}
		childCount := node.NamedChildCount()
		if uint(len(stack))+childCount > maxScoredSyntaxNodes {
			return 1 << 60
		}
		for index := uint(0); index < childCount; index++ {
			stack = append(stack, node.NamedChild(index))
		}
	}
	return score
}

// kotlinBraceLineRecovery works around a grammar ambiguity for compact valid
// declarations such as `class A { fun f() = 1 }` followed by a generic class.
// Replacing existing horizontal whitespace adjacent to braces with newlines
// preserves byte offsets. Strings and comments are left untouched.
// kotlinCodeMask marks every byte of source that is real code: outside
// comments, character literals, and string literals of every form. A recovery
// rewrites source before a retry parse, so it must never reach inside a
// literal, where a rewrite would change what the program means.
func kotlinCodeMask(source []byte) []bool {
	mask := make([]bool, len(source))
	const (
		normal = iota
		lineComment
		blockComment
		doubleQuoted
		singleQuoted
		tripleQuoted
	)
	state, blockDepth, escaped := normal, 0, false
	for index := 0; index < len(source); index++ {
		value := source[index]
		switch state {
		case lineComment:
			if value == '\n' {
				state = normal
			}
			continue
		case blockComment:
			if value == '/' && index+1 < len(source) && source[index+1] == '*' {
				blockDepth++
				index++
			} else if value == '*' && index+1 < len(source) && source[index+1] == '/' {
				blockDepth--
				index++
				if blockDepth == 0 {
					state = normal
				}
			}
			continue
		case doubleQuoted, singleQuoted:
			quote := byte('"')
			if state == singleQuoted {
				quote = '\''
			}
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				state = normal
			}
			continue
		case tripleQuoted:
			if value == '"' && index+2 < len(source) && source[index+1] == '"' && source[index+2] == '"' {
				state = normal
				index += 2
			}
			continue
		}
		if value == '/' && index+1 < len(source) && source[index+1] == '/' {
			state = lineComment
			index++
			continue
		}
		if value == '/' && index+1 < len(source) && source[index+1] == '*' {
			state, blockDepth = blockComment, 1
			index++
			continue
		}
		if value == '"' {
			if index+2 < len(source) && source[index+1] == '"' && source[index+2] == '"' {
				state = tripleQuoted
				index += 2
			} else {
				state = doubleQuoted
			}
			continue
		}
		if value == '\'' {
			state = singleQuoted
			continue
		}
		mask[index] = true
	}
	return mask
}

func kotlinBraceLineRecovery(source []byte) []byte {
	recovered := append([]byte(nil), source...)
	mask := kotlinCodeMask(source)
	for index, isCode := range mask {
		if !isCode {
			continue
		}
		value := source[index]
		if value == '{' && index+1 < len(source) && (source[index+1] == ' ' || source[index+1] == '\t') {
			recovered[index+1] = '\n'
		}
		if value == '}' && index > 0 && (source[index-1] == ' ' || source[index-1] == '\t') {
			recovered[index-1] = '\n'
		}
	}
	return recovered
}

// kotlinEmptyCollectionDefaultRecovery blanks `= []` defaults.
//
// tree-sitter-kotlin requires a collection literal to hold at least one
// element, so the empty array literal in `val groups: Array<KClass<*>> = []`
// does not parse -- ordinary Kotlin, and near-universal in annotation
// declarations. A single occurrence degrades to a MISSING element, but two in
// one declaration exhaust the grammar's recovery and collapse the whole class
// into a single ERROR node: every declaration inside it is lost, and its own
// name is then reported as an unresolved reference.
//
// The rewrite preserves length and line structure, so every byte offset in the
// resulting tree still addresses the original source and node text may be read
// from it unchanged. Only the record that the parameter had a default is lost,
// and no node spans a blanked span.
func kotlinEmptyCollectionDefaultRecovery(source []byte) []byte {
	recovered := append([]byte(nil), source...)
	mask := kotlinCodeMask(source)
	isCodeSpace := func(index int) bool {
		return mask[index] && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r')
	}
	for index := 0; index < len(source); index++ {
		if !mask[index] || source[index] != '[' {
			continue
		}
		closing := index + 1
		for closing < len(source) && isCodeSpace(closing) {
			closing++
		}
		if closing >= len(source) || !mask[closing] || source[closing] != ']' {
			continue
		}
		// Walk back to the assignment this literal is the default for. Without
		// one there is nothing safe to blank, so the literal is left alone.
		assign := index - 1
		for assign >= 0 && isCodeSpace(assign) {
			assign--
		}
		if assign < 0 || !mask[assign] || source[assign] != '=' {
			continue
		}
		// A compound or comparison operator is not an assignment.
		if assign > 0 && mask[assign-1] && bytes.IndexByte([]byte("=!<>+-*/%&|^"), source[assign-1]) >= 0 {
			continue
		}
		for n := assign; n <= closing; n++ {
			if source[n] != '\n' && source[n] != '\r' {
				recovered[n] = ' '
			}
		}
		index = closing
	}
	return recovered
}

type parseBuilder struct {
	ctx               context.Context
	doc               *textdoc.Document
	parsed            *ParsedFile
	source            []byte
	declarations      map[string]declarationSpec
	keywords          map[string]bool
	fieldIDs          map[string]uint16
	syntax            *syntaxSnapshot
	container         []int
	selectionBytes    map[[2]int]bool
	lexicalOccupied   []Token
	lexicalTokens     []Token
	ancestorNodes     []*sitter.Node
	ancestorKinds     []string
	checkSyntaxErrors bool
	allowParallel     bool
	depthLimited      bool
}

const maxParserDiagnostics = 500

func (b *parseBuilder) nodeKind(node *sitter.Node) string {
	if record, _ := b.syntax.record(node); record != nil {
		return record.kind
	}
	if node == nil {
		return ""
	}
	return node.Kind()
}

func (b *parseBuilder) nodeSpan(node *sitter.Node) (int, int) {
	if record, _ := b.syntax.record(node); record != nil {
		return record.start, record.end
	}
	if node == nil {
		return 0, 0
	}
	return int(node.StartByte()), int(node.EndByte())
}

func (b *parseBuilder) nodeIsError(node *sitter.Node) bool {
	if record, _ := b.syntax.record(node); record != nil {
		return record.flags&1 != 0
	}
	return node != nil && node.IsError()
}

func (b *parseBuilder) nodeIsMissing(node *sitter.Node) bool {
	if record, _ := b.syntax.record(node); record != nil {
		return record.flags&2 != 0
	}
	return node != nil && node.IsMissing()
}

func (b *parseBuilder) nodeHasError(node *sitter.Node) bool {
	if record, _ := b.syntax.record(node); record != nil {
		return record.flags&4 != 0
	}
	return node != nil && node.HasError()
}

func (b *parseBuilder) nodeParent(node *sitter.Node) *sitter.Node {
	if record, _ := b.syntax.record(node); record != nil {
		return b.syntax.node(record.parent)
	}
	if node == nil {
		return nil
	}
	return node.Parent()
}

func (b *parseBuilder) namedChildren(node *sitter.Node) []*sitter.Node {
	if record, _ := b.syntax.record(node); record != nil {
		children := make([]*sitter.Node, 0, 4)
		for index := record.firstChild; index != noSyntaxNode; index = b.syntax.nodes[index].nextSibling {
			if b.syntax.nodes[index].flags&8 != 0 {
				children = append(children, &b.syntax.nodes[index].node)
			}
		}
		return children
	}
	return directNamedChildren(node)
}

func (b *parseBuilder) namedChildCount(node *sitter.Node) uint {
	if record, _ := b.syntax.record(node); record != nil {
		var count uint
		for index := record.firstChild; index != noSyntaxNode; index = b.syntax.nodes[index].nextSibling {
			if b.syntax.nodes[index].flags&8 != 0 {
				count++
			}
		}
		return count
	}
	if node == nil {
		return 0
	}
	return node.NamedChildCount()
}

func (b *parseBuilder) walkNamedChildren(node *sitter.Node, parentKind string) {
	if record, _ := b.syntax.record(node); record != nil {
		for index := record.firstChild; index != noSyntaxNode; index = b.syntax.nodes[index].nextSibling {
			child := &b.syntax.nodes[index]
			if child.flags&8 != 0 {
				b.walk(&child.node, parentKind)
			}
		}
		return
	}
	for index, count := uint(0), node.NamedChildCount(); index < count; index++ {
		b.walk(node.NamedChild(index), parentKind)
	}
}

func (b *parseBuilder) firstDirectIdentifier(node *sitter.Node) *sitter.Node {
	for _, child := range b.namedChildren(node) {
		if isIdentifierKind(b.nodeKind(child)) {
			return child
		}
	}
	return nil
}

func (b *parseBuilder) firstIdentifier(node *sitter.Node) *sitter.Node {
	stack := []*sitter.Node{node}
	for visited := 0; len(stack) > 0 && visited < 100_000; visited++ {
		candidate := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if candidate == nil {
			continue
		}
		if isIdentifierKind(b.nodeKind(candidate)) {
			return candidate
		}
		children := b.namedChildren(candidate)
		if len(stack)+len(children) > 100_000 {
			return nil
		}
		for index := len(children) - 1; index >= 0; index-- {
			stack = append(stack, children[index])
		}
	}
	return nil
}

func (b *parseBuilder) walk(n *sitter.Node, parentKind string) {
	if n == nil || b.ctx != nil && b.ctx.Err() != nil {
		return
	}
	if len(b.ancestorNodes) >= 1024 {
		if !b.depthLimited {
			start, end := b.nodeSpan(n)
			if len(b.parsed.Diagnostics) < maxParserDiagnostics {
				b.parsed.Diagnostics = append(b.parsed.Diagnostics, protocol.Diagnostic{
					Range: b.doc.Range(start, end), Severity: 1, Source: "kotlsp", Code: "syntax-depth-limit",
					Message: "syntax nesting exceeds the parser's 1024-level safety limit; deeper analysis was withheld",
				})
			}
			b.depthLimited = true
		}
		return
	}
	startByte, endByte := b.nodeSpan(n)
	if startByte > endByte || endByte > len(b.source) {
		return
	}
	kind := b.nodeKind(n)
	if b.checkSyntaxErrors && (b.nodeIsError(n) || b.nodeIsMissing(n)) {
		r := b.doc.Range(startByte, endByte)
		if r.Start == r.End && startByte < len(b.source) {
			r.End = b.doc.Position(startByte + 1)
		}
		msg := "syntax error"
		if b.nodeIsMissing(n) {
			msg = "missing " + strings.Trim(kind, "\"")
		}
		if len(b.parsed.Diagnostics) < maxParserDiagnostics {
			b.parsed.Diagnostics = append(b.parsed.Diagnostics, protocol.Diagnostic{Range: r, Severity: 1, Source: "kotlsp", Code: "syntax", Message: msg})
		}
	}

	if kind == "package_header" || kind == "package_declaration" {
		b.parsed.Package = qualifiedName(b.source, n)
		b.parsed.PackageRange = b.doc.Range(startByte, endByte)
	}
	if kind == "import" || kind == "import_header" || kind == "import_declaration" {
		b.addImport(n)
	}
	if b.parsed.Language == LanguageJava {
		switch kind {
		case "labeled_statement":
			b.addJavaLabelDeclaration(n)
		case "break_statement", "continue_statement":
			b.addJavaLabelReference(n)
		}
	} else if b.parsed.Language == LanguageKotlin {
		if kind == "label" {
			b.addKotlinLabelDeclaration(n)
		} else if kind == "labeled_expression" {
			b.addKotlinLabelReference(n)
		} else if kind == "navigation_expression" {
			b.addKotlinQualifiedThisReference(n)
		}
	}

	containerPushed := false
	_, propertyBinding := b.declarations[kind]
	if kind == "variable_declaration" && parentKind == "property_declaration" {
		propertyBinding = false
	}
	var declarationChildren []*sitter.Node
	if spec, ok := b.declarations[kind]; ok && propertyBinding {
		declarationChildren = b.namedChildren(n)
		indices := b.addDeclarations(n, spec, parentKind, kind, startByte, endByte, declarationChildren)
		if len(indices) > 0 && isContainerKind(b.parsed.Symbols[indices[0]].Kind) && kind != "primary_constructor" {
			b.container = append(b.container, indices[0])
			containerPushed = true
		}
	}
	if b.parsed.Language == LanguageKotlin && kind == "lambda_literal" && !hasNamedDescendant(n, "lambda_parameters", 2) {
		b.addImplicitLambdaParameter(n, startByte, endByte)
	}
	if b.parsed.Language == LanguageJava && kind == "lambda_expression" {
		b.addJavaLambdaParameters(n, startByte, endByte)
	}
	if b.parsed.Language == LanguageKotlin {
		b.addKotlinConventionReferences(n, parentKind)
		if kind == "if_expression" {
			b.addKotlinSmartCasts(n)
		} else if kind == "when_expression" {
			b.addKotlinWhenSmartCasts(n)
		} else if kind == "binary_expression" {
			// A guard does not need an `if` around it: `a != null && a.member`
			// is an expression in its own right, and commonly the whole body.
			b.addKotlinNullShortCircuitCasts(n)
		}
	}

	if foldKind := foldingKind(kind); foldKind != "" {
		start, end := b.doc.Position(startByte), b.doc.Position(endByte)
		if end.Line > start.Line {
			sc, ec := start.Character, end.Character
			b.parsed.Folds = append(b.parsed.Folds, protocol.FoldingRange{StartLine: start.Line, StartCharacter: &sc, EndLine: end.Line, EndCharacter: &ec, Kind: foldKind})
		}
	}

	if isIdentifierKind(kind) && !b.selectionBytes[[2]int{startByte, endByte}] && !inPackageOrImport(parentKind) && !containsPackageOrImportAncestor(b.ancestorKinds) {
		name := nodeText(b.source, n)
		if name != "" && !b.keywords[name] {
			role := roleForAncestors(parentKind, b.ancestorKinds)
			if b.isCallCallee(n) {
				role = RoleCall
			}
			ref := Reference{Name: name, Qualifier: b.qualifier(n), URI: b.doc.URI, Range: b.doc.Range(startByte, endByte), StartByte: startByte, EndByte: endByte, ContainerID: b.currentContainerID(), Role: role, Arity: -1, ArgumentLabel: b.isNamedArgumentLabel(n, parentKind)}
			ref.ContextualBranch = role == RoleRead && ref.Qualifier == "" && b.isContextualBranchReference(n)
			if role == RoleCall {
				if arguments, ok := b.callArguments(n); ok {
					ref.Arguments = arguments
					ref.Arity = len(arguments)
				}
			}
			b.parsed.References = append(b.parsed.References, ref)
		}
	}

	b.ancestorNodes = append(b.ancestorNodes, n)
	b.ancestorKinds = append(b.ancestorKinds, kind)
	count := b.namedChildCount(n)
	if b.allowParallel && kind == "class_body" && count >= 128 {
		b.walkClassBodyParallel(n, kind, count)
	} else if declarationChildren != nil {
		for _, child := range declarationChildren {
			b.walk(child, kind)
		}
	} else if count >= 128 {
		// Node.NamedChild(index) restarts a sibling search in tree-sitter and
		// becomes quadratic for source files containing tens of thousands of
		// top-level comments/declarations. A cursor traverses siblings once.
		for _, child := range b.namedChildren(n) {
			b.walk(child, kind)
		}
	} else {
		b.walkNamedChildren(n, kind)
	}
	b.ancestorNodes = b.ancestorNodes[:len(b.ancestorNodes)-1]
	b.ancestorKinds = b.ancestorKinds[:len(b.ancestorKinds)-1]
	if containerPushed {
		b.container = b.container[:len(b.container)-1]
	}
}

// isContextualBranchReference uses the retained syntax ancestry rather than
// file-wide keywords or same-line arrow text. Kotlin's when-entry body is the
// last named child; Java exposes case/default labels as switch_label nodes.
// A malformed entry with no distinct body is not treated as proof either way.
func (b *parseBuilder) isContextualBranchReference(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	_, referenceEnd := b.nodeSpan(node)
	for index := len(b.ancestorNodes) - 1; index >= 0; index-- {
		ancestor := b.ancestorNodes[index]
		switch b.nodeKind(ancestor) {
		case "switch_label":
			return true
		case "when_entry", "switch_rule":
			children := b.namedChildren(ancestor)
			if len(children) < 2 {
				return false
			}
			bodyStart, _ := b.nodeSpan(children[len(children)-1])
			return referenceEnd <= bodyStart
		case "function_declaration", "method_declaration", "lambda_literal", "lambda_expression":
			return false
		}
	}
	return false
}

func (b *parseBuilder) appendLabelSymbol(name string, nameStart, nameEnd, scopeStart, scopeEnd int) {
	if name == "" || b.selectionBytes[[2]int{nameStart, nameEnd}] {
		return
	}
	containerID, containerName := b.currentContainerID(), ""
	if len(b.container) > 0 {
		containerName = b.parsed.Symbols[b.container[len(b.container)-1]].Name
	}
	fqn := name
	if containerName != "" {
		fqn = containerName + "." + name
	}
	b.parsed.Symbols = append(b.parsed.Symbols, Symbol{
		ID: SymbolID(b.doc.URI, nameStart, KindLabel, name), Name: name, FQN: fqn, Kind: KindLabel,
		Language: b.parsed.Language, URI: b.doc.URI, Range: b.doc.Range(nameStart, nameEnd), SelectionRange: b.doc.Range(nameStart, nameEnd),
		StartByte: nameStart, EndByte: nameEnd, NameStartByte: nameStart, NameEndByte: nameEnd,
		ScopeStartByte: scopeStart, ScopeEndByte: scopeEnd, ContainerID: containerID, ContainerName: containerName, Package: b.parsed.Package,
		Signature: name + ":",
	})
	b.selectionBytes[[2]int{nameStart, nameEnd}] = true
}

func (b *parseBuilder) appendLabelReference(name string, start, end int) {
	if name == "" || b.selectionBytes[[2]int{start, end}] {
		return
	}
	b.parsed.References = append(b.parsed.References, Reference{Name: name, URI: b.doc.URI, Range: b.doc.Range(start, end), StartByte: start, EndByte: end, ContainerID: b.currentContainerID(), Role: RoleLabel, Arity: -1})
	b.selectionBytes[[2]int{start, end}] = true
}

func (b *parseBuilder) addJavaLabelDeclaration(node *sitter.Node) {
	identifier := b.firstDirectIdentifier(node)
	if identifier == nil {
		return
	}
	start, end := b.nodeSpan(identifier)
	scopeStart, scopeEnd := b.nodeSpan(node)
	b.appendLabelSymbol(nodeText(b.source, identifier), start, end, scopeStart, scopeEnd)
}

func (b *parseBuilder) addJavaLabelReference(node *sitter.Node) {
	identifier := b.firstDirectIdentifier(node)
	if identifier == nil {
		return
	}
	start, end := b.nodeSpan(identifier)
	b.appendLabelReference(nodeText(b.source, identifier), start, end)
}

func (b *parseBuilder) addKotlinLabelDeclaration(node *sitter.Node) {
	raw := strings.TrimSpace(nodeText(b.source, node))
	name := strings.TrimSuffix(raw, "@")
	if name == "break" || name == "continue" || name == "return" || name == "this" || name == "super" || name == raw {
		return
	}
	start, end := b.nodeSpan(node)
	end--
	parent := b.nodeParent(node)
	scopeStart, scopeEnd := b.nodeSpan(parent)
	b.appendLabelSymbol(name, start, end, scopeStart, scopeEnd)
}

func (b *parseBuilder) addKotlinLabelReference(node *sitter.Node) {
	children := b.namedChildren(node)
	if len(children) < 2 || b.nodeKind(children[0]) != "label" {
		return
	}
	keyword := strings.TrimSuffix(strings.TrimSpace(nodeText(b.source, children[0])), "@")
	if keyword != "break" && keyword != "continue" && keyword != "return" && keyword != "this" && keyword != "super" {
		return
	}
	identifier := children[len(children)-1]
	if !isIdentifierKind(b.nodeKind(identifier)) {
		return
	}
	start, end := b.nodeSpan(identifier)
	b.appendLabelReference(nodeText(b.source, identifier), start, end)
}

func (b *parseBuilder) addKotlinQualifiedThisReference(node *sitter.Node) {
	raw := nodeText(b.source, node)
	if !strings.HasPrefix(strings.TrimSpace(raw), "this@") {
		return
	}
	dot := strings.LastIndexByte(raw, '.')
	if dot < 0 {
		return
	}
	name := strings.TrimSpace(raw[dot+1:])
	if name == "" || strings.ContainsAny(name, " \t\r\n(){}[]") {
		return
	}
	nodeStart, _ := b.nodeSpan(node)
	nameStart := nodeStart + dot + 1
	for nameStart < len(b.source) && unicode.IsSpace(rune(b.source[nameStart])) {
		nameStart++
	}
	nameEnd := nameStart + len(name)
	if nameEnd > len(b.source) || b.selectionBytes[[2]int{nameStart, nameEnd}] {
		return
	}
	qualifier := strings.TrimSpace(raw[:dot])
	b.parsed.References = append(b.parsed.References, Reference{Name: name, Qualifier: qualifier, URI: b.doc.URI, Range: b.doc.Range(nameStart, nameEnd), StartByte: nameStart, EndByte: nameEnd, ContainerID: b.currentContainerID(), Role: RoleRead, Arity: -1})
	b.selectionBytes[[2]int{nameStart, nameEnd}] = true
}

func containsPackageOrImportAncestor(ancestors []string) bool {
	for index := len(ancestors) - 1; index >= 0; index-- {
		if inPackageOrImport(ancestors[index]) {
			return true
		}
	}
	return false
}

type parallelWalkResult struct {
	symbols     []Symbol
	references  []Reference
	smartCasts  []SmartCast
	folds       []protocol.FoldingRange
	diagnostics []protocol.Diagnostic
}

func (b *parseBuilder) walkClassBodyParallel(node *sitter.Node, parentKind string, count uint) {
	children := b.namedChildren(node)
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers > len(children) {
		workers = len(children)
	}
	if workers < 2 {
		for _, child := range children {
			b.walk(child, parentKind)
		}
		return
	}

	results := make([]parallelWalkResult, workers)
	prefixSymbols := append([]Symbol(nil), b.parsed.Symbols...)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		start := len(children) * worker / workers
		end := len(children) * (worker + 1) / workers
		go func(slot, start, end int) {
			defer wait.Done()
			localFile := &ParsedFile{
				URI: b.parsed.URI, Language: b.parsed.Language, Version: b.parsed.Version,
				TextHash: b.parsed.TextHash, Package: b.parsed.Package, PackageRange: b.parsed.PackageRange,
				Symbols: append([]Symbol(nil), prefixSymbols...),
			}
			local := *b
			local.parsed = localFile
			local.container = append([]int(nil), b.container...)
			local.selectionBytes = make(map[[2]int]bool)
			local.ancestorNodes = append([]*sitter.Node(nil), b.ancestorNodes...)
			local.ancestorKinds = append([]string(nil), b.ancestorKinds...)
			local.allowParallel = false
			for _, child := range children[start:end] {
				local.walk(child, parentKind)
			}
			results[slot] = parallelWalkResult{
				symbols: localFile.Symbols[len(prefixSymbols):], references: localFile.References,
				smartCasts: localFile.SmartCasts, folds: localFile.Folds, diagnostics: localFile.Diagnostics,
			}
		}(worker, start, end)
	}
	wait.Wait()
	for _, result := range results {
		b.parsed.Symbols = append(b.parsed.Symbols, result.symbols...)
		b.parsed.References = append(b.parsed.References, result.references...)
		b.parsed.SmartCasts = append(b.parsed.SmartCasts, result.smartCasts...)
		b.parsed.Folds = append(b.parsed.Folds, result.folds...)
		remaining := maxParserDiagnostics - len(b.parsed.Diagnostics)
		if remaining > 0 {
			b.parsed.Diagnostics = append(b.parsed.Diagnostics, result.diagnostics[:min(remaining, len(result.diagnostics))]...)
		}
	}
}

func (b *parseBuilder) addDeclarations(n *sitter.Node, spec declarationSpec, parentKind, nodeKind string, start, end int, children []*sitter.Node) []int {
	nameNodes := []*sitter.Node{}
	if spec.nameField != "" && nodeKind != "companion_object" {
		// The Kotlin grammar's sparse/global field table can return a modifier
		// subtree for declarations that do not actually define a `name` field.
		// Kotlin declaration names are positionally the first identifier.
		if b.parsed.Language == LanguageKotlin {
			if nn := b.firstDirectIdentifier(n); nn != nil {
				nameNodes = append(nameNodes, nn)
			}
		} else if nn := b.fieldNode(n, spec.nameField); nn != nil {
			nameNodes = append(nameNodes, nn)
		}
	}
	if len(nameNodes) == 0 {
		switch nodeKind {
		case "property_declaration":
			// The maintained Kotlin grammar deliberately has few field names.
			// Restrict property names to the binding subtree; recursively taking
			// every simple_identifier also mistakes initializer calls for extra
			// declarations.
			for _, child := range children {
				if b.nodeKind(child) == "variable_declaration" {
					nameNodes = append(nameNodes, child)
				}
			}
			if len(nameNodes) == 0 {
				for _, child := range children {
					if b.nodeKind(child) == "simple_identifier" {
						nameNodes = append(nameNodes, child)
						break
					}
				}
			}
		case "field_declaration":
			collectChildrenOfKinds(n, map[string]bool{"variable_declarator": true}, &nameNodes, 2)
		case "primary_constructor", "secondary_constructor":
			if len(b.container) > 0 {
				cs := b.parsed.Symbols[b.container[len(b.container)-1]]
				fake := *n
				nameNodes = append(nameNodes, &fake)
				_ = cs
			}
		case "companion_object":
			// Anonymous companion objects still need a stable container symbol so
			// their members resolve to Outer.Companion rather than leaking into
			// the outer class.
			fake := *n
			nameNodes = append(nameNodes, &fake)
		case "class_parameter", "parameter", "type_parameter", "catch_block":
			if identifier := b.firstIdentifier(n); identifier != nil {
				nameNodes = append(nameNodes, identifier)
			}
		case "type_pattern", "record_pattern_component":
			for _, child := range children {
				if b.nodeKind(child) == "identifier" {
					nameNodes = append(nameNodes, child)
					break
				}
			}
		default:
			// fwcd/tree-sitter-kotlin models declaration names by child
			// position rather than a `name` field. The first identifier is the
			// declared name for classes, objects, functions, and type aliases.
			if spec.nameField != "" {
				if identifier := b.firstIdentifier(n); identifier != nil {
					nameNodes = append(nameNodes, identifier)
				}
			}
		}
	}
	indices := make([]int, 0, len(nameNodes))
	for _, nameNode := range nameNodes {
		actualName := nameNode
		if b.nodeKind(nameNode) == "variable_declarator" || b.nodeKind(nameNode) == "variable_declaration" {
			if x := b.fieldNode(nameNode, "name"); x != nil {
				actualName = x
			} else if x := b.firstIdentifier(nameNode); x != nil {
				actualName = x
			}
		}
		name := nodeText(b.source, actualName)
		if spec.kind == KindConstructor {
			if len(b.container) == 0 {
				continue
			}
			name = b.parsed.Symbols[b.container[len(b.container)-1]].Name
			actualName = n
		}
		anonymousCompanion := nodeKind == "companion_object" && b.nodeKind(actualName) == "companion_object"
		if anonymousCompanion {
			name = "Companion"
		}
		name = strings.Trim(name, "`")
		if name == "" || strings.ContainsAny(name, " \t\r\n=,:(){}") {
			continue
		}
		kind := spec.kind
		if b.parsed.Language == LanguageKotlin {
			if nodeKind == "class_declaration" {
				kind = kotlinClassKind(b.source, n)
			}
			if kind == KindFunction && len(b.container) > 0 && isContainerKind(b.parsed.Symbols[b.container[len(b.container)-1]].Kind) {
				kind = KindMethod
			}
			if nodeKind == "class_parameter" && !classParameterDeclaresProperty(n) {
				kind = KindParameter
			}
			if nodeKind == "property_declaration" && kind == KindProperty && len(b.container) > 0 && IsCallableKind(b.parsed.Symbols[b.container[len(b.container)-1]].Kind) {
				kind = KindVariable
			}
		} else if kind == KindVariable && parentKind == "field_declaration" {
			kind = KindField
		} else if kind == KindParameter && nodeKind == "formal_parameter" && len(b.container) > 0 && b.parsed.Symbols[b.container[len(b.container)-1]].Kind == KindRecord {
			kind = KindProperty
		}
		ns, ne := b.nodeSpan(actualName)
		if spec.kind == KindConstructor && len(b.container) > 0 {
			owner := b.parsed.Symbols[b.container[len(b.container)-1]]
			ns, ne = owner.NameStartByte, owner.NameEndByte
		}
		if anonymousCompanion {
			ne = ns + len("companion")
			if _, nodeEnd := b.nodeSpan(n); ne > nodeEnd {
				ne = nodeEnd
			}
		}
		containerID, containerName := "", ""
		if len(b.container) > 0 {
			c := b.parsed.Symbols[b.container[len(b.container)-1]]
			containerID, containerName = c.ID, c.Name
		}
		fqn := name
		if containerID != "" {
			c := b.parsed.Symbols[b.container[len(b.container)-1]]
			if c.FQN != "" {
				fqn = c.FQN + "." + name
			}
		} else if b.parsed.Package != "" {
			fqn = b.parsed.Package + "." + name
		}
		scopeStart, scopeEnd := b.declarationScope(n, kind, start, end)
		s := Symbol{ID: SymbolID(b.doc.URI, start, kind, name), Name: name, FQN: fqn, Kind: kind, Language: b.parsed.Language, URI: b.doc.URI, Range: b.doc.Range(start, end), SelectionRange: b.doc.Range(ns, ne), StartByte: start, EndByte: end, NameStartByte: ns, NameEndByte: ne, ScopeStartByte: scopeStart, ScopeEndByte: scopeEnd, AdditionalScopes: b.additionalDeclarationScopes(n, kind), ContainerID: containerID, ContainerName: containerName, Package: b.parsed.Package}
		s.Modifiers = b.modifiers(children)
		// tree-sitter-java represents modifiers as individual children for some
		// declarations instead of a Kotlin-style `modifiers` node. Recover the
		// declaration keywords from the prefix as well. Besides semantic tokens,
		// resolution and JVM projections rely on these flags being retained.
		modifierStart := start
		if parentKind == "field_declaration" {
			if parent := b.nodeParent(n); parent != nil && b.nodeKind(parent) == parentKind {
				modifierStart, _ = b.nodeSpan(parent)
			}
		}
		if modifierStart <= ns && ns <= len(b.source) {
			s.Modifiers = unique(append(s.Modifiers, declarationModifiers(string(b.source[modifierStart:ns]))...))
		}
		if b.parsed.Language == LanguageKotlin {
			// Only declaration-prefix annotations apply here. Scanning the whole
			// class node incorrectly transfers a member's @JvmName to its owner.
			annotationPrefix := ""
			if start <= ns && ns <= len(b.source) {
				annotationPrefix = string(b.source[start:ns])
			}
			s.JVMName = kotlinAnnotationString(annotationPrefix, "JvmName")
			if nodeKind == "class_parameter" {
				s.Modifiers = append(s.Modifiers, "constructor-property")
			}
			if kind == KindClass && kotlinDeclarationPrefixHasModifier(b.source, start, "data") {
				s.Modifiers = append(s.Modifiers, "data")
			}
		}
		// A local is a variable rather than a property, but whether it was
		// bound with val or var matters just as much: assigning to a val is an
		// error the index can prove without a compiler.
		if kind == KindProperty || kind == KindVariable {
			if keyword := kotlinBindingKeyword(n); keyword != "" {
				s.Modifiers = append(s.Modifiers, keyword)
			}
		}
		if nodeKind == "companion_object" {
			s.Modifiers = append(s.Modifiers, "companion")
		}
		s.Deprecated = contains(s.Modifiers, "deprecated") || contains(s.Modifiers, "Deprecated")
		s.ReceiverType = b.receiverType(n, actualName)
		s.Type = b.typeFor(n, actualName, children)
		if kind == KindVariable || kind == KindProperty || kind == KindField {
			s.Initializer = declarationInitializer(nodeText(b.source, n))
		}
		s.Parameters = b.parameters(n, children)
		s.TypeParameters, s.TypeParameterBounds = b.typeParameters(n, children)
		s.Supertypes = b.supertypes(children)
		s.Documentation = b.documentationBefore(start)
		s.Signature = b.signature(&s)
		idx := len(b.parsed.Symbols)
		b.parsed.Symbols = append(b.parsed.Symbols, s)
		indices = append(indices, idx)
		b.selectionBytes[[2]int{ns, ne}] = true
	}
	return indices
}

// Kotlin annotations can be qualified and may contain ordinary whitespace.
// This deliberately recognizes only a quoted first argument: JVM names cannot
// be computed dynamically and the compiler requires a string constant here.
func kotlinAnnotationString(source, annotation string) string {
	needle := annotation
	for search := 0; search < len(source); {
		at := strings.Index(source[search:], needle)
		if at < 0 {
			return ""
		}
		at += search
		before := source[:at]
		marker := strings.LastIndexByte(before, '@')
		if marker < 0 || strings.ContainsAny(source[marker:at], "\n\r(){};") {
			search = at + len(needle)
			continue
		}
		cursor := at + len(needle)
		for cursor < len(source) && (source[cursor] == ' ' || source[cursor] == '\t' || source[cursor] == '\r' || source[cursor] == '\n') {
			cursor++
		}
		if cursor >= len(source) || source[cursor] != '(' {
			search = at + len(needle)
			continue
		}
		cursor++
		for cursor < len(source) && (source[cursor] == ' ' || source[cursor] == '\t' || source[cursor] == '\r' || source[cursor] == '\n') {
			cursor++
		}
		if cursor >= len(source) || source[cursor] != '"' {
			return ""
		}
		cursor++
		var value strings.Builder
		for cursor < len(source) {
			if source[cursor] == '"' {
				return value.String()
			}
			if source[cursor] == '\\' && cursor+1 < len(source) {
				cursor++
			}
			value.WriteByte(source[cursor])
			cursor++
		}
		return ""
	}
	return ""
}

func kotlinFileAnnotationString(source, annotation string) string {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "@file:") || !strings.Contains(trimmed, annotation) {
			continue
		}
		if value := kotlinAnnotationString("@"+strings.TrimPrefix(trimmed, "@file:"), annotation); value != "" {
			return value
		}
	}
	return ""
}

func hasKotlinFileAnnotation(source, annotation string) bool {
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "@file:") && strings.Contains(trimmed, annotation) {
			return true
		}
	}
	return false
}

func kotlinDeclarationPrefixHasModifier(source []byte, start int, modifier string) bool {
	if start <= 0 || start > len(source) {
		return false
	}
	found := false
	for offset := 0; offset < start; {
		switch {
		case source[offset] == '/' && offset+1 < start && source[offset+1] == '/':
			offset += 2
			for offset < start && source[offset] != '\n' {
				offset++
			}
			continue
		case source[offset] == '/' && offset+1 < start && source[offset+1] == '*':
			offset += 2
			depth := 1
			for offset < start && depth > 0 {
				if offset+1 < start && source[offset] == '/' && source[offset+1] == '*' {
					depth++
					offset += 2
				} else if offset+1 < start && source[offset] == '*' && source[offset+1] == '/' {
					depth--
					offset += 2
				} else {
					offset++
				}
			}
			continue
		case source[offset] == '"' || source[offset] == '\'':
			quote := source[offset]
			triple := quote == '"' && offset+2 < start && source[offset+1] == '"' && source[offset+2] == '"'
			if triple {
				offset += 3
				for offset+2 < start && !(source[offset] == '"' && source[offset+1] == '"' && source[offset+2] == '"') {
					offset++
				}
				offset += 3
				continue
			}
			offset++
			for offset < start {
				if source[offset] == '\\' {
					offset += 2
					continue
				}
				value := source[offset]
				offset++
				if value == quote {
					break
				}
			}
			continue
		case source[offset] == '{' || source[offset] == '}' || source[offset] == ';':
			found = false
			offset++
			continue
		}
		if source[offset] == '_' || source[offset] >= 'A' && source[offset] <= 'Z' || source[offset] >= 'a' && source[offset] <= 'z' {
			end := offset + 1
			for end < start && (source[end] == '_' || source[end] >= 'A' && source[end] <= 'Z' || source[end] >= 'a' && source[end] <= 'z' || source[end] >= '0' && source[end] <= '9') {
				end++
			}
			word := string(source[offset:end])
			if word == modifier {
				found = true
			} else {
				switch word {
				case "class", "interface", "object", "fun", "val", "var", "typealias":
					found = false
				}
			}
			offset = end
			continue
		}
		offset++
	}
	return found
}

// declarationScope records enough lexical structure for shadowing resolution
// after the tree has been released.  ContainerID alone identifies a callable,
// but two block-local declarations in that callable can have different
// visibility ranges.
func (b *parseBuilder) declarationScope(node *sitter.Node, kind SymbolKind, start, end int) (int, int) {
	if (IsTypeKind(kind) || IsCallableKind(kind)) && len(b.container) > 0 && IsCallableKind(b.parsed.Symbols[b.container[len(b.container)-1]].Kind) {
		// Local types and callables are visible throughout their containing
		// lexical block, but never escape into a sibling callable.
		for current := b.nodeParent(node); current != nil; current = b.nodeParent(current) {
			switch b.nodeKind(current) {
			case "block", "function_body", "lambda_literal", "lambda_expression", "when_entry":
				return b.nodeSpan(current)
			}
		}
	}
	if kind != KindVariable && kind != KindProperty && kind != KindParameter && kind != KindTypeParameter {
		return start, end
	}
	if b.nodeKind(node) == "type_pattern" || b.nodeKind(node) == "instanceof_expression" || b.nodeKind(node) == "record_pattern_component" {
		for current := b.nodeParent(node); current != nil; current = b.nodeParent(current) {
			switch b.nodeKind(current) {
			case "if_statement":
				if consequence := current.ChildByFieldName("consequence"); consequence != nil {
					if javaNegatedPatternGuard(b.source, current, consequence) {
						_, scopeStart := b.nodeSpan(current)
						for enclosing := b.nodeParent(current); enclosing != nil; enclosing = b.nodeParent(enclosing) {
							if kind := b.nodeKind(enclosing); kind == "block" || kind == "constructor_body" {
								_, scopeEnd := b.nodeSpan(enclosing)
								return scopeStart, scopeEnd
							}
						}
					}
					_, consequenceEnd := b.nodeSpan(consequence)
					return start, consequenceEnd
				}
			case "while_statement":
				if body := current.ChildByFieldName("body"); body != nil {
					_, bodyEnd := b.nodeSpan(body)
					return start, bodyEnd
				}
			case "switch_rule", "switch_block_statement_group":
				return b.nodeSpan(current)
			}
		}
	}
	for current := node; current != nil; current = b.nodeParent(current) {
		name := b.nodeKind(current)
		if kind == KindTypeParameter && (name == "class_declaration" || name == "object_declaration" || name == "companion_object") {
			return b.nodeSpan(current)
		}
		switch name {
		case "when_expression":
			_, scopeEnd := b.nodeSpan(current)
			for _, child := range b.namedChildren(current) {
				if b.nodeKind(child) == "when_subject" {
					_, scopeStart := b.nodeSpan(child)
					return scopeStart, scopeEnd
				}
			}
			return end, scopeEnd
		case "try_with_resources_statement":
			if body := current.ChildByFieldName("body"); body != nil {
				_, scopeEnd := b.nodeSpan(body)
				return end, scopeEnd
			}
		case "for_statement", "enhanced_for_statement":
			if body := current.ChildByFieldName("body"); body != nil {
				return b.nodeSpan(body)
			}
			children := b.namedChildren(current)
			if len(children) > 0 {
				return b.nodeSpan(children[len(children)-1])
			}
		case "catch_clause", "catch_block":
			if body := current.ChildByFieldName("body"); body != nil {
				return b.nodeSpan(body)
			}
			children := b.namedChildren(current)
			if len(children) > 0 {
				return b.nodeSpan(children[len(children)-1])
			}
		case "block", "function_body", "lambda_literal", "lambda_expression", "when_entry",
			"function_declaration", "method_declaration", "constructor_declaration", "secondary_constructor":
			_, scopeEnd := b.nodeSpan(current)
			if kind == KindTypeParameter {
				scopeStart, _ := b.nodeSpan(current)
				return scopeStart, scopeEnd
			}
			return end, scopeEnd
		}
	}
	return start, end
}

func javaNegatedPatternGuard(source []byte, statement, consequence *sitter.Node) bool {
	if statement == nil || consequence == nil {
		return false
	}
	kind := consequence.Kind()
	if kind != "return_statement" && kind != "throw_statement" && kind != "break_statement" && kind != "continue_statement" {
		return false
	}
	condition := statement.ChildByFieldName("condition")
	if condition == nil {
		return false
	}
	text := strings.TrimSpace(nodeText(source, condition))
	for strings.HasPrefix(text, "(") && strings.HasSuffix(text, ")") {
		text = strings.TrimSpace(text[1 : len(text)-1])
	}
	return strings.HasPrefix(text, "!") && strings.Contains(text, "instanceof")
}

func (b *parseBuilder) additionalDeclarationScopes(node *sitter.Node, kind SymbolKind) []ByteScope {
	if b.parsed.Language != LanguageJava || kind != KindVariable || b.nodeKind(node) != "type_pattern" && b.nodeKind(node) != "instanceof_expression" && b.nodeKind(node) != "record_pattern_component" {
		return nil
	}
	var pattern, condition *sitter.Node
	for current := node; current != nil; current = b.nodeParent(current) {
		if pattern == nil && b.nodeKind(current) == "instanceof_expression" {
			pattern = current
		}
		if b.nodeKind(current) == "if_statement" {
			condition = current.ChildByFieldName("condition")
			break
		}
	}
	if pattern == nil || condition == nil {
		return nil
	}
	conditionStart, conditionEnd := b.nodeSpan(condition)
	patternStart, patternEnd := b.nodeSpan(pattern)
	if patternStart < conditionStart || patternEnd >= conditionEnd {
		return nil
	}
	tail := string(b.source[patternEnd:conditionEnd])
	andAt, orAt := strings.Index(tail, "&&"), strings.Index(tail, "||")
	operatorAt, operator := -1, ""
	if andAt >= 0 && (orAt < 0 || andAt < orAt) {
		operatorAt, operator = andAt, "&&"
	} else if orAt >= 0 {
		operatorAt, operator = orAt, "||"
	}
	if operatorAt < 0 {
		return nil
	}
	prefix := string(b.source[conditionStart:patternStart])
	negated := strings.LastIndex(prefix, "!") > strings.LastIndex(prefix, "||") && strings.LastIndex(prefix, "!") > strings.LastIndex(prefix, "&&")
	if operator == "&&" && negated || operator == "||" && !negated {
		return nil
	}
	start := patternEnd + operatorAt + len(operator)
	if start >= conditionEnd {
		return nil
	}
	return []ByteScope{{StartByte: start, EndByte: conditionEnd}}
}

func declarationInitializer(declaration string) string {
	if equals := strings.IndexByte(declaration, '='); equals >= 0 {
		// Initializers drive type definitions, inferred inlays, member
		// completion, and hover. Keep the complete syntax node: line and byte
		// ceilings silently corrupted valid generated identifiers and multiline
		// expressions.
		return strings.TrimSpace(strings.TrimSuffix(declaration[equals+1:], ";"))
	}
	if delegated := strings.Index(declaration, " by "); delegated >= 0 {
		// Preserve the `by` marker so type inference distinguishes the
		// property's effective getValue type from the delegate object's type.
		return strings.TrimSpace(strings.TrimSuffix(declaration[delegated+1:], ";"))
	}
	return ""
}

func (b *parseBuilder) receiverType(n, name *sitter.Node) string {
	if b.parsed.Language != LanguageKotlin || n.Kind() != "function_declaration" && n.Kind() != "property_declaration" {
		return ""
	}
	for _, field := range []string{"receiver_type", "receiver"} {
		if receiver := b.fieldNode(n, field); receiver != nil {
			return normalizeSpace(nodeText(b.source, receiver))
		}
	}
	// Grammar versions without a named receiver field still place `Type.`
	// between the declaration keyword and name.
	headEnd := int(name.StartByte())
	if headEnd <= int(n.StartByte()) || headEnd > len(b.source) {
		return ""
	}
	head := string(b.source[n.StartByte():name.StartByte()])
	dot := strings.LastIndexByte(head, '.')
	if dot < 0 {
		return ""
	}
	head = strings.TrimSpace(head[:dot])
	if at := strings.LastIndex(head, "fun "); at >= 0 {
		head = strings.TrimSpace(head[at+4:])
	} else if at := strings.LastIndex(head, "val "); at >= 0 {
		head = strings.TrimSpace(head[at+4:])
	} else if at := strings.LastIndex(head, "var "); at >= 0 {
		head = strings.TrimSpace(head[at+4:])
	}
	if strings.HasPrefix(head, "<") {
		depth, close := 0, -1
		for index := 0; index < len(head); index++ {
			switch head[index] {
			case '<':
				depth++
			case '>':
				depth--
				if depth == 0 {
					close = index
					index = len(head)
				}
			}
		}
		if close >= 0 {
			head = strings.TrimSpace(head[close+1:])
		}
	}
	if strings.ContainsAny(head, " \t\r\n={}") {
		return ""
	}
	return normalizeSpace(head)
}

func (b *parseBuilder) addImport(n *sitter.Node) {
	raw := nodeText(b.source, n)
	text := strings.TrimSpace(raw)
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSuffix(strings.TrimSpace(text), ";")
	static := strings.HasPrefix(text, "static ")
	text = strings.TrimSpace(strings.TrimPrefix(text, "static "))
	alias := ""
	if before, after, ok := strings.Cut(text, " as "); ok {
		text, alias = strings.TrimSpace(before), strings.TrimSpace(after)
	}
	wild := strings.HasSuffix(text, ".*")
	text = strings.TrimSuffix(text, ".*")
	b.parsed.Imports = append(b.parsed.Imports, Import{Path: text, Alias: alias, Wildcard: wild, Static: static, Range: b.doc.Range(int(n.StartByte()), int(n.EndByte()))})

	// The generic walker intentionally skips package/import subtrees. Add the
	// imported declaration explicitly so definition, hover, references and
	// rename work while the cursor is on an import directive as they do in the
	// IntelliJ implementation.
	nameStart := strings.LastIndexByte(text, '.') + 1
	name := text[nameStart:]
	if name == "" {
		return
	}
	pathAt := strings.Index(raw, text)
	if pathAt < 0 {
		return
	}
	start := int(n.StartByte()) + pathAt + nameStart
	qualifier := strings.TrimSuffix(text[:nameStart], ".")
	b.parsed.References = append(b.parsed.References, Reference{
		Name: name, Qualifier: qualifier, URI: b.doc.URI,
		Range: b.doc.Range(start, start+len(name)), StartByte: start,
		EndByte: start + len(name), Role: RoleImport, Arity: -1,
	})
	if alias != "" {
		if aliasAt := strings.LastIndex(raw, alias); aliasAt >= 0 {
			aliasStart := int(n.StartByte()) + aliasAt
			// Resolve the alias token to the imported declaration while keeping
			// the token's source range for navigation/highlighting.
			b.parsed.References = append(b.parsed.References, Reference{
				Name: name, Qualifier: qualifier, URI: b.doc.URI,
				Range: b.doc.Range(aliasStart, aliasStart+len(alias)), StartByte: aliasStart,
				EndByte: aliasStart + len(alias), Role: RoleImport, Arity: -1,
			})
		}
	}
}

func (b *parseBuilder) modifiers(children []*sitter.Node) []string {
	var out []string
	for _, c := range children {
		if c.Kind() == "modifiers" {
			text := nodeText(b.source, c)
			words := strings.FieldsFunc(text, func(r rune) bool { return !(unicode.IsLetter(r) || r == '_') })
			for _, w := range words {
				if b.keywords[w] || w == "Deprecated" || w == "JvmStatic" || w == "JvmSynthetic" || w == "JvmOverloads" || w == "JvmField" || w == "JvmName" {
					out = append(out, w)
				}
			}
			out = append(out, annotationSimpleNames(text)...)
		}
	}
	return unique(out)
}

func annotationSimpleNames(source string) []string {
	var result []string
	for cursor := 0; cursor < len(source); cursor++ {
		if source[cursor] != '@' {
			continue
		}
		cursor++
		// Kotlin use-site targets precede a colon: @field:Ann, @get:Ann, ...
		wordStart := cursor
		for cursor < len(source) && (isIdentifierByte(source[cursor]) || source[cursor] == '.') {
			cursor++
		}
		if cursor < len(source) && source[cursor] == ':' {
			cursor++
			wordStart = cursor
			for cursor < len(source) && (isIdentifierByte(source[cursor]) || source[cursor] == '.') {
				cursor++
			}
		}
		qualified := strings.Trim(source[wordStart:cursor], ".")
		if dot := strings.LastIndexByte(qualified, '.'); dot >= 0 {
			qualified = qualified[dot+1:]
		}
		if qualified != "" {
			result = append(result, qualified)
		}
		cursor--
	}
	return unique(result)
}

func declarationModifiers(prefix string) []string {
	// This is intentionally a declaration-only allowlist. Scanning all language
	// keywords would incorrectly record a Java field's primitive type as a
	// modifier, while scanning the whole declaration would inspect initializers.
	allowed := map[string]bool{
		"public": true, "protected": true, "private": true, "internal": true,
		"static": true, "final": true, "abstract": true, "default": true,
		"native": true, "synchronized": true, "strictfp": true,
		"transient": true, "volatile": true,
		"open": true, "sealed": true, "data": true, "const": true,
		"lateinit": true, "override": true, "suspend": true, "inline": true,
		"value": true, "operator": true, "infix": true, "tailrec": true,
		"external": true, "expect": true, "actual": true,
		"vararg": true, "crossinline": true, "noinline": true,
	}
	words := strings.FieldsFunc(prefix, func(r rune) bool { return !(unicode.IsLetter(r) || r == '_') })
	out := make([]string, 0, 4)
	for _, word := range words {
		if allowed[word] {
			out = append(out, word)
		}
	}
	return unique(out)
}

func (b *parseBuilder) typeFor(n, name *sitter.Node, children []*sitter.Node) string {
	if n.Kind() == "class_declaration" || n.Kind() == "object_declaration" || n.Kind() == "companion_object" {
		return ""
	}
	if n.Kind() == "type_alias" {
		declaration := nodeText(b.source, n)
		if equals := strings.IndexByte(declaration, '='); equals >= 0 {
			return normalizeSpace(strings.TrimSpace(declaration[equals+1:]))
		}
		return ""
	}
	if b.parsed.Language == LanguageKotlin && (n.Kind() == "function_declaration" || n.Kind() == "property_declaration") {
		if explicit := b.kotlinExplicitResultType(n, name); explicit != "" {
			return explicit
		}
	}
	for _, field := range []string{"type", "return_type"} {
		if t := b.fieldNode(n, field); t != nil {
			return normalizeSpace(nodeText(b.source, t))
		}
	}
	if n.Kind() == "variable_declarator" && n.Parent() != nil {
		return b.typeFor(n.Parent(), name, nil)
	}
	if n.Kind() == "property_declaration" {
		for _, child := range directNamedChildren(n) {
			if child.Kind() == "variable_declaration" {
				if typ := b.typeFor(child, name, nil); typ != "" {
					return typ
				}
			}
		}
	}
	if children == nil {
		children = directNamedChildren(n)
	}
	for _, c := range children {
		if isTypeNode(c.Kind()) {
			return normalizeSpace(nodeText(b.source, c))
		}
	}
	return ""
}

func (b *parseBuilder) kotlinExplicitResultType(n, name *sitter.Node) string {
	start, end := int(name.EndByte()), int(n.EndByte())
	if start < 0 || start >= end || end > len(b.source) {
		return ""
	}
	for start < end && isSpaceByte(b.source[start]) {
		start++
	}
	if n.Kind() == "function_declaration" && start < end && b.source[start] == '(' {
		depth := 0
		for start < end {
			value := b.source[start]
			start++
			if value == '(' {
				depth++
			} else if value == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		for start < end && isSpaceByte(b.source[start]) {
			start++
		}
	}
	if start >= end || b.source[start] != ':' {
		return ""
	}
	start++
	typeStart := start
	angles, parens, brackets := 0, 0, 0
	for start < end {
		value := b.source[start]
		if angles == 0 && parens == 0 && brackets == 0 {
			if value == '=' || value == '{' {
				break
			}
			if isSpaceByte(value) {
				wordStart := start
				for wordStart < end && isSpaceByte(b.source[wordStart]) {
					wordStart++
				}
				wordEnd := wordStart
				for wordEnd < end && (b.source[wordEnd] == '_' || b.source[wordEnd] >= 'A' && b.source[wordEnd] <= 'Z' || b.source[wordEnd] >= 'a' && b.source[wordEnd] <= 'z') {
					wordEnd++
				}
				word := string(b.source[wordStart:wordEnd])
				if word == "where" || n.Kind() == "property_declaration" && (word == "get" || word == "set" || word == "by") {
					break
				}
			}
		}
		switch value {
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
		}
		start++
	}
	return normalizeSpace(strings.TrimSpace(string(b.source[typeStart:start])))
}

func (b *parseBuilder) parameters(n *sitter.Node, children []*sitter.Node) []Parameter {
	var root *sitter.Node
	for _, field := range []string{"parameters", "value_parameters"} {
		if root = b.fieldNode(n, field); root != nil {
			break
		}
	}
	if root == nil {
		for _, c := range children {
			if c.Kind() == "function_value_parameters" || c.Kind() == "class_parameters" || strings.Contains(c.Kind(), "parameter_list") {
				root = c
				break
			}
		}
	}
	if root == nil {
		return nil
	}
	var nodes []*sitter.Node
	collectChildrenOfKinds(root, map[string]bool{"parameter": true, "formal_parameter": true, "spread_parameter": true, "class_parameter": true}, &nodes, 3)
	out := make([]Parameter, 0, len(nodes))
	for parameterIndex, p := range nodes {
		nn := b.fieldNode(p, "name")
		if nn == nil {
			nn = firstIdentifier(p)
		}
		if nn == nil {
			continue
		}
		name := strings.Trim(nodeText(b.source, nn), "`")
		typ := b.typeFor(p, nn, nil)
		def := ""
		if v := b.fieldNode(p, "value"); v != nil {
			def = normalizeSpace(nodeText(b.source, v))
		}
		if def == "" {
			nextStart, _ := b.nodeSpan(root)
			_, rootEnd := b.nodeSpan(root)
			nextStart = rootEnd
			if parameterIndex+1 < len(nodes) {
				nextStart, _ = b.nodeSpan(nodes[parameterIndex+1])
			}
			def = b.parameterDefaultExpression(p, root, nextStart)
		}
		raw := nodeText(b.source, p)
		variadic := p.Kind() == "spread_parameter" || strings.Contains(raw, "...") || wordIndex(raw, "vararg") >= 0
		if b.parsed.Language == LanguageKotlin && !variadic {
			prefix := string(b.source[root.StartByte():p.StartByte()])
			if separator := strings.LastIndexAny(prefix, "(,"); separator >= 0 {
				prefix = prefix[separator+1:]
			}
			variadic = wordIndex(prefix, "vararg") >= 0
		}
		out = append(out, Parameter{Name: name, Type: typ, Default: def, Variadic: variadic, Range: b.doc.Range(int(p.StartByte()), int(p.EndByte()))})
	}
	return out
}

func (b *parseBuilder) parameterDefaultExpression(parameter, root *sitter.Node, nextParameterStart int) string {
	parameterStart, parameterEnd := b.nodeSpan(parameter)
	for _, child := range b.namedChildren(parameter) {
		childStart, _ := b.nodeSpan(child)
		if childStart > parameterStart && childStart <= len(b.source) && strings.Contains(string(b.source[parameterStart:childStart]), "=") {
			return normalizeSpace(nodeText(b.source, child))
		}
	}
	for _, child := range b.namedChildren(root) {
		childStart, childEnd := b.nodeSpan(child)
		if childStart < parameterEnd || childEnd > nextParameterStart || childStart > len(b.source) || parameterEnd > len(b.source) {
			continue
		}
		if strings.Contains(string(b.source[parameterEnd:childStart]), "=") {
			return normalizeSpace(nodeText(b.source, child))
		}
	}
	return ""
}

func (b *parseBuilder) typeParameters(declaration *sitter.Node, children []*sitter.Node) ([]string, map[string][]string) {
	var out []string
	bounds := make(map[string][]string)
	var nodes []*sitter.Node
	for _, c := range children {
		if c.Kind() == "type_parameters" {
			collectChildrenOfKinds(c, map[string]bool{"type_parameter": true}, &nodes, 2)
		}
	}
	for _, x := range nodes {
		name := ""
		if nn := b.fieldNode(x, "name"); nn != nil {
			name = nodeText(b.source, nn)
		} else if nn := firstIdentifier(x); nn != nil {
			name = nodeText(b.source, nn)
		}
		if name != "" {
			out = append(out, name)
			bounds[name] = append(bounds[name], declaredTypeParameterBounds(nodeText(b.source, x), name)...)
		}
	}
	if declaration != nil && b.parsed.Language == LanguageKotlin {
		raw := nodeText(b.source, declaration)
		if where := wordIndex(raw, "where"); where >= 0 {
			for _, constraint := range splitTypeConstraints(raw[where+len("where"):], ',') {
				if name, bound, ok := strings.Cut(constraint, ":"); ok {
					name, bound = strings.TrimSpace(name), strings.TrimSpace(bound)
					if name != "" && bound != "" {
						bounds[name] = append(bounds[name], bound)
					}
				}
			}
		}
	}
	for name, values := range bounds {
		values = unique(values)
		if len(values) == 0 {
			delete(bounds, name)
		} else {
			bounds[name] = values
		}
	}
	if len(bounds) == 0 {
		bounds = nil
	}
	return out, bounds
}

func declaredTypeParameterBounds(raw, name string) []string {
	if at := strings.Index(raw, name); at >= 0 {
		raw = strings.TrimSpace(raw[at+len(name):])
	}
	if strings.HasPrefix(raw, ":") {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, ":"))
	} else if strings.HasPrefix(raw, "extends ") {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "extends "))
	} else {
		return nil
	}
	return splitTypeConstraints(raw, '&')
}

func splitTypeConstraints(raw string, separator byte) []string {
	depth, start := 0, 0
	var out []string
	for index := 0; index <= len(raw); index++ {
		if index == len(raw) || raw[index] == separator && depth == 0 {
			if value := strings.TrimSpace(raw[start:index]); value != "" {
				out = append(out, value)
			}
			start = index + 1
			continue
		}
		switch raw[index] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return out
}

func (b *parseBuilder) supertypes(children []*sitter.Node) []string {
	var out []string
	for _, c := range children {
		switch c.Kind() {
		case "delegation_specifier", "delegation_specifiers", "superclass", "super_interfaces", "extends_interfaces", "class_heritage":
			out = append(out, declaredSupertypeTexts(nodeText(b.source, c))...)
		}
	}
	return unique(out)
}

func declaredSupertypeTexts(value string) []string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"extends ", "implements ", "permits ", ":"} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
			break
		}
	}
	start, angles, parens, brackets := 0, 0, 0, 0
	result := make([]string, 0, 2)
	appendValue := func(end int) {
		candidate := strings.TrimSpace(value[start:end])
		angleDepth := 0
		for index := 0; index < len(candidate); index++ {
			switch candidate[index] {
			case '<':
				angleDepth++
			case '>':
				if angleDepth > 0 {
					angleDepth--
				}
			case '(':
				if angleDepth == 0 {
					candidate = strings.TrimSpace(candidate[:index])
					index = len(candidate)
				}
			}
		}
		if by := strings.Index(candidate, " by "); by >= 0 {
			candidate = strings.TrimSpace(candidate[:by])
		}
		if candidate != "" {
			result = append(result, normalizeSpace(candidate))
		}
	}
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' && angles == 0 && parens == 0 && brackets == 0 {
			appendValue(index)
			start = index + 1
			continue
		}
		switch value[index] {
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
		}
	}
	return result
}

func (b *parseBuilder) signature(s *Symbol) string {
	var out strings.Builder
	mods := make([]string, 0, len(s.Modifiers))
	for _, m := range s.Modifiers {
		if m != "public" {
			mods = append(mods, m)
		}
	}
	if len(mods) > 0 {
		out.WriteString(strings.Join(mods, " "))
		out.WriteByte(' ')
	}
	switch s.Kind {
	case KindClass:
		out.WriteString("class ")
	case KindInterface:
		out.WriteString("interface ")
	case KindEnum:
		out.WriteString("enum ")
	case KindObject:
		out.WriteString("object ")
	case KindAnnotation:
		out.WriteString("annotation class ")
	case KindRecord:
		out.WriteString("record ")
	case KindFunction, KindMethod, KindConstructor:
		if s.Language == LanguageKotlin && s.Kind != KindConstructor {
			out.WriteString("fun ")
			if len(s.TypeParameters) > 0 {
				out.WriteByte('<')
				out.WriteString(typeParameterSignature(s))
				out.WriteString("> ")
			}
		}
	}
	if s.Language == LanguageKotlin && s.Kind == KindProperty && len(s.TypeParameters) > 0 {
		out.WriteByte('<')
		out.WriteString(typeParameterSignature(s))
		out.WriteString("> ")
	}
	if s.ReceiverType != "" {
		out.WriteString(s.ReceiverType)
		out.WriteByte('.')
	}
	out.WriteString(s.Name)
	if len(s.TypeParameters) > 0 && !(s.Language == LanguageKotlin && (s.Kind == KindFunction || s.Kind == KindMethod || s.Kind == KindProperty)) {
		out.WriteByte('<')
		out.WriteString(typeParameterSignature(s))
		out.WriteByte('>')
	}
	if IsCallableKind(s.Kind) {
		out.WriteByte('(')
		for i, p := range s.Parameters {
			if i > 0 {
				out.WriteString(", ")
			}
			if s.Language == LanguageJava && p.Type != "" {
				out.WriteString(p.Type)
				out.WriteByte(' ')
				out.WriteString(p.Name)
			} else {
				out.WriteString(p.Name)
				if p.Type != "" {
					out.WriteString(": ")
					out.WriteString(p.Type)
				}
			}
			if p.Default != "" {
				out.WriteString(" = ")
				out.WriteString(p.Default)
			}
		}
		out.WriteByte(')')
	}
	if s.Type != "" {
		if s.Language == LanguageKotlin {
			out.WriteString(": ")
			out.WriteString(s.Type)
		} else if !IsTypeKind(s.Kind) {
			return s.Type + " " + out.String()
		}
	}
	if len(s.Supertypes) > 0 {
		out.WriteString(" : ")
		out.WriteString(strings.Join(s.Supertypes, ", "))
	}
	return normalizeSpace(out.String())
}

func typeParameterSignature(symbol *Symbol) string {
	parts := make([]string, 0, len(symbol.TypeParameters))
	for _, name := range symbol.TypeParameters {
		part := name
		if bounds := symbol.TypeParameterBounds[name]; len(bounds) > 0 {
			if symbol.Language == LanguageJava {
				part += " extends " + strings.Join(bounds, " & ")
			} else {
				part += " : " + strings.Join(bounds, " & ")
			}
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

func (b *parseBuilder) documentationBefore(start int) string {
	if start > len(b.source) {
		start = len(b.source)
	}
	if start < 0 {
		start = 0
	}
	i := start
	for i > 0 && (b.source[i-1] == ' ' || b.source[i-1] == '\t' || b.source[i-1] == '\r' || b.source[i-1] == '\n') {
		i--
	}
	if i >= 2 && b.source[i-2] == '*' && b.source[i-1] == '/' {
		if j := bytes.LastIndex(b.source[:i-2], []byte("/**")); j >= 0 {
			return cleanDoc(string(b.source[j:i]))
		}
	}
	lines := []string{}
	p := i
	for p > 0 {
		lineStart := p
		for lineStart > 0 && b.source[lineStart-1] != '\n' {
			lineStart--
		}
		line := strings.TrimSpace(string(b.source[lineStart:p]))
		if !strings.HasPrefix(line, "//") {
			break
		}
		lines = append(lines, strings.TrimSpace(strings.TrimPrefix(line, "//")))
		p = lineStart
		if p > 0 {
			p--
		}
	}
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return strings.Join(lines, "\n")
}

func (b *parseBuilder) qualifier(n *sitter.Node) string {
	if len(b.ancestorNodes) == 0 {
		return ""
	}
	p := b.ancestorNodes[len(b.ancestorNodes)-1]
	if p.Kind() == "navigation_expression" || p.Kind() == "member_access_expression" || p.Kind() == "field_access" || p.Kind() == "method_invocation" || p.Kind() == "callable_reference" || p.Kind() == "method_reference" {
		if obj := b.fieldNode(p, "object"); obj != nil && obj.EndByte() <= n.StartByte() {
			return strings.TrimSpace(nodeText(b.source, obj))
		}
		if recv := b.fieldNode(p, "receiver"); recv != nil && recv.EndByte() <= n.StartByte() {
			return strings.TrimSpace(nodeText(b.source, recv))
		}
	}
	return lexicalQualifier(b.source, int(n.StartByte()))
}

func lexicalQualifier(source []byte, start int) string {
	index := start - 1
	for index >= 0 && (source[index] == ' ' || source[index] == '\t') {
		index--
	}
	if index >= 1 && source[index] == ':' && source[index-1] == ':' {
		index -= 2
	} else {
		if index < 0 || source[index] != '.' {
			return ""
		}
		index--
	}
	if index >= 0 && source[index] == '?' {
		index--
	} else if index >= 1 && source[index] == '!' && source[index-1] == '!' {
		index -= 2
	}
	end := index + 1
	for index >= 0 {
		value := source[index]
		if value == '_' || value == '$' || value == '.' || value == ':' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
			index--
			continue
		}
		break
	}
	return strings.Trim(string(source[index+1:end]), ".")
}

func (b *parseBuilder) isCallCallee(n *sitter.Node) bool {
	for depth, index := 0, len(b.ancestorNodes)-1; index >= 0 && depth < 6; depth, index = depth+1, index-1 {
		call := b.ancestorNodes[index]
		switch call.Kind() {
		case "call_expression", "method_invocation", "object_creation_expression", "explicit_constructor_invocation":
			arguments := b.fieldNode(call, "arguments")
			if arguments == nil {
				if b.nodeKind(call) == "call_expression" {
					for _, child := range b.namedChildren(call) {
						if b.nodeKind(child) == "value_arguments" {
							arguments = child
							break
						}
					}
				} else {
					arguments = descendantOfKinds(call, map[string]bool{"argument_list": true}, 3)
				}
			}
			if arguments == nil && b.nodeKind(call) == "call_expression" {
				for _, child := range b.namedChildren(call) {
					if b.nodeKind(child) == "annotated_lambda" || b.nodeKind(child) == "lambda_literal" {
						arguments = child
						break
					}
				}
			}
			if arguments == nil && b.nodeKind(call) == "call_expression" {
				_, nodeEnd := b.nodeSpan(n)
				for nodeEnd < len(b.source) && (b.source[nodeEnd] == ' ' || b.source[nodeEnd] == '\t' || b.source[nodeEnd] == '\r' || b.source[nodeEnd] == '\n') {
					nodeEnd++
				}
				if nodeEnd < len(b.source) && b.source[nodeEnd] == '{' {
					return true
				}
			}
			if arguments == nil || n.EndByte() > arguments.StartByte() {
				return false
			}
			// The callee is the last identifier before the argument list. A
			// receiver in repository.findAll() is therefore a normal read.
			for offset := int(n.EndByte()); offset < int(arguments.StartByte()) && offset < len(b.source); offset++ {
				value := b.source[offset]
				if value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}

// classParameterDeclaresProperty reports whether a primary-constructor
// parameter also declares a property, which it does exactly when it carries the
// val or var keyword. The grammar emits that keyword as its own child, and that
// is the only dependable signal: reading it out of the parameter's text is
// defeated by a use-site-target annotation such as `@field:Column(...)`, whose
// colon precedes the keyword. Misreading it demotes the property to a plain
// parameter, which is deliberately kept out of the global name index, so every
// reference to it elsewhere in the class then looks unresolved.
func classParameterDeclaresProperty(node *sitter.Node) bool {
	return kotlinBindingKeyword(node) != ""
}

// kotlinBindingKeyword returns the val or var a declaration was written with.
// The grammar emits the keyword as its own child, which is the only dependable
// reading: the declaration's text includes its initialiser, where the words
// appear inside strings and identifiers that mean nothing.
func kotlinBindingKeyword(node *sitter.Node) string {
	if node == nil {
		return ""
	}
	for index := uint(0); index < node.ChildCount(); index++ {
		switch kind := node.Child(index).Kind(); kind {
		case "val", "var":
			return kind
		}
	}
	return ""
}

func (b *parseBuilder) isNamedArgumentLabel(node *sitter.Node, parentKind string) bool {
	if parentKind != "value_argument" && parentKind != "element_value_pair" || len(b.ancestorNodes) == 0 {
		return false
	}
	argument := b.ancestorNodes[len(b.ancestorNodes)-1]
	children := b.namedChildren(argument)
	if len(children) < 2 || children[0].Id() != node.Id() || !isIdentifierKind(b.nodeKind(children[0])) {
		return false
	}
	_, nameEnd := b.nodeSpan(children[0])
	valueStart, _ := b.nodeSpan(children[1])
	if nameEnd < 0 || valueStart < nameEnd || valueStart > len(b.source) {
		return false
	}
	separator := string(b.source[nameEnd:valueStart])
	return strings.Contains(separator, "=") && !strings.Contains(separator, "==")
}

func (b *parseBuilder) callArguments(n *sitter.Node) ([]protocol.Range, bool) {
	for depth, index := 0, len(b.ancestorNodes)-1; index >= 0 && depth < 5; depth, index = depth+1, index-1 {
		call := b.ancestorNodes[index]
		switch call.Kind() {
		case "call_expression", "method_invocation", "object_creation_expression", "explicit_constructor_invocation":
			var arguments *sitter.Node
			if arguments = b.fieldNode(call, "arguments"); arguments == nil {
				if b.nodeKind(call) == "call_expression" {
					for _, child := range b.namedChildren(call) {
						if b.nodeKind(child) == "value_arguments" {
							arguments = child
							break
						}
					}
				} else {
					arguments = descendantOfKinds(call, map[string]bool{"argument_list": true}, 3)
				}
			}
			var out []protocol.Range
			if arguments != nil {
				children := b.namedChildren(arguments)
				out = make([]protocol.Range, 0, len(children)+1)
				for _, argument := range children {
					start, end := b.nodeSpan(argument)
					out = append(out, b.doc.Range(start, end))
				}
			}
			trailingLambdaIncluded := false
			if b.nodeKind(call) == "call_expression" {
				for _, child := range b.namedChildren(call) {
					if b.nodeKind(child) == "annotated_lambda" || b.nodeKind(child) == "lambda_literal" {
						start, end := b.nodeSpan(child)
						out = append(out, b.doc.Range(start, end))
						trailingLambdaIncluded = true
					}
				}
				// This Kotlin grammar sometimes makes a trailing lambda a sibling
				// of call_expression. Preserve it as the final argument anyway so
				// overload selection, signature help, and contextual generic type
				// inference see the source-level call's complete arity.
				if !trailingLambdaIncluded {
					_, callEnd := b.nodeSpan(call)
					if start, end, ok := kotlinTrailingLambdaAfter(b.source, callEnd); ok {
						out = append(out, b.doc.Range(start, end))
					}
				}
			}
			if len(out) == 0 && b.nodeKind(call) == "call_expression" {
				_, calleeEnd := b.nodeSpan(n)
				_, callEnd := b.nodeSpan(call)
				for calleeEnd < callEnd && (b.source[calleeEnd] == ' ' || b.source[calleeEnd] == '\t' || b.source[calleeEnd] == '\r' || b.source[calleeEnd] == '\n') {
					calleeEnd++
				}
				if calleeEnd < callEnd && b.source[calleeEnd] == '{' {
					out = append(out, b.doc.Range(calleeEnd, callEnd))
				}
			}
			if arguments == nil && len(out) == 0 {
				return nil, false
			}
			return out, true
		}
	}
	return nil, false
}

func kotlinTrailingLambdaAfter(source []byte, offset int) (int, int, bool) {
	for offset < len(source) && (source[offset] == ' ' || source[offset] == '\t' || source[offset] == '\r' || source[offset] == '\n') {
		offset++
	}
	if offset >= len(source) || source[offset] != '{' {
		return 0, 0, false
	}
	start, depth := offset, 0
	quote, escaped, lineComment, blockDepth := byte(0), false, false, 0
	for index := offset; index < len(source); index++ {
		value := source[index]
		if lineComment {
			if value == '\n' {
				lineComment = false
			}
			continue
		}
		if blockDepth > 0 {
			if value == '/' && index+1 < len(source) && source[index+1] == '*' {
				blockDepth++
				index++
			} else if value == '*' && index+1 < len(source) && source[index+1] == '/' {
				blockDepth--
				index++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				quote = 0
			}
			continue
		}
		if value == '/' && index+1 < len(source) {
			if source[index+1] == '/' {
				lineComment = true
				index++
				continue
			}
			if source[index+1] == '*' {
				blockDepth = 1
				index++
				continue
			}
		}
		if value == '"' || value == '\'' {
			quote = value
			continue
		}
		switch value {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return start, index + 1, true
			}
		}
	}
	return 0, 0, false
}

func (b *parseBuilder) currentContainerID() string {
	if len(b.container) == 0 {
		return ""
	}
	return b.parsed.Symbols[b.container[len(b.container)-1]].ID
}

func (b *parseBuilder) addImplicitLambdaParameter(node *sitter.Node, start, end int) {
	selectionEnd := start + 1
	if selectionEnd > end {
		selectionEnd = end
	}
	containerID, containerName := "", ""
	if len(b.container) > 0 {
		container := b.parsed.Symbols[b.container[len(b.container)-1]]
		containerID, containerName = container.ID, container.Name
	}
	symbol := Symbol{
		ID: SymbolID(b.doc.URI, start, KindParameter, "it"), Name: "it", FQN: "it",
		Kind: KindParameter, Language: b.parsed.Language, URI: b.doc.URI,
		Range: b.doc.Range(start, end), SelectionRange: b.doc.Range(start, selectionEnd),
		StartByte: start, EndByte: end, NameStartByte: start, NameEndByte: selectionEnd,
		ScopeStartByte: start, ScopeEndByte: end, ContainerID: containerID, ContainerName: containerName,
		Package: b.parsed.Package, Signature: "it",
	}
	b.parsed.Symbols = append(b.parsed.Symbols, symbol)
	b.selectionBytes[[2]int{start, selectionEnd}] = true
	_ = node
}

func (b *parseBuilder) addJavaLambdaParameters(node *sitter.Node, start, end int) {
	parameters := b.fieldNode(node, "parameters")
	if parameters == nil || parameters.Kind() == "formal_parameters" {
		return // Typed parameters are handled by the normal declaration walk.
	}
	var identifiers []*sitter.Node
	if parameters.Kind() == "identifier" {
		identifiers = append(identifiers, parameters)
	} else {
		collectChildrenOfKinds(parameters, map[string]bool{"identifier": true}, &identifiers, 2)
	}
	containerID, containerName := "", ""
	if len(b.container) > 0 {
		container := b.parsed.Symbols[b.container[len(b.container)-1]]
		containerID, containerName = container.ID, container.Name
	}
	for _, identifier := range identifiers {
		name := nodeText(b.source, identifier)
		nameStart, nameEnd := int(identifier.StartByte()), int(identifier.EndByte())
		if name == "" || b.selectionBytes[[2]int{nameStart, nameEnd}] {
			continue
		}
		fqn := name
		if containerName != "" {
			fqn = containerName + "." + name
		}
		b.parsed.Symbols = append(b.parsed.Symbols, Symbol{
			ID: SymbolID(b.doc.URI, nameStart, KindParameter, name), Name: name, FQN: fqn,
			Kind: KindParameter, Language: LanguageJava, URI: b.doc.URI,
			Range: b.doc.Range(nameStart, nameEnd), SelectionRange: b.doc.Range(nameStart, nameEnd),
			StartByte: nameStart, EndByte: nameEnd, NameStartByte: nameStart, NameEndByte: nameEnd,
			ScopeStartByte: start, ScopeEndByte: end, ContainerID: containerID, ContainerName: containerName,
			Package: b.parsed.Package, Signature: name,
		})
		b.selectionBytes[[2]int{nameStart, nameEnd}] = true
	}
}

func (b *parseBuilder) addKotlinBinaryConventionReference(node *sitter.Node) {
	operator := node.ChildByFieldName("operator")
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if operator == nil || left == nil || right == nil {
		return
	}
	name := map[string]string{
		"+": "plus", "-": "minus", "*": "times", "/": "div", "%": "rem",
		"==": "equals", "!=": "equals", "<": "compareTo", "<=": "compareTo", ">": "compareTo", ">=": "compareTo",
	}[nodeText(b.source, operator)]
	if name == "" {
		return
	}
	start, end := int(operator.StartByte()), int(operator.EndByte())
	b.parsed.References = append(b.parsed.References, Reference{
		Name: name, Qualifier: strings.TrimSpace(nodeText(b.source, left)), URI: b.doc.URI,
		Range: b.doc.Range(start, end), StartByte: start, EndByte: end,
		ContainerID: b.currentContainerID(), Role: RoleCall, Arity: 1,
		Arguments: []protocol.Range{b.doc.Range(int(right.StartByte()), int(right.EndByte()))},
	})
}

// The Kotlin grammar represents the suffix of `receiver.member()` as syntax
// punctuation inside a navigation expression rather than as a named
// identifier node. The ordinary identifier walk therefore sees the receiver
// and the synthetic invoke convention, but would otherwise lose `member`—the
// exact token definition, completion, references, and diagnostics need.
func (b *parseBuilder) addKotlinQualifiedCallReference(callee *sitter.Node, arguments []*sitter.Node) {
	if callee == nil || b.nodeKind(callee) != "navigation_expression" {
		return
	}
	start, end := b.nodeSpan(callee)
	for end > start && unicode.IsSpace(rune(b.source[end-1])) {
		end--
	}
	nameStart, nameEnd := end, end
	if nameEnd > start && b.source[nameEnd-1] == '`' {
		nameStart--
		for nameStart > start && b.source[nameStart-1] != '`' {
			nameStart--
		}
		if nameStart <= start || b.source[nameStart-1] != '`' {
			return
		}
		nameStart--
	} else {
		for nameStart > start {
			r, size := utf8.DecodeLastRune(b.source[start:nameStart])
			if r != '_' && r != '$' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				break
			}
			nameStart -= size
		}
	}
	if nameStart >= nameEnd {
		return
	}
	name := strings.Trim(string(b.source[nameStart:nameEnd]), "`")
	qualifier := strings.TrimSpace(string(b.source[start:nameStart]))
	qualifier = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(qualifier, "?."), "!!."), "."), "::"))
	if name == "" || qualifier == "" || b.selectionBytes[[2]int{nameStart, nameEnd}] {
		return
	}
	ranges := make([]protocol.Range, len(arguments))
	for index, argument := range arguments {
		if argument != nil {
			ranges[index] = b.doc.Range(int(argument.StartByte()), int(argument.EndByte()))
		}
	}
	b.parsed.References = append(b.parsed.References, Reference{
		Name: name, Qualifier: qualifier, URI: b.doc.URI,
		Range: b.doc.Range(nameStart, nameEnd), StartByte: nameStart, EndByte: nameEnd,
		ContainerID: b.currentContainerID(), Role: RoleCall, Arity: len(arguments), Arguments: ranges,
	})
	b.selectionBytes[[2]int{nameStart, nameEnd}] = true
}

func (b *parseBuilder) addKotlinConventionReferences(node *sitter.Node, parentKind string) {
	switch node.Kind() {
	case "binary_expression":
		b.addKotlinBinaryConventionReference(node)
	case "unary_expression":
		operator := childWithKind(node, "+", "-", "!", "++", "--")
		argument := node.NamedChild(0)
		if operator == nil || argument == nil {
			return
		}
		name := map[string]string{"+": "unaryPlus", "-": "unaryMinus", "!": "not", "++": "inc", "--": "dec"}[operator.Kind()]
		b.addKotlinConventionReference(name, nodeText(b.source, argument), operator, nil)
	case "index_expression":
		// An indexed assignment is represented by the surrounding assignment;
		// emit set there so the same bracket is not also reported as get.
		if parentKind == "assignment" && b.isCurrentAssignmentLeft(node) {
			return
		}
		children := directNamedChildren(node)
		if len(children) < 2 {
			return
		}
		b.addKotlinConventionReference("get", nodeText(b.source, children[0]), childWithKind(node, "["), children[1:])
	case "assignment":
		left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
		if left == nil || right == nil {
			return
		}
		operator := childWithKind(node, "=", "+=", "-=", "*=", "/=", "%=")
		if operator == nil {
			return
		}
		if left.Kind() == "index_expression" {
			children := directNamedChildren(left)
			if len(children) < 2 {
				return
			}
			arguments := append([]*sitter.Node(nil), children[1:]...)
			arguments = append(arguments, right)
			b.addKotlinConventionReference("set", nodeText(b.source, children[0]), childWithKind(left, "["), arguments)
			return
		}
		name := map[string]string{"+=": "plusAssign", "-=": "minusAssign", "*=": "timesAssign", "/=": "divAssign", "%=": "remAssign"}[operator.Kind()]
		if name != "" {
			b.addKotlinConventionReference(name, nodeText(b.source, left), operator, []*sitter.Node{right})
			// If no *Assign member is applicable Kotlin falls back to the
			// corresponding binary operator followed by assignment.
			fallback := map[string]string{"+=": "plus", "-=": "minus", "*=": "times", "/=": "div", "%=": "rem"}[operator.Kind()]
			b.addKotlinConventionReference(fallback, nodeText(b.source, left), operator, []*sitter.Node{right})
		}
	case "in_expression":
		children := directNamedChildren(node)
		operator := childWithKind(node, "in", "!in")
		if len(children) == 2 && operator != nil {
			// `a in b` is translated to b.contains(a).
			b.addKotlinConventionReference("contains", nodeText(b.source, children[1]), operator, children[:1])
		}
	case "range_expression":
		children := directNamedChildren(node)
		operator := childWithKind(node, "..", "..<")
		if len(children) == 2 && operator != nil {
			name := map[string]string{"..": "rangeTo", "..<": "rangeUntil"}[operator.Kind()]
			b.addKotlinConventionReference(name, nodeText(b.source, children[0]), operator, children[1:])
		}
	case "call_expression":
		children := directNamedChildren(node)
		if len(children) < 2 || children[len(children)-1].Kind() != "value_arguments" {
			return
		}
		callee, arguments := children[0], directNamedChildren(children[len(children)-1])
		b.addKotlinQualifiedCallReference(callee, arguments)
		anchor := childWithKind(children[len(children)-1], "(")
		b.addKotlinConventionReference("invoke", nodeText(b.source, callee), anchor, arguments)
	case "for_statement":
		children := directNamedChildren(node)
		operator := childWithKind(node, "in")
		if len(children) < 2 || operator == nil {
			return
		}
		iterable := children[len(children)-2]
		qualifier := nodeText(b.source, iterable)
		b.addKotlinConventionReference("iterator", qualifier, operator, nil)
		iteratorCall := strings.TrimSpace(qualifier) + ".iterator()"
		b.addKotlinConventionReference("hasNext", iteratorCall, operator, nil)
		b.addKotlinConventionReference("next", iteratorCall, operator, nil)
	case "multi_variable_declaration":
		if len(b.ancestorNodes) == 0 {
			return
		}
		property := b.ancestorNodes[len(b.ancestorNodes)-1]
		if property.Kind() != "property_declaration" {
			return
		}
		var initializer *sitter.Node
		for _, child := range directNamedChildren(property) {
			if child.StartByte() > node.EndByte() && child.Kind() != "property_delegate" {
				initializer = child
			}
		}
		if initializer == nil {
			return
		}
		for index, binding := range directNamedChildren(node) {
			b.addKotlinConventionReference("component"+integerString(index+1), nodeText(b.source, initializer), binding, nil)
		}
	case "property_delegate":
		delegate := node.NamedChild(0)
		anchor := childWithKind(node, "by")
		if delegate == nil || anchor == nil {
			return
		}
		qualifier := nodeText(b.source, delegate)
		b.addKotlinConventionReference("provideDelegate", qualifier, anchor, make([]*sitter.Node, 2))
		b.addKotlinConventionReference("getValue", qualifier, anchor, make([]*sitter.Node, 2))
		if len(b.ancestorNodes) > 0 && strings.Contains(" "+nodeText(b.source, b.ancestorNodes[len(b.ancestorNodes)-1])+" ", " var ") {
			b.addKotlinConventionReference("setValue", qualifier, anchor, make([]*sitter.Node, 3))
		}
	}
}

func (b *parseBuilder) addKotlinSmartCasts(node *sitter.Node) {
	condition := b.fieldNode(node, "condition")
	if condition == nil {
		return
	}
	if name, nonNullBranch, ok := kotlinNullCheck(nodeText(b.source, condition)); ok {
		branches := b.kotlinIfBranches(node, condition)
		if nonNullBranch < len(branches) {
			start, end := b.nodeSpan(branches[nonNullBranch])
			b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: "!", StartByte: start, EndByte: end})
		} else {
			nullBranch := 1 - nonNullBranch
			if nullBranch >= 0 && nullBranch < len(branches) && b.kotlinBranchAlwaysExits(branches[nullBranch]) {
				_, start := b.nodeSpan(node)
				if end := b.enclosingKotlinBlockEnd(); end > start {
					b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: "!", StartByte: start, EndByte: end})
				}
			}
		}
		return
	}
	b.addKotlinNullBranchCasts(node, condition)
	tests := make([]*sitter.Node, 0, 2)
	if b.nodeKind(condition) == "is_expression" {
		tests = append(tests, condition)
	} else {
		collectChildrenOfKinds(condition, map[string]bool{"is_expression": true}, &tests, 8)
	}
	branches := b.kotlinIfBranches(node, condition)
	conditionText := nodeText(b.source, condition)
	conditionConjunctive := !strings.Contains(conditionText, "||")
	for _, test := range tests {
		b.addKotlinTypeSmartCast(node, condition, test, branches, conditionConjunctive)
	}
}

func (b *parseBuilder) addKotlinTypeSmartCast(node, condition, test *sitter.Node, branches []*sitter.Node, conditionConjunctive bool) {
	left, right := b.fieldNode(test, "left"), b.fieldNode(test, "right")
	if left == nil || right == nil {
		return
	}
	name := strings.Trim(strings.TrimSpace(nodeText(b.source, left)), "`")
	if name == "" || strings.ContainsAny(name, ".()[]{} 	\r\n") {
		return
	}
	typ := normalizeSpace(nodeText(b.source, right))
	if typ == "" {
		return
	}
	_, leftEnd := b.nodeSpan(left)
	rightStart, _ := b.nodeSpan(right)
	negated := leftEnd <= rightStart && rightStart <= len(b.source) && strings.Contains(string(b.source[leftEnd:rightStart]), "!is")
	branch := 0
	if negated {
		branch = 1
	}
	if branch >= len(branches) {
		// A negative check which exits its enclosing block refines the value
		// for the remainder of that block: `if (x !is T) return; x.member()`.
		if negated && len(branches) == 1 && b.kotlinBranchAlwaysExits(branches[0]) {
			_, start := b.nodeSpan(node)
			if end := b.enclosingKotlinBlockEnd(); end > start {
				b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: typ, StartByte: start, EndByte: end})
			}
		}
	} else if conditionConjunctive {
		start, end := b.nodeSpan(branches[branch])
		b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: typ, StartByte: start, EndByte: end})
	}
	// A positive fact is available to the RHS of `&&`: that expression is
	// evaluated only when the type test succeeded. Stop before a later `||`,
	// whose RHS can run when the fact is false.
	if !negated {
		_, testEnd := b.nodeSpan(test)
		_, conditionEnd := b.nodeSpan(condition)
		if testEnd < conditionEnd {
			tail := string(b.source[testEnd:conditionEnd])
			leading := len(tail) - len(strings.TrimLeft(tail, " \t\r\n"))
			if strings.HasPrefix(tail[leading:], "&&") {
				start := testEnd + leading + 2
				end := conditionEnd
				if relative := strings.Index(string(b.source[start:end]), "||"); relative >= 0 {
					end = start + relative
				}
				if start < end {
					b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: typ, StartByte: start, EndByte: end})
				}
			}
		}
	}
}

// conditionOperand is one operand of a condition's top-level && / || chain,
// together with the operator that introduced it.
type conditionOperand struct {
	text       string
	start, end int
	precededBy string
}

// splitKotlinCondition breaks a condition into its top-level operands, ignoring
// operators nested in parentheses, string literals, or comments.
func splitKotlinCondition(source []byte, start, end int) []conditionOperand {
	if start < 0 || end > len(source) || start >= end {
		return nil
	}
	text := source[start:end]
	mask := kotlinCodeMask(text)
	operands := make([]conditionOperand, 0, 4)
	depth, operandStart, operator := 0, 0, ""
	for index := 0; index < len(text); index++ {
		if !mask[index] {
			continue
		}
		switch text[index] {
		case '(', '[':
			depth++
			continue
		case ')', ']':
			depth--
			continue
		}
		if depth != 0 || index+1 >= len(text) || !mask[index+1] {
			continue
		}
		pair := string(text[index : index+2])
		if pair != "&&" && pair != "||" {
			continue
		}
		operands = append(operands, conditionOperand{
			text: string(text[operandStart:index]), start: start + operandStart, end: start + index, precededBy: operator,
		})
		operator = pair
		index++
		operandStart = index + 1
	}
	operands = append(operands, conditionOperand{
		text: string(text[operandStart:]), start: start + operandStart, end: end, precededBy: operator,
	})
	return operands
}

// addKotlinNullShortCircuitCasts records the non-null facts that hold only for
// part of a condition. In `x == null || x.member` the right operand runs only
// when x is non-null, and `x != null && x.member` is the same guarantee written
// the other way round; both are how Kotlin code ordinarily guards a nullable.
// Only a condition that was nothing but a null check used to be recognised, so
// neither idiom resolved its members at all.
// addKotlinNullShortCircuitCasts records the non-null facts that hold only for
// part of a boolean expression. In `x == null || x.member` the right operand
// runs only when x is non-null, and `x != null && x.member` is the same
// guarantee written the other way round; both are how Kotlin code ordinarily
// guards a nullable. Only an expression that was nothing but a null check used
// to be recognised, so neither idiom resolved its members at all.
func (b *parseBuilder) addKotlinNullShortCircuitCasts(node *sitter.Node) {
	start, end := b.nodeSpan(node)
	if start < 0 || end > len(b.source) || start >= end {
		return
	}
	span := b.source[start:end]
	if !bytes.Contains(span, []byte("&&")) && !bytes.Contains(span, []byte("||")) {
		return
	}
	operands := splitKotlinCondition(b.source, start, end)
	for index, operand := range operands {
		name, nonNullBranch, ok := kotlinNullCheck(operand.text)
		if !ok || index+1 >= len(operands) {
			continue
		}
		following := operands[index+1]
		if following.precededBy != "||" && following.precededBy != "&&" {
			continue
		}
		// `x == null || rest` and `x != null && rest` both leave the rest
		// reachable only when x is non-null.
		if following.precededBy == "||" && nonNullBranch != 1 || following.precededBy == "&&" && nonNullBranch != 0 {
			continue
		}
		limit := end
		if following.precededBy == "&&" {
			// A later `||` restores reachability when the fact is false.
			for _, later := range operands[index+1:] {
				if later.precededBy == "||" {
					limit = later.start
					break
				}
			}
		}
		if following.start < limit {
			b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: "!", StartByte: following.start, EndByte: limit})
		}
	}
}

// addKotlinNullBranchCasts records the non-null facts a compound if-condition
// establishes for a whole branch: the fact holds there only when no other
// operand could have made the condition true without it.
func (b *parseBuilder) addKotlinNullBranchCasts(node, condition *sitter.Node) {
	conditionStart, conditionEnd := b.nodeSpan(condition)
	operands := splitKotlinCondition(b.source, conditionStart, conditionEnd)
	if len(operands) < 2 {
		return
	}
	disjunctive, conjunctive := false, false
	for _, operand := range operands {
		switch operand.precededBy {
		case "||":
			disjunctive = true
		case "&&":
			conjunctive = true
		}
	}
	branches := b.kotlinIfBranches(node, condition)
	for _, operand := range operands {
		name, nonNullBranch, ok := kotlinNullCheck(operand.text)
		if !ok {
			continue
		}
		branch := -1
		if nonNullBranch == 0 && conjunctive && !disjunctive {
			branch = 0
		} else if nonNullBranch == 1 && disjunctive && !conjunctive {
			branch = 1
		}
		if branch >= 0 && branch < len(branches) {
			start, end := b.nodeSpan(branches[branch])
			b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: "!", StartByte: start, EndByte: end})
		}
	}
}

func kotlinNullCheck(value string) (name string, nonNullBranch int, ok bool) {
	value = strings.TrimSpace(value)
	for len(value) >= 2 && value[0] == '(' && value[len(value)-1] == ')' {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	operator := "!="
	index := strings.Index(value, operator)
	if index < 0 {
		operator = "=="
		index = strings.Index(value, operator)
	}
	if index < 0 {
		return "", 0, false
	}
	left, right := strings.TrimSpace(value[:index]), strings.TrimSpace(value[index+len(operator):])
	if left == "null" {
		left, right = right, left
	}
	left = strings.Trim(left, "`")
	if right != "null" || left == "" || strings.ContainsAny(left, ".()[]{} \t\r\n") {
		return "", 0, false
	}
	if operator == "==" {
		return left, 1, true
	}
	return left, 0, true
}

func (b *parseBuilder) kotlinIfBranches(node, condition *sitter.Node) []*sitter.Node {
	_, conditionEnd := b.nodeSpan(condition)
	branches := make([]*sitter.Node, 0, 2)
	for _, child := range b.namedChildren(node) {
		childStart, _ := b.nodeSpan(child)
		if childStart >= conditionEnd && child.Id() != condition.Id() {
			branches = append(branches, child)
		}
	}
	return branches
}

func (b *parseBuilder) addKotlinWhenSmartCasts(node *sitter.Node) {
	var subject *sitter.Node
	for _, child := range b.namedChildren(node) {
		if b.nodeKind(child) == "when_subject" {
			subject = child
			break
		}
	}
	identifier := b.firstIdentifier(subject)
	if identifier == nil {
		return
	}
	name := strings.Trim(strings.TrimSpace(nodeText(b.source, identifier)), "`")
	if name == "" {
		return
	}
	// Only a stable simple name can be refined. A subject such as `obj.value`
	// must not accidentally refine `obj` merely because it is the first token.
	subjectText := strings.TrimSpace(nodeText(b.source, subject))
	subjectText = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(subjectText, "("), ")"))
	if subjectText != name && !strings.HasPrefix(subjectText, "val "+name+" =") {
		return
	}
	for _, entry := range b.namedChildren(node) {
		if b.nodeKind(entry) != "when_entry" {
			continue
		}
		condition := b.fieldNode(entry, "condition")
		if condition == nil || b.nodeKind(condition) != "type_test" || strings.Contains(nodeText(b.source, condition), "!is") {
			continue
		}
		typeNode := condition.NamedChild(0)
		if typeNode == nil {
			continue
		}
		typ := normalizeSpace(nodeText(b.source, typeNode))
		if typ == "" {
			continue
		}
		var body *sitter.Node
		for _, child := range b.namedChildren(entry) {
			if child.Id() != condition.Id() {
				body = child
			}
		}
		if body == nil {
			continue
		}
		start, end := b.nodeSpan(body)
		b.parsed.SmartCasts = append(b.parsed.SmartCasts, SmartCast{Name: name, Type: typ, StartByte: start, EndByte: end})
	}
}

func (b *parseBuilder) kotlinBranchAlwaysExits(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	kind := b.nodeKind(node)
	if kind == "jump_expression" || kind == "return_expression" || kind == "throw_expression" {
		text := strings.TrimSpace(nodeText(b.source, node))
		return text == "return" || strings.HasPrefix(text, "return ") || strings.HasPrefix(text, "return\n") || strings.HasPrefix(text, "throw ") || strings.HasPrefix(text, "throw\n")
	}
	children := b.namedChildren(node)
	if len(children) == 0 {
		return false
	}
	return b.kotlinBranchAlwaysExits(children[len(children)-1])
}

func (b *parseBuilder) enclosingKotlinBlockEnd() int {
	for index := len(b.ancestorNodes) - 1; index >= 0; index-- {
		switch b.nodeKind(b.ancestorNodes[index]) {
		case "block", "function_body":
			_, end := b.nodeSpan(b.ancestorNodes[index])
			return end
		}
	}
	return 0
}

func (b *parseBuilder) descendantOfKinds(node *sitter.Node, kinds map[string]bool, depth int) *sitter.Node {
	if node == nil || depth < 0 {
		return nil
	}
	for _, child := range b.namedChildren(node) {
		if kinds[b.nodeKind(child)] {
			return child
		}
		if found := b.descendantOfKinds(child, kinds, depth-1); found != nil {
			return found
		}
	}
	return nil
}

func (b *parseBuilder) addKotlinConventionReference(name, qualifier string, anchor *sitter.Node, arguments []*sitter.Node) {
	if name == "" || anchor == nil {
		return
	}
	start, end := int(anchor.StartByte()), int(anchor.EndByte())
	ranges := make([]protocol.Range, len(arguments))
	for index, argument := range arguments {
		if argument != nil {
			ranges[index] = b.doc.Range(int(argument.StartByte()), int(argument.EndByte()))
		}
	}
	b.parsed.References = append(b.parsed.References, Reference{
		Name: name, Qualifier: strings.TrimSpace(qualifier), URI: b.doc.URI,
		Range: b.doc.Range(start, end), StartByte: start, EndByte: end,
		ContainerID: b.currentContainerID(), Role: RoleCall, Arity: len(arguments), Arguments: ranges,
	})
}

func (b *parseBuilder) isCurrentAssignmentLeft(node *sitter.Node) bool {
	if len(b.ancestorNodes) == 0 {
		return false
	}
	assignment := b.ancestorNodes[len(b.ancestorNodes)-1]
	left := assignment.ChildByFieldName("left")
	return left != nil && left.StartByte() == node.StartByte() && left.EndByte() == node.EndByte()
}

func childWithKind(node *sitter.Node, kinds ...string) *sitter.Node {
	if node == nil {
		return nil
	}
	for index, count := uint(0), node.ChildCount(); index < count; index++ {
		child := node.Child(index)
		for _, kind := range kinds {
			if child.Kind() == kind {
				return child
			}
		}
	}
	return nil
}

func integerString(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

func (b *parseBuilder) fieldNode(node *sitter.Node, field string) *sitter.Node {
	if id := b.fieldIDs[field]; id != 0 {
		if record, _ := b.syntax.record(node); record != nil {
			for index := record.firstChild; index != noSyntaxNode; index = b.syntax.nodes[index].nextSibling {
				child := &b.syntax.nodes[index]
				if child.field == id {
					return &child.node
				}
			}
			return nil
		}
		return node.ChildByFieldId(id)
	}
	return nil
}

func (b *parseBuilder) finish() {
	if b.parsed.Language == LanguageKotlin {
		b.addKotlinSimpleStringTemplateReferences()
	}
	b.addDocumentationReferences()
	sort.SliceStable(b.parsed.Symbols, func(left, right int) bool {
		return b.parsed.Symbols[left].StartByte < b.parsed.Symbols[right].StartByte
	})
	sort.SliceStable(b.parsed.References, func(left, right int) bool {
		return b.parsed.References[left].StartByte < b.parsed.References[right].StartByte
	})
	b.addLineFolds()
	sort.SliceStable(b.parsed.Folds, func(i, j int) bool {
		if b.parsed.Folds[i].StartLine == b.parsed.Folds[j].StartLine {
			return b.parsed.Folds[i].EndLine < b.parsed.Folds[j].EndLine
		}
		return b.parsed.Folds[i].StartLine < b.parsed.Folds[j].StartLine
	})
	b.buildSemanticTokens()
}

// The Kotlin grammar exposes ${expression} as normal expression nodes, but a
// simple $name template is string content rather than a simple_identifier.
// Synthesize the missing read reference from lexical string spans while
// preserving Kotlin's escaped-dollar behavior in ordinary strings.
func (b *parseBuilder) addKotlinSimpleStringTemplateReferences() {
	existing := make(map[[2]int]bool, len(b.parsed.References))
	for _, reference := range b.parsed.References {
		existing[[2]int{reference.StartByte, reference.EndByte}] = true
	}
	for _, token := range b.lexicalTokens {
		if token.Type != 18 || token.StartByte < 0 || token.EndByte > len(b.source) || token.EndByte <= token.StartByte {
			continue
		}
		raw := token.StartByte+2 < token.EndByte && bytes.Equal(b.source[token.StartByte:token.StartByte+3], []byte(`"""`))
		for at := token.StartByte; at < token.EndByte; at++ {
			if b.source[at] != '$' || at+1 >= token.EndByte || b.source[at+1] == '{' {
				continue
			}
			if !raw {
				backslashes := 0
				for previous := at - 1; previous >= token.StartByte && b.source[previous] == '\\'; previous-- {
					backslashes++
				}
				if backslashes%2 == 1 {
					continue
				}
			}
			start := at + 1
			first, size := utf8.DecodeRune(b.source[start:token.EndByte])
			if first == utf8.RuneError && size == 1 || !(unicode.IsLetter(first) || first == '_') {
				continue
			}
			end := start + size
			for end < token.EndByte {
				r, runeSize := utf8.DecodeRune(b.source[end:token.EndByte])
				if r == utf8.RuneError && runeSize == 1 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') {
					break
				}
				end += runeSize
			}
			if existing[[2]int{start, end}] {
				continue
			}
			b.parsed.References = append(b.parsed.References, Reference{
				Name: string(b.source[start:end]), URI: b.doc.URI, Range: b.doc.Range(start, end),
				StartByte: start, EndByte: end, ContainerID: b.containerAt(start), Role: RoleRead, Arity: -1,
			})
			existing[[2]int{start, end}] = true
			at = end - 1
		}
	}
}

func (b *parseBuilder) containerAt(offset int) string {
	bestID, bestWidth := "", int(^uint(0)>>1)
	for _, symbol := range b.parsed.Symbols {
		if !isContainerKind(symbol.Kind) || offset < symbol.StartByte || offset > symbol.EndByte {
			continue
		}
		if width := symbol.EndByte - symbol.StartByte; width < bestWidth {
			bestID, bestWidth = symbol.ID, width
		}
	}
	return bestID
}

func (b *parseBuilder) addDocumentationReferences() {
	for _, token := range b.lexicalTokens {
		if token.Type != 17 || token.StartByte < 0 || token.EndByte > len(b.source) || token.StartByte >= token.EndByte {
			continue
		}
		comment := string(b.source[token.StartByte:token.EndByte])
		if b.parsed.Language == LanguageJava {
			for _, marker := range []string{"{@link", "{@linkplain", "@see"} {
				for search := 0; search < len(comment); {
					relative := strings.Index(comment[search:], marker)
					if relative < 0 {
						break
					}
					start := search + relative + len(marker)
					for start < len(comment) && unicode.IsSpace(rune(comment[start])) {
						start++
					}
					end := documentationTargetEnd(comment, start)
					b.addDocumentationTarget(token.StartByte+start, token.StartByte+end)
					search = max(end, start+1)
				}
			}
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(comment), "/**") {
			continue
		}
		for search := 0; search < len(comment); {
			open := strings.IndexByte(comment[search:], '[')
			if open < 0 {
				break
			}
			open += search
			close := strings.IndexByte(comment[open+1:], ']')
			if close < 0 {
				break
			}
			close += open + 1
			start, end := open+1, close
			if start < end && documentationTargetEnd(comment, start) == end {
				b.addDocumentationTarget(token.StartByte+start, token.StartByte+end)
			}
			search = close + 1
		}
	}
}

func documentationTargetEnd(value string, start int) int {
	end := start
	for end < len(value) {
		r, size := utf8.DecodeRuneInString(value[end:])
		if r == utf8.RuneError && size == 1 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$' || r == '.' || r == '#' || r == '`') {
			break
		}
		end += size
	}
	return end
}

func (b *parseBuilder) addDocumentationTarget(start, end int) {
	if start < 0 || end <= start || end > len(b.source) {
		return
	}
	raw := strings.Trim(string(b.source[start:end]), "`")
	if raw == "" || strings.HasPrefix(raw, "http") {
		return
	}
	if hash := strings.LastIndexByte(raw, '#'); hash >= 0 {
		owner := strings.Trim(raw[:hash], "`")
		member := strings.Trim(raw[hash+1:], "`")
		if owner != "" {
			b.addDocumentationNamedTarget(start, start+hash, owner, RoleType)
		}
		if member != "" {
			memberStart := start + hash + 1
			b.parsed.References = append(b.parsed.References, Reference{Name: member, Qualifier: owner, URI: b.doc.URI, Range: b.doc.Range(memberStart, end), StartByte: memberStart, EndByte: end, ContainerID: b.currentContainerID(), Role: RoleRead, Arity: -1})
		}
		return
	}
	b.addDocumentationNamedTarget(start, end, raw, RoleType)
}

func (b *parseBuilder) addDocumentationNamedTarget(start, end int, raw string, role ReferenceRole) {
	name, qualifier := raw, ""
	if dot := strings.LastIndexByte(raw, '.'); dot >= 0 {
		qualifier, name = raw[:dot], raw[dot+1:]
		start += dot + 1
	}
	if name != "" {
		b.parsed.References = append(b.parsed.References, Reference{Name: name, Qualifier: qualifier, URI: b.doc.URI, Range: b.doc.Range(start, end), StartByte: start, EndByte: end, ContainerID: b.currentContainerID(), Role: role, Arity: -1})
	}
}

func (b *parseBuilder) addLineFolds() {
	lines := strings.Split(string(b.source), "\n")
	add := func(start, end int, kind, collapsed string) {
		if end <= start {
			return
		}
		for _, existing := range b.parsed.Folds {
			if existing.StartLine == start && existing.EndLine == end && existing.Kind == kind {
				return
			}
		}
		b.parsed.Folds = append(b.parsed.Folds, protocol.FoldingRange{StartLine: start, EndLine: end, Kind: kind, CollapsedText: collapsed})
	}
	firstImport, lastImport := -1, -1
	commentStart := -1
	regions := []int{}
	for lineNumber, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "import ") {
			if firstImport < 0 {
				firstImport = lineNumber
			}
			lastImport = lineNumber
		}
		lineComment := strings.HasPrefix(trim, "//") && !strings.HasPrefix(trim, "//region") && !strings.HasPrefix(trim, "// region") && !strings.HasPrefix(trim, "//endregion") && !strings.HasPrefix(trim, "// endregion")
		if lineComment && commentStart < 0 {
			commentStart = lineNumber
		}
		if !lineComment && commentStart >= 0 {
			add(commentStart, lineNumber-1, "comment", "")
			commentStart = -1
		}
		lower := strings.ToLower(trim)
		if strings.HasPrefix(lower, "//region") || strings.HasPrefix(lower, "// region") {
			regions = append(regions, lineNumber)
		}
		if (strings.HasPrefix(lower, "//endregion") || strings.HasPrefix(lower, "// endregion")) && len(regions) > 0 {
			start := regions[len(regions)-1]
			regions = regions[:len(regions)-1]
			label := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(lines[start]), "//"), "region"))
			add(start, lineNumber, "region", label)
		}
	}
	if commentStart >= 0 {
		add(commentStart, len(lines)-1, "comment", "")
	}
	if firstImport >= 0 {
		add(firstImport, lastImport, "imports", "")
	}
}

func (b *parseBuilder) buildSemanticTokens() {
	symbolTokens := make([]Token, 0, len(b.parsed.Symbols))
	for _, s := range b.parsed.Symbols {
		typ := semanticTypeForKind(s.Kind)
		mods := SemanticModifierDeclaration
		if contains(s.Modifiers, "static") || contains(s.Modifiers, "companion") {
			mods |= SemanticModifierStatic
		}
		if contains(s.Modifiers, "abstract") {
			mods |= SemanticModifierAbstract
		}
		if contains(s.Modifiers, "final") || contains(s.Modifiers, "const") || contains(s.Modifiers, "val") {
			mods |= SemanticModifierReadonly
		}
		if contains(s.Modifiers, "suspend") {
			mods |= SemanticModifierAsync
		}
		if s.Deprecated {
			mods |= SemanticModifierDeprecated
		}
		symbolTokens = append(symbolTokens, Token{Range: s.SelectionRange, StartByte: s.NameStartByte, EndByte: s.NameEndByte, Type: typ, Modifiers: mods})
	}
	referenceTokens := make([]Token, 0, len(b.parsed.References))
	for _, r := range b.parsed.References {
		typ := uint32(8)
		if r.Role == RoleType {
			typ = 1
		}
		if r.Role == RoleCall {
			typ = 13
		}
		referenceTokens = append(referenceTokens, Token{Range: r.Range, StartByte: r.StartByte, EndByte: r.EndByte, Type: typ})
	}
	b.parsed.Tokens = mergeSortedTokens(symbolTokens, referenceTokens)
	b.lexicalOccupied = append([]Token(nil), b.parsed.Tokens...)
	semanticCount := len(b.parsed.Tokens)
	for _, token := range b.lexicalTokens {
		b.addLexicalSpan(token.StartByte, token.EndByte, token.Type, token.Modifiers)
	}
	b.parsed.Tokens = mergeSortedTokens(b.parsed.Tokens[:semanticCount], b.parsed.Tokens[semanticCount:])
}

func mergeSortedTokens(left, right []Token) []Token {
	out := make([]Token, 0, len(left)+len(right))
	for len(left) > 0 && len(right) > 0 {
		if left[0].StartByte < right[0].StartByte || left[0].StartByte == right[0].StartByte && left[0].EndByte <= right[0].EndByte {
			out = append(out, left[0])
			left = left[1:]
		} else {
			out = append(out, right[0])
			right = right[1:]
		}
	}
	out = append(out, left...)
	out = append(out, right...)
	return out
}

func qualifiedName(source []byte, n *sitter.Node) string {
	text := nodeText(source, n)
	text = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "package"), "import"))
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSuffix(text, ".*")
	if i := strings.Index(text, " as "); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(text)
}
func nodeText(source []byte, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	a, z := int(n.StartByte()), int(n.EndByte())
	if a < 0 || z < a || z > len(source) {
		return ""
	}
	return string(source[a:z])
}
func normalizeSpace(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	if len(fields) == 1 {
		return fields[0]
	}
	return strings.Join(fields, " ")
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func unique(xs []string) []string {
	seen := map[string]bool{}
	out := xs[:0]
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
func firstIdentifier(n *sitter.Node) *sitter.Node {
	stack := []*sitter.Node{n}
	for visited := 0; len(stack) > 0 && visited < 100_000; visited++ {
		candidate := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if candidate == nil {
			continue
		}
		if isIdentifierKind(candidate.Kind()) {
			return candidate
		}
		count := candidate.NamedChildCount()
		if uint(len(stack))+count > 100_000 {
			return nil
		}
		for index := int(count) - 1; index >= 0; index-- {
			stack = append(stack, candidate.NamedChild(uint(index)))
		}
	}
	return nil
}

func directNamedChildren(n *sitter.Node) []*sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	if n.NamedChildCount() > 1_000_000 {
		return nil
	}
	cursor := n.Walk()
	defer cursor.Close()
	children := make([]*sitter.Node, 0, n.NamedChildCount())
	if !cursor.GotoFirstChild() {
		return children
	}
	for {
		child := cursor.Node()
		if child.IsNamed() {
			copy := *child
			children = append(children, &copy)
		}
		if !cursor.GotoNextSibling() {
			break
		}
	}
	return children
}
func collectChildrenOfKinds(n *sitter.Node, kinds map[string]bool, out *[]*sitter.Node, depth int) {
	if n == nil || depth < 0 {
		return
	}
	for i, count := uint(0), n.NamedChildCount(); i < count; i++ {
		c := n.NamedChild(i)
		if kinds[c.Kind()] {
			*out = append(*out, c)
		} else {
			collectChildrenOfKinds(c, kinds, out, depth-1)
		}
	}
}

func hasNamedDescendant(node *sitter.Node, kind string, depth int) bool {
	if node == nil || depth < 0 {
		return false
	}
	for index, count := uint(0), node.NamedChildCount(); index < count; index++ {
		child := node.NamedChild(index)
		if child.Kind() == kind || hasNamedDescendant(child, kind, depth-1) {
			return true
		}
	}
	return false
}
func isIdentifierKind(k string) bool {
	return k == "identifier" || k == "type_identifier" || k == "simple_identifier"
}
func inPackageOrImport(k string) bool {
	return k == "package_header" || k == "package_declaration" || k == "import" || k == "import_header" || k == "import_declaration"
}
func isContainerKind(k SymbolKind) bool {
	return IsTypeKind(k) || k == KindFunction || k == KindMethod || k == KindConstructor
}
func isTypeNode(k string) bool {
	return k == "type" || k == "user_type" || k == "nullable_type" || k == "type_identifier" || k == "generic_type" || k == "integral_type" || k == "floating_point_type" || k == "void_type" || k == "scoped_type_identifier" || k == "function_type" || k == "parenthesized_type"
}
func roleFor(parent string) ReferenceRole {
	switch parent {
	case "user_type", "type_identifier", "generic_type", "superclass", "super_interfaces", "delegation_specifier":
		return RoleType
	case "assignment", "variable_declarator":
		return RoleWrite
	default:
		return RoleRead
	}
}

func roleForAncestors(parent string, ancestors []string) ReferenceRole {
	role := roleFor(parent)
	if role != RoleRead {
		return role
	}
	for depth, index := 0, len(ancestors)-1; index >= 0 && depth < 4; depth, index = depth+1, index-1 {
		switch ancestors[index] {
		case "user_type", "generic_type", "scoped_type_identifier", "superclass", "super_interfaces", "delegation_specifier":
			return RoleType
		}
	}
	return role
}

func descendantOfKinds(node *sitter.Node, kinds map[string]bool, depth int) *sitter.Node {
	if node == nil || depth < 0 {
		return nil
	}
	for i, count := uint(0), node.NamedChildCount(); i < count; i++ {
		child := node.NamedChild(i)
		if kinds[child.Kind()] {
			return child
		}
		if found := descendantOfKinds(child, kinds, depth-1); found != nil {
			return found
		}
	}
	return nil
}
func foldingKind(k string) string {
	switch k {
	case "block_comment", "line_comment", "multiline_comment":
		return "comment"
	case "import_list":
		return "imports"
	case "class_body", "function_body", "block", "enum_body", "switch_block", "constructor_body", "lambda_literal":
		return "region"
	default:
		return ""
	}
}
func kotlinClassKind(src []byte, n *sitter.Node) SymbolKind {
	text := nodeText(src, n)
	head := text
	if i := strings.IndexByte(text, '{'); i >= 0 {
		head = text[:i]
	}
	// Some Kotlin grammar revisions attach `annotation`/`enum` as a sibling
	// modifier rather than including it in class_declaration. Include only the
	// immediately preceding declaration fragment so an earlier declaration
	// cannot change this symbol's kind.
	switch {
	case strings.Contains(head, "interface"):
		return KindInterface
	case strings.Contains(head, "enum class") || kotlinDeclarationPrefixHasModifier(src, int(n.StartByte()), "enum"):
		return KindEnum
	case strings.Contains(head, "annotation class") || kotlinDeclarationPrefixHasModifier(src, int(n.StartByte()), "annotation"):
		return KindAnnotation
	default:
		return KindClass
	}
}
func extractTypeNames(src []byte, n *sitter.Node) []string {
	var out []string
	stack := []*sitter.Node{n}
	for visited := 0; len(stack) > 0 && visited < 100_000; visited++ {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if x == nil {
			continue
		}
		if x.Kind() == "user_type" || x.Kind() == "type_identifier" || x.Kind() == "scoped_type_identifier" {
			v := normalizeSpace(nodeText(src, x))
			if i := strings.IndexByte(v, '('); i >= 0 {
				v = v[:i]
			}
			if i := strings.IndexByte(v, '<'); i >= 0 {
				v = v[:i]
			}
			out = append(out, strings.TrimSpace(v))
			continue
		}
		count := x.NamedChildCount()
		if uint(len(stack))+count > 100_000 {
			return unique(out)
		}
		for index := int(count) - 1; index >= 0; index-- {
			stack = append(stack, x.NamedChild(uint(index)))
		}
	}
	return unique(out)
}
func cleanDoc(s string) string {
	s = strings.TrimPrefix(s, "/**")
	s = strings.TrimSuffix(s, "*/")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), "*"))
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
func semanticTypeForKind(k SymbolKind) uint32 {
	return k.SemanticToken()
}
