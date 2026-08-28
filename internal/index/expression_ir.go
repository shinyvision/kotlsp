package index

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/lexical"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

type expressionKind uint8

const (
	expressionUnknown expressionKind = iota
	expressionLiteral
	expressionName
	expressionMember
	expressionCall
	expressionConstructor
	expressionUnary
	expressionBinary
	expressionCast
	expressionLambda
	expressionCallableReference
	expressionConditional
	expressionBlock
)

type expressionIR struct {
	Kind     expressionKind
	Text     string
	Operator string
	Children []expressionIR
}

type inferenceConfidence uint8

const (
	inferenceUnknown inferenceConfidence = iota
	inferenceConservative
	inferenceExact
)

type inferredExpressionType struct {
	Type       string
	Confidence inferenceConfidence
	Expression expressionIR
}

// ExpressionEvidence is the stable, deliberately small semantic surface used
// by editor features. Consumers share one expression shape/type decision and
// can abstain without re-parsing source with feature-specific regexes.
type ExpressionEvidence struct {
	Type            string
	Shape           string
	Exact           bool
	Constant        bool
	RefactoringSafe bool
}

func (i *Index) ExpressionEvidence(uri protocol.URI, source string, at int) ExpressionEvidence {
	i.mu.RLock()
	defer i.mu.RUnlock()
	file := i.files[uri]
	if file == nil {
		return ExpressionEvidence{}
	}
	result := i.inferExpressionResultLocked(file, source, at)
	return ExpressionEvidence{
		Type: result.Type, Shape: result.Expression.Kind.String(),
		Exact: result.Confidence == inferenceExact, Constant: expressionIRConstant(result.Expression, file.Language),
		RefactoringSafe: expressionIRRefactoringSafe(result.Expression),
	}
}

func (kind expressionKind) String() string {
	switch kind {
	case expressionLiteral:
		return "literal"
	case expressionName:
		return "name"
	case expressionMember:
		return "member"
	case expressionCall:
		return "call"
	case expressionConstructor:
		return "constructor"
	case expressionUnary:
		return "unary"
	case expressionBinary:
		return "binary"
	case expressionCast:
		return "cast"
	case expressionLambda:
		return "lambda"
	case expressionCallableReference:
		return "callable-reference"
	case expressionConditional:
		return "conditional"
	case expressionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// expressionIRConstant reports whether an expression is a compile-time
// constant tree: literals combined by operators which can neither trap nor
// dispatch to user code. Division and remainder are excluded because a zero
// divisor makes the constant a runtime failure.
func expressionIRConstant(expression expressionIR, language analysis.Language) bool {
	switch expression.Kind {
	case expressionLiteral:
		text := strings.TrimSpace(expression.Text)
		if language == analysis.LanguageKotlin && strings.Contains(text, "$") {
			return false
		}
		return text != "null"
	case expressionUnary:
		return (expression.Operator == "+" || expression.Operator == "-" || expression.Operator == "!") && len(expression.Children) == 1 && expressionIRConstant(expression.Children[0], language)
	case expressionBinary:
		if len(expression.Children) != 2 || !operatorTypable(expression.Operator) || expression.Operator == "/" || expression.Operator == "%" {
			return false
		}
		return expressionIRConstant(expression.Children[0], language) && expressionIRConstant(expression.Children[1], language)
	default:
		return false
	}
}

func expressionIRRefactoringSafe(expression expressionIR) bool {
	switch expression.Kind {
	case expressionLiteral, expressionName:
		return true
	case expressionUnary:
		return (expression.Operator == "+" || expression.Operator == "-" || expression.Operator == "!") && len(expression.Children) == 1 && expressionIRRefactoringSafe(expression.Children[0])
	case expressionBinary:
		if expression.Operator == "/" || expression.Operator == "%" || expression.Operator == "?:" {
			return false
		}
		for _, child := range expression.Children {
			if !expressionIRRefactoringSafe(child) {
				return false
			}
		}
		return len(expression.Children) == 2
	default:
		return false
	}
}

func parseExpressionIR(source string, language analysis.Language) expressionIR {
	return parseExpressionIRDepth(source, language, 0)
}

func parseExpressionIRDepth(source string, language analysis.Language, depth int) expressionIR {
	source = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(source), ";"))
	if source == "" || depth > 256 {
		return expressionIR{}
	}
	kotlin := language == analysis.LanguageKotlin
	tokens, complete := lexical.TokenizeBounded(source, kotlin, 100_000)
	if !complete {
		return expressionIR{Text: source}
	}
	if len(tokens) == 0 {
		return expressionIR{Text: source}
	}
	if tokens[0].Text == "(" && matchingIRDelimiter(tokens, 0, "(", ")") == len(tokens)-1 {
		// A fully parenthesized expression has the shape of its content.
		return parseExpressionIRDepth(source[tokens[0].End:tokens[len(tokens)-1].Start], language, depth+1)
	}
	root := expressionIR{Text: source}
	if len(tokens) == 1 {
		switch tokens[0].Kind {
		case lexical.String, lexical.Character, lexical.Number:
			root.Kind = expressionLiteral
		case lexical.Identifier:
			if tokens[0].Text == "true" || tokens[0].Text == "false" || tokens[0].Text == "null" {
				root.Kind = expressionLiteral
			} else {
				root.Kind = expressionName
			}
		}
		return root
	}
	first := strings.Trim(tokens[0].Text, "`")
	switch first {
	case "if", "when", "try", "switch":
		root.Kind = expressionConditional
		root.Children = expressionBranchIR(source, language, depth+1)
		return root
	case "new":
		root.Kind = expressionConstructor
		return root
	case "by":
		root.Kind = expressionUnary
		root.Operator = "by"
		root.Children = []expressionIR{parseExpressionIRDepth(strings.TrimSpace(source[tokens[0].End:]), language, depth+1)}
		return root
	}
	if tokens[0].Text == "+" || tokens[0].Text == "-" || tokens[0].Text == "!" {
		root.Kind = expressionUnary
		root.Operator = tokens[0].Text
		root.Children = []expressionIR{parseExpressionIRDepth(strings.TrimSpace(source[tokens[0].End:]), language, depth+1)}
		return root
	}
	if tokens[0].Text == "{" && tokens[len(tokens)-1].Text == "}" {
		root.Kind = expressionLambda
		body := strings.TrimSpace(source[tokens[0].End:tokens[len(tokens)-1].Start])
		if arrow := topLevelIRToken(tokens[1:len(tokens)-1], "->"); arrow >= 0 {
			body = strings.TrimSpace(source[tokens[arrow+1].End:tokens[len(tokens)-1].Start])
		}
		root.Children = []expressionIR{parseExpressionIRDepth(lastExpressionSegment(body, kotlin), language, depth+1)}
		return root
	}
	for _, token := range tokens {
		if token.Text == "::" {
			root.Kind, root.Operator = expressionCallableReference, token.Text
			return root
		}
	}
	if index := topLevelIRToken(tokens, "as"); index >= 0 && index+1 < len(tokens) && tokens[index+1].Text == "?" {
		root.Kind, root.Operator = expressionCast, "as?"
		root.Children = []expressionIR{
			parseExpressionIRDepth(source[:tokens[index].Start], language, depth+1),
			parseExpressionIRDepth(source[tokens[index+1].End:], language, depth+1),
		}
		return root
	}
	if index := topLevelIRToken(tokens, "!"); index >= 0 && index+1 < len(tokens) && tokens[index+1].Text == "is" {
		root.Kind, root.Operator = expressionCast, "!is"
		root.Children = []expressionIR{
			parseExpressionIRDepth(source[:tokens[index].Start], language, depth+1),
			parseExpressionIRDepth(source[tokens[index+1].End:], language, depth+1),
		}
		return root
	}
	for _, operator := range []string{"?:", "as", "instanceof", "is", "==", "!=", "<=", ">=", "&&", "||", "<", ">", "+", "-", "*", "/", "%", "to"} {
		if index := topLevelIRToken(tokens, operator); index >= 0 {
			kind := expressionBinary
			if operator == "as" || operator == "as?" || operator == "instanceof" || operator == "is" || operator == "!is" {
				kind = expressionCast
			}
			root.Kind, root.Operator = kind, operator
			root.Children = []expressionIR{
				parseExpressionIRDepth(source[:tokens[index].Start], language, depth+1),
				parseExpressionIRDepth(source[tokens[index].End:], language, depth+1),
			}
			return root
		}
	}
	for index, token := range tokens {
		if token.Text != "(" || tokenDepthBefore(tokens, index) != 0 {
			continue
		}
		kind := expressionCall
		callee := strings.TrimSpace(source[:token.Start])
		calleeTokens, calleeComplete := lexical.TokenizeBounded(callee, kotlin, 100_000)
		if first == "new" || callee != "" && calleeComplete && len(resolveIRPathTokens(calleeTokens)) == 1 && upperInitial(callee) {
			kind = expressionConstructor
		}
		root.Kind = kind
		root.Children = append(root.Children, expressionIR{Kind: expressionName, Text: callee})
		if close := matchingIRDelimiter(tokens, index, "(", ")"); close > index {
			arguments := lexical.SplitTopLevel(source[token.End:tokens[close].Start], ",", kotlin)
			for _, argument := range arguments {
				root.Children = append(root.Children, parseExpressionIRDepth(argument, language, depth+1))
			}
		}
		return root
	}
	if path := resolveIRPathTokens(tokens); len(path) > 0 {
		root.Kind = expressionName
		if len(path) > 1 {
			root.Kind = expressionMember
			for _, part := range path {
				root.Children = append(root.Children, expressionIR{Kind: expressionName, Text: part})
			}
		}
		return root
	}
	root.Kind = expressionBlock
	for _, segment := range lexical.SplitTopLevel(source, ";", kotlin) {
		root.Children = append(root.Children, parseExpressionIRDepth(segment, language, depth+1))
	}
	return root
}

func topLevelIRToken(tokens []lexical.Token, wanted string) int {
	parens, brackets, braces, angles := 0, 0, 0, 0
	for index, token := range tokens {
		if parens == 0 && brackets == 0 && braces == 0 && angles == 0 && token.Text == wanted && !(wanted == "<" && lexical.GenericAngleOpening(tokens, index)) {
			return index
		}
		switch token.Text {
		case "(":
			parens++
		case ")":
			parens--
		case "[":
			brackets++
		case "]":
			brackets--
		case "{":
			braces++
		case "}":
			braces--
		case "<":
			if angles > 0 || lexical.GenericAngleOpening(tokens, index) {
				angles++
			}
		case ">":
			if angles > 0 {
				angles--
			}
		default:
			if angles > 0 && strings.Trim(token.Text, ">") == "" {
				angles -= min(angles, len(token.Text))
			}
		}
	}
	return -1
}

func upperInitial(value string) bool {
	value = strings.Trim(value, "`")
	first, _ := utf8.DecodeRuneInString(value)
	return first != utf8.RuneError && unicode.IsUpper(first)
}

func tokenDepthBefore(tokens []lexical.Token, end int) int {
	depth := 0
	for _, token := range tokens[:end] {
		switch token.Text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
	}
	return depth
}

func matchingIRDelimiter(tokens []lexical.Token, open int, opening, closing string) int {
	depth := 0
	for index := open; index < len(tokens); index++ {
		if tokens[index].Text == opening {
			depth++
		} else if tokens[index].Text == closing {
			depth--
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func resolveIRPathTokens(tokens []lexical.Token) []string {
	var parts []string
	expectIdentifier := true
	for _, token := range tokens {
		if expectIdentifier && token.Kind == lexical.Identifier {
			parts = append(parts, strings.Trim(token.Text, "`"))
			expectIdentifier = false
			continue
		}
		if !expectIdentifier && (token.Text == "." || token.Text == "?.") {
			expectIdentifier = true
			continue
		}
		return nil
	}
	if expectIdentifier {
		return nil
	}
	return parts
}

func expressionBranchIR(source string, language analysis.Language, depth int) []expressionIR {
	kotlin := language == analysis.LanguageKotlin
	var branches []expressionIR
	for _, segment := range lexical.SplitTopLevel(source, ";", kotlin) {
		if arrow := strings.Index(segment, "->"); arrow >= 0 {
			branches = append(branches, parseExpressionIRDepth(segment[arrow+2:], language, depth+1))
		}
	}
	return branches
}

func lastExpressionSegment(source string, kotlin bool) string {
	segments := lexical.SplitTopLevel(source, ";", kotlin)
	if len(segments) == 0 {
		return source
	}
	return segments[len(segments)-1]
}
