package index

import (
	"strings"
)

// typeRef is a Kotlin type spelling taken apart: `Map<String, out List<T>>?`,
// `suspend Receiver.(Int) -> Unit`, `*`. Types travel through the index as
// strings, and every helper that needed to look inside one used to cut it up
// its own way; typeRef is the one parser they can share. Parsing is total in
// the sense that matters: anything it does not understand fails instead of
// guessing, and callers keep the string.
type typeRef struct {
	// Name is the classifier as written: `kotlin.collections.List`, `T`,
	// `Map.Entry`. Empty for a function type.
	Name     string
	Args     []typeArgument
	Nullable bool
	// Function is set for a function type, which has no Name.
	Function *functionTypeRef
}

type typeArgument struct {
	// Variance is "in", "out" or "".
	Variance string
	// Star is the star projection `*`, which has no Type.
	Star bool
	Type typeRef
}

type functionTypeRef struct {
	Suspend    bool
	Receiver   *typeRef
	Parameters []typeRef
	Result     typeRef
}

// parseTypeRef parses a type spelling, or reports false.
func parseTypeRef(value string) (typeRef, bool) {
	parser := typeRefParser{text: strings.TrimSpace(value)}
	ref, ok := parser.parseType(0)
	parser.skipSpace()
	if !ok || parser.at != len(parser.text) {
		return typeRef{}, false
	}
	return ref, true
}

type typeRefParser struct {
	text string
	at   int
}

func (p *typeRefParser) skipSpace() {
	for p.at < len(p.text) && (p.text[p.at] == ' ' || p.text[p.at] == '\t' || p.text[p.at] == '\n' || p.text[p.at] == '\r') {
		p.at++
	}
}

func (p *typeRefParser) consume(token string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.text[p.at:], token) {
		p.at += len(token)
		return true
	}
	return false
}

// keyword consumes a word followed by a space: `suspend ` or `out `.
func (p *typeRefParser) keyword(word string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.text[p.at:], word) && p.at+len(word) < len(p.text) && (p.text[p.at+len(word)] == ' ' || p.text[p.at+len(word)] == '\t') {
		p.at += len(word)
		return true
	}
	return false
}

func (p *typeRefParser) parseType(depth int) (typeRef, bool) {
	if depth > 32 {
		return typeRef{}, false
	}
	p.skipSpace()
	suspend := p.keyword("suspend")
	p.skipSpace()
	// A parenthesised start is either a function type's parameter list or a
	// parenthesised type (`(() -> Unit)?`).
	if p.at < len(p.text) && p.text[p.at] == '(' {
		save := p.at
		if function, ok := p.parseFunctionTail(nil, suspend, depth); ok {
			return function, true
		}
		p.at = save + 1
		inner, ok := p.parseType(depth + 1)
		if !ok || !p.consume(")") {
			return typeRef{}, false
		}
		if p.consume("?") {
			inner.Nullable = true
		}
		return inner, true
	}
	ref, ok := p.parseClassifier(depth)
	if !ok {
		return typeRef{}, false
	}
	// `Receiver.(Int) -> Unit`: a classifier followed by `.(`.
	save := p.at
	if p.consume(".") {
		p.skipSpace()
		if p.at < len(p.text) && p.text[p.at] == '(' {
			receiver := ref
			if function, ok := p.parseFunctionTail(&receiver, suspend, depth); ok {
				return function, true
			}
		}
		p.at = save
	}
	if suspend {
		return typeRef{}, false
	}
	return ref, true
}

// parseFunctionTail parses `(params) -> Result` at a `(`.
func (p *typeRefParser) parseFunctionTail(receiver *typeRef, suspend bool, depth int) (typeRef, bool) {
	if !p.consume("(") {
		return typeRef{}, false
	}
	var parameters []typeRef
	p.skipSpace()
	if !p.consume(")") {
		for {
			p.skipSpace()
			// A named parameter: `(name: Type) -> R`.
			if colon := p.namedParameterPrefix(); colon > 0 {
				p.at = colon
			}
			parameter, ok := p.parseType(depth + 1)
			if !ok {
				return typeRef{}, false
			}
			parameters = append(parameters, parameter)
			if p.consume(",") {
				continue
			}
			if p.consume(")") {
				break
			}
			return typeRef{}, false
		}
	}
	if !p.consume("->") {
		return typeRef{}, false
	}
	result, ok := p.parseType(depth + 1)
	if !ok {
		return typeRef{}, false
	}
	function := typeRef{Function: &functionTypeRef{Suspend: suspend, Receiver: receiver, Parameters: parameters, Result: result}}
	return function, true
}

// namedParameterPrefix returns the offset after `name:` at the cursor, or 0.
func (p *typeRefParser) namedParameterPrefix() int {
	index := p.at
	for index < len(p.text) && (p.text[index] == '_' || p.text[index] >= 'a' && p.text[index] <= 'z' || p.text[index] >= 'A' && p.text[index] <= 'Z' || p.text[index] >= '0' && p.text[index] <= '9') {
		index++
	}
	if index == p.at {
		return 0
	}
	rest := index
	for rest < len(p.text) && p.text[rest] == ' ' {
		rest++
	}
	if rest < len(p.text) && p.text[rest] == ':' && !(rest+1 < len(p.text) && p.text[rest+1] == ':') {
		return rest + 1
	}
	return 0
}

func (p *typeRefParser) parseClassifier(depth int) (typeRef, bool) {
	p.skipSpace()
	start := p.at
	for p.at < len(p.text) {
		c := p.text[p.at]
		if c == '_' || c == '$' || c == '`' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80 {
			p.at++
			continue
		}
		// A dot continues a qualified name unless `.(` starts a receiver's
		// parameter list.
		if c == '.' && p.at+1 < len(p.text) && p.text[p.at+1] != '(' && p.text[p.at+1] != ' ' {
			p.at++
			continue
		}
		break
	}
	if p.at == start {
		return typeRef{}, false
	}
	ref := typeRef{Name: p.text[start:p.at]}
	if p.consume("<") {
		for {
			argument, ok := p.parseArgument(depth)
			if !ok {
				return typeRef{}, false
			}
			ref.Args = append(ref.Args, argument)
			if p.consume(",") {
				continue
			}
			if p.consume(">") {
				break
			}
			return typeRef{}, false
		}
	}
	if p.consume("?") {
		ref.Nullable = true
	}
	return ref, true
}

func (p *typeRefParser) parseArgument(depth int) (typeArgument, bool) {
	p.skipSpace()
	if p.consume("*") {
		return typeArgument{Star: true}, true
	}
	variance := ""
	if p.keyword("out") {
		variance = "out"
	} else if p.keyword("in") {
		variance = "in"
	}
	argument, ok := p.parseType(depth + 1)
	if !ok {
		return typeArgument{}, false
	}
	return typeArgument{Variance: variance, Type: argument}, true
}

// String spells the type the way Kotlin source does.
func (t typeRef) String() string {
	var out strings.Builder
	t.write(&out)
	return out.String()
}

func (t typeRef) write(out *strings.Builder) {
	if t.Function != nil {
		if t.Nullable {
			out.WriteByte('(')
		}
		if t.Function.Suspend {
			out.WriteString("suspend ")
		}
		if t.Function.Receiver != nil {
			t.Function.Receiver.write(out)
			out.WriteByte('.')
		}
		out.WriteByte('(')
		for index, parameter := range t.Function.Parameters {
			if index > 0 {
				out.WriteString(", ")
			}
			parameter.write(out)
		}
		out.WriteString(") -> ")
		t.Function.Result.write(out)
		if t.Nullable {
			out.WriteString(")?")
		}
		return
	}
	out.WriteString(t.Name)
	if len(t.Args) > 0 {
		out.WriteByte('<')
		for index, argument := range t.Args {
			if index > 0 {
				out.WriteString(", ")
			}
			switch {
			case argument.Star:
				out.WriteByte('*')
			default:
				if argument.Variance != "" {
					out.WriteString(argument.Variance)
					out.WriteByte(' ')
				}
				argument.Type.write(out)
			}
		}
		out.WriteByte('>')
	}
	if t.Nullable {
		out.WriteByte('?')
	}
}

// transform rebuilds the type bottom-up, letting visit replace any classifier.
func (t typeRef) transform(visit func(typeRef) typeRef) typeRef {
	if t.Function != nil {
		function := *t.Function
		if function.Receiver != nil {
			receiver := function.Receiver.transform(visit)
			function.Receiver = &receiver
		}
		parameters := make([]typeRef, len(function.Parameters))
		for index, parameter := range function.Parameters {
			parameters[index] = parameter.transform(visit)
		}
		function.Parameters = parameters
		function.Result = function.Result.transform(visit)
		t.Function = &function
		return visit(t)
	}
	if len(t.Args) > 0 {
		arguments := make([]typeArgument, len(t.Args))
		for index, argument := range t.Args {
			if !argument.Star {
				argument.Type = argument.Type.transform(visit)
			}
			arguments[index] = argument
		}
		t.Args = arguments
	}
	return visit(t)
}
