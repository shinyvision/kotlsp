package lsp

import (
	"regexp"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

type javaTemplate struct {
	key  string
	body func(string) string
}

var javaPostfixTemplates = []javaTemplate{
	{"if", func(e string) string { return "if (" + e + ") {\n\t$0\n}" }},
	{"else", func(e string) string { return "if (!(" + e + ")) {\n\t$0\n}" }},
	{"while", func(e string) string { return "while (" + e + ") {\n\t$0\n}" }},
	{"not", func(e string) string { return "!(" + e + ")" }},
	{"null", func(e string) string { return e + " == null" }},
	{"notnull", func(e string) string { return e + " != null" }},
	{"nn", func(e string) string { return e + " != null" }},
	{"return", func(e string) string { return "return " + e + ";" }},
	{"throw", func(e string) string { return "throw " + e + ";" }},
	{"sout", func(e string) string { return "System.out.println(" + e + ");" }},
	{"serr", func(e string) string { return "System.err.println(" + e + ");" }},
	{"par", func(e string) string { return "(" + e + ")" }},
	{"optional", func(e string) string { return "java.util.Optional.ofNullable(" + e + ")" }},
	{"requireNonNull", func(e string) string { return "java.util.Objects.requireNonNull(" + e + ")" }},
	{"iter", func(e string) string { return "for (var ${1:item} : " + e + ") {\n\t$0\n}" }},
	{"for", func(e string) string { return "for (var ${1:item} : " + e + ") {\n\t$0\n}" }},
	{"switch", func(e string) string { return "switch (" + e + ") {\n\t$0\n}" }},
	{"try", func(e string) string { return "try {\n\t" + e + ";\n} catch (Exception ${1:e}) {\n\t$0\n}" }},
	{"stream", func(e string) string { return "java.util.Arrays.stream(" + e + ")" }},
	{"assert", func(e string) string { return "assert " + e + ";" }},
}

var javaLiveTemplates = map[string]string{
	"sout": "System.out.println($0);",
	"serr": "System.err.println($0);",
	"psvm": "public static void main(String[] args) {\n\t$0\n}",
	"fori": "for (int ${1:i} = 0; ${1:i} < ${2:length}; ${1:i}++) {\n\t$0\n}",
	"iter": "for (var ${1:item} : ${2:items}) {\n\t$0\n}",
	"try":  "try {\n\t$0\n} catch (Exception ${1:e}) {\n\t\n}",
}

func javaTemplateCompletions(doc *textdoc.Document, position protocol.Position, snippets bool) []protocol.CompletionItem {
	offset := doc.Offset(position)
	if offset < 0 || offset > len(doc.Text) {
		return nil
	}
	wordStart := offset
	for wordStart > 0 && isTemplateIdentifier(doc.Text[wordStart-1]) {
		wordStart--
	}
	prefix := doc.Text[wordStart:offset]
	var out []protocol.CompletionItem
	if wordStart > 0 && doc.Text[wordStart-1] == '.' {
		dot := wordStart - 1
		expressionStart := postfixExpressionStart(doc.Text, dot)
		expression := strings.TrimSpace(doc.Text[expressionStart:dot])
		if expression == "" {
			return nil
		}
		for _, template := range javaPostfixTemplates {
			if prefix != "" && !strings.HasPrefix(strings.ToLower(template.key), strings.ToLower(prefix)) {
				continue
			}
			body := template.body(expression)
			format := 2
			if !snippets {
				body, format = plainTemplate(body), 1
			}
			out = append(out, protocol.CompletionItem{Label: template.key, FilterText: prefix, Kind: protocol.CompletionSnippet,
				Detail: "Java postfix template", SortText: "0000_postfix_" + template.key, InsertTextFormat: format,
				TextEdit: &protocol.TextEdit{Range: doc.Range(expressionStart, offset), NewText: body}})
		}
		return out
	}
	keys := make([]string, 0, len(javaLiveTemplates))
	for key := range javaLiveTemplates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		template := javaLiveTemplates[key]
		if prefix == "" || !strings.HasPrefix(strings.ToLower(key), strings.ToLower(prefix)) {
			continue
		}
		format := 2
		if !snippets {
			template, format = plainTemplate(template), 1
		}
		out = append(out, protocol.CompletionItem{Label: key, Kind: protocol.CompletionSnippet, Detail: "Java live template",
			SortText: "0001_live_" + key, InsertTextFormat: format, TextEdit: &protocol.TextEdit{Range: doc.Range(wordStart, offset), NewText: template}})
	}
	return out
}

func postfixExpressionStart(text string, dot int) int {
	depth := 0
	for index := dot - 1; index >= 0; index-- {
		switch text[index] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth > 0 {
				depth--
				continue
			}
			return index + 1
		case ';', '=', ',', '\n':
			if depth == 0 {
				return index + 1
			}
		case ' ', '\t':
			if depth == 0 {
				return index + 1
			}
		}
	}
	return 0
}

func isTemplateIdentifier(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

var templatePlaceholder = regexp.MustCompile(`\$\{\d+(?::([^}]*))?\}|\$0`)

func plainTemplate(value string) string {
	return templatePlaceholder.ReplaceAllString(value, "$1")
}
