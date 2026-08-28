package lsp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// completionFixture opens a workspace with far more candidates than one
// response may carry, plus one distinctively named class that sorts nowhere
// near the front.
func completionFixture(t *testing.T) (*Server, protocol.URI, string) {
	t.Helper()
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	for n := 0; n < completionCandidateLimit*3; n++ {
		name := "Zeta" + strconv.Itoa(n)
		uri := protocol.URI("file:///workspace/" + name + ".java")
		s.index.Open(context.Background(), protocol.TextDocumentItem{
			URI: uri, LanguageID: "java", Version: 1,
			Text: "package demo;\npublic class " + name + " {}\n",
		})
	}
	target := "QqqDistinctlyNamedTarget"
	s.index.Open(context.Background(), protocol.TextDocumentItem{
		URI: protocol.URI("file:///workspace/" + target + ".java"), LanguageID: "java", Version: 1,
		Text: "package demo;\npublic class " + target + " {}\n",
	})
	uri := protocol.URI("file:///workspace/Caller.java")
	source := "package demo;\nclass Caller {\n    void use() {\n        \n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	return s, uri, target
}

func complete(t *testing.T, s *Server, uri protocol.URI, line, character int) protocol.CompletionList {
	t.Helper()
	params, err := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]int{"line": line, "character": character},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/completion", params)
	if responseErr != nil {
		t.Fatalf("completion failed: %v", responseErr)
	}
	list, ok := result.(protocol.CompletionList)
	if !ok {
		t.Fatalf("unexpected completion result type %T", result)
	}
	return list
}

// An unbounded response on a real dependency graph is tens of thousands of
// items and misses the interaction budget outright.
func TestCompletionResponseIsBoundedAndReportedIncomplete(t *testing.T) {
	s, uri, _ := completionFixture(t)
	list := complete(t, s, uri, 3, 8)
	if len(list.Items) == 0 {
		t.Fatal("completion returned nothing")
	}
	// Keywords and templates are appended after the bounded candidate set.
	if len(list.Items) > completionCandidateLimit*2 {
		t.Fatalf("completion returned %d items, candidate bound is %d", len(list.Items), completionCandidateLimit)
	}
	if !list.IsIncomplete {
		t.Fatal("a truncated candidate set must be reported as incomplete so the client re-queries")
	}
}

// Bounding must never drop a candidate that matches what was typed: the prefix
// filter runs before the bound, so a rare name stays reachable no matter how
// many other declarations exist.
func TestCompletionBoundKeepsPrefixMatches(t *testing.T) {
	s, uri, target := completionFixture(t)
	prefix := target[:7]
	edited := "package demo;\nclass Caller {\n    void use() {\n        " + prefix + "\n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 2, Text: edited})

	list := complete(t, s, uri, 3, 8+len(prefix))
	for _, item := range list.Items {
		if item.Label == target {
			return
		}
	}
	labels := make([]string, 0, 8)
	for n, item := range list.Items {
		if n == 8 {
			break
		}
		labels = append(labels, item.Label)
	}
	t.Fatalf("prefix %q lost its only match among %d items: %s", prefix, len(list.Items), strings.Join(labels, ", "))
}
