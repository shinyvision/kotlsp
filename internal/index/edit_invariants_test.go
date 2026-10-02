package index

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Typing, one keystroke at a time, at every lambda opening of a file must
// never leave the index inconsistent; see checkInvariantsLocked. Every word
// is typed at every site, so a failure always reproduces.
func TestEditsAtLambdaOpeningsKeepIndexConsistent(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///workspace/src/main/kotlin/app/Repository.kt")
	text := `package app

data class Item(val id: Int, val name: String, val tags: List<String>)

class Transaction { fun dsl(): Repository = Repository() }

class Repository {
    private val items = mutableListOf<Item>()

    fun names(): List<String> = items.map { item ->
        item.name
    }

    fun tagged(tag: String): List<Item> = items.filter {
        it.tags.contains(tag)
    }

    fun <T> transactional(block: (Transaction) -> T): T = block(Transaction())

    fun rename(id: Int, name: String): Item? = transactional { trx ->
        trx.dsl().items.firstOrNull { it.id == id }?.let { found ->
            found.copy(name = name)
        }
    }

    companion object {
        fun empty(): Repository = Repository().also {
            it.items.clear()
        }
    }
}
`
	words := []string{"tr", "it.", "undefinedThi", "descr", "this.", "listOf(1).ma", "xs.fi", "trx.dsl().", "copy(", "map { it.", "let { x -> x.", "}", "{", "\"unterminated"}
	sites := regexp.MustCompile(`\{ *(\w+ *->)?\n`).FindAllStringIndex(text, -1)
	if len(sites) < 5 {
		t.Fatalf("the sample has %d lambda openings; the test needs several", len(sites))
	}
	version := 1
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: version, Text: text})
	change := func(content string) {
		version++
		if _, err := idx.Change(ctx, protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: content}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, site := range sites {
		offset := site[1]
		for _, word := range words {
			for length := 1; length <= len(word); length++ {
				change(text[:offset] + "        " + word[:length] + "\n" + text[offset:])
				idx.mu.RLock()
				problems := idx.checkInvariantsLocked()
				idx.mu.RUnlock()
				if len(problems) > 0 {
					t.Fatalf("after typing %q at byte %d:\n%s", word[:length], offset, strings.Join(problems, "\n"))
				}
			}
			change(text)
		}
	}
}
