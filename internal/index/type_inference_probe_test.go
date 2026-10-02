package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// TestKotlinInferenceShapes covers the expression shapes ordinary Kotlin uses
// to produce a value. Each one is a step away from a plain call, and the first
// that yields nothing is where a value loses its type -- and with it its
// members, its navigation and its rename.
func TestKotlinInferenceShapes(t *testing.T) {
	ctx := context.Background()
	uri := protocol.URI("file:///workspace/Shapes.kt")
	source := "package demo\n" +
		"\n" +
		"class Account {\n" +
		"    val id: Long = 1\n" +
		"    fun label(): String = \"a\"\n" +
		"}\n" +
		"\n" +
		"class Repo {\n" +
		"    fun find(token: String): Account? = null\n" +
		"    fun all(): List<Account> = emptyList()\n" +
		"}\n" +
		"\n" +
		"class Service(private val repo: Repo) {\n" +
		"    private fun direct(token: String) = repo.find(token)\n" +
		"\n" +
		"    private fun branched(token: String, lock: Boolean) =\n" +
		"        if (lock) repo.find(token) else repo.find(token)\n" +
		"\n" +
		"    fun use(token: String) {\n" +
		"        val marker = 0\n" +
		"    }\n" +
		"}\n"
	idx := New(nil)
	defer idx.Close()
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	if file == nil {
		t.Fatal("document not indexed")
	}
	at := strings.Index(source, "val marker = 0")
	for expression, want := range map[string]string{
		"repo.find(token)":                                 "Account?",
		"direct(token)":                                    "Account?",
		"branched(token, true)":                            "Account?",
		"repo.find(token)?.label()":                        "String?",
		"repo.all().first()":                               "Account",
		"if (true) repo.find(token) else repo.find(token)": "Account?",
	} {
		if got := idx.inferExpressionTypeLocked(ctx, file, expression, at); got != want {
			t.Errorf("%s -> %q, want %q", expression, got, want)
		}
	}
}

// TestKotlinInferenceShapesWithTheStandardLibrary covers the shapes that need
// the standard library: a scope function is an ordinary extension whose
// declaration lives in kotlin-stdlib. Its class is copied from kotlin-stdlib
// 2.4.10 into testdata, and the same functions are declared again as library
// sources, the way a stdlib with its sources jar arrives.
func TestKotlinInferenceShapesWithTheStandardLibrary(t *testing.T) {
	ctx := context.Background()
	class, err := os.ReadFile(filepath.Join("testdata", "kotlin-stdlib", "2.4.10", "kotlin", "StandardKt__StandardKt.class"))
	if err != nil {
		t.Fatal(err)
	}
	stdlib := writeTestArchive(t, "kotlin-stdlib-2.4.10.jar", map[string]string{"kotlin/StandardKt__StandardKt.class": string(class)})
	idx := New(nil)
	defer idx.Close()
	if complete := idx.indexSourceArchive(ctx, sourceArchive{path: stdlib, binary: true, release: idx.javaReleaseForLibrary(stdlib)}, 0, func(int64) {}); !complete {
		t.Fatal("the standard-library class did not index completely")
	}
	sources := `package kotlin
public inline fun <T> T.takeIf(predicate: (T) -> Boolean): T? = if (predicate(this)) this else null
public inline fun <T, R> T.let(block: (T) -> R): R = block(this)
`
	parsed := analysis.Parse(ctx, textdoc.NewDocument(protocol.URI("file:///libs/kotlin/Standard.kt"), "kotlin", 0, sources))
	idx.AddLibraryBatch([]LibraryFile{{
		Source: LibrarySource{Archive: "/deps/kotlin-stdlib-2.4.10-sources.jar", Entry: "kotlin/Standard.kt", LanguageID: "kotlin"},
		Parsed: *parsed,
	}})
	uri := protocol.URI("file:///workspace/Reset.kt")
	source := `package demo

class Instant
class Clock { fun instant(): Instant = Instant() }
class User(var password: String, val passwordTokenCreatedAt: Instant?)

class Users { fun byToken(token: String, lock: Boolean): User? = null }

class ResetPasswordController(private val users: Users, private val clock: Clock) {
    private fun validUser(token: String, lock: Boolean) = users.byToken(token, lock)?.takeIf { it.passwordTokenCreatedAt != null }

    fun reset(passwordToken: String, user: User) {
        user.password = passwordToken
    }
}
`
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	at := strings.Index(source, "user.password = passwordToken")
	for expression, want := range map[string]string{
		// An expression body with no declared return type, ending in a scope
		// function applied to a safe call: the shape that decides whether
		// `val user = validUser(token)` has members at all.
		"validUser(passwordToken, lock = true)": "User?",
		// A trailing lambda whose body contains a call: the brace opens before
		// the parenthesis, and reading it as a parenthesised call named the
		// member "takeIf { it.isNotEmpty".
		"passwordToken.takeIf { it.isNotEmpty() }": "String?",
		"passwordToken.takeIf { true }":            "String?",
		"passwordToken.let { it }":                 "String",
		"user.passwordTokenCreatedAt":              "Instant?",
		"clock.instant()":                          "Instant",
	} {
		if got := idx.inferExpressionTypeLocked(ctx, file, expression, at); got != want {
			t.Errorf("%s -> %q, want %q", expression, got, want)
		}
	}
	// `takeIf` is declared by the sources and again by the binary facade.
	// Identical answers are one answer.
	if result, ambiguous := idx.uniqueExtensionResultTypeLocked(ctx, file, "String", "takeIf", true, nil, at); ambiguous || result != "String?" {
		t.Errorf("takeIf on String -> %q ambiguous=%v, want \"String?\" and no ambiguity", result, ambiguous)
	}
}
