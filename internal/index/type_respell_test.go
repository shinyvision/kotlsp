package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A declaring file names its result types through its own package and
// imports. The call site, which imports only the repository, must still see
// the members of what the finder returns, whether the type reaches it
// through a member result or through a supertype's type arguments.
func TestMemberResultTypeSpelledForCallSiteFile(t *testing.T) {
	ctx := context.Background()
	userURI := protocol.URI("file:///workspace/domain/User.kt")
	repoURI := protocol.URI("file:///workspace/domain/UserRepository.kt")
	baseURI := protocol.URI("file:///workspace/data/Repository.kt")
	ctrlURI := protocol.URI("file:///workspace/web/Ctrl.kt")
	user := "package demo.domain\n\nopen class User(var id: Long? = null) {\n    var password: String = \"\"\n    var passwordToken: String? = null\n}\n"
	base := "package demo.data\n\ninterface Repository<T, ID> {\n    fun findById(id: ID): T?\n    fun save(entity: T): T\n}\n"
	repo := "package demo.domain\n\nimport demo.data.Repository\n\ninterface UserRepository : Repository<User, Long> {\n    fun findFirstByPasswordToken(passwordToken: String): User?\n    fun User.stamp(): User\n}\n"
	ctrl := "package demo.web\n\nimport demo.domain.UserRepository\n\nclass Ctrl(private val userRepository: UserRepository) {\n    fun post(passwordToken: String): String {\n        val user = userRepository.findFirstByPasswordToken(passwordToken)\n        ?: return \"redirect:/\"\n        user.passwordToken = null\n        val loaded = userRepository.findById(1L)\n        loaded.password = \"\"\n        val saved = userRepository.save(user)\n        saved.password = \"\"\n        return \"x\"\n    }\n}\n"
	idx := New(nil)
	idx.Open(ctx, protocol.TextDocumentItem{URI: userURI, LanguageID: "kotlin", Version: 1, Text: user})
	idx.Open(ctx, protocol.TextDocumentItem{URI: baseURI, LanguageID: "kotlin", Version: 1, Text: base})
	idx.Open(ctx, protocol.TextDocumentItem{URI: repoURI, LanguageID: "kotlin", Version: 1, Text: repo})
	idx.Open(ctx, protocol.TextDocumentItem{URI: ctrlURI, LanguageID: "kotlin", Version: 1, Text: ctrl})
	doc := textdoc.NewDocument(ctrlURI, "kotlin", 1, ctrl)

	for _, expression := range []struct{ name, expression, want string }{
		{"member result", "user", "demo.domain.User"},
		{"supertype type argument", "loaded", "demo.domain.User?"},
		{"substituted parameter", "saved", "demo.domain.User"},
	} {
		idx.mu.RLock()
		typ := idx.inferExpressionResultLocked(idx.files[ctrlURI], expression.expression, strings.Index(ctrl, "return \"x\"")).Type
		idx.mu.RUnlock()
		if typ != expression.want {
			t.Errorf("%s: inferred %q, want %q", expression.name, typ, expression.want)
		}
	}
	for _, marker := range []string{"user.passwordToken", "loaded.password", "saved.password"} {
		at := strings.Index(ctrl, marker) + strings.Index(marker, ".") + 1
		completion := idx.Completion(ctrlURI, doc.Position(at), 100)
		if !containsNamedSymbol(completion, "passwordToken") || !containsNamedSymbol(completion, "id") {
			t.Errorf("%s: member completion missing: %#v", marker, completion)
		}
		if containsNamedSymbol(completion, "User") {
			t.Errorf("%s: constructor offered through a value receiver: %#v", marker, completion)
		}
	}
}

// A name that resolves on both sides to the same declaration keeps its
// spelling; one the declaring file cannot resolve uniquely is left alone.
func TestRespellDeclaredTypeKeepsSharedAndUnprovenSpellings(t *testing.T) {
	ctx := context.Background()
	aURI := protocol.URI("file:///workspace/a/A.kt")
	bURI := protocol.URI("file:///workspace/b/B.kt")
	a := "package a\n\nclass Shared\n\nclass Producer<T> {\n    fun shared(): Shared = Shared()\n    fun text(): String = \"\"\n    fun own(): T? = null\n    fun unknown(): Missing? = null\n    fun both(): Pair<Shared, T> = TODO()\n}\n"
	b := "package b\n\nimport a.Producer\nimport a.Shared\n\nclass Use(val producer: Producer<Int>) {\n    fun go() {\n        val x = 0\n    }\n}\n"
	idx := New(nil)
	idx.Open(ctx, protocol.TextDocumentItem{URI: aURI, LanguageID: "kotlin", Version: 1, Text: a})
	idx.Open(ctx, protocol.TextDocumentItem{URI: bURI, LanguageID: "kotlin", Version: 1, Text: b})
	at := strings.Index(b, "val x")
	for _, c := range []struct{ expression, want string }{
		{"producer.shared()", "Shared"},
		{"producer.text()", "String"},
		{"producer.own()", "Int?"},
		{"producer.unknown()", "Missing?"},
		{"producer.both()", "Pair<Shared, Int>"},
	} {
		idx.mu.RLock()
		typ := idx.inferExpressionResultLocked(idx.files[bURI], c.expression, at).Type
		idx.mu.RUnlock()
		if typ != c.want {
			t.Errorf("%s: inferred %q, want %q", c.expression, typ, c.want)
		}
	}
}
