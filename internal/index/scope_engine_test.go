package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A stand-in for the parts of the standard library the scope engine has to
// reason about: scope functions with and without receivers, a builder with a
// concrete receiver, and a collection with a plain lambda parameter.
const kotlinScopeStdlib = `package kotlin

open class Any
abstract class Enum<E>
class String { val length: Int = 0 }
class Int
class Long
class Boolean
class Unit
class Nothing
class StringBuilder { fun append(value: Any): StringBuilder = this }
inline fun <T> T.apply(block: T.() -> Unit): T = this
inline fun <T, R> T.let(block: (T) -> R): R = block(this)
inline fun <T, R> T.run(block: T.() -> R): R = block()
inline fun <T, R> with(receiver: T, block: T.() -> R): R = receiver.block()
inline fun buildString(builderAction: StringBuilder.() -> Unit): String = ""
fun println(message: Any) {}
interface List<E> { fun forEach(action: (E) -> Unit) }
`

func scopeIndex(t *testing.T, files map[string]string) *Index {
	t.Helper()
	idx := New(nil)
	t.Cleanup(idx.Close)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///stdlib/kotlin/Stdlib.kt", LanguageID: "kotlin", Version: 1, Text: kotlinScopeStdlib})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///stdlib/java/lang/Object.java", LanguageID: "java", Version: 1, Text: "package java.lang;\npublic class Object { public String toString() { return null; } }\nclass String {}\npublic interface Runnable { void run(); }\n"})
	for path, text := range files {
		language := "kotlin"
		if strings.HasSuffix(path, ".java") {
			language = "java"
		}
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI("file:///workspace/" + path), LanguageID: language, Version: 1, Text: text})
	}
	idx.markReady()
	return idx
}

func unresolvedNames(idx *Index, uri protocol.URI) []string {
	var out []string
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Source != "kotlsp" {
			continue
		}
		if code, _ := diagnostic.Code.(string); code == "UNRESOLVED_REFERENCE" || diagnostic.Message == "cannot find symbol" {
			name, _ := diagnostic.Data.(map[string]any)["name"].(string)
			out = append(out, name)
		}
	}
	return out
}

// The case that motivated the engine: a property of a sibling class, used
// inside a scope-function lambda whose receiver is a library type.
func TestScopeEngineReportsASiblingClassPropertyInsideAReceiverLambda(t *testing.T) {
	idx := scopeIndex(t, map[string]string{
		"lib/Context.kt": "package lib\nclass Context { fun setVariable(name: String, value: Any) {} }\n",
		"app/SignUp.kt":  "package app\nclass SignUpController(private val baseUrl: String) { fun link() = baseUrl }\n",
		"app/Forgot.kt": `package app

import lib.Context

class ForgotPasswordController {
    fun send(token: String) {
        val context = Context().apply {
            setVariable("link", "$baseUrl/user/reset-password/$token")
        }
        println(context)
    }
}
`,
	})
	got := unresolvedNames(idx, "file:///workspace/app/Forgot.kt")
	if len(got) != 1 || got[0] != "baseUrl" {
		t.Fatalf("wanted exactly the baseUrl finding, got %q", got)
	}
}

func TestScopeEngineReportsProvablyUnresolvedNames(t *testing.T) {
	for _, fixture := range []struct{ label, source, want string }{
		{"top-level function body", "package app\nclass Other { val secret = 1 }\nfun f() { println(secret) }\n", "secret"},
		{"inside a class with a resolved hierarchy", "package app\nopen class Base { val base = 1 }\nclass Other { val secret = 1 }\nclass C : Base() { fun f() = base + secret }\n", "secret"},
		{"inside a plain lambda", "package app\nclass Other { val secret = 1 }\nfun f(xs: List<Int>) { xs.forEach { println(secret) } }\n", "secret"},
		{"inside let", "package app\nclass Other { val secret = 1 }\nfun f(s: String) { s.let { println(secret) } }\n", "secret"},
		{"inside a builder with a concrete receiver", "package app\nclass Other { val secret = 1 }\nfun f() = buildString { append(secret) }\n", "secret"},
		{"inside with over a resolvable argument", "package app\nclass Ctx { fun put(x: Any) {} }\nclass Other { val secret = 1 }\nfun f(c: Ctx) { with(c) { put(secret) } }\n", "secret"},
		{"call to a member of another class", "package app\nclass Other { fun helper() = 1 }\nfun f() = helper()\n", "helper"},
		{"other package top-level not imported", "package app\nfun f() = util()\n", "util"},
	} {
		files := map[string]string{"app/Probe.kt": fixture.source, "other/Util.kt": "package other\nfun util() = 1\n"}
		idx := scopeIndex(t, files)
		got := unresolvedNames(idx, "file:///workspace/app/Probe.kt")
		if len(got) != 1 || got[0] != fixture.want {
			t.Errorf("%s: wanted %q, got %q", fixture.label, fixture.want, got)
		}
	}
}

// Every one of these compiles. A finding is a false positive.
func TestScopeEngineAbstainsWhereANameCouldBeVisible(t *testing.T) {
	for _, fixture := range []struct{ label, source, allowed string }{
		{"member of the receiver lambda", "package app\nclass Ctx { fun put(x: Any) {} }\nfun f() { Ctx().apply { put(1) } }\n", ""},
		{"member of an unresolvable lambda callee", "package app\nfun f() { mystery { secret } }\n", "mystery"},
		{"member of a with argument", "package app\nclass Ctx { val secret = 1 }\nfun f(c: Ctx) { with(c) { println(secret) } }\n", ""},
		{"member through a companion", "package app\nclass Other { companion object { val secret = 1 } }\nclass C { fun f() = Other.secret }\n", ""},
		{"own companion member", "package app\nclass C { companion object { val secret = 1 }\n fun f() = secret }\n", ""},
		{"inherited companion member", "package app\nopen class Base { companion object { val secret = 1 } }\nclass C : Base() { fun f() = secret }\n", ""},
		{"star import", "package app\nimport other.*\nfun f() = util()\n", ""},
		{"explicit import", "package app\nimport other.util\nfun f() = util()\n", ""},
		{"anonymous object supertype member", "package app\ninterface Greeter { val greeting: String }\nfun f() { val g = object : Greeter { override val greeting = \"\"; fun show() = println(greeting) } }\n", ""},
		{"anonymous receiver function", "package app\nclass Ctx { val secret = 1 }\nfun f() { val g = fun Ctx.(): Int { return secret } }\n", ""},
		{"extension receiver member", "package app\nclass Ctx { val secret = 1 }\nfun Ctx.f() = secret\n", ""},
		{"destructured lambda parameter", "package app\nfun f(xs: List<Pair<Int, Int>>) { xs.forEach { (secret, other) -> println(secret + other) } }\nclass Pair<A, B>\n", ""},
		{"lambda parameter", "package app\nfun f(xs: List<Int>) { xs.forEach { secret -> println(secret) } }\n", ""},
		{"unresolvable supertype", "package app\nclass C : Mystery() { fun f() = secret }\nclass Other { val secret = 1 }\n", "Mystery"},
		{"java getter as property", "package app\nclass C : Bean() { fun f() = secret }\n", ""},
		{"enum entry in when", "package app\nenum class Color { RED }\nfun f(c: Color) = when (c) { RED -> 1 }\n", ""},
		{"string template of a lexical", "package app\nfun f() { val secret = 1; println(\"$secret\") }\n", ""},
		{"context receivers", "package app\nclass Ctx { val secret = 1 }\ncontext(Ctx)\nfun f() = secret\n", ""},
		{"value invoked through an imported invoke operator", "package app\nimport dsl.invoke\nclass Http\nfun f(http: Http) { http { secret() } }\n", ""},
		{"member access continued on the next line", "package app\nclass Ctx { fun first(): Ctx = this }\nfun f(c: Ctx) {\n    c.first()\n        .secret()\n}\n", ""},
	} {
		files := map[string]string{
			"app/Probe.kt":   fixture.source,
			"other/Util.kt":  "package other\nfun util() = 1\n",
			"app/Bean.java":  "package app;\npublic class Bean { public int getSecret() { return 1; } }\n",
			"app/Sibling.kt": "package app\nclass Sibling { val secret = 2 }\n",
			"dsl/Dsl.kt":     "package dsl\nimport app.Http\nclass HttpDsl { fun secret() {} }\noperator fun Http.invoke(block: HttpDsl.() -> Unit) {}\n",
		}
		idx := scopeIndex(t, files)
		for _, got := range unresolvedNames(idx, "file:///workspace/app/Probe.kt") {
			if got != fixture.allowed {
				t.Errorf("%s: false positive %q", fixture.label, got)
			}
		}
	}
}

func TestScopeEngineHandlesJava(t *testing.T) {
	idx := scopeIndex(t, map[string]string{
		"app/Other.java": "package app;\npublic class Other { public int secret = 1; public static int shared = 2; }\n",
		"app/Base.java":  "package app;\npublic class Base { protected int inherited = 1; }\n",
		"app/Probe.java": `package app;

import static app.Other.shared;

public class Probe extends Base {
    private int own = 1;

    int f(int parameter) {
        int local = own + inherited + parameter + shared + toString().length();
        Runnable r = new Runnable() { public void run() { int x = own; } };
        return local + secret;
    }
}
`,
	})
	got := unresolvedNames(idx, "file:///workspace/app/Probe.java")
	if len(got) != 1 {
		t.Fatalf("wanted exactly the secret finding, got %q", got)
	}
}

func TestCodeMaskMarksTemplatesAsCode(t *testing.T) {
	text := `val s = "a $name ${f("in")} b" // name
val c = 'x'; val t = """raw $name"""`
	mask := codeMask(text, true)
	check := func(needle string, want bool) {
		t.Helper()
		at := strings.Index(text, needle)
		if mask[at] != want {
			t.Errorf("%q: code=%v, want %v", needle, mask[at], want)
		}
	}
	check("val s", true)
	check("a $", false)
	check("name ${", true)
	check("f(\"in\")", true)
	check("in\")", false)
	check(" b\"", false)
	check("// name", false)
	check("'x'", false)
	check("raw", false)
	check("name\"\"\"", true)
}
