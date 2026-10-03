package index

import (
	"context"
	"github.com/shinyvision/kotlsp/internal/analysis"
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
		{"local in another function", "package app\nfun first() { val secret = 1 }\nfun second() = secret\n", "secret"},
		{"familiar generated-member spelling without receiver", "package app\nclass Other { val length = 1 }\nfun f() = length\n", "length"},
		// A function body whose first statement declares a local once read as
		// a lambda of unknown receiver, which silenced the whole function.
		{"function whose body starts with a val", "package app\nclass Other { val secret = 1 }\nfun f(): List<Int> {\n    val records = listOf(1)\n    secret\n    return records\n}\n", "secret"},
		{"suspend override whose body starts with a var", "package app\ninterface Repo { suspend fun all(): List<Int> }\nclass Other { val secret = 1 }\nclass Impl : Repo {\n    override suspend fun all(): List<Int> {\n        var records = listOf(1)\n        secret\n        return records\n    }\n}\n", "secret"},
		{"body starting with lateinit-free val after a comment", "package app\nclass Other { val secret = 1 }\nfun f() {\n    // first\n    val x = 1\n    println(secret + x)\n}\n", "secret"},
	} {
		files := map[string]string{"app/Probe.kt": fixture.source, "other/Util.kt": "package other\nfun util() = 1\n"}
		idx := scopeIndex(t, files)
		got := unresolvedNames(idx, "file:///workspace/app/Probe.kt")
		if len(got) != 1 || got[0] != fixture.want {
			t.Errorf("%s: wanted %q, got %q", fixture.label, fixture.want, got)
		}
	}
}

func TestScopeEngineDoesNotBroadenEnumVisibilityFromRawWhenText(t *testing.T) {
	idx := scopeIndex(t, map[string]string{
		"other/Color.kt": "package other\nenum class Color { RED }\n",
		"app/Probe.kt":   "package app\n// when mentioned only in a comment\nfun f() = RED\n",
	})
	got := unresolvedNames(idx, "file:///workspace/app/Probe.kt")
	if len(got) != 1 || got[0] != "RED" {
		t.Fatalf("comment text broadened enum visibility: %q", got)
	}
}

// Every one of these compiles. A finding is a false positive.
func TestScopeEngineAbstainsWhereANameCouldBeVisible(t *testing.T) {
	for _, fixture := range []struct{ label, source, allowed string }{
		{"member of the receiver lambda", "package app\nclass Ctx { fun put(x: Any) {} }\nfun f() { Ctx().apply { put(1) } }\n", ""},
		{"member of an unresolvable lambda callee", "package app\nfun f() { mystery { secret } }\n", "mystery"},
		{"reified type parameter as a value", "package app\nclass Row { fun into(type: Any): Any? = null }\nclass Rows { fun map(f: (Row) -> Any?): Any? = null }\nobject Queries {\n    suspend inline fun <reified T> ids(rows: Rows): Any? {\n        val first = 1\n        return rows\n            .map { it.into(T::class) }\n    }\n}\n", ""},
		{"return to a lambda label", "package app\nclass Mono { fun contextWrite(f: (Int) -> Int): Int = f(1) }\nfun f(mono: Mono): Int {\n    val x = 1\n    return mono.contextWrite { v ->\n        return@contextWrite v + x\n    }\n}\n", ""},
		{"lambda parameter list on its own line", "package app\nfun f() { mystery {\n    x ->\n    secret\n} }\n", "mystery"},
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

// `every { ... } answers { secondArg() }`: the lambda belongs to an infix
// call, and its receiver is a member type of the left operand's type. The
// engine cannot name that receiver, so it must not prove secondArg unbound.
func TestScopeEngineAbstainsInsideAnInfixCallLambda(t *testing.T) {
	idx := scopeIndex(t, map[string]string{
		"mock/Stub.kt": "package mock\nclass Answers { fun secondArg(): Any = Unit }\nclass Stub { infix fun answers(block: Answers.() -> Any) {} }\nfun every(block: () -> Any): Stub = Stub()\n",
		"app/Use.kt":   "package app\n\nimport mock.every\n\nclass Use {\n    fun run() {\n        every { 1 } answers {\n            secondArg()\n        }\n    }\n}\n",
	})
	for _, name := range unresolvedNames(idx, "file:///workspace/app/Use.kt") {
		if name == "secondArg" {
			t.Fatalf("secondArg inside an infix call's lambda was reported unresolved")
		}
	}
}

// `when (this) { is Fixed -> overrides }` refines the implicit receiver, so
// the subtype's members are bound in that branch.
func TestScopeEngineSeesMembersOfASmartCastReceiver(t *testing.T) {
	idx := scopeIndex(t, map[string]string{
		"app/Cells.kt": "package app\n\nsealed class Cell\nclass Fixed(val overrides: Int) : Cell()\nclass Empty : Cell()\n\nfun Cell.glass(): Int? = when (this) {\n    is Fixed -> overrides\n    else -> null\n}\n",
	})
	for _, name := range unresolvedNames(idx, "file:///workspace/app/Cells.kt") {
		if name == "overrides" {
			t.Fatalf("a member of the smart-cast receiver was reported unresolved")
		}
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files["file:///workspace/app/Cells.kt"]
	for _, reference := range file.References {
		if reference.Name == "overrides" && reference.Role == analysis.RoleRead {
			if resolved := idx.resolveLocked(context.Background(), file, reference); len(resolved) != 1 || resolved[0].Name != "overrides" {
				t.Fatalf("overrides resolved to %v", resolved)
			}
			return
		}
	}
	t.Fatal("no overrides reference")
}
