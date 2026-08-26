package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

const javaLangStub = `package java.lang;
public class Object { public String toString() { return null; } public boolean equals(Object o) { return false; } public int hashCode() { return 0; } }
public final class String { public int length() { return 0; } }
public class Throwable {}
public class Exception extends Throwable {}
public class RuntimeException extends Exception {}
public class Error extends Throwable {}
public class IllegalStateException extends RuntimeException {}
public interface Runnable { void run(); }
public @interface Override {}
`

func javaRuleIndex(t *testing.T, source string) (*Index, protocol.URI) {
	t.Helper()
	idx := New(nil)
	t.Cleanup(idx.Close)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///stdlib/java/lang/Lang.java", LanguageID: "java", Version: 1, Text: javaLangStub})
	uri := protocol.URI("file:///workspace/app/Probe.java")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	idx.markReady()
	return idx, uri
}

func TestJavaRulesPredictJavacsExactMessages(t *testing.T) {
	for _, fixture := range []struct{ label, source, message string }{
		{"public class file name", "package app;\npublic class Other {}\n", "class Other is public, should be declared in a file named Other.java"},
		{"abstract not implemented", "package app;\nabstract class Base { abstract void b(String s, int i); }\nclass Impl extends Base { }\n", "Impl is not abstract and does not override abstract method b(String,int) in Base"},
		{"interface not implemented", "package app;\nclass Impl implements Runnable { }\n", "Impl is not abstract and does not override abstract method run() in Runnable"},
		{"assign final field", "package app;\nclass Fin { final int f = 1; void m() { f = 2; } }\n", "cannot assign a value to final variable f"},
		{"assign final param", "package app;\nclass Fin { void p(final int q) { q = 3; } }\n", "final parameter q may not be assigned"},
		{"assign final local", "package app;\nclass Fin { void p() { final int z = 1; z = 2; } }\n", "cannot assign a value to final variable z"},
		{"missing return value", "package app;\nclass R { int r() { return; } }\n", "incompatible types: missing return value"},
		{"unexpected return value", "package app;\nclass R { void v() { return 1; } }\n", "incompatible types: unexpected return value"},
		{"override nothing", "package app;\nclass Ov { @Override void x() {} }\n", "method does not override or implement a method from a supertype"},
		{"non-static variable", "package app;\nclass S { int inst; static void s() { inst = 1; } }\n", "non-static variable inst cannot be referenced from a static context"},
		{"non-static method", "package app;\nclass S { void im() {} static void s() { im(); } }\n", "non-static method im() cannot be referenced from a static context"},
		{"this in static", "package app;\nclass S { static void s() { this.toString(); } }\n", "non-static variable this cannot be referenced from a static context"},
		{"duplicate field", "package app;\nclass D { int d; int d; }\n", "variable d is already defined in class D"},
		{"duplicate method", "package app;\nclass D { void m2(String s) {} void m2(String s) {} }\n", "method m2(String) is already defined in class D"},
		{"duplicate local", "package app;\nclass D { void loc() { int a; int a; } }\n", "variable a is already defined in method loc()"},
		{"duplicate class", "package app;\nclass Dup2 {}\nclass Dup2 {}\n", "duplicate class: app.Dup2"},
		{"string to int", "package app;\nclass L { int i = \"s\"; }\n", "incompatible types: String cannot be converted to int"},
		{"int to string", "package app;\nclass L { String s = 1; }\n", "incompatible types: int cannot be converted to String"},
		{"double to int", "package app;\nclass L { int j = 1.5; }\n", "incompatible types: possible lossy conversion from double to int"},
		{"int to boolean", "package app;\nclass L { boolean b = 1; }\n", "incompatible types: int cannot be converted to boolean"},
		{"string to char", "package app;\nclass L { char c = \"c\"; }\n", "incompatible types: String cannot be converted to char"},
		{"double to float", "package app;\nclass L { float f = 1.5; }\n", "incompatible types: possible lossy conversion from double to float"},
		{"int to byte out of range", "package app;\nclass L { byte by = 200; }\n", "incompatible types: possible lossy conversion from int to byte"},
		{"long to int", "package app;\nclass L { int q = 1L; }\n", "incompatible types: possible lossy conversion from long to int"},
		{"null to int", "package app;\nclass L { int q = null; }\n", "incompatible types: <null> cannot be converted to int"},
		{"char to string", "package app;\nclass L { String s = 'c'; }\n", "incompatible types: char cannot be converted to String"},
		{"abstract instantiated", "package app;\nabstract class Base {}\nclass A { void n() { new Base(); } }\n", "Base is abstract; cannot be instantiated"},
		{"interface instantiated", "package app;\nclass A { void n() { new Runnable(); } }\n", "Runnable is abstract; cannot be instantiated"},
		{"missing return", "package app;\nclass R { int r() { int x = 1; } }\n", "missing return statement"},
		{"unreachable", "package app;\nclass U { void u() { return; int y = 1; } }\n", "unreachable statement"},
		{"unreachable after throw", "package app;\nclass U { void u() { throw new RuntimeException(); int y = 1; } }\n", "unreachable statement"},
		{"unreported exception", "package app;\nclass E { void n() { throw new Exception(); } }\n", "unreported exception Exception; must be caught or declared to be thrown"},
		{"primitive dereferenced", "package app;\nclass P { void n(int x) { x.foo(); } }\n", "int cannot be dereferenced"},
		{"cannot find symbol", "package app;\nclass Other { int hidden; }\nclass P { int n() { return hidden; } }\n", "cannot find symbol"},
	} {
		idx, uri := javaRuleIndex(t, fixture.source)
		found := kotlspFindings(idx, uri)
		matched := false
		for _, diagnostic := range found {
			if diagnostic.Message == fixture.message {
				matched = true
			}
		}
		if !matched {
			got := make([]string, 0, len(found))
			for _, diagnostic := range found {
				got = append(got, diagnostic.Message)
			}
			t.Errorf("%s: wanted %q, got %s", fixture.label, fixture.message, strings.Join(got, " | "))
		}
	}
}

func TestJavaRulesStaySilentOnNearMisses(t *testing.T) {
	for _, fixture := range []struct{ label, source string }{
		{"matching file name", "package app;\npublic class Probe {}\n"},
		{"abstract implemented", "package app;\nabstract class Base { abstract void b(); }\nclass Impl extends Base { void b() {} }\n"},
		{"abstract inherited implementation", "package app;\ninterface I { void b(); }\nabstract class Mid implements I { public void b() {} }\nclass Impl extends Mid { }\n"},
		{"two abstract methods missing", "package app;\nabstract class Base { abstract void a(); abstract void b(); }\nclass Impl extends Base { }\n"},
		{"final field assigned in constructor", "package app;\nclass Fin { final int f; Fin() { f = 1; } }\n"},
		{"final local assigned once", "package app;\nclass Fin { void p() { final int z; z = 2; } }\n"},
		{"returns match", "package app;\nclass R { int r() { return 1; } void v() { return; } }\n"},
		{"return inside lambda", "package app;\nclass R { void v() { Runnable r = () -> { return; }; } }\n"},
		{"override of Object method", "package app;\nclass Ov { @Override public String toString() { return null; } }\n"},
		{"override of interface method", "package app;\nclass Ov implements Runnable { @Override public void run() {} }\n"},
		{"static field from static", "package app;\nclass S { static int inst; static void s() { inst = 1; } }\n"},
		{"instance field from instance", "package app;\nclass S { int inst; void s() { inst = 1; } }\n"},
		{"anonymous class in static", "package app;\nclass S { static void s() { Runnable r = new Runnable() { int inst; public void run() { inst = 1; } }; } }\n"},
		{"overloads", "package app;\nclass D { void m() {} void m(int x) {} }\n"},
		{"locals in sibling blocks", "package app;\nclass D { void loc() { { int a; } { int a; } } }\n"},
		{"widening literals", "package app;\nclass L { long l = 1; double d = 1; float f = 1.5f; byte b = 100; char c = 'c'; String s = null; int i = 'c'; double e = 1e3; }\n"},
		{"concrete instantiated", "package app;\nclass Base {}\nclass A { void n() { new Base(); } }\n"},
		{"abstract anonymous", "package app;\nabstract class Base {}\nclass A { void n() { new Base() { }; } }\n"},
		{"return present", "package app;\nclass R { int r() { return 1; } }\n"},
		{"throw ends", "package app;\nclass R { int r() { throw new RuntimeException(); } }\n"},
		{"infinite loop", "package app;\nclass R { int r() { while (true) { } } }\n"},
		{"for loop", "package app;\nclass R { int r() { for (;;) { } } }\n"},
		{"if return", "package app;\nclass U { void u(boolean b) { if (b) return; int y = 1; } }\n"},
		{"else return", "package app;\nclass U { void u(boolean b) { if (b) b = false; else return; } }\n"},
		{"break before case", "package app;\nclass U { void u(int x) { switch (x) { case 1: break; case 2: break; default: break; } } }\n"},
		{"unchecked exception", "package app;\nclass E { void n() { throw new IllegalStateException(); } }\n"},
		{"declared exception", "package app;\nclass E { void n() throws Exception { throw new Exception(); } }\n"},
		{"caught exception", "package app;\nclass E { void n() { try { throw new Exception(); } catch (Exception e) { } } }\n"},
		{"exception in lambda", "package app;\nclass E { void n() { Runnable r = () -> { throw new Exception(); }; } }\n"},
		{"object dereferenced", "package app;\nclass P { void n(String x) { x.length(); } }\n"},
		{"sibling via import", "package app;\nimport static app.Other.hidden;\nclass Other { static int hidden; }\nclass P { int n() { return hidden; } }\n"},
	} {
		idx, uri := javaRuleIndex(t, fixture.source)
		if found := kotlspFindings(idx, uri); len(found) != 0 {
			got := make([]string, 0, len(found))
			for _, diagnostic := range found {
				got = append(got, diagnostic.Message)
			}
			t.Errorf("%s: false positive %s", fixture.label, strings.Join(got, " | "))
		}
	}
}
