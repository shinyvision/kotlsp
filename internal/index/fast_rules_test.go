package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// kotlspFindings returns predictions only.
func kotlspFindings(idx *Index, uri protocol.URI) []protocol.Diagnostic {
	out := make([]protocol.Diagnostic, 0, 4)
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Source == "kotlsp" && isFastDiagnostic(diagnostic) {
			out = append(out, diagnostic)
		}
	}
	return out
}

func ruleIndex(t *testing.T, source string) (*Index, protocol.URI) {
	t.Helper()
	idx := New(nil)
	t.Cleanup(idx.Close)
	openKotlinBuiltins(idx)
	uri := protocol.URI("file:///workspace/app/Probe.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.markReady()
	return idx, uri
}

// Each prediction carries the compiler's own code and wording, verbatim from
// a captured compiler run, so the finding that confirms it changes nothing.
func TestFastRulesPredictTheCompilersExactMessages(t *testing.T) {
	for _, fixture := range []struct{ label, source, code, message string }{
		{"initializer", "package app\nfun f() { val s: String = 1 }\n", "INITIALIZER_TYPE_MISMATCH", "Initializer type mismatch: expected 'String', actual 'Int'."},
		{"initializer double", "package app\nfun f() { val d: Double = 1 }\n", "INITIALIZER_TYPE_MISMATCH", "Initializer type mismatch: expected 'Double', actual 'Int'."},
		{"initializer char", "package app\nfun f() { val c: Char = \"a\" }\n", "INITIALIZER_TYPE_MISMATCH", "Initializer type mismatch: expected 'Char', actual 'String'."},
		{"assignment", "package app\nfun f() { var s: String = \"\"; s = 1 }\n", "ASSIGNMENT_TYPE_MISMATCH", "Assignment type mismatch: actual type is 'Int', but 'String' was expected."},
		{"return expression", "package app\nfun f(): String = 1\n", "RETURN_TYPE_MISMATCH", "Return type mismatch: expected 'String', actual 'Int'."},
		{"return block", "package app\nfun f(): String { return 1 }\n", "RETURN_TYPE_MISMATCH", "Return type mismatch: expected 'String', actual 'Int'."},
		{"argument", "package app\nfun g(x: Int) = x\nfun f() = g(\"s\")\n", "ARGUMENT_TYPE_MISMATCH", "Argument type mismatch: actual type is 'String', but 'Int' was expected."},
		{"missing argument", "package app\nfun g(x: Int, y: String = \"\") = x\nfun f() = g()\n", "NO_VALUE_FOR_PARAMETER", "No value passed for parameter 'x'."},
		{"overrides nothing", "package app\nopen class P { open fun a() {} }\nclass C : P() { override fun b() {} }\n", "NOTHING_TO_OVERRIDE", "'b' overrides nothing."},
		{"abstract member", "package app\ninterface S { fun area(): Int }\nclass Sq : S\n", "ABSTRACT_MEMBER_NOT_IMPLEMENTED", "Class 'Sq' is not abstract and does not implement abstract member:"},
		{"no type no init", "package app\nfun f() { val q }\n", "VARIABLE_WITH_NO_TYPE_NO_INITIALIZER", "This variable must either have an explicit type or be initialized."},
		{"no body", "package app\nfun f(): Int\n", "NON_MEMBER_FUNCTION_NO_BODY", "Function 'f' must have a body."},
		{"uninitialised property", "package app\nclass H { val h: Int }\n", "MUST_BE_INITIALIZED_OR_BE_ABSTRACT", "Property must be initialized or be abstract."},
		{"val reassigned", "package app\nfun f() { val x = 1; x = 2 }\n", "VAL_REASSIGNMENT", "'val' cannot be reassigned."},
		{"class redeclared", "package app\nclass D\nclass D\n", "CLASSIFIER_REDECLARATION", "Redeclaration:"},
		{"function redeclared", "package app\nfun a() = 1\nfun a() = 2\n", "CONFLICTING_OVERLOADS", "Conflicting overloads:"},
		{"supertype not initialised", "package app\nopen class B\nclass C : B\n", "SUPERTYPE_NOT_INITIALIZED", "This type has a constructor, so it must be initialized here."},
		{"abstract supertype not initialised", "package app\nabstract class B\nclass C : B\n", "SUPERTYPE_NOT_INITIALIZED", "This type has a constructor, so it must be initialized here."},
		{"final supertype", "package app\nclass B\nclass C : B()\n", "FINAL_SUPERTYPE", "This type is final, so it cannot be extended."},
		{"hidden member", "package app\nopen class B { open fun f() {} }\nclass C : B() { fun f() {} }\n", "VIRTUAL_MEMBER_HIDDEN", "'f' hides member of supertype 'B' and needs an 'override' modifier."},
		{"hidden property", "package app\nopen class B { open val p: Int = 1 }\nclass C : B() { val p: Int = 2 }\n", "VIRTUAL_MEMBER_HIDDEN", "'p' hides member of supertype 'B' and needs an 'override' modifier."},
		{"overriding final", "package app\nopen class B { fun g() {} }\nclass C : B() { override fun g() {} }\n", "OVERRIDING_FINAL_MEMBER", "'g' in 'B' is final and cannot be overridden."},
		{"member without body", "package app\nclass C { fun h() }\n", "NON_ABSTRACT_FUNCTION_WITH_NO_BODY", "Function 'h' without a body must be abstract."},
		{"abstract in concrete", "package app\nclass C { abstract fun h() }\n", "ABSTRACT_FUNCTION_IN_NON_ABSTRACT_CLASS", "Abstract function 'h' in non-abstract class 'C'."},
		{"untyped uninitialised property", "package app\nclass C { val v }\n", "MUST_BE_INITIALIZED_OR_BE_ABSTRACT", "Property must be initialized or be abstract."},
		{"lateinit primitive", "package app\nclass C { lateinit var a: Int }\n", "INAPPLICABLE_LATEINIT_MODIFIER", "'lateinit' modifier is not allowed on properties of primitive types."},
		{"lateinit nullable", "package app\nclass C { lateinit var b: String? }\n", "INAPPLICABLE_LATEINIT_MODIFIER", "'lateinit' modifier is not allowed on properties of a type with nullable upper bound."},
		{"lateinit initialised", "package app\nclass C { lateinit var c: String = \"x\" }\n", "INAPPLICABLE_LATEINIT_MODIFIER", "'lateinit' modifier is not allowed on properties with initializer."},
		{"lateinit val", "package app\nclass C { lateinit val d: String }\n", "INAPPLICABLE_LATEINIT_MODIFIER", "'lateinit' modifier is allowed only on mutable properties."},
		{"two companions", "package app\nclass C { companion object A; companion object B }\n", "MANY_COMPANION_OBJECTS", "Only one companion object is allowed per class."},
		{"data class without parameters", "package app\ndata class D\n", "DATA_CLASS_WITHOUT_PARAMETERS", "Data class must have at least one primary constructor parameter."},
		{"data class plain parameter", "package app\ndata class D(x: Int)\n", "DATA_CLASS_NOT_PROPERTY_PARAMETER", "Primary constructor of data class must only have property ('val' / 'var') parameters."},
		{"missing return", "package app\nfun f(): Int { val x = 1 }\n", "NO_RETURN_IN_FUNCTION_WITH_BLOCK_BODY", "Missing return statement."},
		{"missing return after call", "package app\nfun g() = 1\nfun f(): Int {\n    g()\n}\n", "NO_RETURN_IN_FUNCTION_WITH_BLOCK_BODY", "Missing return statement."},
		{"bare return", "package app\nfun f(): Int { return }\n", "RETURN_TYPE_MISMATCH", "Return type mismatch: expected 'Int', actual 'Unit'."},
		{"value returned from unit", "package app\nfun f() { return 1 }\n", "RETURN_TYPE_MISMATCH", "Return type mismatch: expected 'Unit', actual 'Int'."},
		{"if without else", "package app\nfun f(c: Boolean) { val x = if (c) 1 }\n", "INVALID_IF_AS_EXPRESSION", "'if' must have both main and 'else' branches when used as an expression."},
		{"if body without else", "package app\nfun f(c: Boolean): Int = if (c) 1\n", "INVALID_IF_AS_EXPRESSION", "'if' must have both main and 'else' branches when used as an expression."},
		{"unsafe call", "package app\nfun f(s: String?) = s.length\n", "UNSAFE_CALL", "Only safe (?.) or non-null asserted (!!.) calls are allowed on a nullable receiver of type 'String?'."},
		{"null for non-null", "package app\nfun f() { val s: String = null }\n", "NULL_FOR_NONNULL_TYPE", "Null cannot be a value of a non-null type 'String'."},
		{"null returned", "package app\nfun f(): String { return null }\n", "NULL_FOR_NONNULL_TYPE", "Null cannot be a value of a non-null type 'String'."},
		{"condition int", "package app\nfun f(x: Int) { if (x) {} }\n", "CONDITION_TYPE_MISMATCH", "Condition type mismatch: inferred type is 'Int' but 'Boolean' was expected."},
		{"break outside loop", "package app\nfun f() { break }\n", "BREAK_OR_CONTINUE_OUTSIDE_A_LOOP", "'break' and 'continue' are only allowed inside loops."},
		{"abstract instantiated", "package app\nabstract class A\nfun f() { A() }\n", "CREATING_AN_INSTANCE_OF_ABSTRACT_CLASS", "Cannot create an instance of an abstract class."},
		{"enum instantiated", "package app\nenum class E { X }\nfun f() { E() }\n", "ENUM_CLASS_CONSTRUCTOR_CALL", "Enum types cannot be instantiated."},
		{"interface called", "package app\ninterface I\nfun f() { I() }\n", "INTERFACE_AS_FUNCTION", "Interface 'interface I : Any' does not have constructors."},
	} {
		idx, uri := ruleIndex(t, fixture.source)
		found := kotlspFindings(idx, uri)
		matched := false
		for _, diagnostic := range found {
			if code, _ := diagnostic.Code.(string); code == fixture.code && diagnostic.Message == fixture.message {
				matched = true
			}
		}
		if !matched {
			got := make([]string, 0, len(found))
			for _, diagnostic := range found {
				got = append(got, diagnostic.Code.(string)+": "+diagnostic.Message)
			}
			t.Errorf("%s: wanted %s %q, got %s", fixture.label, fixture.code, fixture.message, strings.Join(got, " | "))
		}
	}
}

// Every one of these is one step from an error and compiles. A prediction here
// is a false positive, and the rules exist only under the promise of none.
func TestFastRulesStaySilentOnNearMisses(t *testing.T) {
	for _, fixture := range []struct{ label, source string }{
		{"int widens to long", "package app\nval l: Long = 1\n"},
		{"matching literal", "package app\nval s: String = \"x\"\n"},
		{"nullable declared type", "package app\nval s: String? = 1\n"},
		{"user type named String", "package app\nclass String\nval s: String = 1\n"},
		{"default parameter", "package app\nfun g(x: Int = 1) = x\nfun f() = g()\n"},
		{"supertype initialised", "package app\nopen class B\nclass C : B()\n"},
		{"secondary constructor initialises supertype", "package app\nopen class B\nclass C : B { constructor() : super() }\n"},
		{"interface supertype without parens", "package app\ninterface B\nclass C : B\n"},
		{"annotated class may be open", "package app\n@Deprecated(\"\") class B\nclass C : B()\n"},
		{"sealed supertype", "package app\nsealed class B\nclass C : B()\n"},
		{"override present", "package app\nopen class B { open fun f() {} }\nclass C : B() { override fun f() {} }\n"},
		{"overload not hiding", "package app\nopen class B { open fun f() {} }\nclass C : B() { fun f(x: Int) {} }\n"},
		{"private member not hidden", "package app\nopen class B { private fun f() {} }\nclass C : B() { fun f() {} }\n"},
		{"generic supertype member", "package app\nopen class B<T> { open fun f(x: T) {} }\nclass C : B<Int>() { fun f(x: Int) {} }\n"},
		{"overriding open member", "package app\nopen class B { open fun g() {} }\nclass C : B() { override fun g() {} }\n"},
		{"overriding an override", "package app\nopen class A { open fun g() {} }\nopen class B : A() { override fun g() {} }\nclass C : B() { override fun g() {} }\n"},
		{"interface member without body", "package app\ninterface I { fun h() }\n"},
		{"abstract in abstract", "package app\nabstract class C { abstract fun h() }\n"},
		{"external member", "package app\nclass C { external fun h() }\n"},
		{"lateinit ok", "package app\nclass C { lateinit var s: String }\n"},
		{"lateinit two problems", "package app\nclass C { lateinit val a: Int }\n"},
		{"one companion", "package app\nclass C { companion object }\n"},
		{"data class ok", "package app\ndata class D(val x: Int)\n"},
		{"data class vararg", "package app\ndata class D(val x: Int, vararg y: Int)\n"},
		{"return present", "package app\nfun f(): Int { return 1 }\n"},
		{"throw ends flow", "package app\nfun f(): Int { throw Exception() }\n"},
		{"todo ends flow", "package app\nfun f(): Int { TODO() }\n"},
		{"never-returning workspace call", "package app\nfun boom(): Nothing = throw Exception()\nfun f(): Int { boom() }\n"},
		{"infinite loop", "package app\nfun f(): Int { while (true) { } }\n"},
		{"unit block", "package app\nfun f(): Unit { val x = 1 }\n"},
		{"expression body", "package app\nfun f(): Int = 1\n"},
		{"if with else", "package app\nfun f(c: Boolean) { val x = if (c) 1 else 2 }\n"},
		{"if with else on next line", "package app\nfun f(c: Boolean) { val x = if (c) 1\n else 2 }\n"},
		{"if statement", "package app\nfun f(c: Boolean) { if (c) println(1) }\n"},
		{"safe call", "package app\nfun f(s: String?) = s?.length\n"},
		{"smart cast", "package app\nfun f(s: String?): Int { if (s == null) return 0; return s.length }\n"},
		{"nullable extension", "package app\nfun String?.orEmpty2(): String = \"\"\nfun f(s: String?) = s.orEmpty2()\n"},
		{"unknown member on nullable", "package app\nfun f(s: String?) = s.nothingHere\n"},
		{"null for nullable", "package app\nfun f() { val s: String? = null }\n"},
		{"boolean condition", "package app\nfun f(b: Boolean) { if (b) {} }\n"},
		{"break in loop", "package app\nfun f() { while (true) { break } }\n"},
		{"break in when in loop", "package app\nfun f(x: Int) { for (i in 0..1) { when (x) { 1 -> break } } }\n"},
		{"abstract anonymous object", "package app\nabstract class A\nfun f() { val o = object : A() {} }\n"},
		{"abstract shadowed by function", "package app\nabstract class A\nfun A() = 1\nfun f() { A() }\n"},
		{"companion invoke", "package app\nabstract class A { companion object { operator fun invoke() = 1 } }\nfun f() { A() }\n"},
		{"interface with supertype", "package app\ninterface J\ninterface I : J\nfun f() { I() }\n"},
		{"named argument", "package app\nfun g(a: Int, b: Int) = a\nfun f() = g(b = 1, a = 2)\n"},
		{"vararg", "package app\nfun g(vararg xs: Int) = 1\nfun f() = g()\n"},
		{"overloaded callee", "package app\nfun g(x: Int) = x\nfun g(x: Int, y: Int) = x\nfun f() = g()\n"},
		{"trailing lambda counts", "package app\nfun g(x: Int, block: () -> Int) = x\nfun f() = g(1) { 2 }\n"},
		{"override of inherited", "package app\nopen class P { open fun a() {} }\nclass C : P() { override fun a() {} }\n"},
		{"override of Any", "package app\nclass C { override fun toString() = \"\" }\n"},
		{"unresolved supertype abstains", "package app\nclass C : Unknown() { override fun b() {} }\n"},
		{"interface default body", "package app\ninterface S { fun f(): Int = 1 }\nclass C : S\n"},
		{"implemented via override", "package app\ninterface S { fun f(): Int }\nclass C : S { override fun f() = 1 }\n"},
		{"delegated", "package app\ninterface S { fun f(): Int }\nclass C(i: S) : S by i\n"},
		{"abstract class", "package app\ninterface S { fun f(): Int }\nabstract class C : S\n"},
		{"lateinit", "package app\nclass H { lateinit var s: String }\n"},
		{"getter", "package app\nclass H { val g: Int get() = 1 }\n"},
		{"constructor property", "package app\nclass H(val c: Int)\n"},
		{"interface property", "package app\ninterface H { val c: Int }\n"},
		{"destructuring", "package app\nfun f() { val (a, b) = 1 to 2 }\n"},
		{"loop variable", "package app\nfun f(xs: List<Int>) { for (x in xs) {} }\n"},
		{"expression body function", "package app\nfun f() = 1\n"},
		{"external function", "package app\nexternal fun f(): Int\n"},
		{"var reassigned", "package app\nfun f() { var x = 1; x = 2 }\n"},
		{"block body with nested block abstains", "package app\nfun f(c: Boolean): String { if (c) { return 1 }; return \"\" }\n"},
	} {
		idx, uri := ruleIndex(t, fixture.source)
		for _, diagnostic := range kotlspFindings(idx, uri) {
			code, _ := diagnostic.Code.(string)
			if code == "UNRESOLVED_REFERENCE" {
				// The stub standard library is minimal; unresolved names are
				// not what these cases are about.
				continue
			}
			t.Errorf("%s: predicted %s %q on compiling code", fixture.label, code, diagnostic.Message)
		}
	}
}

// A build script resolves its names against Gradle's classpath, which the index
// never sees, and the compiler pass never compiles it. Every prediction there
// would be unconfirmable, so none may be made.
func TestPredictionsAbstainOnScripts(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	openKotlinBuiltins(idx)
	uri := protocol.URI("file:///workspace/build.gradle.kts")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1,
		Text: "plugins { id(\"x\") }\nrepositories { mavenCentral() }\nval unknown: Missing = 1\n",
	})
	idx.markReady()
	if found := kotlspFindings(idx, uri); len(found) != 0 {
		t.Fatalf("predicted on a build script: %#v", found)
	}
}

// A named argument to a callee that cannot be resolved yields one finding, on
// the callee. The label is not a reference in its own right.
func TestArgumentLabelsAreNotReportedAsUnresolved(t *testing.T) {
	idx, uri := ruleIndex(t, "package app\nfun f() = unknownFn(label = 1)\n")
	for _, diagnostic := range kotlspFindings(idx, uri) {
		if strings.Contains(diagnostic.Message, "'label'") {
			t.Fatalf("the argument label was reported as unresolved: %#v", diagnostic)
		}
	}
	found := false
	for _, diagnostic := range kotlspFindings(idx, uri) {
		if diagnostic.Message == "Unresolved reference 'unknownFn'." {
			found = true
		}
	}
	if !found {
		t.Fatal("the unresolved callee itself was not reported")
	}
}
