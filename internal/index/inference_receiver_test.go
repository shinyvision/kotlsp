package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

var receiverStubs = []struct{ name, text string }{
	{"String.kt", `package kotlin
public class String {
    public val length: Int
    public fun isEmpty(): Boolean
}
public class Int
public class Boolean
public class Char { public val code: Int }
public open class Any {
    public open fun toString(): String
    public open fun equals(other: Any?): Boolean
    public open fun hashCode(): Int
}
public abstract class Enum<E : Enum<E>> {
    public val name: String
    public val ordinal: Int
}
public class Array<T> {
    public val size: Int
    public operator fun get(index: Int): T
}
public inline fun <reified T : Enum<T>> enumValues(): Array<T>
`},
	{"Collections.kt", `package kotlin.collections
public interface List<out E> {
    public val size: Int
    public operator fun get(index: Int): E
}
public interface Map<K, out V> { public val size: Int }
public fun <T> listOf(element: T): List<T>
public fun <T> listOf(vararg elements: T): List<T>
public fun <T> List<T>.first(): T
public fun <T> Array<out T>.first(): T
public fun <T> Array<out T>.toList(): List<T>
public fun <K, V> mapOf(pair: Pair<K, V>): Map<K, V>
`},
}

func inferenceFixture(t *testing.T) (*Index, *analysis.ParsedFile, int) {
	t.Helper()
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	for _, stub := range receiverStubs {
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(protocol.URI("file:///libs/stdlib/"+stub.name), "kotlin", 0, stub.text))
		idx.AddLibraryBatch([]LibraryFile{{
			Source: LibrarySource{Archive: "/deps/kotlin-stdlib.jar", Entry: stub.name, LanguageID: "kotlin"},
			Parsed: *parsed,
		}})
	}
	uri := protocol.URI("file:///workspace/Use.kt")
	source := `package app

enum class Color { RED, GREEN; fun label(): String = name }

class Box {
    fun open(): Boolean = true
    val size: Int = 1
    fun self(): Box = this
    companion object { fun standard(): Box = Box() }
}

class Holder<T>(val value: T) {
    fun get(): T = value
}

fun makeBox(): Box = Box()
fun <T> holder(): Holder<T> = Holder<T>(TODO())
fun <T> wrap(value: T): Holder<T> = Holder(value)

fun use(box: Box, color: Color) {
    val marker = 0
}
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	t.Cleanup(idx.mu.RUnlock)
	file := idx.files[uri]
	if file == nil {
		t.Fatal("document not indexed")
	}
	return idx, file, strings.Index(source, "val marker")
}

func TestReceiverTypeInference(t *testing.T) {
	ctx := context.Background()
	idx, file, at := inferenceFixture(t)
	for _, c := range []struct{ expression, want string }{
		{"makeBox()", "Box"},
		{"Box()", "Box"},
		{"box", "Box"},
		{"color", "Color"},
		{"Color.RED", "Color"},
		{"Color.GREEN", "Color"},
		{`"abc"`, "String"},
		{"'c'", "Char"},
		{"1", "Int"},
		{"holder<Color>()", "Holder<Color>"},
		{"wrap(Color.RED)", "Holder<Color>"},
		{"wrap(box)", "Holder<Box>"},
		{"wrap(makeBox())", "Holder<Box>"},
		{"wrap(Color.RED).get()", "Color"},
		{"wrap(Color.RED).value", "Color"},
		{"listOf(1)", "List<Int>"},
		{"listOf(Color.RED)", "List<Color>"},
		{"listOf(box)", "List<Box>"},
		{"listOf(box).first()", "Box"},
		{"enumValues<Color>()", "Array<Color>"},
		{"enumValues<Color>().first()", "Color"},
		{"Box.standard()", "Box"},
		{"box.self().self()", "Box"},
	} {
		got := idx.inferExpressionResultLocked(ctx, file, c.expression, at).Type
		if got != c.want {
			t.Errorf("%-34s -> %-16q want %q", c.expression, got, c.want)
		}
	}
}
