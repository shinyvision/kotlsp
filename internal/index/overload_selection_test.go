package index

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// Overloads of a library function are chosen by what the call passes, never
// by where in the library's class file they sit, and an extension taking a
// lambda is not rejected by the lambda's own spelling.
func TestOverloadSelectionShapesFromJooq(t *testing.T) {
	ctx := context.Background()
	sources := map[string]string{
		"org/jooq/Record":          "package org.jooq;\npublic interface Record {}\n",
		"org/jooq/RecordMapper":    "package org.jooq;\npublic interface RecordMapper<R, E> { E map(R record); }\n",
		"org/jooq/OrderField":      "package org.jooq;\npublic interface OrderField<T> {}\n",
		"org/jooq/SortField":       "package org.jooq;\npublic interface SortField<T> extends OrderField<T> {}\n",
		"org/jooq/OrderFields":     "package org.jooq;\npublic interface OrderFields {}\n",
		"org/jooq/SelectSeekStep1": "package org.jooq;\npublic interface SelectSeekStep1<R, T1> {}\n",
		"org/jooq/SelectSeekStepN": "package org.jooq;\npublic interface SelectSeekStepN<R> {}\n",
		"org/jooq/SelectOrderByStep": `package org.jooq;
public interface SelectOrderByStep<R extends Record> {
    <T1> SelectSeekStep1<R, T1> orderBy(OrderField<T1> field1);
    SelectSeekStepN<R> orderBy(OrderFields fields);
    SelectSeekStepN<R> orderBy(OrderField<?>... fields);
}
`,
	}
	// Twelve `mapping` overloads, so the ones for longer callable references
	// sit far into the rendered class -- beyond any offset in the small file
	// below, which is what used to rank them out.
	var records strings.Builder
	records.WriteString("package org.jooq;\npublic final class Records {\n")
	for arity := 1; arity <= 12; arity++ {
		var types, parameters []string
		for n := 1; n <= arity; n++ {
			types = append(types, fmt.Sprintf("T%d", n))
			parameters = append(parameters, fmt.Sprintf("? super T%d", n))
		}
		function := fmt.Sprintf("Function%d", arity)
		sources["org/jooq/"+function] = fmt.Sprintf("package org.jooq;\npublic interface %s<%s, R> { R apply(%s); }\n", function, strings.Join(types, ", "), strings.Join(argumentList(types), ", "))
		// Each answers its own type, as jOOQ's answer RecordMapper<RecordN<...>, R>.
		mapper := fmt.Sprintf("Mapper%d", arity)
		sources["org/jooq/"+mapper] = fmt.Sprintf("package org.jooq;\npublic interface %s<R> extends RecordMapper<Record, R> {}\n", mapper)
		records.WriteString(fmt.Sprintf("    public static <%s, R> %s<R> mapping(%s<%s, ? extends R> function) { return null; }\n", strings.Join(types, ", "), mapper, function, strings.Join(parameters, ", ")))
	}
	records.WriteString("}\n")
	sources["org/jooq/Records"] = records.String()

	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	jooq := writeTestArchive(t, "jooq.jar", compileTestClasses(t, sources))
	if complete := idx.indexSourceArchive(ctx, sourceArchive{path: jooq, binary: true, release: idx.javaReleaseForLibrary(jooq)}, 0, func(int64) {}); !complete {
		t.Fatal("the jOOQ stand-in jar did not index completely")
	}
	stdlib := `package kotlin.collections
public interface Iterable<out T>
public interface List<out E> : Iterable<E>
public fun <T> listOf(vararg elements: T): List<T>
public inline fun <T> Iterable<T>.filter(predicate: (T) -> Boolean): List<T>
public inline fun <T, R : Any> Iterable<T>.mapNotNull(transform: (T) -> R?): List<R>
`
	parsed := analysis.Parse(ctx, textdoc.NewDocument(protocol.URI("file:///libs/kotlin/collections/Collections.kt"), "kotlin", 0, stdlib))
	idx.AddLibraryBatch([]LibraryFile{{
		Source: LibrarySource{Archive: "/deps/kotlin-stdlib-sources.jar", Entry: "kotlin/collections/Collections.kt", LanguageID: "kotlin"},
		Parsed: *parsed,
	}})

	uri := protocol.URI("file:///workspace/Use.kt")
	source := `package app
import org.jooq.Records.mapping
fun use(query: org.jooq.SelectOrderByStep<org.jooq.Record>, sort: org.jooq.SortField<Int>, rows: List<org.jooq.Record>) {
    val records = rows.mapNotNull { Rec.create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) }
    val marker = 0
}
data class Rec(val id: Int) {
    companion object {
        fun create(a: Int?, b: Int?, c: Int?, d: Int?, e: Int?, f: Int?, g: Int?, h: Int?, i: Int?, j: Int?): Rec = Rec(a!!)
    }
}
`
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	at := strings.Index(source, "val marker")
	for expression, want := range map[string]string{
		// Ten parameters: only `mapping(Function10)` fits. The call is not in
		// the source, so only its text says what it passes.
		"mapping(Rec::create)": "org.jooq.Mapper10<Rec>",
		// A SortField is an OrderField and no OrderFields.
		"query.orderBy(sort)": "org.jooq.SelectSeekStep1<org.jooq.Record, Int>",
		// `{ true }` alone reads as `() -> Boolean`; passed to filter it is a
		// `(T) -> Boolean`.
		"listOf(1).filter { true }": "List<Int>",
		// A `(T) -> R?` lambda answering a non-null Rec binds R to Rec.
		"records": "List<Rec>",
	} {
		if got := idx.inferExpressionTypeLocked(ctx, file, expression, at); got != want {
			t.Errorf("%s: got %q, want %q", expression, got, want)
		}
	}
}

func argumentList(types []string) []string {
	out := make([]string, len(types))
	for index, typ := range types {
		out[index] = fmt.Sprintf("%s t%d", typ, index+1)
	}
	return out
}
