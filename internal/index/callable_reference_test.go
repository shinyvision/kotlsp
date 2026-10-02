package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// jOOQ's `mapping(Rec::create).map(row)` and `insertInto(table)`: the
// overload follows the reference's arity, its result binds the mapper's type,
// and a fixed-arity overload wins over one spreading nothing into a vararg.
func TestCallableReferenceBindsJavaSamResult(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	// The jOOQ stand-ins are compiled into a jar, because jOOQ arrives as
	// class files: their member types are spelled in full, unlike sources.
	classes := compileTestClasses(t, map[string]string{
		"org/jooq/Function1":    "package org.jooq;\npublic interface Function1<T1, R> { R apply(T1 t1); }\n",
		"org/jooq/Function2":    "package org.jooq;\npublic interface Function2<T1, T2, R> { R apply(T1 t1, T2 t2); }\n",
		"org/jooq/Record1":      "package org.jooq;\npublic interface Record1<T1> {}\n",
		"org/jooq/Record2":      "package org.jooq;\npublic interface Record2<T1, T2> {}\n",
		"org/jooq/RecordMapper": "package org.jooq;\npublic interface RecordMapper<R, E> { E map(R record); }\n",
		"org/jooq/Records": `package org.jooq;
public final class Records {
    public static <T1, R> RecordMapper<Record1<T1>, R> mapping(Function1<? super T1, ? extends R> function) { return null; }
    public static <T1, T2, R> RecordMapper<Record2<T1, T2>, R> mapping(Function2<? super T1, ? super T2, ? extends R> function) { return null; }
}
`,
		"org/jooq/InsertSetStep":     "package org.jooq;\npublic interface InsertSetStep<R> {}\n",
		"org/jooq/InsertValuesStep1": "package org.jooq;\npublic interface InsertValuesStep1<R, T1> {}\n",
		"org/jooq/InsertValuesStep2": "package org.jooq;\npublic interface InsertValuesStep2<R, T1, T2> {}\n",
		"org/jooq/InsertValuesStepN": "package org.jooq;\npublic interface InsertValuesStepN<R> {}\n",
		"org/jooq/DSLContext": `package org.jooq;
public interface DSLContext {
    <R extends Record> InsertSetStep<R> insertInto(Table<R> into);
    <R extends Record> InsertValuesStepN<R> insertInto(Table<R> into, Field<?>... fields);
    <R extends Record> InsertValuesStepN<R> insertInto(Table<R> into, java.util.Collection<? extends Field<?>> fields);
    <R extends Record, T1> InsertValuesStep1<R, T1> insertInto(Table<R> into, Field<T1> field1);
    <R extends Record, T1, T2> InsertValuesStep2<R, T1, T2> insertInto(Table<R> into, Field<T1> field1, Field<T2> field2);
}
`,
		"org/jooq/Record":             "package org.jooq;\npublic interface Record {}\n",
		"org/jooq/impl/TableImpl":     "package org.jooq.impl;\npublic class TableImpl<R extends org.jooq.Record> extends AbstractTable<R> {}\n",
		"org/jooq/impl/AbstractTable": "package org.jooq.impl;\npublic abstract class AbstractTable<R extends org.jooq.Record> implements org.jooq.Table<R> {}\n",
		"org/jooq/Configuration":      "package org.jooq;\npublic interface Configuration { DSLContext dsl(); }\n",
		"org/jooq/Table":              "package org.jooq;\npublic interface Table<R extends Record> {}\n",
		"org/jooq/Field":              "package org.jooq;\npublic interface Field<T> {}\n",
	})
	jooq := writeTestArchive(t, "jooq.jar", classes)
	if complete := idx.indexSourceArchive(ctx, sourceArchive{path: jooq, binary: true, release: idx.javaReleaseForLibrary(jooq)}, 0, func(int64) {}); !complete {
		t.Fatal("the jOOQ stand-in jar did not index completely")
	}
	standard := analysis.Parse(ctx, textdoc.NewDocument(protocol.URI("file:///libs/kotlin/Standard.kt"), "kotlin", 0, "package kotlin\npublic inline fun <T, R> T.let(block: (T) -> R): R\n"))
	idx.AddLibraryBatch([]LibraryFile{{
		Source: LibrarySource{Archive: "/deps/kotlin-stdlib-sources.jar", Entry: "kotlin/Standard.kt", LanguageID: "kotlin"},
		Parsed: *standard,
	}})
	uri := protocol.URI("file:///workspace/Use.kt")
	source := `package app

import org.jooq.DSLContext
import tables.PRODUCT_TYPES
import org.jooq.Record2
import org.jooq.Records.mapping

data class Rec(val id: String, val name: String?) {
    companion object {
        fun create(id: String?, name: String?): Rec = Rec(id!!, name)
    }
}

fun use(trx: org.jooq.Configuration, dsl: DSLContext, table: org.jooq.Table<Rec>, row: Record2<String?, String?>?) {
    row?.let { mapping(Rec::create).map(it) }
        ?.let { record ->
            record.id
        }
}
`
	// jOOQ generates each table in a file of its own, with its own imports.
	tables := `package tables

import org.jooq.Record
import org.jooq.impl.TableImpl

open class ProductTypes : TableImpl<Record>()
val PRODUCT_TYPES = ProductTypes()
`
	idx.Open(ctx, protocol.TextDocumentItem{URI: "file:///workspace/ProductTypes.kt", LanguageID: "kotlin", Version: 1, Text: tables})
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	at := strings.Index(source, "record.id")
	for expression, want := range map[string]string{
		"mapping(Rec::create)":                      "org.jooq.RecordMapper<org.jooq.Record2<*, *>, Rec>",
		"row?.let { mapping(Rec::create).map(it) }": "Rec?",
		"dsl.insertInto(table)":                     "org.jooq.InsertSetStep<Rec>",
		"dsl.insertInto(PRODUCT_TYPES)":             "org.jooq.InsertSetStep<org.jooq.Record>",
		"trx.dsl().insertInto(PRODUCT_TYPES)":       "org.jooq.InsertSetStep<org.jooq.Record>",
		"record":                                    "Rec",
	} {
		if got := idx.inferExpressionResultLocked(ctx, file, expression, at).Type; got != want {
			t.Errorf("%s: got %q, want %q", expression, got, want)
		}
	}
	for _, reference := range file.References {
		if reference.Name == "id" && reference.Qualifier == "record" {
			if targets := idx.resolveLocked(ctx, file, reference); len(targets) != 1 || targets[0].FQN != "app.Rec.id" {
				t.Errorf("record.id resolves to %v", targets)
			}
		}
	}
}
