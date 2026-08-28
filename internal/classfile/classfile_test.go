package classfile_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestParseAndRenderCompiledJavaClass(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "Sample.java")
	source := `package fixtures;
public final class Sample implements java.io.Serializable {
    public static final long serialVersionUID = 1L;
    private final String value;
    public Sample(String value) { this.value = value; }
    public String combine(int count, String suffix) { return value + count + suffix; }
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(javac, "-parameters", "-d", dir, sourcePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixtures", "Sample.class"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := classfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.InternalName != "fixtures/Sample" || parsed.SuperName != "java/lang/Object" {
		t.Fatalf("unexpected class identity: %#v", parsed)
	}
	if len(parsed.Interfaces) != 1 || parsed.Interfaces[0] != "java/io/Serializable" {
		t.Fatalf("interfaces = %#v", parsed.Interfaces)
	}
	var combineFound bool
	for _, method := range parsed.Methods {
		if method.Name == "combine" {
			combineFound = method.Descriptor == "(ILjava/lang/String;)Ljava/lang/String;" && strings.Join(method.ParameterNames, ",") == "count,suffix"
		}
	}
	if !combineFound {
		t.Fatalf("combine metadata missing: %#v", parsed.Methods)
	}

	rendered := classfile.RenderJava(parsed)
	for _, fragment := range []string{"package fixtures;", "final class Sample", "implements java.io.Serializable", "String combine(int count, java.lang.String suffix)"} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("rendered stub lacks %q:\n%s", fragment, rendered)
		}
	}
	file := analysis.Parse(context.Background(), textdoc.NewDocument("jar:///sample.jar!/fixtures/Sample.class", "java", 0, rendered))
	if len(file.Diagnostics) != 0 {
		t.Fatalf("rendered stub is not valid Java: %#v\n%s", file.Diagnostics, rendered)
	}
	if !hasSymbol(file.Symbols, "Sample") || !hasSymbol(file.Symbols, "combine") {
		t.Fatalf("rendered stub is not navigable: %#v", file.Symbols)
	}
}

func TestRejectsInvalidClass(t *testing.T) {
	if _, err := classfile.Parse([]byte("not a class")); err == nil {
		t.Fatal("invalid class file was accepted")
	}
}

func TestRenderManglesJvmIdentifiersThatAreJavaKeywords(t *testing.T) {
	class := &classfile.Class{
		InternalName: "fixtures/when",
		SuperName:    "java/lang/Object",
		Access:       0x0001,
		Fields:       []classfile.Field{{Name: "class", Descriptor: "I", Access: 0x0001}},
		Methods:      []classfile.Method{{Name: "switch", Descriptor: "(I)V", Access: 0x0001, ParameterNames: []string{"var"}}},
	}
	rendered := classfile.RenderJava(class)
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument("jar:///keywords.jar!/fixtures/when.class", "java", 0, rendered))
	if len(parsed.Diagnostics) != 0 {
		t.Fatalf("keyword-safe stub did not parse: %#v\n%s", parsed.Diagnostics, rendered)
	}
	for _, original := range []string{"when", "class", "switch", "var"} {
		safe := classfile.SourceJavaIdentifier(original)
		if !strings.Contains(rendered, safe) || classfile.RestoreSourceJavaIdentifiers(safe) != original {
			t.Fatalf("identifier %q was not reversibly rendered in:\n%s", original, rendered)
		}
	}
}

func TestRecoversParameterNamesFromLocalVariableTable(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "DebugNames.java")
	source := `package fixtures;
public class DebugNames {
    public long combine(long left, double right, String[] labels) { return left + (long) right + labels.length; }
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, compileErr := exec.Command(javac, "-g", "-d", dir, sourcePath).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixtures", "DebugNames.class"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := classfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range parsed.Methods {
		if method.Name == "combine" {
			if got := strings.Join(method.ParameterNames, ","); got != "left,right,labels" {
				t.Fatalf("LocalVariableTable parameter names = %q", got)
			}
			return
		}
	}
	t.Fatal("combine method missing")
}

func TestParsePreservesMethodAndParameterAnnotations(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "Annotated.java")
	source := `package fixtures;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS) @Target({ElementType.METHOD, ElementType.PARAMETER}) @interface Nullable {}
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE_USE) @interface TypeNullable {}
public class Annotated {
    @Nullable public String echo(@Nullable String value) { return value; }
    public @TypeNullable String typeEcho(@TypeNullable String value) { return value; }
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, compileErr := exec.Command(javac, "-parameters", "-d", dir, sourcePath).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixtures", "Annotated.class"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := classfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	echoFound, typeEchoFound := false, false
	for _, method := range parsed.Methods {
		if method.Name == "typeEcho" {
			typeEchoFound = true
			returnNullable, parameterNullable := false, false
			for _, annotation := range method.TypeAnnotations {
				returnNullable = returnNullable || annotation.TargetType == 0x14 && strings.Contains(annotation.Annotation, "TypeNullable")
				parameterNullable = parameterNullable || annotation.TargetType == 0x16 && annotation.ParameterIndex == 0 && strings.Contains(annotation.Annotation, "TypeNullable")
			}
			if !returnNullable || !parameterNullable {
				t.Fatalf("type-use annotations = %#v", method.TypeAnnotations)
			}
		}
		if method.Name != "echo" {
			continue
		}
		echoFound = true
		if len(method.Annotations) != 1 || len(method.ParameterAnnotations) != 1 || len(method.ParameterAnnotations[0]) != 1 {
			t.Fatalf("annotation metadata = method %#v, parameters %#v", method.Annotations, method.ParameterAnnotations)
		}
		if rendered := classfile.RenderJava(parsed); !strings.Contains(rendered, "@fixtures.Nullable java.lang.String value") {
			t.Fatalf("rendered parameter annotation missing:\n%s", rendered)
		}
	}
	if !echoFound || !typeEchoFound {
		t.Fatalf("annotated methods missing: echo=%v typeEcho=%v", echoFound, typeEchoFound)
	}
}

func TestRenderPreservesGenericSignaturesAndNestedContainment(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "Outer.java")
	source := `package fixtures;
public class Outer<T extends Number & Comparable<T>> {
    public java.util.List<? extends T> values;
    public <X extends Exception> T map(java.util.List<? super T> input) throws X { return null; }
    public static class Inner<U> { public U value; public java.util.List<U> list() { return null; } }
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, compileErr := exec.Command(javac, "-parameters", "-d", dir, sourcePath).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	outerData, err := os.ReadFile(filepath.Join(dir, "fixtures", "Outer.class"))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := classfile.Parse(outerData)
	if err != nil {
		t.Fatal(err)
	}
	outerRendered := classfile.RenderJava(outer)
	for _, fragment := range []string{
		"class Outer<T extends java.lang.Number & java.lang.Comparable<T>>",
		"java.util.List<? extends T> values",
		"<X extends java.lang.Exception> T map(java.util.List<? super T> input) throws X",
	} {
		if !strings.Contains(outerRendered, fragment) {
			t.Fatalf("generic outer stub lacks %q:\n%s", fragment, outerRendered)
		}
	}
	innerData, err := os.ReadFile(filepath.Join(dir, "fixtures", "Outer$Inner.class"))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := classfile.Parse(innerData)
	if err != nil {
		t.Fatal(err)
	}
	innerRendered := classfile.RenderJava(inner)
	for _, fragment := range []string{"package fixtures;", "class Outer {", "class Inner<U>", "U value", "java.util.List<U> list()"} {
		if !strings.Contains(innerRendered, fragment) {
			t.Fatalf("nested generic stub lacks %q:\n%s", fragment, innerRendered)
		}
	}
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument("jar:///generic.jar!/fixtures/Outer$Inner.class", "java", 0, innerRendered))
	var innerSymbol analysis.Symbol
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "Inner" && symbol.Kind == analysis.KindClass {
			innerSymbol = symbol
		}
	}
	if innerSymbol.FQN != "fixtures.Outer.Inner" || innerSymbol.ContainerName != "Outer" {
		t.Fatalf("nested class containment = %#v\n%s", innerSymbol, innerRendered)
	}
}

func TestRenderPreservesRecordComponentsAndRealInnerClassMetadata(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	sources := map[string]string{
		"Point.java":       "package fixtures; public record Point<T>(T value, int count) {}",
		"Dollar$Name.java": "package fixtures; public class Dollar$Name {}",
		"Container.java":   "package fixtures; public class Container { public static class Nested {} }",
	}
	paths := make([]string, 0, len(sources))
	for name, source := range sources {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	arguments := append([]string{"-parameters", "-d", dir}, paths...)
	if output, compileErr := exec.Command(javac, arguments...).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	parseRendered := func(className string) (*classfile.Class, string) {
		t.Helper()
		data, readErr := os.ReadFile(filepath.Join(dir, "fixtures", className+".class"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		parsed, parseErr := classfile.Parse(data)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return parsed, classfile.RenderJava(parsed)
	}
	record, renderedRecord := parseRendered("Point")
	if len(record.Components) != 2 || record.Components[0].Name != "value" || record.Components[0].Signature != "TT;" || record.Components[1].Name != "count" {
		t.Fatalf("record components = %#v", record.Components)
	}
	if !strings.Contains(renderedRecord, "record Point<T>(T value, int count)") || strings.Contains(renderedRecord, " T value;") || strings.Contains(renderedRecord, " value()") {
		t.Fatalf("record stub is incomplete or duplicates generated members:\n%s", renderedRecord)
	}
	parsedRecord := analysis.Parse(context.Background(), textdoc.NewDocument("jar:///records.jar!/fixtures/Point.class", "java", 0, renderedRecord))
	if !hasSymbol(parsedRecord.Symbols, "value") || !hasSymbol(parsedRecord.Symbols, "count") || len(parsedRecord.Diagnostics) != 0 {
		t.Fatalf("record stub is not navigable: %#v %#v\n%s", parsedRecord.Symbols, parsedRecord.Diagnostics, renderedRecord)
	}

	_, renderedDollar := parseRendered("Dollar$Name")
	if !strings.Contains(renderedDollar, "class Dollar$Name") || strings.Contains(renderedDollar, "class Dollar {") {
		t.Fatalf("literal dollar class was fabricated as nesting:\n%s", renderedDollar)
	}
	_, renderedNested := parseRendered("Container$Nested")
	if !strings.Contains(renderedNested, "class Container {") || !strings.Contains(renderedNested, "static class Nested") {
		t.Fatalf("real nested metadata was not rendered:\n%s", renderedNested)
	}
}

func TestRenderPreservesRuntimeAnnotationsDefaultsAndConstants(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	markSource := `package fixtures;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE, ElementType.FIELD, ElementType.METHOD})
public @interface Mark { String value() default "default-value"; int number() default 7; }`
	annotatedSource := `package fixtures;
@Mark(value="class-value", number=9)
public class Annotated {
  @Mark("field-value") public static final String NAME = "constant-value";
  @Mark("method-value") public void run() {}
}`
	paths := []string{filepath.Join(dir, "Mark.java"), filepath.Join(dir, "Annotated.java")}
	for index, source := range []string{markSource, annotatedSource} {
		if err := os.WriteFile(paths[index], []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, compileErr := exec.Command(javac, "-d", dir, paths[0], paths[1]).CombinedOutput(); compileErr != nil {
		t.Fatalf("javac: %v\n%s", compileErr, output)
	}
	read := func(name string) (*classfile.Class, string) {
		data, readErr := os.ReadFile(filepath.Join(dir, "fixtures", name+".class"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		parsed, parseErr := classfile.Parse(data)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return parsed, classfile.RenderJava(parsed)
	}
	mark, markRendered := read("Mark")
	defaults := map[string]string{}
	for _, method := range mark.Methods {
		defaults[method.Name] = method.DefaultValue
	}
	if defaults["value"] != `"default-value"` || defaults["number"] != "7" || !strings.Contains(markRendered, `default "default-value"`) || !strings.Contains(markRendered, "default 7") {
		t.Fatalf("annotation defaults = %#v\n%s", defaults, markRendered)
	}
	annotated, rendered := read("Annotated")
	if len(annotated.Annotations) == 0 || !strings.Contains(strings.Join(annotated.Annotations, " "), "class-value") || !strings.Contains(rendered, `@fixtures.Mark(value = "class-value", number = 9)`) || !strings.Contains(rendered, `NAME = "constant-value"`) || !strings.Contains(rendered, `@fixtures.Mark("method-value")`) {
		t.Fatalf("annotations/constants were lost: %#v\n%s", annotated, rendered)
	}
	parsedStub := analysis.Parse(context.Background(), textdoc.NewDocument("jar:///annotated.jar!/fixtures/Annotated.class", "java", 0, rendered))
	if len(parsedStub.Diagnostics) != 0 {
		t.Fatalf("annotated stub is invalid: %#v\n%s", parsedStub.Diagnostics, rendered)
	}
}

func TestParseStructuredKotlinMetadataAndModifiedUTF8(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "Metadata.java")
	facadePath := filepath.Join(dir, "Facade.java")
	metadataSource := `package kotlin;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS)
public @interface Metadata {
  int k(); int[] mv() default {}; String[] d1() default {}; String[] d2() default {};
  String xs() default ""; String pn() default ""; int xi() default 0;
}`
	facadeSource := `package demo;
@kotlin.Metadata(k=2, mv={2,0,0}, d1={"\000payload"}, d2={"main"}, pn="logical", xi=48)
public class Facade {}`
	for path, source := range map[string]string{metadataPath: metadataSource, facadePath: facadeSource} {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command(javac, "-d", dir, metadataPath, facadePath).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(dir, "demo", "Facade.class"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := classfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	metadata := parsed.KotlinMetadata
	if metadata == nil || metadata.Kind != 2 || len(metadata.MetadataVersion) != 3 || len(metadata.Data1) != 1 || len(metadata.Data1[0]) == 0 || metadata.Data1[0][0] != 0 || len(metadata.Data2) != 1 || metadata.Data2[0] != "main" || metadata.PackageName != "logical" || metadata.ExtraInt != 48 {
		t.Fatalf("structured Kotlin Metadata = %#v", metadata)
	}
}

func hasSymbol(symbols []analysis.Symbol, name string) bool {
	for _, symbol := range symbols {
		if symbol.Name == name {
			return true
		}
	}
	return false
}
