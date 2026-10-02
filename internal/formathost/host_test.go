package formathost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAdapter stands in for Spotless's ktlint adapter: the host loads it by
// the same name and calls the same method. It reports what it was given, so
// the test can see every field cross the protocol, and fails on `class {`
// the way ktlint fails on source it cannot parse.
const fakeAdapter = `package com.diffplug.spotless.glue.ktlint.compat;

import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;

public class KtLintCompat1Dot0Dot0Adapter {
    private int calls;

    public String format(String text, Path path, Path editorConfig, Map<String, Object> settings) {
        if (text.contains("class {")) {
            throw new IllegalArgumentException("Expecting a name");
        }
        calls++;
        return "// call " + calls + " " + path.getFileName() + " editorconfig=" + editorConfig + " " + new TreeMap<>(settings) + "\n"
            + text.replaceAll(" +", " ");
    }
}
`

func TestFormatsThroughTheAdapter(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("javac is not installed")
	}
	classes := t.TempDir()
	source := filepath.Join(t.TempDir(), "KtLintCompat1Dot0Dot0Adapter.java")
	if err := os.WriteFile(source, []byte(fakeAdapter), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(javac, "-d", classes, source).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	pool := &Pool{}
	defer pool.Close()
	spec := Spec{Classpath: []string{classes}, Overrides: map[string]string{"ktlint_standard_no-unused-imports": "enabled"}}
	path := filepath.Join(t.TempDir(), "A.kt")

	formatted, err := pool.Format(context.Background(), spec, path, "class   A {\n  fun f( x:Int ) =  x\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := "// call 1 A.kt editorconfig=null {ktlint_standard_no-unused-imports=enabled}\nclass A {\n fun f( x:Int ) = x\n}\n"; formatted != want {
		t.Fatalf("formatted:\n%s\nwant:\n%s", formatted, want)
	}
	// The second request goes to the same warm JVM.
	if formatted, err = pool.Format(context.Background(), spec, path, "val  x = 1\n"); err != nil || !strings.HasPrefix(formatted, "// call 2 ") {
		t.Fatalf("second request: %q, %v", formatted, err)
	}
	// The formatter's own failure is the request's error, and the host survives it.
	if _, err := pool.Format(context.Background(), spec, path, "package p\nclass {"); err == nil || !strings.Contains(err.Error(), "Expecting a name") {
		t.Fatalf("unparseable source: err = %v", err)
	}
	if formatted, err = pool.Format(context.Background(), spec, path, "val y = 2\n"); err != nil || !strings.HasPrefix(formatted, "// call 3 ") {
		t.Fatalf("after a failure: %q, %v", formatted, err)
	}
}
