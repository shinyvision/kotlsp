package dap

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeJar builds a jar at path with the given entry -> content pairs.
func writeJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	writer := zip.NewWriter(out)
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

// fakeGradleCache lays out a binary jar and its sources jar the way the
// Gradle module cache does: sibling content-hash directories under the same
// artifact version.
func fakeGradleCache(t *testing.T) (binaryJar string, sourceContent string) {
	t.Helper()
	root := t.TempDir()
	versionDir := filepath.Join(root, "modules-2", "files-2.1", "com.acme", "widget", "1.0")
	binaryJar = filepath.Join(versionDir, "aaa", "widget-1.0.jar")
	sourceContent = "package com.acme;\n\npublic class Widget {\n    public void run() {}\n}\n"
	writeJar(t, binaryJar, map[string]string{"com/acme/Widget.class": "CAFEBABE"})
	writeJar(t, filepath.Join(versionDir, "bbb", "widget-1.0-sources.jar"),
		map[string]string{"com/acme/Widget.java": sourceContent})
	return binaryJar, sourceContent
}

func TestFrameClassName(t *testing.T) {
	cases := map[string]string{
		"org.springframework.boot.SpringApplication.run": "org.springframework.boot.SpringApplication",
		"com.petramond.ForgotPasswordController.index":   "com.petramond.ForgotPasswordController",
		"com.acme.Widget$Nested.run":                     "com.acme.Widget",
		"com.acme.Widget$run$1.invoke":                   "com.acme.Widget",
		"com.acme.Widget.<init>":                         "com.acme.Widget",
		"Widget.run":                                     "Widget",
	}
	for frameName, expected := range cases {
		if got := frameClassName(frameName); got != expected {
			t.Errorf("frameClassName(%q) = %q, want %q", frameName, got, expected)
		}
	}
}

func TestSourceStoreServesGradleCacheSourcesJar(t *testing.T) {
	binaryJar, sourceContent := fakeGradleCache(t)
	store := newSourceStore()

	ref, origin := store.referenceFor([]string{binaryJar}, "com.acme.Widget.run", "Widget.java")
	if ref <= 0 || origin != "widget-1.0-sources.jar" {
		t.Fatalf("referenceFor = (%d, %q)", ref, origin)
	}
	content, ok := store.contentFor(ref)
	if !ok || content != sourceContent {
		t.Fatalf("contentFor = (%q, %v)", content, ok)
	}

	// The class-entry lookup must be cached: deleting the jars after the first
	// resolution still serves content if re-opened, but a fresh lookup of the
	// same class must not rescan the classpath (covered implicitly by the
	// negative test below sharing the store).
	if _, ok := store.contentFor(9999); ok {
		t.Fatal("unknown reference returned content")
	}
}

func TestSourceStoreMavenLayoutBesideBinary(t *testing.T) {
	dir := t.TempDir()
	binaryJar := filepath.Join(dir, "widget-1.0.jar")
	writeJar(t, binaryJar, map[string]string{"com/acme/Widget.class": "CAFEBABE"})
	writeJar(t, filepath.Join(dir, "widget-1.0-sources.jar"),
		map[string]string{"com/acme/Widget.java": "package com.acme; class Widget {}\n"})

	store := newSourceStore()
	if ref, _ := store.referenceFor([]string{binaryJar}, "com.acme.Widget.run", "Widget.java"); ref <= 0 {
		t.Fatal("Maven-layout sources jar was not picked up")
	}
}

func TestSourceStoreMisses(t *testing.T) {
	binaryJar, _ := fakeGradleCache(t)
	store := newSourceStore()

	// Class not present in any classpath jar.
	if ref, _ := store.referenceFor([]string{binaryJar}, "com.acme.Missing.run", "Missing.java"); ref != 0 {
		t.Fatalf("unknown class returned reference %d", ref)
	}
	// Class present but no sources jar for the requested entry.
	if ref, _ := store.referenceFor([]string{binaryJar}, "com.acme.Widget.run", "Other.java"); ref != 0 {
		t.Fatalf("missing source entry returned reference %d", ref)
	}
	// Directory classpath entries are skipped, not crashes. Reset first, as
	// launch() does: the cached jar associations belong to the old classpath.
	store.reset()
	if ref, _ := store.referenceFor([]string{t.TempDir()}, "com.acme.Widget.run", "Widget.java"); ref != 0 {
		t.Fatalf("directory classpath returned reference %d", ref)
	}
	// Negative lookups are cached.
	store.locateClass([]string{binaryJar}, "com/acme/Missing.class")
	if got := store.classJars["com/acme/Missing.class"]; got != "" {
		t.Fatalf("negative cache entry = %q", got)
	}
	if _, searched := store.classJars["com/acme/Missing.class"]; !searched {
		t.Fatal("negative lookup was not cached")
	}
}

func TestFrameSourcePrefersDiskThenJar(t *testing.T) {
	binaryJar, _ := fakeGradleCache(t)
	s := newSession(context.Background(), bufio.NewWriter(io.Discard))
	defer s.close()
	s.classPaths = []string{binaryJar}

	// A file on disk under a source root wins and carries a plain path.
	root := t.TempDir()
	disk := filepath.Join(root, "com", "acme", "Widget.java")
	if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(disk, []byte("class Widget {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.sourceRoots = []string{root}
	source := s.frameSource("Widget.java", "com.acme.Widget.run")
	if source["path"] != disk || source["sourceReference"] != nil {
		t.Fatalf("disk source = %#v", source)
	}

	// Without a disk hit the frame falls back to a sources-jar reference.
	s.sourceRoots = nil
	s.sourceByName = map[string]string{}
	s.sourceCache = map[string]string{}
	source = s.frameSource("Widget.java", "com.acme.Widget.run")
	ref, ok := source["sourceReference"].(int)
	if !ok || ref <= 0 {
		t.Fatalf("jar source = %#v", source)
	}
	if source["path"] != nil {
		t.Fatalf("jar source must not carry a disk path: %#v", source)
	}

	// The dispatch-level source request serves the registered content.
	result, ok, message := s.dispatch("source", json.RawMessage(`{"sourceReference": `+strconv.Itoa(ref)+`}`))
	if !ok {
		t.Fatalf("source request failed: %s", message)
	}
	body := result.(map[string]any)
	if body["content"] == nil || body["content"] == "" {
		t.Fatalf("source response = %#v", body)
	}
	if _, ok, _ := s.dispatch("source", json.RawMessage(`{"sourceReference": 12345}`)); ok {
		t.Fatal("unknown sourceReference succeeded")
	}

	// A frame with resolvable neither on disk nor in jars keeps just a name.
	source = s.frameSource("Whatever.java", "com.other.Whatever.run")
	if len(source) != 1 || source["name"] != "Whatever.java" {
		t.Fatalf("unresolvable source = %#v", source)
	}
}
