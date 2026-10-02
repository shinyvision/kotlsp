package index

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/shinyvision/kotlsp/internal/classfile"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A Java getter from a compiled library reads as a Kotlin property, the same
// as one declared in Java source.
func TestBinaryJavaGettersBecomeKotlinProperties(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac not available")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "Stamp.java")
	if err := os.WriteFile(source, []byte("package lib;\npublic class Stamp {\n    public int getYear() { return 1; }\n    public boolean isLeap() { return false; }\n    public String getZone() { return \"\"; }\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("javac", "-d", directory, source).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(directory, "lib", "Stamp.class"))
	if err != nil {
		t.Fatal(err)
	}
	class, err := classfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	doc := textdoc.NewDocument("file:///libs/Stamp.class", "java", 0, classfile.RenderJava(class))
	parsed := parsedBinaryClassfile(doc, class)
	summarizeLibraryFile(parsed)
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	idx.AddLibraryBatch([]LibraryFile{{Source: LibrarySource{Archive: "/deps/lib.jar", Entry: "lib/Stamp.class", LanguageID: "java", Binary: true}, Parsed: *parsed}})

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	found := map[string]bool{}
	for _, id := range idx.byFQN["lib.Stamp"] {
		owner := idx.symbols[id]
		for _, memberID := range idx.byContainerName[owner.ID] {
			member := idx.symbols[memberID]
			found[member.Name+"/"+itoa(int(member.Kind))] = true
		}
	}
	for _, want := range []string{"year", "isLeap", "zone"} {
		ok := false
		for key := range found {
			if len(key) > len(want) && key[:len(want)+1] == want+"/" {
				ok = true
			}
		}
		if !ok {
			t.Errorf("no member %q on a compiled Java class", want)
		}
	}
}
