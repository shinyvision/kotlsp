package index

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// The fallback watcher compares the fingerprint of an ordinary poll against the
// fingerprint of the every-tenth rediscovery pass. When those disagreed for
// inputs nobody had touched, every poll looked like a build change and rebuilt
// the entire project model -- cancelling compiler passes and republishing every
// library archive -- for as long as the session lasted.
func TestBuildFingerprintIsStableAcrossVerificationDepth(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "settings.gradle.kts"), []byte("rootProject.name = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins { }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(root, "gradle", "wrapper")
	if err := os.MkdirAll(wrapper, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJar(t, filepath.Join(wrapper, "gradle-wrapper.jar"), "a.class", "one")

	clearFingerprintCaches := func() {
		buildInputManifestCache.Lock()
		buildInputManifestCache.byRoot = make(map[string]buildInputManifest)
		buildInputManifestCache.Unlock()
		buildInputDigestCache.Lock()
		buildInputDigestCache.values = make(map[string]buildInputDigestEntry)
		buildInputDigestCache.Unlock()
		archiveIdentityCache.Lock()
		archiveIdentityCache.values = make(map[string]archiveIdentityEntry)
		archiveIdentityCache.Unlock()
	}

	clearFingerprintCaches()
	deep, err := buildModelFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := buildModelFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if deep != warm {
		t.Fatalf("a warm poll disagreed with the verifying pass for unchanged inputs:\n deep=%x\n warm=%x", deep, warm)
	}
	clearFingerprintCaches()
	again, err := buildModelFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if again != warm {
		t.Fatalf("re-verification disagreed with the warm value for unchanged inputs:\n again=%x\n warm=%x", again, warm)
	}

	// A jar replaced with different content at the same size and timestamp is
	// exactly what the deep pass exists to notice.
	info, err := os.Stat(filepath.Join(wrapper, "gradle-wrapper.jar"))
	if err != nil {
		t.Fatal(err)
	}
	writeJar(t, filepath.Join(wrapper, "gradle-wrapper.jar"), "a.class", "two")
	if err := os.Chtimes(filepath.Join(wrapper, "gradle-wrapper.jar"), info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	clearFingerprintCaches()
	replaced, err := buildModelFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if replaced == warm {
		t.Fatal("the verifying pass did not notice a jar replaced with equal size and timestamp")
	}
}

func writeJar(t *testing.T, path, entry, body string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	member, err := writer.Create(entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
