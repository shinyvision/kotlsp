package uri

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestPathHandlesFileAuthoritiesExplicitly(t *testing.T) {
	remote := protocol.URI("file://server/share/project/Main.kt")
	path, ok := Path(remote)
	if runtime.GOOS == "windows" {
		if !ok || path != filepath.FromSlash("//server/share/project/Main.kt") {
			t.Fatalf("UNC path = %q, %v", path, ok)
		}
		if roundTrip := File(path); roundTrip != remote {
			t.Fatalf("UNC round trip = %q, want %q", roundTrip, remote)
		}
	} else if ok {
		t.Fatalf("remote authority was silently treated as local path %q", path)
	}

	local, ok := Path("file://localhost/tmp/Main.kt")
	if !ok || local != filepath.FromSlash("/tmp/Main.kt") {
		t.Fatalf("localhost path = %q, %v", local, ok)
	}
}
