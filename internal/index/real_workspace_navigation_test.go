package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// This opt-in test exercises the exact cold-start boundary which is hard to
// reproduce with synthetic archive batches: build-model restoration, archive
// priority, generic inherited Java members, and Kotlin stdlib metadata all
// race the first foreground definition request. CI can point it at any Spring
// workspace without making that workspace a repository fixture.
func TestRealWorkspaceDefinitionsResolveDuringWarmup(t *testing.T) {
	root := os.Getenv("KOTLSP_REAL_WORKSPACE")
	if root == "" {
		t.Skip("set KOTLSP_REAL_WORKSPACE to exercise cold workspace navigation")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	previousSkip, previousFilter := skipLibraryScan, libraryArchiveFilter
	skipLibraryScan, libraryArchiveFilter = false, nil
	t.Cleanup(func() { skipLibraryScan, libraryArchiveFilter = previousSkip, previousFilter })
	idx := New(nil)
	defer idx.Close()
	idx.SetCompilerTrigger(CompilerOnSave)
	uri := uriutil.File(filepath.Join(root, "src", "main", "kotlin", "KotlspWarmupProbe.kt"))
	source := `package kotlsp.warmup
import org.springframework.validation.BindingResult
import org.springframework.data.repository.CrudRepository
import org.springframework.mail.javamail.JavaMailSender
class User
class Context
fun probe(bindingResult: BindingResult, userRepository: CrudRepository<User, Long>, mailSender: JavaMailSender, user: User) {
    bindingResult.hasErrors()
    userRepository.save(user)
    mailSender.createMimeMessage()
    Context().apply { }
}
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	document, ok := idx.Document(uri)
	if !ok {
		t.Fatal("warm-up document was not indexed")
	}
	scanCtx, cancelScan := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelScan()
	idx.Start(scanCtx, []protocol.URI{uriutil.File(root)})
	t.Logf("priority imports = %#v", idx.workspaceLibraryImports(context.Background()))

	for _, name := range []string{"hasErrors", "save", "createMimeMessage", "apply"} {
		position := strings.LastIndex(source, name)
		if position < 0 {
			t.Fatalf("missing probe %s", name)
		}
		requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Second)
		started := time.Now()
		definitions := idx.DefinitionsContext(requestCtx, uri, document.Position(position+1))
		cancelRequest()
		if len(definitions) == 0 || definitions[0].Name != name {
			t.Fatalf("%s definition during warm-up after %s = %#v; owner=%#v member=%#v progress=%+v health=%+v", name, time.Since(started), definitions, idx.SymbolsByFQN("org.springframework.validation.BindingResult"), idx.SymbolsByFQN("org.springframework.validation.Errors.hasErrors"), idx.Progress(), idx.Health())
		}
		t.Logf("%s became navigable in %s", name, time.Since(started).Round(time.Millisecond))
	}
}
