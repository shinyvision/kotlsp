package index

import (
	"archive/zip"
	"testing"

	"github.com/shinyvision/kotlsp/internal/archiveio"
)

func TestJmodBudgetExcludesNativePayloadsTheIndexNeverReads(t *testing.T) {
	class := &zip.File{FileHeader: zip.FileHeader{
		Name: "classes/java/lang/Object.class", Method: zip.Store,
		CompressedSize64: 1, UncompressedSize64: 1,
	}}
	native := &zip.File{FileHeader: zip.FileHeader{
		Name: "lib/server/libjvm.so", Method: zip.Store,
		CompressedSize64:   archiveio.MaxEntryCompressedBytes + 1,
		UncompressedSize64: archiveio.MaxEntryCompressedBytes + 1,
	}}
	if _, err := archiveio.NewBudget([]*zip.File{class, native}); err == nil {
		t.Fatal("control budget unexpectedly accepted the oversized native payload")
	}
	semantic := archiveSemanticBudgetFiles(sourceArchive{binary: true, jdk: true, module: "java.base"}, []*zip.File{class, native})
	if len(semantic) != 1 || semantic[0] != class {
		t.Fatalf("semantic JMOD entries = %#v", semantic)
	}
	if _, err := archiveio.NewBudget(semantic); err != nil {
		t.Fatalf("class-only JMOD budget was rejected: %v", err)
	}
}

func TestDirectlyImportedArchiveOutranksJavaBaseDuringWarmup(t *testing.T) {
	archives := []sourceArchive{
		{path: "/jdk/java.base.jmod", binary: true, jdk: true, module: "java.base", manifestOK: true, manifest: []string{"classes/java/lang/Object.class"}},
		{path: "/deps/spring-validation.jar", binary: true, manifestOK: true, manifest: []string{"org/springframework/validation/BindingResult.class"}},
	}
	prioritizeLibraryArchives(archives, []string{"org.springframework.validation.BindingResult"})
	if archives[0].path != "/deps/spring-validation.jar" {
		t.Fatalf("warm-up order = %#v", archives)
	}
}

func TestLibraryImportScoreDoesNotMatchUnrelatedArchive(t *testing.T) {
	imports := []string{"org.springframework.validation.BindingResult"}
	if score := libraryEntryImportScore([]string{"classes/java/lang/Object.class"}, imports); score != 0 {
		t.Fatalf("java.base import score = %d", score)
	}
	if score := libraryEntryImportScore([]string{"org/springframework/context/ApplicationContext.class"}, imports); score != 0 {
		t.Fatalf("different Spring package import score = %d", score)
	}
	if score := libraryEntryImportScore([]string{"org/springframework/validation/BindingResult.class"}, imports); score != 1000 {
		t.Fatalf("exact import score = %d", score)
	}
}
