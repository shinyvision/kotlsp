package archiveio

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testZipFile(t *testing.T, content string) *zip.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.zip")
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(output)
	entry, err := writer.Create("entry.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = output.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader.File[0]
}

func TestReadZipFileEnforcesLimit(t *testing.T) {
	file := testZipFile(t, "0123456789")
	if _, err := ReadZipFile(file, 9); !errors.Is(err, ErrEntryTooLarge) {
		t.Fatalf("oversized entry error = %v", err)
	}
	data, err := ReadZipFile(file, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("0123456789")) {
		t.Fatalf("entry data = %q", data)
	}
}

func TestBudgetAccountsActualExpansionAcrossMembers(t *testing.T) {
	file := testZipFile(t, "0123456789")
	budget, err := NewBudget([]*zip.File{file})
	if err != nil {
		t.Fatal(err)
	}
	budget.expanded = MaxArchiveExpandedBytes - 5
	if _, err = budget.Read(file, 10); !errors.Is(err, ErrArchiveBudget) {
		t.Fatalf("aggregate actual-expansion error = %v", err)
	}
}

func TestBudgetValidatesCRCFromActualOutput(t *testing.T) {
	file := testZipFile(t, "verified")
	file.CRC32++
	budget, err := NewBudget([]*zip.File{file})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = budget.Read(file, 32); !errors.Is(err, ErrArchiveBudget) {
		t.Fatalf("actual CRC error = %v", err)
	}
}

func TestBudgetRejectsDeclaredCompressedInputAboveEntryLimit(t *testing.T) {
	file := testZipFile(t, "small")
	file.CompressedSize64 = MaxEntryCompressedBytes + 1
	if _, err := NewBudget([]*zip.File{file}); !errors.Is(err, ErrArchiveBudget) {
		t.Fatalf("compressed entry error = %v", err)
	}
}

func TestBudgetReadContextCancelsWhileWaitingForArchiveGate(t *testing.T) {
	file := testZipFile(t, "small")
	budget, err := NewBudget([]*zip.File{file})
	if err != nil {
		t.Fatal(err)
	}
	<-budget.gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = budget.ReadContext(ctx, file, 16); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled gate wait error = %v", err)
	}
	budget.gate <- struct{}{}
}
