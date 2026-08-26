package lsp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
)

// A pass takes seconds even when warm, so the editor needs a way to say whether
// the server is busy, how long the last pass took, and whether it ran hot.
func TestStatusReportsIndexingAndValidation(t *testing.T) {
	s, _ := diagnosticServer(t, map[string]any{})
	s.progressSource = func() index.Progress {
		return index.Progress{Ready: true, FilesParsed: 7, FilesTotal: 7, LibrariesParsed: 900, LibrariesTotal: 900}
	}
	result, err := s.Request(context.Background(), "kotlsp/status", nil)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var status struct {
		Indexing struct {
			Ready       bool  `json:"ready"`
			FilesParsed int64 `json:"filesParsed"`
		} `json:"indexing"`
		Validation         []map[string]any `json:"validation"`
		DiagnosticsTrigger string           `json:"diagnosticsTrigger"`
	}
	if unmarshalErr := json.Unmarshal(encoded, &status); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if !status.Indexing.Ready || status.Indexing.FilesParsed != 7 {
		t.Fatalf("indexing state not reported: %s", encoded)
	}
	if status.DiagnosticsTrigger != "change" {
		t.Fatalf("default trigger reported as %q", status.DiagnosticsTrigger)
	}
}

// The trigger is configuration the author chose; status has to reflect it.
func TestStatusReportsTheConfiguredTrigger(t *testing.T) {
	s, _ := diagnosticServer(t, map[string]any{})
	s.index.SetCompilerTrigger(index.CompilerOnSave)
	result, err := s.Request(context.Background(), "kotlsp/status", nil)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	encoded, _ := json.Marshal(result)
	var status struct {
		DiagnosticsTrigger string `json:"diagnosticsTrigger"`
	}
	_ = json.Unmarshal(encoded, &status)
	if status.DiagnosticsTrigger != "save" {
		t.Fatalf("configured trigger reported as %q", status.DiagnosticsTrigger)
	}
}

// On-save means nothing runs while typing.
func TestOnSaveTriggerSkipsValidationWhileTyping(t *testing.T) {
	idx := index.New(nil)
	defer idx.Close()
	idx.SetCompilerTrigger(index.CompilerOnSave)
	notified := make(chan struct{}, 1)
	idx.SetDiagnosticsListener(func() {
		select {
		case notified <- struct{}{}:
		default:
		}
	})
	idx.ScheduleCompilerDiagnostics(context.Background())
	select {
	case <-notified:
		t.Fatal("validation ran on a change although the trigger is save")
	case <-time.After(2 * time.Second):
	}
	idx.ScheduleCompilerDiagnosticsForSave(context.Background())
	select {
	case <-notified:
	case <-time.After(60 * time.Second):
		t.Fatal("validation did not run on save")
	}
}
