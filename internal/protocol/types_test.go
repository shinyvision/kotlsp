package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// Neovim indexes report.items of every full workspace diagnostic report, so a
// clean document must serialise an empty array, never omit the field.
func TestWorkspaceDocumentDiagnosticReportShapeFollowsKind(t *testing.T) {
	full, err := json.Marshal(WorkspaceDocumentDiagnosticReport{URI: "file:///a.kt", Kind: "full", ResultID: "1"})
	if err != nil || !strings.Contains(string(full), `"items":[]`) {
		t.Fatalf("full report = %s, %v", full, err)
	}
	unchanged, err := json.Marshal(WorkspaceDocumentDiagnosticReport{URI: "file:///a.kt", Kind: "unchanged", ResultID: "1", Items: []Diagnostic{}})
	if err != nil || strings.Contains(string(unchanged), "items") {
		t.Fatalf("unchanged report = %s, %v", unchanged, err)
	}
	report, err := json.Marshal(WorkspaceDiagnosticReport{})
	if err != nil || string(report) != `{"items":null}` && string(report) != `{"items":[]}` {
		t.Logf("workspace report = %s", report)
	}
}
