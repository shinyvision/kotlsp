package lsp

import (
	"runtime"
	"time"

	"github.com/shinyvision/kotlsp/internal/jsonrpc"

	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

// serverStatus answers kotlsp/status: what indexing and background validation
// are doing right now, and how long the last pass took. A validation pass is
// measured in seconds even when warm, so an editor needs a way to say whether
// the server is busy or idle rather than leaving the author guessing.
func (s *Server) serverStatus() (any, *jsonrpc.ResponseError) {
	progress := s.indexProgressNow()
	passes := make([]map[string]any, 0, 2)
	for _, status := range s.index.CompilerStatus() {
		entry := map[string]any{
			"language":            status.Language,
			"passes":              status.Passes,
			"running":             status.Running,
			"hosted":              status.Hosted,
			"lastOutcome":         status.LastOutcome,
			"compiler":            status.Compiler,
			"requestedVersion":    status.RequestedVersion,
			"compilerVersion":     status.CompilerVersion,
			"fallbackReason":      status.FallbackReason,
			"diagnosticTransport": status.DiagnosticTransport,
			"effectiveArguments":  status.EffectiveArguments,
			"published":           status.Published,
			"publicationOutcome":  status.PublicationOutcome,
		}
		if status.LastError != "" {
			entry["lastError"] = status.LastError
		}
		if status.LastDuration > 0 {
			entry["lastDurationMs"] = status.LastDuration.Milliseconds()
		}
		if !status.LastFinished.IsZero() {
			entry["finishedSecondsAgo"] = int64(time.Since(status.LastFinished).Seconds())
		}
		passes = append(passes, entry)
	}
	health := make([]map[string]any, 0)
	for _, issue := range s.index.Health() {
		entry := map[string]any{
			"subsystem":   issue.Subsystem,
			"scope":       issue.Scope,
			"message":     issue.Message,
			"occurrences": issue.Occurrences,
		}
		if !issue.LastSeen.IsZero() {
			entry["lastSeenSecondsAgo"] = int64(time.Since(issue.LastSeen).Seconds())
		}
		health = append(health, entry)
	}
	buildModels := make([]map[string]any, 0)
	allBuildModels := s.index.BuildModels()
	buildModelsTruncated := len(allBuildModels) > 512
	if buildModelsTruncated {
		allBuildModels = allBuildModels[:512]
	}
	for _, model := range allBuildModels {
		entry := map[string]any{
			"module":           model.Module,
			"directory":        model.Directory,
			"importer":         model.Importer,
			"authoritative":    model.Authoritative,
			"compilerSettings": model.CompilerSettings,
		}
		if model.Failure != "" {
			entry["failure"] = model.Failure
			entry["retry"] = "touch or save a build file, or restart workspace indexing"
		}
		buildModels = append(buildModels, entry)
	}
	memory := resourcebudget.Current()
	var goMemory runtime.MemStats
	runtime.ReadMemStats(&goMemory)
	observedRSS := processTreeRSSBytes()
	fast := s.index.FastDiagnosticStatus()
	return map[string]any{
		"indexing": map[string]any{
			"ready":           progress.Ready,
			"filesParsed":     progress.FilesParsed,
			"filesTotal":      progress.FilesTotal,
			"librariesParsed": progress.LibrariesParsed,
			"librariesTotal":  progress.LibrariesTotal,
		},
		"validation":           passes,
		"buildModels":          buildModels,
		"buildModelsTruncated": buildModelsTruncated,
		"diagnosticsTrigger":   s.diagnosticsTriggerName(),
		"fastDiagnostics": map[string]any{
			"mode":                     "conservative predictions with authoritative compiler backstop",
			"rules":                    fast.RuleCount,
			"localRules":               fast.LocalRuleCount,
			"workspaceRules":           fast.WorkspaceRuleCount,
			"codes":                    fast.Codes,
			"compilerBackstopObserved": fast.CompilerBackstop,
			"files":                    fast.Files,
			"localEligibleFiles":       fast.LocalEligibleFiles,
			"workspaceEligibleFiles":   fast.WorkspaceEligibleFiles,
			"workspaceAbstainedFiles":  fast.WorkspaceAbstainedFiles,
			"currentPredictions":       fast.CurrentPredictions,
			"statusTruncated":          fast.StatusTruncated,
			"unavailableFilesByReason": fast.UnavailableFilesByReason,
		},
		"droppedNotifications": s.droppedNotifications.Load(),
		"degradedOperations":   health,
		"memoryBudget": map[string]any{
			"coordinationEnvelopeBytes":   memory.ProcessTreeSoftLimit,
			"enforcement":                 "Go runtime soft limit plus child-JVM -Xmx admission",
			"observedRSS":                 observedRSS > 0,
			"observedProcessTreeRSSBytes": observedRSS,
			"observedWithinEnvelope":      observedRSS == 0 || observedRSS <= uint64(memory.ProcessTreeSoftLimit),
			"goHeapAllocBytes":            goMemory.HeapAlloc,
			"goHeapInUseBytes":            goMemory.HeapInuse,
			"goRuntimeSysBytes":           goMemory.Sys,
			"debugTargetIncluded":         false,
			"goSoftLimitBytes":            memory.GoSoftLimit, "effectiveGoSoftLimitBytes": memory.EffectiveGoSoftLimit, "toolProcessLimitBytes": memory.ToolProcessLimit,
			"toolCurrentBytes": memory.ToolCurrent, "toolPeakBytes": memory.ToolPeak, "components": memory.Components,
		},
	}, nil
}

func (s *Server) diagnosticsTriggerName() string {
	if s.index.CompilerTrigger() == index.CompilerOnSave {
		return "save"
	}
	return "change"
}
