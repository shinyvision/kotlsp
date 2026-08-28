package index

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	"github.com/shinyvision/kotlsp/internal/resourcebudget"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

var javacDiagnosticPattern = regexp.MustCompile(`^(.+\.java):(\d+):\s+(warning|error):\s+(.+)$`)
var javacDrawDiagnosticPattern = regexp.MustCompile(`^(.+\.java):(\d+):(\d+):\s+(compiler\.(err|warn)\.[^:]+)(?::\s*(.*))?$`)
var kotlincDiagnosticPattern = regexp.MustCompile(`^(.+\.kts?):(\d+):(\d+):\s+(warning|error):\s+(?:\[([A-Z0-9_]+)\]\s+)?(.+)$`)

const (
	maxCompilerOutputBytes          = 16 << 20
	maxCompilerDiagnosticsPerFile   = 500
	maxCompilerDiagnosticsWorkspace = 5000
)

var errCompilerOutputLimit = errors.New("compiler output exceeded limit")

type boundedCompilerOutput struct {
	data      []byte
	limit     int
	truncated bool
}

func (w *boundedCompilerOutput) Write(value []byte) (int, error) {
	written := len(value)
	remaining := w.limit - len(w.data)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		w.data = append(w.data, value[:remaining]...)
	}
	if remaining < len(value) {
		w.truncated = true
	}
	return written, nil
}

func runCompilerCommand(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reserveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	release, reserveErr := resourcebudget.Acquire(reserveCtx, "compiler-one-shot", resourcebudget.CompilerOneShotBytes)
	if reserveErr != nil {
		return nil, reserveErr
	}
	defer release()
	output := &boundedCompilerOutput{limit: maxCompilerOutputBytes}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		return output.data, err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	var err error
	select {
	case err = <-waited:
	case <-ctx.Done():
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		err = errors.Join(<-waited, ctx.Err())
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		err = errors.Join(<-waited, context.DeadlineExceeded)
	}
	if output.truncated {
		return output.data, errors.Join(err, errCompilerOutputLimit)
	}
	return output.data, err
}

// scanJavaCompilerDiagnostics runs javac outside every foreground LSP path and
// atomically publishes its last complete result. This adds genuine compiler
// errors and lint warnings without allowing compiler startup or I/O to consume
// any part of the 100 ms request budget.
type compilerDiagnosticTransaction struct {
	succeeded map[string]bool
	clear     map[protocol.URI]bool
	values    map[protocol.URI][]protocol.Diagnostic
}

func newCompilerDiagnosticTransaction() *compilerDiagnosticTransaction {
	return &compilerDiagnosticTransaction{succeeded: make(map[string]bool, 2), clear: make(map[protocol.URI]bool), values: make(map[protocol.URI][]protocol.Diagnostic)}
}

func (transaction *compilerDiagnosticTransaction) stage(language string, files []*analysis.ParsedFile, diagnostics map[protocol.URI][]protocol.Diagnostic) {
	transaction.succeeded[language] = true
	for _, file := range files {
		if file == nil {
			continue
		}
		lower := strings.ToLower(string(file.URI))
		if language == "java" && strings.HasSuffix(lower, ".java") || language == "kotlin" && (strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")) {
			transaction.clear[file.URI] = true
		}
	}
	for uri, values := range diagnostics {
		transaction.values[uri] = append([]protocol.Diagnostic(nil), values...)
	}
}

func (i *Index) commitCompilerDiagnosticTransaction(transaction *compilerDiagnosticTransaction, run, generation uint64) bool {
	if transaction == nil || !transaction.succeeded["kotlin"] || !transaction.succeeded["java"] {
		return false
	}
	budgetCompilerDiagnostics(transaction.values)
	// Scheduling/cancellation increments compilerRun while holding this mutex.
	// Holding it across the version check and publication gives the commit one
	// linearization point: a newly requested pass is either before it (and this
	// transaction is rejected) or after it (and will supersede this snapshot).
	i.compilerCancelMu.Lock()
	defer i.compilerCancelMu.Unlock()
	if i.compilerRun.Load() != run || i.modelRefreshing.Load() {
		return false
	}
	i.mu.Lock()
	if i.generation.Load() != generation || i.compilerRun.Load() != run || i.modelRefreshing.Load() {
		i.mu.Unlock()
		return false
	}
	for uri := range transaction.clear {
		delete(i.compilerDiagnostics, uri)
	}
	for uri, values := range transaction.values {
		i.compilerDiagnostics[uri] = values
	}
	i.diagnosticsVersion.Add(1)
	i.mu.Unlock()
	if i.onParsed != nil {
		for uri := range transaction.clear {
			i.onParsed(uri, i.Diagnostics(uri))
		}
	}
	return true
}

func (i *Index) scanJavaCompilerDiagnostics(parent context.Context, generation uint64, transactions ...*compilerDiagnosticTransaction) {
	started := i.compilerStatus.begin("java")
	javacHosted := false
	outcome, failure, compilerName := "skipped", "", ""
	fallbackReason, diagnosticTransport, modelNote := "", "", ""
	var effectiveArguments []string
	defer func() {
		if failure != "" {
			i.recordHealth("compiler-java", compilerName, failure)
		}
		i.compilerStatus.finish("java", started, javacHosted, outcome, failure, compilerName, "", "", joinStatusReasons(fallbackReason, modelNote), diagnosticTransport, effectiveArguments)
	}()
	if i.generation.Load() != generation {
		return
	}
	files, truncated := i.WorkspaceFilesContext(parent, 100_001)
	if truncated || len(files) > 100_000 {
		outcome, failure = "unavailable", "compiler validation exceeds its 100000-source safety limit"
		return
	}
	units, unitsErr := i.compilerUnitsContext(parent, files)
	if unitsErr != nil {
		outcome, failure = "unavailable", unitsErr.Error()
		return
	}
	if !anyUnitHasLanguage(units, "java") {
		if len(transactions) > 0 {
			transactions[0].stage("java", files, nil)
			outcome = "succeeded"
		}
		return
	}
	temporary, err := os.MkdirTemp("", "kotlsp-javac-")
	if err != nil {
		outcome, failure = "failed", err.Error()
		return
	}
	defer os.RemoveAll(temporary)
	ctx := parent
	diagnostics := make(map[protocol.URI][]protocol.Diagnostic)
	passSuccessful := true
	for unitIndex, unit := range units {
		if i.generation.Load() != generation || ctx.Err() != nil {
			break
		}
		// A unit with none of this language cannot produce a finding for it.
		// Skipping the unit is not the same as abandoning the pass: units are
		// not ordered by language, so stopping here silently dropped every
		// later unit's diagnostics.
		if !unit.hasPrimaryLanguage("java") {
			continue
		}
		if unit.Settings.IncompleteReason != "" {
			passSuccessful = false
			outcome, failure = "unavailable", "project compiler model is incomplete: "+unit.Settings.IncompleteReason
			continue
		}
		if unit.ModelNote != "" {
			modelNote = unit.ModelNote
		}
		if cached, ok := i.compilerCacheLookup("java", unit); ok {
			mergePrimaryCompilerDiagnostics(diagnostics, cached.Diagnostics, unit.Primary, "java")
			continue
		}
		plan := i.compilerIncrementalPlan("java", unit)
		javac := javacExecutableInHome(unit.JavaHome)
		if javac == "" && unit.JavaHome == "" {
			javac, _ = exec.LookPath("javac")
		}
		if javac == "" {
			passSuccessful = false
			outcome, failure = "failed", "javac was not found for the module toolchain"
			continue
		}
		compilerName = javac
		unitDirectory := filepath.Join(temporary, "unit-"+strconv.Itoa(unitIndex))
		if makeErr := os.MkdirAll(unitDirectory, 0o700); makeErr != nil {
			passSuccessful = false
			outcome, failure = "failed", makeErr.Error()
			continue
		}
		paths, staged, pathErr := i.compilerSourcePaths(ctx, plan.Inputs, unitDirectory, func(path string) bool {
			return strings.HasSuffix(strings.ToLower(path), ".java")
		})
		if pathErr != nil || len(paths) == 0 {
			passSuccessful = false
			outcome, failure = "failed", "could not stage Java sources"
			if pathErr != nil {
				failure = pathErr.Error()
			}
			continue
		}
		argumentFile := filepath.Join(unitDirectory, "sources.args")
		var arguments strings.Builder
		for _, path := range paths {
			arguments.WriteString(quoteJavacArgument(path))
			arguments.WriteByte('\n')
		}
		if writeErr := os.WriteFile(argumentFile, []byte(arguments.String()), 0o600); writeErr != nil {
			passSuccessful = false
			outcome, failure = "failed", writeErr.Error()
			continue
		}
		// javac defaults to truncating errors/warnings. The protocol requires a
		// complete diagnostic snapshot, so use its maximum accepted limits.
		// No -XDrawDiagnostics: the raw formatter prints only the source's short
		// name, which cannot be mapped back to a staged input once two files
		// share a base name, and its messages are resource keys rather than the
		// wording the fast Java rules predict.
		commandArgs := []string{"-Xlint:all", "-Xmaxerrs", strconv.Itoa(maxCompilerDiagnosticsWorkspace), "-Xmaxwarns", strconv.Itoa(maxCompilerDiagnosticsWorkspace)}
		if !javaProcessorConfigured(unit.Settings.JavaArguments) {
			commandArgs = append(commandArgs, "-proc:none")
		}
		commandArgs = append(commandArgs, normalizedJavaCompilerArguments(unit.Settings)...)
		classes, classesErr := i.compilerClassesDirectory("java", unit)
		if classesErr != nil {
			passSuccessful = false
			outcome, failure = "failed", classesErr.Error()
			continue
		}
		_ = os.RemoveAll(classes)
		if makeErr := os.MkdirAll(classes, 0o700); makeErr != nil {
			i.discardCompilerDirectoryIfUnretained(classes)
			passSuccessful = false
			outcome, failure = "failed", makeErr.Error()
			continue
		}
		commandArgs = append(commandArgs, "-d", classes)
		classpath := append([]string(nil), unit.Classpath...)
		if plan.Incremental {
			classpath = append(classpath, plan.Previous.Classes...)
		}
		// The Kotlin pass runs first and publishes one class artifact per unit.
		// Reuse it here instead of compiling the same mixed source closure twice.
		if unit.hasInputLanguage("kotlin") {
			if artifact, available := i.compilerCacheLookup("kotlin", unit); available && len(artifact.Classes) > 0 {
				classpath = append(classpath, artifact.Classes...)
				if compiler, ok := findKotlinCompilerVersionContext(ctx, unit.Settings.KotlinVersion); ok && compiler.stdlib != "" {
					classpath = append(classpath, compiler.stdlib)
				}
			} else {
				i.discardCompilerDirectoryIfUnretained(classes)
				passSuccessful = false
				outcome, failure = "failed", "Kotlin analysis artifact was unavailable for the mixed Java unit"
				continue
			}
		}
		if len(classpath) > 0 {
			commandArgs = append(commandArgs, "-classpath", strings.Join(classpath, string(os.PathListSeparator)))
		}
		if len(unit.ModulePath) > 0 {
			commandArgs = append(commandArgs, "--module-path", strings.Join(unit.ModulePath, string(os.PathListSeparator)))
		}
		effectiveArguments = redactCompilerArguments(commandArgs)
		// The warm host can run javac in-process, but only when it is the same
		// JDK: a module with its own toolchain must still get that toolchain.
		var output []byte
		hostedJavac := false
		if compiler, available := i.kotlinCompilerContext(ctx); available && compiler.embedded && sameJavaHome(unit.JavaHome, i.DefaultJavaHome()) {
			// The tool API takes source paths directly, so no argument file and
			// no command-line length limit.
			hostedArgs := append(append([]string(nil), commandArgs...), paths...)
			if answer, ok := i.compilerHosts.runJavac(ctx, compiler, i.DefaultJavaHome(), hostedArgs); ok {
				output, hostedJavac = answer, true
			}
		}
		// Both transports are javac's text formatter: full staged path, the
		// rich formatter's wording, and a caret line for the column. The tool
		// API's DiagnosticListener would add javac's diagnostic key, but its
		// messages come from the basic formatter (qualified class names) and
		// would not reconcile with the wording the fast Java rules predict.
		diagnosticTransport = "javac text formatter with caret columns"
		if !hostedJavac {
			fallbackReason = "warm compiler host was unavailable or used a different JDK; one-shot javac was used"
			commandArgs = append(commandArgs, "@"+argumentFile)
			command := exec.CommandContext(ctx, javac, commandArgs...)
			configureCompilerProcess(command)
			var runErr error
			output, runErr = runCompilerCommand(ctx, command)
			if !compilerCommandCompleted(ctx, runErr) {
				i.discardCompilerDirectoryIfUnretained(classes)
				passSuccessful = false
				outcome, failure = compilerFailureOutcome(ctx, runErr)
				continue
			}
		}
		javacHosted = javacHosted || hostedJavac
		values := remapCompilerDiagnostics(parseJavacDiagnostics(string(output)), staged)
		if count, sample := unmatchedCompilerDiagnosticHeaders(string(output), "java", values); count > 0 {
			i.discardCompilerDirectoryIfUnretained(classes)
			i.recordHealth("compiler-java-output", unit.Key, strconv.Itoa(count)+" diagnostic records were not parseable; first: "+sample)
			passSuccessful = false
			outcome, failure = "failed", "javac emitted unparseable diagnostic records"
			continue
		}
		i.expandCompilerDiagnosticRanges(values)
		values = compilerMergedIncrementalDiagnostics(plan, values)
		layers := 1
		classLayers := []string{classes}
		if plan.Incremental {
			layers = plan.Previous.Layers + 1
			classLayers = append(classLayers, plan.Previous.Classes...)
		}
		if !i.compilerCacheStore("java", unit, compilerCacheEntry{
			Classes:           classLayers,
			Layers:            layers,
			InputHashes:       plan.InputHashes,
			DeclarationShapes: plan.DeclarationShapes,
			Diagnostics:       values,
		}) {
			passSuccessful = false
			outcome, failure = "unavailable", "compiler class cache exceeded its 4 GiB/1000000-entry safety limit"
			continue
		}
		mergePrimaryCompilerDiagnostics(diagnostics, values, unit.Primary, "java")
	}
	if !passSuccessful || ctx.Err() != nil || i.generation.Load() != generation {
		if ctx.Err() != nil {
			outcome, failure = "cancelled", ctx.Err().Error()
		} else if i.generation.Load() != generation {
			outcome, failure = "superseded", "a newer workspace generation replaced this pass"
		}
		return
	}
	if len(transactions) > 0 {
		transactions[0].stage("java", files, diagnostics)
		outcome, failure = "succeeded", ""
		return
	}
	budgetCompilerDiagnostics(diagnostics)
	i.mu.Lock()
	if i.generation.Load() != generation {
		i.mu.Unlock()
		return
	}
	for _, file := range files {
		if strings.HasSuffix(strings.ToLower(string(file.URI)), ".java") {
			delete(i.compilerDiagnostics, file.URI)
		}
	}
	for uri, values := range diagnostics {
		i.compilerDiagnostics[uri] = values
	}
	i.diagnosticsVersion.Add(1)
	outcome, failure = "succeeded", ""
	i.mu.Unlock()
	if i.onParsed != nil {
		for _, file := range files {
			if strings.HasSuffix(strings.ToLower(string(file.URI)), ".java") {
				i.onParsed(file.URI, i.Diagnostics(file.URI))
			}
		}
	}
}

type kotlinCompiler struct {
	executable string
	prefix     []string
	stdlib     string
	embedded   bool
	// runtimeJars is the compiler's own classpath, kept separately so the
	// persistent host can be launched with the same one.
	runtimeJars []string
	jvmFlags    []string
	version     string
}

// scanKotlinCompilerDiagnostics uses the installed kotlinc command when
// available, otherwise Kotlin's compiler-embeddable artifact from the local
// Gradle cache. It is optional and entirely background; the in-memory
// diagnostic providers remain available when neither compiler is installed.
func (i *Index) scanKotlinCompilerDiagnostics(parent context.Context, generation uint64, transactions ...*compilerDiagnosticTransaction) {
	started := i.compilerStatus.begin("kotlin")
	hosted := false
	outcome, failure, compilerName, compilerVersion := "skipped", "", "", ""
	requestedVersion, fallbackReason, diagnosticTransport, modelNote := "", "", "", ""
	var effectiveArguments []string
	defer func() {
		if failure != "" {
			i.recordHealth("compiler-kotlin", compilerName, failure)
		}
		i.compilerStatus.finish("kotlin", started, hosted, outcome, failure, compilerName, requestedVersion, compilerVersion, joinStatusReasons(fallbackReason, modelNote), diagnosticTransport, effectiveArguments)
	}()
	files, truncated := i.WorkspaceFilesContext(parent, 100_001)
	if truncated || len(files) > 100_000 {
		outcome, failure = "unavailable", "compiler validation exceeds its 100000-source safety limit"
		return
	}
	units, unitsErr := i.compilerUnitsContext(parent, files)
	if unitsErr != nil {
		outcome, failure = "unavailable", unitsErr.Error()
		return
	}
	if !anyUnitHasLanguage(units, "kotlin") {
		if len(transactions) > 0 {
			transactions[0].stage("kotlin", files, nil)
			outcome = "succeeded"
		}
		return
	}
	compiler, ok := i.kotlinCompilerContext(parent)
	if !ok || i.generation.Load() != generation {
		if !ok {
			outcome, failure = "unavailable", "no Kotlin compiler matching the available toolchain was found"
		}
		return
	}
	compilerName, compilerVersion = compiler.executable, compiler.version
	temporary, err := os.MkdirTemp("", "kotlsp-kotlinc-")
	if err != nil {
		outcome, failure = "failed", err.Error()
		return
	}
	defer os.RemoveAll(temporary)
	ctx := parent
	diagnostics := make(map[protocol.URI][]protocol.Diagnostic)
	passSuccessful := true
	for unitIndex, unit := range units {
		if i.generation.Load() != generation || ctx.Err() != nil {
			break
		}
		// A unit with none of this language cannot produce a finding for it.
		// Skipping the unit is not the same as abandoning the pass: units are
		// not ordered by language, so stopping here silently dropped every
		// later unit's diagnostics.
		if !unit.hasInputLanguage("kotlin") {
			continue
		}
		if unit.Settings.IncompleteReason != "" {
			passSuccessful = false
			outcome, failure = "unavailable", "project compiler model is incomplete: "+unit.Settings.IncompleteReason
			continue
		}
		if unit.ModelNote != "" {
			modelNote = unit.ModelNote
		}
		if cached, ok := i.compilerCacheLookup("kotlin", unit); ok {
			mergePrimaryCompilerDiagnostics(diagnostics, cached.Diagnostics, unit.Primary, "kotlin")
			continue
		}
		plan := i.compilerIncrementalPlan("kotlin", unit)
		if plan.Incremental && !compilerInputsContainKotlin(plan.Inputs) {
			entry := plan.Previous
			entry.InputHashes = plan.InputHashes
			entry.DeclarationShapes = plan.DeclarationShapes
			if !i.compilerCacheStore("kotlin", unit, entry) {
				passSuccessful = false
				outcome, failure = "unavailable", "compiler class cache exceeded its 4 GiB/1000000-entry safety limit"
				continue
			}
			mergePrimaryCompilerDiagnostics(diagnostics, entry.Diagnostics, unit.Primary, "kotlin")
			continue
		}
		unitCompiler := compiler
		requested := unit.Settings.KotlinVersion
		if requested != "" {
			if requestedVersion == "" {
				requestedVersion = requested
			} else if requestedVersion != requested {
				requestedVersion = "multiple project versions"
			}
		}
		if requested != "" && !strings.Contains(unitCompiler.version, requested) {
			matching, found := findKotlinCompilerVersionContext(ctx, requested)
			if !found {
				passSuccessful = false
				outcome, failure = "failed", "project Kotlin compiler "+requested+" was not available in the wrapper/cache"
				continue
			}
			unitCompiler = matching
		}
		if unitCompiler.embedded {
			if java := javaExecutableInConfiguredHome(unit.JavaHome); java != "" {
				unitCompiler.executable = java
			}
		}
		compilerName, compilerVersion = unitCompiler.executable, unitCompiler.version
		unitDirectory := filepath.Join(temporary, "unit-"+strconv.Itoa(unitIndex))
		if makeErr := os.MkdirAll(unitDirectory, 0o700); makeErr != nil {
			passSuccessful = false
			outcome, failure = "failed", makeErr.Error()
			continue
		}
		// K2 receives only the primary source set's accessible mixed-language
		// closure, preventing unrelated modules and test-only sources leaking in.
		paths, staged, pathErr := i.compilerSourcePaths(ctx, plan.Inputs, unitDirectory, isJavaOrKotlinSource)
		if pathErr != nil || len(paths) == 0 {
			passSuccessful = false
			outcome, failure = "failed", "could not stage Kotlin sources"
			if pathErr != nil {
				failure = pathErr.Error()
			}
			continue
		}
		classpath := append([]string(nil), unit.Classpath...)
		if unitCompiler.stdlib != "" {
			classpath = append(classpath, unitCompiler.stdlib)
		}
		if plan.Incremental {
			classpath = append(classpath, plan.Previous.Classes...)
		}
		classes, classesErr := i.compilerClassesDirectory("kotlin", unit)
		if classesErr != nil {
			passSuccessful = false
			outcome, failure = "failed", classesErr.Error()
			continue
		}
		_ = os.RemoveAll(classes)
		if makeErr := os.MkdirAll(classes, 0o700); makeErr != nil {
			i.discardCompilerDirectoryIfUnretained(classes)
			passSuccessful = false
			outcome, failure = "failed", makeErr.Error()
			continue
		}
		settings := unit.Settings
		if len(unit.ModulePath) > 0 {
			settings.KotlinArguments = append(append([]string(nil), settings.KotlinArguments...), "-Xmodule-path="+strings.Join(unit.ModulePath, string(os.PathListSeparator)))
		}
		effectiveArguments = redactCompilerArguments(kotlinCompilerArgumentsWithSettings(unitCompiler, classes, "<sources>", classpath, settings))
		var output []byte
		var usedHost bool
		var compileErr error
		if sameJavaHome(unit.JavaHome, i.DefaultJavaHome()) {
			output, usedHost, compileErr = i.runKotlinCompilerHostedTrackedWithSettings(ctx, unitCompiler, paths, classes, classpath, settings)
		} else {
			output, compileErr = runKotlinCompilerWithSettings(ctx, unitCompiler, paths, classes, classpath, settings)
		}
		if structured, note := i.compilerHosts.structuredTransport(); usedHost && structured {
			diagnosticTransport = "structured Kotlin message renderer"
		} else if usedHost {
			diagnosticTransport = "text parser (degraded)"
			fallbackReason = "warm host has no structured renderer API; its text output was parsed: " + note
		} else {
			diagnosticTransport = "text parser (degraded)"
			fallbackReason = "structured warm host was unavailable or used a different JDK; one-shot compiler output was parsed"
		}
		if !compilerCommandCompleted(ctx, compileErr) {
			i.discardCompilerDirectoryIfUnretained(classes)
			passSuccessful = false
			outcome, failure = compilerFailureOutcome(ctx, compileErr)
			continue
		}
		hosted = hosted || usedHost
		values := remapCompilerDiagnostics(parseKotlincDiagnostics(string(output)), staged)
		if count, sample := unmatchedCompilerDiagnosticHeaders(string(output), "kotlin", values); count > 0 {
			i.discardCompilerDirectoryIfUnretained(classes)
			i.recordHealth("compiler-kotlin-output", unit.Key, strconv.Itoa(count)+" diagnostic records were not parseable; first: "+sample)
			passSuccessful = false
			outcome, failure = "failed", "Kotlin compiler emitted unparseable diagnostic records"
			continue
		}
		i.expandCompilerDiagnosticRanges(values)
		values = compilerMergedIncrementalDiagnostics(plan, values)
		layers := 1
		classLayers := []string{classes}
		if plan.Incremental {
			layers = plan.Previous.Layers + 1
			classLayers = append(classLayers, plan.Previous.Classes...)
		}
		if !i.compilerCacheStore("kotlin", unit, compilerCacheEntry{
			Classes:           classLayers,
			Layers:            layers,
			InputHashes:       plan.InputHashes,
			DeclarationShapes: plan.DeclarationShapes,
			Diagnostics:       values,
		}) {
			passSuccessful = false
			outcome, failure = "unavailable", "compiler class cache exceeded its 4 GiB/1000000-entry safety limit"
			continue
		}
		mergePrimaryCompilerDiagnostics(diagnostics, values, unit.Primary, "kotlin")
	}
	if !passSuccessful || ctx.Err() != nil || i.generation.Load() != generation {
		if ctx.Err() != nil {
			outcome, failure = "cancelled", ctx.Err().Error()
		} else if i.generation.Load() != generation {
			outcome, failure = "superseded", "a newer workspace generation replaced this pass"
		}
		return
	}
	if len(transactions) > 0 {
		transactions[0].stage("kotlin", files, diagnostics)
		outcome, failure = "succeeded", ""
		return
	}
	budgetCompilerDiagnostics(diagnostics)
	i.mu.Lock()
	if i.generation.Load() != generation {
		i.mu.Unlock()
		return
	}
	for _, file := range files {
		lower := strings.ToLower(string(file.URI))
		if strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts") {
			delete(i.compilerDiagnostics, file.URI)
		}
	}
	for uri, values := range diagnostics {
		i.compilerDiagnostics[uri] = values
	}
	i.diagnosticsVersion.Add(1)
	outcome, failure = "succeeded", ""
	i.mu.Unlock()
	if i.onParsed != nil {
		for _, file := range files {
			lower := strings.ToLower(string(file.URI))
			if strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts") {
				i.onParsed(file.URI, i.Diagnostics(file.URI))
			}
		}
	}
}

type compilerUnit struct {
	Key               string
	Hash              uint64
	ConfigurationHash uint64
	Primary           []*analysis.ParsedFile
	Inputs            []*analysis.ParsedFile
	Classpath         []string
	ModulePath        []string
	JavaHome          string
	Settings          CompilerSettings
	// ModelNote describes a build model that is complete but not produced by
	// a build tool, so status can say what the compiler's classpath came from.
	ModelNote string
}

func (unit compilerUnit) hasPrimaryLanguage(language string) bool {
	for _, file := range unit.Primary {
		lower := strings.ToLower(string(file.URI))
		if language == "java" && strings.HasSuffix(lower, ".java") ||
			language == "kotlin" && (strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")) {
			return true
		}
	}
	return false
}

func (unit compilerUnit) hasInputLanguage(language string) bool {
	for _, file := range unit.Inputs {
		lower := strings.ToLower(string(file.URI))
		if language == "java" && strings.HasSuffix(lower, ".java") || language == "kotlin" && (strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")) {
			return true
		}
	}
	return false
}

// compilerUnits snapshots independently compilable module/source-set views.
// Primary files receive diagnostics; Inputs additionally contains only source
// sets reachable through that primary's declared project dependencies.
func (i *Index) compilerUnits(files []*analysis.ParsedFile) []compilerUnit {
	units, _ := i.compilerUnitsContext(context.Background(), files)
	return units
}

func (i *Index) compilerUnitsContext(ctx context.Context, files []*analysis.ParsedFile) ([]compilerUnit, error) {
	const maxCompilerUnits = 2048
	type unitIdentity struct {
		moduleDir string
		module    *ModuleInfo
		sourceSet string
	}
	i.mu.RLock()
	moduleSnapshot := make([]ModuleInfo, len(i.modules))
	for moduleIndex, module := range i.modules {
		moduleSnapshot[moduleIndex] = cloneModuleInfo(module)
	}
	fallbackClasspath := append([]string(nil), i.classpath...)
	defaultJavaHome := i.defaultJavaHome
	environmentVersion := i.semanticEnvironmentVersion
	i.mu.RUnlock()
	identities := make(map[string]*unitIdentity)
	primaryByKey := make(map[string][]*analysis.ParsedFile)
	for fileIndex, file := range files {
		if fileIndex&255 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if file == nil {
			continue
		}
		// An index without a build model (an editor fragment opened before
		// Start, an embedder, or a workspace whose build produced no modules)
		// has exactly one compilation unit: every source and the fallback
		// classpath. Ownership can only be missing or ambiguous once modules
		// exist to claim files.
		var module *ModuleInfo
		set, key := "main", "<workspace>\x00main"
		if len(moduleSnapshot) > 0 {
			var uniqueModule bool
			module, uniqueModule = moduleForURIInModules(file.URI, moduleSnapshot)
			if !uniqueModule {
				if !anyModuleClaimsURI(file.URI, moduleSnapshot) {
					// A document outside every module (a scratch file the editor
					// opened from elsewhere) belongs to no compilation unit; it
					// must not abort validation of the units that do exist.
					i.recordHealth("compiler-units", string(file.URI), "document lies outside every module and is excluded from compiler validation")
					continue
				}
				return nil, fmt.Errorf("compiler validation has ambiguous module ownership for %s", file.URI)
			}
			var uniqueSourceSet bool
			set, uniqueSourceSet = sourceSetForURIInModule(file.URI, module)
			if !uniqueSourceSet {
				return nil, fmt.Errorf("compiler validation has ambiguous source-set ownership for %s", file.URI)
			}
			key = module.Root + "\x00" + module.Dir + "\x00" + module.Name + "\x00" + set
		}
		if identities[key] == nil {
			if len(identities) >= maxCompilerUnits {
				return nil, fmt.Errorf("compiler model exceeds its %d-unit safety limit", maxCompilerUnits)
			}
			identities[key] = &unitIdentity{module: module, sourceSet: set}
			if module != nil {
				identities[key].moduleDir = module.Dir
			}
		}
		primaryByKey[key] = append(primaryByKey[key], file)
	}
	keys := make([]string, 0, len(identities))
	for key := range identities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	modulesByName := make(map[string][]*ModuleInfo, len(moduleSnapshot))
	for moduleIndex := range moduleSnapshot {
		module := &moduleSnapshot[moduleIndex]
		nameKey := module.Root + "\x00" + module.Name
		modulesByName[nameKey] = append(modulesByName[nameKey], module)
	}
	accessByKey := make(map[string]map[string]bool, len(keys))
	for _, key := range keys {
		identity := identities[key]
		if identity.module != nil {
			var complete bool
			accessByKey[key], complete = moduleAccessSet(identity.module, identity.sourceSet, modulesByName)
			if !complete {
				return nil, fmt.Errorf("compiler dependency closure for %s exceeds its 100000-state safety limit", key)
			}
		}
	}
	units := make([]compilerUnit, 0, len(keys))
	totalInputMembership := 0
	for keyIndex, key := range keys {
		if keyIndex&31 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		identity := identities[key]
		unit := compilerUnit{Key: key, Primary: append([]*analysis.ParsedFile(nil), primaryByKey[key]...)}
		for candidateIndex, candidateKey := range keys {
			if candidateIndex&255 == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			candidateIdentity := identities[candidateKey]
			candidateModule, candidateSet := candidateIdentity.module, candidateIdentity.sourceSet
			accessible := identity.module == nil && candidateModule == nil
			if identity.module != nil && candidateModule != nil {
				if identity.module.Name == candidateModule.Name && identity.module.Dir == candidateModule.Dir {
					accessible = sourceSetCanAccess(identity.module, identity.sourceSet, candidateSet)
				} else if candidateSet == "main" || candidateSet == "commonMain" {
					accessible = accessByKey[key][moduleAccessIdentity(candidateModule)]
				}
			}
			if accessible {
				unit.Inputs = append(unit.Inputs, primaryByKey[candidateKey]...)
				totalInputMembership += len(primaryByKey[candidateKey])
				if totalInputMembership > 1_000_000 {
					return nil, fmt.Errorf("compiler dependency closures exceed their 1000000-source-membership safety limit")
				}
			}
		}
		if len(unit.Primary) > 0 {
			if identity.module != nil {
				unit.Classpath, unit.ModulePath, _ = classpathForModuleSnapshot(unit.Primary[0].URI, identity.module, moduleSnapshot, fallbackClasspath)
				unit.JavaHome = identity.module.JavaHome
				unit.Settings = identity.module.CompilerSettingsBySourceSet[identity.sourceSet]
				if unit.Settings.JavaHome != "" {
					unit.JavaHome = unit.Settings.JavaHome
				}
				if identity.module.BuildModelSelfContained {
					unit.ModelNote = identity.module.BuildModelFailure
				}
			} else {
				unit.Classpath = append([]string(nil), fallbackClasspath...)
				unit.JavaHome = defaultJavaHome
			}
			if len(unit.Classpath)+len(unit.ModulePath) > 8192 {
				return nil, fmt.Errorf("compiler unit %s exceeds its 8192-entry path safety limit", unit.Key)
			}
		}
		units = append(units, unit)
	}
	for unitIndex := range units {
		if unitIndex&31 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		sort.Slice(units[unitIndex].Primary, func(a, b int) bool { return units[unitIndex].Primary[a].URI < units[unitIndex].Primary[b].URI })
		sort.Slice(units[unitIndex].Inputs, func(a, b int) bool { return units[unitIndex].Inputs[a].URI < units[unitIndex].Inputs[b].URI })
		configurationHash := sha256.New()
		writeDigestString(configurationHash, units[unitIndex].Key)
		for _, path := range units[unitIndex].Classpath {
			writeDigestString(configurationHash, path)
			if digest, ok := i.cachedArchiveDigest(path); ok {
				_, _ = configurationHash.Write(digest[:])
			}
			if info, err := os.Stat(path); err == nil {
				writeDigestUint64(configurationHash, uint64(info.Size()))
				writeDigestUint64(configurationHash, uint64(info.ModTime().UnixNano()))
			}
		}
		for _, path := range units[unitIndex].ModulePath {
			writeDigestString(configurationHash, path)
			if digest, ok := i.cachedArchiveDigest(path); ok {
				_, _ = configurationHash.Write(digest[:])
			}
			if info, err := os.Stat(path); err == nil {
				writeDigestUint64(configurationHash, uint64(info.Size()))
				writeDigestUint64(configurationHash, uint64(info.ModTime().UnixNano()))
			}
		}
		for _, argument := range normalizedJavaCompilerArguments(units[unitIndex].Settings) {
			writeDigestString(configurationHash, argument)
		}
		for _, argument := range normalizedKotlinCompilerArguments(units[unitIndex].Settings) {
			writeDigestString(configurationHash, argument)
		}
		writeDigestString(configurationHash, units[unitIndex].JavaHome)
		writeDigestString(configurationHash, units[unitIndex].Settings.KotlinVersion)
		units[unitIndex].ConfigurationHash = binary.LittleEndian.Uint64(configurationHash.Sum(nil)[:8])
		contentHash := sha256.New()
		writeDigestUint64(contentHash, units[unitIndex].ConfigurationHash)
		for _, file := range units[unitIndex].Inputs {
			writeDigestString(contentHash, string(file.URI))
			writeDigestUint64(contentHash, file.TextHash)
		}
		units[unitIndex].Hash = binary.LittleEndian.Uint64(contentHash.Sum(nil)[:8])
	}
	i.mu.RLock()
	modelCurrent := i.semanticEnvironmentVersion == environmentVersion
	i.mu.RUnlock()
	if !modelCurrent {
		return nil, fmt.Errorf("compiler model changed while its unit snapshot was being assembled")
	}
	return units, nil
}

func joinStatusReasons(reasons ...string) string {
	var out []string
	for _, reason := range reasons {
		if reason != "" {
			out = append(out, reason)
		}
	}
	return strings.Join(out, "; ")
}

func writeDigestString(destination interface{ Write([]byte) (int, error) }, value string) {
	writeDigestUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeDigestUint64(destination interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = destination.Write(encoded[:])
}

func (i *Index) cachedArchiveDigest(path string) ([sha256.Size]byte, bool) {
	i.mu.RLock()
	digest, ok := i.archiveDigests[filepath.Clean(path)]
	i.mu.RUnlock()
	return digest, ok
}

func (i *Index) sourceSetForCompilerURI(uri protocol.URI, module ModuleInfo) string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	for sourceSet, roots := range module.SourceSets {
		for _, root := range roots {
			path, ok := uriutil.Path(uri)
			if ok && pathWithin(path, root) {
				return sourceSet
			}
		}
	}
	return "main"
}

type compilerCacheEntry struct {
	Hash              uint64
	ConfigurationHash uint64
	Classes           []string
	Layers            int
	InputHashes       map[protocol.URI]uint64
	DeclarationShapes map[protocol.URI]uint64
	Diagnostics       map[protocol.URI][]protocol.Diagnostic
	LastUsed          uint64
}

func (i *Index) compilerCacheLookup(language string, unit compilerUnit) (compilerCacheEntry, bool) {
	i.compilerCacheMu.Lock()
	defer i.compilerCacheMu.Unlock()
	entry, ok := i.compilerCache[language+"\x00"+unit.Key]
	if !ok || entry.Hash != unit.Hash || !compilerClassLayersExist(entry.Classes) {
		return compilerCacheEntry{}, false
	}
	i.compilerCacheClock++
	entry.LastUsed = i.compilerCacheClock
	i.compilerCache[language+"\x00"+unit.Key] = entry
	return cloneCompilerCacheEntry(entry), true
}

func (i *Index) compilerCacheStore(language string, unit compilerUnit, entry compilerCacheEntry) bool {
	const (
		maxCompilerCacheEntries = 4096
		maxCompilerCacheBytes   = int64(4 << 30)
	)
	entry.Hash = unit.Hash
	entry.ConfigurationHash = unit.ConfigurationHash
	entry = cloneCompilerCacheEntry(entry)
	// Class layers are compiler output, so an entry count alone is not a disk
	// bound: one generated-source unit can emit gigabytes. Measure each new
	// immutable directory outside the cache lock with both byte and entry caps.
	i.compilerCacheMu.Lock()
	unknown := make([]string, 0, len(entry.Classes))
	for _, directory := range entry.Classes {
		if _, known := i.compilerCacheDirectoryBytes[directory]; !known {
			unknown = append(unknown, directory)
		}
	}
	i.compilerCacheMu.Unlock()
	measured := make(map[string]int64, len(unknown))
	for _, directory := range unknown {
		bytes, complete := compilerDirectoryBytesBounded(directory, maxCompilerCacheBytes, 1_000_000)
		if !complete {
			i.compilerCacheMu.Lock()
			discard := i.discardUnretainedCompilerDirectoriesLocked(compilerCacheRetainedDirectories(i.compilerCache))
			i.compilerCacheMu.Unlock()
			for _, candidate := range discard {
				_ = os.RemoveAll(candidate)
			}
			return false
		}
		measured[directory] = bytes
	}
	i.compilerCacheMu.Lock()
	key := language + "\x00" + unit.Key
	for directory, bytes := range measured {
		i.compilerCacheDirectoryBytes[directory] = bytes
	}
	entryDirectories := make(map[string]bool, len(entry.Classes))
	var entryBytes int64
	for _, directory := range entry.Classes {
		if !entryDirectories[directory] {
			entryDirectories[directory] = true
			entryBytes += i.compilerCacheDirectoryBytes[directory]
		}
	}
	if entryBytes > maxCompilerCacheBytes {
		discard := i.discardUnretainedCompilerDirectoriesLocked(compilerCacheRetainedDirectories(i.compilerCache))
		i.compilerCacheMu.Unlock()
		for _, directory := range discard {
			_ = os.RemoveAll(directory)
		}
		return false
	}
	i.compilerCacheClock++
	entry.LastUsed = i.compilerCacheClock
	previous := i.compilerCache[key]
	i.compilerCache[key] = entry
	cacheBytes := func() int64 {
		seen := make(map[string]bool)
		var total int64
		for _, cached := range i.compilerCache {
			for _, directory := range cached.Classes {
				if !seen[directory] {
					seen[directory] = true
					total += i.compilerCacheDirectoryBytes[directory]
				}
			}
		}
		return total
	}
	for len(i.compilerCache) > maxCompilerCacheEntries || cacheBytes() > maxCompilerCacheBytes {
		victimKey := ""
		var victim compilerCacheEntry
		for candidateKey, candidate := range i.compilerCache {
			if candidateKey != key && (victimKey == "" || candidate.LastUsed < victim.LastUsed) {
				victimKey, victim = candidateKey, candidate
			}
		}
		if victimKey == "" {
			if len(previous.Classes) == 0 {
				delete(i.compilerCache, key)
			} else {
				i.compilerCache[key] = previous
			}
			retained := compilerCacheRetainedDirectories(i.compilerCache)
			discard := i.discardUnretainedCompilerDirectoriesLocked(retained)
			i.compilerCacheBytes = cacheBytes()
			i.compilerCacheMu.Unlock()
			for _, directory := range discard {
				_ = os.RemoveAll(directory)
			}
			return false
		}
		delete(i.compilerCache, victimKey)
	}
	retained := compilerCacheRetainedDirectories(i.compilerCache)
	discard := i.discardUnretainedCompilerDirectoriesLocked(retained)
	i.compilerCacheBytes = cacheBytes()
	i.compilerCacheMu.Unlock()
	for _, directory := range discard {
		_ = os.RemoveAll(directory)
	}
	return true
}

func compilerCacheRetainedDirectories(cache map[string]compilerCacheEntry) map[string]bool {
	retained := make(map[string]bool)
	for _, entry := range cache {
		for _, directory := range entry.Classes {
			retained[directory] = true
		}
	}
	return retained
}

func (i *Index) discardUnretainedCompilerDirectoriesLocked(retained map[string]bool) []string {
	var discard []string
	for directory := range i.compilerCacheDirectories {
		if directory != "" && !retained[directory] {
			delete(i.compilerCacheDirectories, directory)
			delete(i.compilerCacheDirectoryBytes, directory)
			discard = append(discard, directory)
		}
	}
	return discard
}

func (i *Index) discardCompilerDirectoryIfUnretained(directory string) {
	if directory == "" {
		return
	}
	i.compilerCacheMu.Lock()
	retained := compilerCacheRetainedDirectories(i.compilerCache)
	if retained[directory] {
		i.compilerCacheMu.Unlock()
		return
	}
	delete(i.compilerCacheDirectories, directory)
	delete(i.compilerCacheDirectoryBytes, directory)
	i.compilerCacheMu.Unlock()
	_ = os.RemoveAll(directory)
}

func compilerDirectoryBytesBounded(root string, byteLimit int64, entryLimit int) (int64, bool) {
	var total int64
	entries := 0
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > entryLimit {
			return fs.SkipAll
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > byteLimit-total {
			total = byteLimit + 1
			return fs.SkipAll
		}
		total += info.Size()
		return nil
	})
	return total, err == nil && entries <= entryLimit && total <= byteLimit
}

func (i *Index) compilerCachePrevious(language string, unit compilerUnit) (compilerCacheEntry, bool) {
	i.compilerCacheMu.Lock()
	defer i.compilerCacheMu.Unlock()
	entry, ok := i.compilerCache[language+"\x00"+unit.Key]
	if !ok || entry.ConfigurationHash != unit.ConfigurationHash || !compilerClassLayersExist(entry.Classes) {
		return compilerCacheEntry{}, false
	}
	i.compilerCacheClock++
	entry.LastUsed = i.compilerCacheClock
	i.compilerCache[language+"\x00"+unit.Key] = entry
	return cloneCompilerCacheEntry(entry), true
}

func (i *Index) compilerClassesDirectory(language string, unit compilerUnit) (string, error) {
	i.compilerCacheMu.Lock()
	defer i.compilerCacheMu.Unlock()
	if i.compilerCacheRoot == "" {
		root, err := os.MkdirTemp("", "kotlsp-compiler-cache-")
		if err != nil {
			return "", err
		}
		i.compilerCacheRoot = root
	}
	identity := sha256.Sum256([]byte(language + "\x00" + unit.Key + "\x00" + strconv.FormatUint(unit.Hash, 16)))
	directory := filepath.Join(i.compilerCacheRoot, language+"-"+hex.EncodeToString(identity[:16]))
	if !i.compilerCacheDirectories[directory] && len(i.compilerCacheDirectories) >= 8192 {
		return "", fmt.Errorf("compiler class cache exceeds its 8192-directory safety limit")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	i.compilerCacheDirectories[directory] = true
	return directory, nil
}

func cloneDiagnosticMap(values map[protocol.URI][]protocol.Diagnostic) map[protocol.URI][]protocol.Diagnostic {
	if values == nil {
		return nil
	}
	out := make(map[protocol.URI][]protocol.Diagnostic, len(values))
	for uri, diagnostics := range values {
		out[uri] = append([]protocol.Diagnostic(nil), diagnostics...)
	}
	return out
}

func cloneCompilerCacheEntry(entry compilerCacheEntry) compilerCacheEntry {
	entry.Classes = append([]string(nil), entry.Classes...)
	entry.Diagnostics = cloneDiagnosticMap(entry.Diagnostics)
	entry.InputHashes = cloneCompilerHashMap(entry.InputHashes)
	entry.DeclarationShapes = cloneCompilerHashMap(entry.DeclarationShapes)
	return entry
}

func cloneCompilerHashMap(values map[protocol.URI]uint64) map[protocol.URI]uint64 {
	if values == nil {
		return nil
	}
	out := make(map[protocol.URI]uint64, len(values))
	for uri, value := range values {
		out[uri] = value
	}
	return out
}

func compilerClassLayersExist(paths []string) bool {
	for _, path := range paths {
		if !directoryExists(path) {
			return false
		}
	}
	return true
}

type incrementalCompilerPlan struct {
	Inputs            []*analysis.ParsedFile
	Previous          compilerCacheEntry
	Incremental       bool
	Affected          map[protocol.URI]bool
	InputHashes       map[protocol.URI]uint64
	DeclarationShapes map[protocol.URI]uint64
}

// compilerIncrementalPlan selects the smallest safe source closure for a
// compiler pass. Class directories are immutable layers: a body-only edit can
// put newly emitted classes ahead of the previous layer, while a declaration
// shape change deliberately falls back to a clean build so removed/renamed
// class files can never survive underneath the new output.
func (i *Index) compilerIncrementalPlan(language string, unit compilerUnit) incrementalCompilerPlan {
	relevant := make([]*analysis.ParsedFile, 0, len(unit.Inputs))
	inputHashes := make(map[protocol.URI]uint64)
	shapes := make(map[protocol.URI]uint64)
	byURI := make(map[protocol.URI]*analysis.ParsedFile)
	for _, file := range unit.Inputs {
		if file == nil || !compilerInputApplies(language, file.URI) {
			continue
		}
		relevant = append(relevant, file)
		byURI[file.URI] = file
		inputHashes[file.URI] = file.TextHash
		shapes[file.URI] = compilerDeclarationShape(file)
	}
	full := incrementalCompilerPlan{Inputs: relevant, InputHashes: inputHashes, DeclarationShapes: shapes}
	previous, ok := i.compilerCachePrevious(language, unit)
	if !ok || len(previous.InputHashes) == 0 || previous.Layers >= 8 {
		return full
	}
	for uri := range previous.InputHashes {
		if _, exists := inputHashes[uri]; !exists {
			return full
		}
	}
	changed := make(map[protocol.URI]bool)
	for uri, hash := range inputHashes {
		oldHash, existed := previous.InputHashes[uri]
		if !existed || oldHash != hash {
			changed[uri] = true
		}
		if existed && previous.DeclarationShapes[uri] != shapes[uri] {
			return full
		}
	}
	if len(changed) == 0 {
		// The exact cache lookup can miss only when an artifact disappeared.
		// Rebuilding cleanly is safer than layering on an incomplete snapshot.
		return full
	}
	affected, complete := i.compilerAffectedClosure(changed, byURI)
	if !complete {
		return full
	}
	if len(affected)*4 > len(relevant)*3 {
		return full
	}
	inputs := make([]*analysis.ParsedFile, 0, len(affected))
	for _, file := range relevant {
		if affected[file.URI] {
			inputs = append(inputs, file)
		}
	}
	if len(inputs) == 0 {
		return full
	}
	return incrementalCompilerPlan{
		Inputs:            inputs,
		Previous:          previous,
		Incremental:       true,
		Affected:          affected,
		InputHashes:       inputHashes,
		DeclarationShapes: shapes,
	}
}

func compilerInputApplies(language string, uri protocol.URI) bool {
	lower := strings.ToLower(string(uri))
	if language == "java" {
		return strings.HasSuffix(lower, ".java")
	}
	return strings.HasSuffix(lower, ".java") || strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")
}

func compilerInputsContainKotlin(files []*analysis.ParsedFile) bool {
	for _, file := range files {
		if file == nil {
			continue
		}
		lower := strings.ToLower(string(file.URI))
		if strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts") {
			return true
		}
	}
	return false
}

func compilerDeclarationShape(file *analysis.ParsedFile) uint64 {
	if file == nil {
		return 0
	}
	const maxDeclarationShapeBytes = 64 << 20
	values := make([]string, 0, len(file.Symbols)+1)
	values = append(values, "package\x00"+file.Package)
	totalBytes := len(values[0])
	for _, symbol := range file.Symbols {
		if isLexicalSymbol(symbol) || symbol.Synthetic {
			continue
		}
		var value strings.Builder
		value.WriteString(strconv.Itoa(int(symbol.Kind)))
		value.WriteByte(0)
		value.WriteString(symbol.FQN)
		value.WriteByte(0)
		value.WriteString(symbol.ContainerName)
		value.WriteByte(0)
		value.WriteString(symbol.Signature)
		value.WriteByte(0)
		value.WriteString(symbol.Type)
		value.WriteByte(0)
		value.WriteString(symbol.ReceiverType)
		value.WriteByte(0)
		value.WriteString(strings.Join(symbol.TypeParameters, ","))
		value.WriteByte(0)
		value.WriteString(strings.Join(symbol.Supertypes, ","))
		value.WriteByte(0)
		value.WriteString(strings.Join(symbol.Modifiers, ","))
		for _, parameter := range symbol.Parameters {
			value.WriteByte(0)
			value.WriteString(parameter.Name)
			value.WriteByte(':')
			value.WriteString(parameter.Type)
			if parameter.Variadic {
				value.WriteByte('*')
			}
		}
		shape := value.String()
		if len(shape) > maxDeclarationShapeBytes-totalBytes {
			// Treat an over-complex declaration surface as changing with any text
			// edit. That disables incremental layering instead of comparing two
			// incomplete shapes as though they were equal.
			return file.TextHash ^ 0x9e3779b97f4a7c15
		}
		totalBytes += len(shape)
		values = append(values, shape)
	}
	sort.Strings(values)
	hash := sha256.New()
	for _, value := range values {
		writeDigestString(hash, value)
	}
	return binary.LittleEndian.Uint64(hash.Sum(nil)[:8])
}

func (i *Index) compilerAffectedClosure(changed map[protocol.URI]bool, files map[protocol.URI]*analysis.ParsedFile) (map[protocol.URI]bool, bool) {
	const maxCompilerDependencyEdges = 1_000_000
	affected := make(map[protocol.URI]bool, len(changed))
	queue := make([]protocol.URI, 0, len(changed))
	for uri := range changed {
		if files[uri] != nil {
			affected[uri] = true
			queue = append(queue, uri)
		}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	edges := 0
	add := func(uri protocol.URI) {
		if files[uri] != nil && !affected[uri] {
			affected[uri] = true
			queue = append(queue, uri)
		}
	}
	for len(queue) > 0 {
		uri := queue[0]
		queue = queue[1:]
		file := files[uri]
		for _, symbol := range file.Symbols {
			if isLexicalSymbol(symbol) || symbol.Synthetic {
				continue
			}
			for _, reference := range i.refsByTarget[symbol.ID] {
				edges++
				if edges > maxCompilerDependencyEdges {
					return nil, false
				}
				add(reference.URI)
			}
			// A reference can still be unresolved while its declaring file is
			// changing. Including name matches is intentionally conservative.
			for _, reference := range i.unresolvedRefsByName[symbol.Name] {
				edges++
				if edges > maxCompilerDependencyEdges {
					return nil, false
				}
				add(reference.URI)
			}
			for _, importer := range i.importersByPrefix[symbol.FQN] {
				edges++
				if edges > maxCompilerDependencyEdges {
					return nil, false
				}
				add(importer)
			}
		}
	}
	return affected, true
}

func compilerMergedIncrementalDiagnostics(plan incrementalCompilerPlan, current map[protocol.URI][]protocol.Diagnostic) map[protocol.URI][]protocol.Diagnostic {
	if !plan.Incremental {
		return current
	}
	merged := cloneDiagnosticMap(plan.Previous.Diagnostics)
	if merged == nil {
		merged = make(map[protocol.URI][]protocol.Diagnostic)
	}
	for uri := range plan.Affected {
		delete(merged, uri)
	}
	for uri, diagnostics := range current {
		merged[uri] = append([]protocol.Diagnostic(nil), diagnostics...)
	}
	return merged
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// sameJavaHome reports whether a unit's toolchain is the one the host runs on.
// An empty unit home means "whatever the server is configured with", which is
// exactly the host's JDK.
// anyUnitHasLanguage reports whether a pass for this language could produce
// anything at all, so a project without it pays nothing.
func anyUnitHasLanguage(units []compilerUnit, language string) bool {
	for _, unit := range units {
		if unit.hasPrimaryLanguage(language) {
			return true
		}
	}
	return false
}

func sameJavaHome(unitHome, defaultHome string) bool {
	if unitHome == "" {
		return true
	}
	if defaultHome == "" {
		return false
	}
	return filepath.Clean(unitHome) == filepath.Clean(defaultHome)
}

func javacExecutableInHome(home string) string {
	if home == "" {
		return ""
	}
	for _, name := range []string{"javac", "javac.exe"} {
		path := filepath.Join(home, "bin", name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func javaExecutableInConfiguredHome(home string) string {
	if home == "" {
		return ""
	}
	for _, name := range []string{"java", "java.exe"} {
		path := filepath.Join(home, "bin", name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func (i *Index) kotlinCompiler() (kotlinCompiler, bool) {
	return i.kotlinCompilerContext(context.Background())
}

func (i *Index) kotlinCompilerContext(ctx context.Context) (kotlinCompiler, bool) {
	compiler, ok := findKotlinCompilerContext(ctx)
	if !ok {
		return kotlinCompiler{}, false
	}
	if compiler.embedded {
		if java := javaExecutableInConfiguredHome(i.DefaultJavaHome()); java != "" {
			compiler.executable = java
		}
	}
	return compiler, true
}

func mergePrimaryCompilerDiagnostics(destination, values map[protocol.URI][]protocol.Diagnostic, primary []*analysis.ParsedFile, language string) {
	allowed := make(map[protocol.URI]bool, len(primary))
	for _, file := range primary {
		if file == nil {
			continue
		}
		lower := strings.ToLower(string(file.URI))
		if language == "java" && strings.HasSuffix(lower, ".java") ||
			language == "kotlin" && (strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")) {
			allowed[file.URI] = true
		}
	}
	for uri, diagnostics := range values {
		if allowed[uri] {
			destination[uri] = append(destination[uri], diagnostics...)
		}
	}
}

func isJavaOrKotlinSource(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".java") || strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")
}

func hasKotlinSource(paths []string) bool {
	for _, path := range paths {
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts") {
			return true
		}
	}
	return false
}

// kotlinCompilerArguments builds the compiler's own arguments, shared by the
// one-shot command line and the persistent host.
func kotlinCompilerArguments(compiler kotlinCompiler, destination, argumentFile string, classpath []string) []string {
	return kotlinCompilerArgumentsWithSettings(compiler, destination, argumentFile, classpath, CompilerSettings{})
}

func kotlinCompilerArgumentsWithSettings(compiler kotlinCompiler, destination, argumentFile string, classpath []string, settings CompilerSettings) []string {
	arguments := make([]string, 0, 8)
	if compiler.embedded {
		arguments = append(arguments, "-no-stdlib", "-no-reflect")
	}
	// Joint compilation is required for cyclic Java/Kotlin source dependencies:
	// Java sources serve as symbols for K2 and are compiled by javac in the same
	// invocation, making both language outputs available to the follow-up lint.
	arguments = append(arguments, "-Xcompile-java", "-Xrender-internal-diagnostic-names")
	arguments = append(arguments, normalizedKotlinCompilerArguments(settings)...)
	arguments = append(arguments, "-d", destination)
	if len(classpath) > 0 {
		arguments = append(arguments, "-classpath", strings.Join(classpath, string(os.PathListSeparator)))
	}
	return append(arguments, "@"+argumentFile)
}

func normalizedJavaCompilerArguments(settings CompilerSettings) []string {
	arguments := make([]string, 0, len(settings.JavaArguments)+6)
	if settings.JavaRelease != "" {
		arguments = append(arguments, "--release", settings.JavaRelease)
	} else {
		if settings.JavaSource != "" {
			arguments = append(arguments, "-source", settings.JavaSource)
		}
		if settings.JavaTarget != "" {
			arguments = append(arguments, "-target", settings.JavaTarget)
		}
	}
	return append(arguments, normalizeCompilerArguments(settings.JavaArguments, true)...)
}

func javaProcessorConfigured(arguments []string) bool {
	for _, argument := range arguments {
		argument = strings.TrimSpace(argument)
		if argument == "-processor" || argument == "-processorpath" || argument == "--processor-path" || strings.HasPrefix(argument, "-processor=") || strings.HasPrefix(argument, "-processorpath=") || strings.HasPrefix(argument, "--processor-path=") || argument == "-proc:full" || argument == "-proc:only" {
			return true
		}
	}
	return false
}

func normalizedKotlinCompilerArguments(settings CompilerSettings) []string {
	arguments := make([]string, 0, len(settings.KotlinArguments)+6)
	if settings.KotlinLanguageVersion != "" {
		arguments = append(arguments, "-language-version", settings.KotlinLanguageVersion)
	}
	if settings.KotlinAPIVersion != "" {
		arguments = append(arguments, "-api-version", settings.KotlinAPIVersion)
	}
	if settings.KotlinJVMTarget != "" {
		arguments = append(arguments, "-jvm-target", settings.KotlinJVMTarget)
	}
	return append(arguments, normalizeCompilerArguments(settings.KotlinArguments, false)...)
}

// normalizeCompilerArguments retains project semantic switches while the
// language server remains authoritative for sources, output, and classpaths.
// Build tools frequently include those locations in their task argument list;
// replaying them would compile stale disk files or write into the project.
func normalizeCompilerArguments(values []string, java bool) []string {
	managedWithValue := map[string]bool{"-d": true, "-classpath": true, "-cp": true, "--class-path": true, "--module-path": true, "-p": true, "-sourcepath": true, "--source-path": true, "-s": true, "-source": true, "-target": true, "--release": true, "-language-version": true, "-api-version": true, "-jvm-target": true}
	managedFlag := map[string]bool{"-no-stdlib": true, "-no-reflect": true, "-Xcompile-java": true, "-Xrender-internal-diagnostic-names": true}
	out := make([]string, 0, len(values))
	for index := 0; index < len(values); index++ {
		value := strings.TrimSpace(values[index])
		if value == "" || strings.HasPrefix(value, "@") || java && strings.HasSuffix(strings.ToLower(value), ".java") || !java && (strings.HasSuffix(strings.ToLower(value), ".kt") || strings.HasSuffix(strings.ToLower(value), ".kts")) {
			continue
		}
		if managedWithValue[value] {
			index++
			continue
		}
		if managedFlag[value] {
			continue
		}
		managedAssignment := false
		for option := range managedWithValue {
			if strings.HasPrefix(value, option+"=") {
				managedAssignment = true
				break
			}
		}
		if !managedAssignment {
			out = append(out, value)
		}
	}
	return out
}

func writeCompilerArgumentFile(destination string, paths []string) (string, error) {
	argumentFile := filepath.Join(filepath.Dir(destination), filepath.Base(destination)+"-sources.args")
	var arguments strings.Builder
	for _, path := range paths {
		arguments.WriteString(quoteJavacArgument(path))
		arguments.WriteByte('\n')
	}
	if err := os.WriteFile(argumentFile, []byte(arguments.String()), 0o600); err != nil {
		return "", err
	}
	return argumentFile, nil
}

// runKotlinCompilerHosted compiles through the long-lived host, falling back to
// a one-shot process whenever the host is unavailable. A failure to keep a warm
// compiler must never cost the user their diagnostics.
func (i *Index) runKotlinCompilerHosted(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string) ([]byte, error) {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, err
	}
	argumentFile, err := writeCompilerArgumentFile(destination, paths)
	if err != nil {
		return nil, err
	}
	arguments := kotlinCompilerArguments(compiler, destination, argumentFile, classpath)
	output, hostErr := i.compilerHosts.run(ctx, compiler, i.DefaultJavaHome(), arguments)
	if hostErr == nil {
		return output, nil
	}
	if ctx.Err() != nil {
		return nil, hostErr
	}
	return runKotlinCompiler(ctx, compiler, paths, destination, classpath)
}

// runKotlinCompilerHostedTracked reports whether the warm host answered, so the
// status surface can say whether validation is running hot or cold.
func (i *Index) runKotlinCompilerHostedTracked(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string) ([]byte, bool, error) {
	return i.runKotlinCompilerHostedTrackedWithSettings(ctx, compiler, paths, destination, classpath, CompilerSettings{})
}

func (i *Index) runKotlinCompilerHostedTrackedWithSettings(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string, settings CompilerSettings) ([]byte, bool, error) {
	if err := os.MkdirAll(destination, 0o700); err == nil {
		if argumentFile, argErr := writeCompilerArgumentFile(destination, paths); argErr == nil {
			arguments := kotlinCompilerArgumentsWithSettings(compiler, destination, argumentFile, classpath, settings)
			if output, hostErr := i.compilerHosts.run(ctx, compiler, i.DefaultJavaHome(), arguments); hostErr == nil {
				return output, true, nil
			} else if ctx.Err() != nil {
				return nil, false, hostErr
			}
		}
	}
	output, err := runKotlinCompilerWithSettings(ctx, compiler, paths, destination, classpath, settings)
	return output, false, err
}

// Exit code 1 is the normal "source did not compile" result for javac and
// kotlinc: its output is an authoritative diagnostic snapshot. Startup errors,
// cancellation, signals, and compiler-internal exit codes are infrastructure
// failures and must not clear the last known-good diagnostics.
func compilerCommandCompleted(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if err == nil {
		return true
	}
	if errors.Is(err, errCompilerOutputLimit) {
		return false
	}
	var exitError *exec.ExitError
	return errors.As(err, &exitError) && exitError.ExitCode() == 1
}

func compilerFailureOutcome(ctx context.Context, err error) (string, string) {
	if ctx != nil && ctx.Err() != nil {
		return "cancelled", ctx.Err().Error()
	}
	if err == nil {
		return "failed", "compiler did not complete"
	}
	return "failed", err.Error()
}

// redactCompilerArguments retains every semantic switch while bounding the
// status payload. Classpaths can be hundreds of thousands of characters and
// temporary output locations are not useful after a pass has finished.
func redactCompilerArguments(arguments []string) []string {
	out := append([]string(nil), arguments...)
	for index := range out {
		switch out[index] {
		case "-classpath", "--class-path", "--module-path", "-p":
			if index+1 < len(out) {
				entries := filepath.SplitList(out[index+1])
				out[index+1] = "<" + strconv.Itoa(len(entries)) + " entries>"
			}
		case "-d":
			if index+1 < len(out) {
				out[index+1] = "<output>"
			}
		}
	}
	return out
}

func runKotlinCompiler(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string) ([]byte, error) {
	return runKotlinCompilerWithSettings(ctx, compiler, paths, destination, classpath, CompilerSettings{})
}

func runKotlinCompilerWithSettings(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string, settings CompilerSettings) ([]byte, error) {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, err
	}
	argumentFile, err := writeCompilerArgumentFile(destination, paths)
	if err != nil {
		return nil, err
	}
	commandArgs := append([]string(nil), compiler.prefix...)
	commandArgs = append(commandArgs, kotlinCompilerArgumentsWithSettings(compiler, destination, argumentFile, classpath, settings)...)
	command := exec.CommandContext(ctx, compiler.executable, commandArgs...)
	configureCompilerProcess(command)
	return runCompilerCommand(ctx, command)
}

func budgetCompilerDiagnostics(values map[protocol.URI][]protocol.Diagnostic) {
	keys := make([]protocol.URI, 0, len(values))
	total := 0
	needsSummary := false
	for uri := range values {
		keys = append(keys, uri)
		total += len(values[uri])
		if len(values[uri]) > maxCompilerDiagnosticsPerFile {
			needsSummary = true
		}
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a] < keys[b] })
	if total > maxCompilerDiagnosticsWorkspace {
		needsSummary = true
	}
	remaining := maxCompilerDiagnosticsWorkspace
	var summaryURI protocol.URI
	if needsSummary {
		remaining--
		for _, uri := range keys {
			if len(values[uri]) > 0 {
				summaryURI = uri
				break
			}
		}
	}
	workspaceOmitted := 0
	for _, uri := range keys {
		diagnostics := values[uri]
		sort.SliceStable(diagnostics, func(a, b int) bool {
			return diagnostics[a].Severity < diagnostics[b].Severity
		})
		if len(diagnostics) == 0 {
			delete(values, uri)
			continue
		}
		limit := maxCompilerDiagnosticsPerFile
		if limit > remaining {
			limit = remaining
		}
		if limit == 0 {
			workspaceOmitted += len(diagnostics)
			delete(values, uri)
			continue
		}
		kept := limit
		if kept > len(diagnostics) {
			kept = len(diagnostics)
		}
		values[uri] = append([]protocol.Diagnostic(nil), diagnostics[:kept]...)
		workspaceOmitted += len(diagnostics) - kept
		remaining -= kept
	}
	if workspaceOmitted > 0 && summaryURI != "" {
		values[summaryURI] = append(values[summaryURI], protocol.Diagnostic{
			Severity: 2,
			Source:   "kotlsp",
			Code:     "diagnostics-omitted",
			Message:  strconv.Itoa(workspaceOmitted) + " additional compiler diagnostics omitted by the workspace safety limit.",
		})
	}
}

// compilerSourcePaths stages every indexed input from its immutable document
// snapshot. Reading closed files directly from disk let a watcher race the
// compiler: diagnostics for new bytes could otherwise be committed under the
// old ParsedFile hash/generation. javac and K2 do not require package-relative
// source paths, and the original base name is retained for Java's public-type
// filename rule.
func (i *Index) compilerSourcePaths(ctx context.Context, files []*analysis.ParsedFile, temporary string, include func(string) bool) ([]string, map[string]protocol.URI, error) {
	const maxStagedCompilerBytes = 512 << 20
	i.mu.RLock()
	snapshots := make(map[protocol.URI]string, min(len(files), 100_000))
	for fileIndex, file := range files {
		if fileIndex&255 == 0 && ctx.Err() != nil {
			i.mu.RUnlock()
			return nil, nil, ctx.Err()
		}
		if file == nil {
			continue
		}
		if len(snapshots) >= 100_000 {
			i.mu.RUnlock()
			return nil, nil, fmt.Errorf("compiler source snapshot exceeds its 100000-file safety limit")
		}
		if doc := i.docs[file.URI]; doc != nil {
			snapshots[file.URI] = doc.Text
		} else if doc := i.indexedDocs[file.URI]; doc != nil {
			snapshots[file.URI] = doc.Text
		}
	}
	i.mu.RUnlock()
	paths := make([]string, 0, len(files))
	staged := make(map[string]protocol.URI)
	stagedBytes := 0
	for n, file := range files {
		if n&255 == 0 && ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if file == nil {
			continue
		}
		path, ok := uriutil.Path(file.URI)
		if !ok || !include(path) {
			continue
		}
		contents, snapshotted := snapshots[file.URI]
		if !snapshotted {
			var snapshotErr error
			contents, snapshotErr = compilerDiskSnapshot(path, file.TextHash)
			if snapshotErr != nil {
				return nil, nil, snapshotErr
			}
		}
		stagedBytes += len(contents)
		if stagedBytes > maxStagedCompilerBytes {
			return nil, nil, fmt.Errorf("compiler source snapshots exceed their 512 MiB staging safety limit")
		}
		directory := filepath.Join(temporary, "snapshots", strconv.Itoa(n))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, nil, err
		}
		path = filepath.Join(directory, filepath.Base(path))
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			return nil, nil, err
		}
		staged[filepath.Clean(path)] = file.URI
		paths = append(paths, path)
	}
	return paths, staged, nil
}

func compilerDiskSnapshot(path string, expectedHash uint64) (string, error) {
	const maxCompilerSourceBytes = 64 << 20
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCompilerSourceBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxCompilerSourceBytes {
		return "", fmt.Errorf("compiler source %s exceeds its 64 MiB safety limit", path)
	}
	digest := sha256.Sum256(data)
	if binary.LittleEndian.Uint64(digest[:8]) != expectedHash {
		return "", fmt.Errorf("compiler source %s changed after its indexed snapshot; validation was superseded", path)
	}
	return string(data), nil
}

func remapCompilerDiagnostics(values map[protocol.URI][]protocol.Diagnostic, staged map[string]protocol.URI) map[protocol.URI][]protocol.Diagnostic {
	if len(staged) == 0 {
		return values
	}
	result := make(map[protocol.URI][]protocol.Diagnostic, len(values))
	for diagnosticURI, diagnostics := range values {
		target := diagnosticURI
		if path, ok := uriutil.Path(diagnosticURI); ok {
			if original, exists := staged[filepath.Clean(path)]; exists {
				target = original
			}
		}
		result[target] = append(result[target], diagnostics...)
	}
	return result
}

func (i *Index) expandCompilerDiagnosticRanges(values map[protocol.URI][]protocol.Diagnostic) {
	for uri, diagnostics := range values {
		document, ok := i.Document(uri)
		if !ok {
			continue
		}
		for index := range diagnostics {
			diagnostic := &diagnostics[index]
			start := document.Offset(diagnostic.Range.Start)
			if start < 0 || start >= len(document.Text) {
				continue
			}
			end := start
			if document.Text[start] == '`' {
				end++
				for end < len(document.Text) && document.Text[end] != '`' && document.Text[end] != '\n' {
					end++
				}
				if end < len(document.Text) && document.Text[end] == '`' {
					end++
				}
			} else {
				for end < len(document.Text) {
					r, width := utf8.DecodeRuneInString(document.Text[end:])
					if r != '_' && r != '$' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
						break
					}
					end += width
				}
			}
			if end > start {
				diagnostic.Range.End = document.Position(end)
			}
		}
		values[uri] = diagnostics
	}
}

func findKotlinCompiler() (kotlinCompiler, bool) {
	return findKotlinCompilerContext(context.Background())
}

func findKotlinCompilerContext(ctx context.Context) (kotlinCompiler, bool) {
	if ctx != nil && ctx.Err() != nil {
		return kotlinCompiler{}, false
	}
	if executable, err := exec.LookPath("kotlinc"); err == nil {
		version := externalKotlinCompilerVersionContext(ctx, executable)
		if ctx != nil && ctx.Err() != nil {
			return kotlinCompiler{}, false
		}
		return kotlinCompiler{executable: executable, version: version}, true
	}
	if ctx != nil && ctx.Err() != nil {
		return kotlinCompiler{}, false
	}
	return embeddedKotlinCompiler("")
}

func findKotlinCompilerVersion(version string) (kotlinCompiler, bool) {
	return findKotlinCompilerVersionContext(context.Background(), version)
}

func findKotlinCompilerVersionContext(ctx context.Context, version string) (kotlinCompiler, bool) {
	if ctx != nil && ctx.Err() != nil {
		return kotlinCompiler{}, false
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return findKotlinCompilerContext(ctx)
	}
	if executable, err := exec.LookPath("kotlinc"); err == nil {
		detected := externalKotlinCompilerVersionContext(ctx, executable)
		if ctx != nil && ctx.Err() != nil {
			return kotlinCompiler{}, false
		}
		if strings.Contains(detected, version) {
			return kotlinCompiler{executable: executable, version: detected}, true
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return kotlinCompiler{}, false
	}
	return embeddedKotlinCompiler(version)
}

func embeddedKotlinCompiler(requestedVersion string) (kotlinCompiler, bool) {
	cacheRoot := os.Getenv("GRADLE_USER_HOME")
	if cacheRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cacheRoot = filepath.Join(home, ".gradle")
		}
	}
	modules := filepath.Join(cacheRoot, "caches", "modules-2", "files-2.1")
	versionPattern := "*"
	if requestedVersion != "" {
		versionPattern = requestedVersion
	}
	compilerJar := latestBinaryGlob(filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-compiler-embeddable", versionPattern, "*", "*.jar"))
	java, javaErr := exec.LookPath("java")
	if compilerJar == "" || javaErr != nil {
		return kotlinCompiler{}, false
	}
	version := filepath.Base(filepath.Dir(filepath.Dir(compilerJar)))
	stdlib := latestBinaryGlob(filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-stdlib", version, "*", "kotlin-stdlib-*.jar"))
	runtimeJars := []string{compilerJar}
	for _, pattern := range []string{
		filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-stdlib", version, "*", "kotlin-stdlib-*.jar"),
		filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-script-runtime", version, "*", "*.jar"),
		filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-reflect", version, "*", "kotlin-reflect-*.jar"),
		filepath.Join(modules, "org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "*", "*", "*.jar"),
		filepath.Join(modules, "org.jetbrains.intellij.deps", "trove4j", "*", "*", "*.jar"),
		filepath.Join(modules, "org.jetbrains", "annotations", "*", "*", "*.jar"),
	} {
		if jar := latestBinaryGlob(pattern); jar != "" {
			runtimeJars = append(runtimeJars, jar)
		}
	}
	if stdlib == "" {
		return kotlinCompiler{}, false
	}
	// A one-shot process never repays compiling the compiler to the top JIT
	// tier, so it stops at C1. A persistent host is the opposite case and keeps
	// the default tiering, since it compiles many times.
	oneShotFlags := []string{"-Xmx768m", "-XX:+ExitOnOutOfMemoryError", "-XX:TieredStopAtLevel=1", "-XX:+UseSerialGC"}
	prefix := append(append([]string(nil), oneShotFlags...), "-cp", strings.Join(runtimeJars, string(os.PathListSeparator)), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler")
	return kotlinCompiler{
		executable: java, prefix: prefix, stdlib: stdlib, embedded: true,
		runtimeJars: runtimeJars, jvmFlags: oneShotFlags, version: version,
	}, true
}

var kotlinCompilerVersions = struct {
	sync.Mutex
	values map[string]compilerVersionCacheEntry
}{values: make(map[string]compilerVersionCacheEntry)}

type compilerVersionCacheEntry struct {
	version  string
	size     int64
	modified int64
}

func externalKotlinCompilerVersion(executable string) string {
	return externalKotlinCompilerVersionContext(context.Background(), executable)
}

func externalKotlinCompilerVersionContext(parent context.Context, executable string) string {
	var size, modified int64
	if info, err := os.Stat(executable); err == nil {
		size, modified = info.Size(), info.ModTime().UnixNano()
	}
	kotlinCompilerVersions.Lock()
	if value, ok := kotlinCompilerVersions.values[executable]; ok && value.size == size && value.modified == modified {
		kotlinCompilerVersions.Unlock()
		return value.version
	}
	kotlinCompilerVersions.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-version")
	output, err := runCompilerCommand(ctx, command)
	value := "unknown"
	if err == nil || compilerCommandCompleted(ctx, err) {
		line := strings.TrimSpace(string(output))
		if newline := strings.IndexByte(line, '\n'); newline >= 0 {
			line = line[:newline]
		}
		if line != "" {
			value = line
		}
	}
	// Cancellation and transient startup failures must not poison every later
	// compiler selection with a process-lifetime "unknown" cache entry.
	if value == "unknown" {
		return value
	}
	kotlinCompilerVersions.Lock()
	if _, exists := kotlinCompilerVersions.values[executable]; !exists && len(kotlinCompilerVersions.values) >= 256 {
		for victim := range kotlinCompilerVersions.values {
			delete(kotlinCompilerVersions.values, victim)
			break
		}
	}
	kotlinCompilerVersions.values[executable] = compilerVersionCacheEntry{version: value, size: size, modified: modified}
	kotlinCompilerVersions.Unlock()
	return value
}

func latestBinaryGlob(pattern string) string {
	matches, complete := boundedGlob(pattern, 100_000, 4096)
	if !complete {
		return ""
	}
	sort.Strings(matches)
	latest := ""
	var latestTime time.Time
	for _, match := range matches {
		lower := strings.ToLower(filepath.Base(match))
		if strings.Contains(lower, "-sources.") || strings.Contains(lower, "-javadoc.") || strings.HasSuffix(lower, "-all.jar") {
			continue
		}
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		if latest == "" || info.ModTime().After(latestTime) || info.ModTime().Equal(latestTime) && match > latest {
			latest, latestTime = match, info.ModTime()
		}
	}
	return latest
}

// CompilerTrigger selects when full validation runs.
type CompilerTrigger int

const (
	// CompilerOnChange validates after every pause in typing. Most responsive,
	// and with a warm host the cost is bounded.
	CompilerOnChange CompilerTrigger = iota
	// CompilerOnSave validates only on save. Nothing runs while typing, which
	// suits a large project where even a warm pass is not instant.
	CompilerOnSave
)

// SetCompilerTrigger selects when background validation runs.
func (i *Index) SetCompilerTrigger(trigger CompilerTrigger) {
	i.compilerTrigger.Store(int32(trigger))
}

// CompilerTrigger reports when background validation runs.
func (i *Index) CompilerTrigger() CompilerTrigger { return i.compilerTriggerValue() }

func (i *Index) compilerTriggerValue() CompilerTrigger {
	return CompilerTrigger(i.compilerTrigger.Load())
}

// ScheduleCompilerDiagnosticsForSave always runs, whatever the trigger policy.
func (i *Index) ScheduleCompilerDiagnosticsForSave(parent context.Context) {
	i.scheduleCompilerDiagnostics(parent, true)
}

// ScheduleCompilerDiagnostics debounces full javac/K2 validation after saves.
// Compilation remains entirely off the foreground notification/request path;
// only the last requested run is allowed to publish results.
func (i *Index) ScheduleCompilerDiagnostics(parent context.Context) {
	i.scheduleCompilerDiagnostics(parent, false)
}

func (i *Index) scheduleCompilerDiagnostics(parent context.Context, saved bool) {
	if !saved && i.compilerTriggerValue() == CompilerOnSave {
		return
	}
	i.scheduleCompilerDiagnosticsNow(parent)
}

// disableCompilerPasses turns background validation off entirely. Only tests
// set it: a test that asserts nothing about compiler output must not start a
// JVM, and the ones that do opt back in for their own duration.
var disableCompilerPasses bool

func (i *Index) scheduleCompilerDiagnosticsNow(parent context.Context) {
	if disableCompilerPasses || i.closed.Load() {
		return
	}
	lifetimeCtx, finish, started := i.beginBackground(parent)
	if !started {
		return
	}
	i.compilerCancelMu.Lock()
	if i.compilerCancel != nil {
		i.compilerCancel()
	}
	ctx, cancel := context.WithCancel(lifetimeCtx)
	i.compilerCancel = cancel
	run := i.compilerRun.Add(1)
	i.compilerCancelMu.Unlock()
	generation := i.generation.Load()
	go func() {
		defer finish()
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if i.closed.Load() || i.compilerRun.Load() != run || i.generation.Load() != generation || i.modelRefreshing.Load() {
			return
		}
		// Kotlin runs first because its cached unit artifact is also javac's
		// authoritative view of unsaved Kotlin sources. Diagnostics remain in a
		// private transaction until both language passes have succeeded.
		transaction := newCompilerDiagnosticTransaction()
		i.compilerMu.Lock()
		superseded := i.closed.Load() || i.compilerRun.Load() != run || i.generation.Load() != generation || i.modelRefreshing.Load()
		if !superseded {
			i.scanKotlinCompilerDiagnostics(ctx, generation, transaction)
		}
		if superseded {
			i.compilerMu.Unlock()
			i.compilerStatus.publication(false, "superseded before both language passes completed")
			return
		}
		superseded = i.closed.Load() || i.compilerRun.Load() != run || i.generation.Load() != generation || i.modelRefreshing.Load()
		if !superseded {
			i.scanJavaCompilerDiagnostics(ctx, generation, transaction)
		}
		i.compilerMu.Unlock()
		if !superseded && i.commitCompilerDiagnosticTransaction(transaction, run, generation) {
			i.compilerStatus.publication(true, "Kotlin and Java diagnostics published as one complete transaction")
			i.notifyDiagnosticsChanged()
		} else {
			i.compilerStatus.publication(false, "not published because the run was superseded or a language pass was incomplete")
		}
	}()
}

func (i *Index) cancelCompilerDiagnostics() {
	i.compilerRun.Add(1)
	i.compilerCancelMu.Lock()
	if i.compilerCancel != nil {
		i.compilerCancel()
		i.compilerCancel = nil
	}
	i.compilerCancelMu.Unlock()
}

func parseJavacDiagnostics(output string) map[protocol.URI][]protocol.Diagnostic {
	result := make(map[protocol.URI][]protocol.Diagnostic)
	lines := strings.Split(output, "\n")
	for index, lineText := range lines {
		if drawn := javacDrawDiagnosticPattern.FindStringSubmatch(strings.TrimSuffix(lineText, "\r")); len(drawn) == 7 {
			line, _ := strconv.Atoi(drawn[2])
			column, _ := strconv.Atoi(drawn[3])
			if line > 0 {
				line--
			}
			if column > 0 {
				column--
			}
			severity := 1
			if drawn[5] == "warn" {
				severity = 2
			}
			message := drawn[4]
			if drawn[6] != "" {
				message += ": " + drawn[6]
			}
			uri := uriutil.File(drawn[1])
			result[uri] = append(result[uri], protocol.Diagnostic{
				Range:    protocol.Range{Start: protocol.Position{Line: line, Character: column}, End: protocol.Position{Line: line, Character: column + 1}},
				Severity: severity, Source: "javac", Code: drawn[4], Message: message,
			})
			continue
		}
		match := javacDiagnosticPattern.FindStringSubmatch(strings.TrimSuffix(lineText, "\r"))
		if len(match) != 5 {
			continue
		}
		line, _ := strconv.Atoi(match[2])
		if line > 0 {
			line--
		}
		severity := 1
		if match[3] == "warning" {
			severity = 2
		}
		uri := uriutil.File(match[1])
		column := 0
		// Standard javac emits the source line and a caret immediately after the
		// diagnostic header. Preserve that exact column instead of expanding the
		// range from the first identifier on the line.
		for lookahead := index + 1; lookahead < len(lines) && lookahead <= index+3; lookahead++ {
			if caret := strings.IndexByte(strings.TrimSuffix(lines[lookahead], "\r"), '^'); caret >= 0 {
				column = caret
				break
			}
			if javacDiagnosticPattern.MatchString(strings.TrimSuffix(lines[lookahead], "\r")) {
				break
			}
		}
		result[uri] = append(result[uri], protocol.Diagnostic{
			Range:    protocol.Range{Start: protocol.Position{Line: line, Character: column}, End: protocol.Position{Line: line, Character: column + 1}},
			Severity: severity, Source: "javac", Code: "compiler", Message: match[4],
		})
	}
	return result
}

func parseKotlincDiagnostics(output string) map[protocol.URI][]protocol.Diagnostic {
	result := make(map[protocol.URI][]protocol.Diagnostic)
	for _, lineText := range strings.Split(output, "\n") {
		if strings.HasPrefix(lineText, "KOTLSP_DIAGNOSTIC\t") {
			parts := strings.SplitN(lineText, "\t", 6)
			if len(parts) != 6 {
				continue
			}
			path, pathErr := base64.StdEncoding.DecodeString(parts[1])
			message, messageErr := base64.StdEncoding.DecodeString(strings.TrimSuffix(parts[5], "\r"))
			line, lineErr := strconv.Atoi(parts[2])
			column, columnErr := strconv.Atoi(parts[3])
			severityName := strings.ToUpper(parts[4])
			if pathErr != nil || messageErr != nil || lineErr != nil || columnErr != nil || len(path) == 0 || !strings.Contains(severityName, "ERROR") && !strings.Contains(severityName, "EXCEPTION") && !strings.Contains(severityName, "WARNING") {
				continue
			}
			if line > 0 {
				line--
			}
			if column > 0 {
				column--
			}
			severity := 1
			if strings.Contains(severityName, "WARNING") {
				severity = 2
			}
			code := "compiler"
			text := string(message)
			// The renderer hands over the complete message; the text layout
			// (and every prediction) carries only its first line, the rest
			// being the declaration list a redeclaration or abstract-member
			// message enumerates.
			if newline := strings.IndexByte(text, '\n'); newline >= 0 {
				text = strings.TrimSpace(text[:newline])
			}
			if strings.HasPrefix(text, "[") {
				if close := strings.IndexByte(text, ']'); close > 1 {
					code = text[1:close]
					text = strings.TrimSpace(text[close+1:])
				}
			}
			uri := uriutil.File(string(path))
			result[uri] = append(result[uri], protocol.Diagnostic{
				Range:    protocol.Range{Start: protocol.Position{Line: line, Character: column}, End: protocol.Position{Line: line, Character: column + 1}},
				Severity: severity, Source: "kotlinc", Code: code, Message: text,
			})
			continue
		}
		match := kotlincDiagnosticPattern.FindStringSubmatch(strings.TrimSuffix(lineText, "\r"))
		if len(match) != 7 {
			continue
		}
		line, _ := strconv.Atoi(match[2])
		column, _ := strconv.Atoi(match[3])
		if line > 0 {
			line--
		}
		if column > 0 {
			column--
		}
		severity := 1
		if match[4] == "warning" {
			severity = 2
		}
		code := match[5]
		if code == "" {
			code = "compiler"
		}
		uri := uriutil.File(match[1])
		result[uri] = append(result[uri], protocol.Diagnostic{
			Range:    protocol.Range{Start: protocol.Position{Line: line, Character: column}, End: protocol.Position{Line: line, Character: column + 1}},
			Severity: severity, Source: "kotlinc", Code: code, Message: match[6],
		})
	}
	return result
}

func unmatchedCompilerDiagnosticHeaders(output, language string, parsed map[protocol.URI][]protocol.Diagnostic) (int, string) {
	parsedCount := 0
	for _, diagnostics := range parsed {
		parsedCount += len(diagnostics)
	}
	headerCount := 0
	sample := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		diagnosticLike := strings.Contains(line, ": error:") || strings.Contains(line, ": warning:") || javacDrawDiagnosticPattern.MatchString(line)
		if language == "kotlin" {
			diagnosticLike = diagnosticLike || strings.HasPrefix(line, "e: ") || strings.HasPrefix(line, "w: ") || strings.HasPrefix(line, "KOTLSP_DIAGNOSTIC\t")
		}
		if diagnosticLike {
			headerCount++
			if sample == "" {
				sample = line
				if len(sample) > 512 {
					sample = sample[:512]
				}
			}
		}
	}
	if headerCount <= parsedCount {
		return 0, ""
	}
	return headerCount - parsedCount, sample
}

func quoteJavacArgument(value string) string {
	if !strings.ContainsAny(value, " \t\r\n\"") {
		return value
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
