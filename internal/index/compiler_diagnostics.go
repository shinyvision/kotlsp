package index

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

var javacDiagnosticPattern = regexp.MustCompile(`^(.+\.java):(\d+):\s+(warning|error):\s+(.+)$`)
var kotlincDiagnosticPattern = regexp.MustCompile(`^(.+\.kts?):(\d+):(\d+):\s+(warning|error):\s+(?:\[([A-Z0-9_]+)\]\s+)?(.+)$`)

// scanJavaCompilerDiagnostics runs javac outside every foreground LSP path and
// atomically publishes its last complete result. This adds genuine compiler
// errors and lint warnings without allowing compiler startup or I/O to consume
// any part of the 100 ms request budget.
func (i *Index) scanJavaCompilerDiagnostics(parent context.Context, generation uint64) {
	if i.generation.Load() != generation {
		return
	}
	files := i.WorkspaceFiles()
	units := i.compilerUnits(files)
	temporary, err := os.MkdirTemp("", "kotlsp-javac-")
	if err != nil {
		return
	}
	defer os.RemoveAll(temporary)
	ctx := parent
	diagnostics := make(map[protocol.URI][]protocol.Diagnostic)
	for unitIndex, unit := range units {
		if i.generation.Load() != generation || ctx.Err() != nil || !unit.hasPrimaryLanguage("java") {
			break
		}
		javac := javacExecutableInHome(unit.JavaHome)
		if javac == "" && unit.JavaHome == "" {
			javac, _ = exec.LookPath("javac")
		}
		if javac == "" {
			continue
		}
		unitDirectory := filepath.Join(temporary, "unit-"+strconv.Itoa(unitIndex))
		if os.MkdirAll(unitDirectory, 0o700) != nil {
			continue
		}
		paths, staged, pathErr := i.compilerSourcePaths(unit.Inputs, unitDirectory, func(path string) bool {
			return strings.HasSuffix(strings.ToLower(path), ".java")
		})
		if pathErr != nil || len(paths) == 0 {
			continue
		}
		argumentFile := filepath.Join(unitDirectory, "sources.args")
		var arguments strings.Builder
		for _, path := range paths {
			arguments.WriteString(quoteJavacArgument(path))
			arguments.WriteByte('\n')
		}
		if os.WriteFile(argumentFile, []byte(arguments.String()), 0o600) != nil {
			continue
		}
		// javac defaults to truncating errors/warnings. The protocol requires a
		// complete diagnostic snapshot, so use its maximum accepted limits.
		commandArgs := []string{"-proc:none", "-Xlint:all", "-Xmaxerrs", "2147483647", "-Xmaxwarns", "2147483647", "-d", filepath.Join(unitDirectory, "java-classes")}
		classpath := append([]string(nil), unit.Classpath...)
		// javac cannot consume Kotlin source directly. Compile the accessible
		// mixed source-set closure first and add only those emitted classes.
		if compiler, available := i.kotlinCompiler(); available {
			mixedPaths, _, mixedErr := i.compilerSourcePaths(unit.Inputs, unitDirectory, isJavaOrKotlinSource)
			if mixedErr == nil && hasKotlinSource(mixedPaths) {
				kotlinClasses := filepath.Join(unitDirectory, "kotlin-classes")
				kotlinClasspath := append([]string(nil), classpath...)
				if compiler.stdlib != "" {
					kotlinClasspath = append(kotlinClasspath, compiler.stdlib)
				}
				_, _ = runKotlinCompiler(ctx, compiler, mixedPaths, kotlinClasses, kotlinClasspath)
				classpath = append(classpath, kotlinClasses)
				if compiler.stdlib != "" {
					classpath = append(classpath, compiler.stdlib)
				}
			}
		}
		if len(classpath) > 0 {
			commandArgs = append(commandArgs, "-classpath", strings.Join(classpath, string(os.PathListSeparator)))
		}
		commandArgs = append(commandArgs, "@"+argumentFile)
		command := exec.CommandContext(ctx, javac, commandArgs...)
		configureCompilerProcess(command)
		output, _ := command.CombinedOutput()
		values := remapCompilerDiagnostics(parseJavacDiagnostics(string(output)), staged)
		i.expandCompilerDiagnosticRanges(values)
		mergePrimaryCompilerDiagnostics(diagnostics, values, unit.Primary, "java")
	}
	if i.generation.Load() != generation {
		return
	}
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
}

// scanKotlinCompilerDiagnostics uses the installed kotlinc command when
// available, otherwise Kotlin's compiler-embeddable artifact from the local
// Gradle cache. It is optional and entirely background; the in-memory
// diagnostic providers remain available when neither compiler is installed.
func (i *Index) scanKotlinCompilerDiagnostics(parent context.Context, generation uint64) {
	compiler, ok := i.kotlinCompiler()
	if !ok || i.generation.Load() != generation {
		return
	}
	files := i.WorkspaceFiles()
	units := i.compilerUnits(files)
	temporary, err := os.MkdirTemp("", "kotlsp-kotlinc-")
	if err != nil {
		return
	}
	defer os.RemoveAll(temporary)
	ctx := parent
	diagnostics := make(map[protocol.URI][]protocol.Diagnostic)
	for unitIndex, unit := range units {
		if i.generation.Load() != generation || ctx.Err() != nil || !unit.hasPrimaryLanguage("kotlin") {
			break
		}
		unitDirectory := filepath.Join(temporary, "unit-"+strconv.Itoa(unitIndex))
		if os.MkdirAll(unitDirectory, 0o700) != nil {
			continue
		}
		// K2 receives only the primary source set's accessible mixed-language
		// closure, preventing unrelated modules and test-only sources leaking in.
		paths, staged, pathErr := i.compilerSourcePaths(unit.Inputs, unitDirectory, isJavaOrKotlinSource)
		if pathErr != nil || len(paths) == 0 {
			continue
		}
		classpath := append([]string(nil), unit.Classpath...)
		if compiler.stdlib != "" {
			classpath = append(classpath, compiler.stdlib)
		}
		output, _ := runKotlinCompiler(ctx, compiler, paths, filepath.Join(unitDirectory, "classes"), classpath)
		values := remapCompilerDiagnostics(parseKotlincDiagnostics(string(output)), staged)
		i.expandCompilerDiagnosticRanges(values)
		mergePrimaryCompilerDiagnostics(diagnostics, values, unit.Primary, "kotlin")
	}
	if i.generation.Load() != generation {
		return
	}
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
	Primary   []*analysis.ParsedFile
	Inputs    []*analysis.ParsedFile
	Classpath []string
	JavaHome  string
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

// compilerUnits snapshots independently compilable module/source-set views.
// Primary files receive diagnostics; Inputs additionally contains only source
// sets reachable through that primary's declared project dependencies.
func (i *Index) compilerUnits(files []*analysis.ParsedFile) []compilerUnit {
	type unitIdentity struct {
		moduleDir string
		module    *ModuleInfo
		sourceSet string
	}
	i.mu.RLock()
	identities := make(map[string]*unitIdentity)
	primaryByKey := make(map[string][]*analysis.ParsedFile)
	fileModules := make(map[protocol.URI]*ModuleInfo, len(files))
	fileSourceSets := make(map[protocol.URI]string, len(files))
	for _, file := range files {
		if file == nil {
			continue
		}
		module := i.moduleForURILocked(file.URI)
		set := i.sourceSetForURILocked(file.URI, module)
		key := "<workspace>\x00main"
		if module != nil {
			key = module.Root + "\x00" + module.Dir + "\x00" + module.Name + "\x00" + set
		}
		if identities[key] == nil {
			identities[key] = &unitIdentity{module: module, sourceSet: set}
			if module != nil {
				identities[key].moduleDir = module.Dir
			}
		}
		primaryByKey[key] = append(primaryByKey[key], file)
		fileModules[file.URI], fileSourceSets[file.URI] = module, set
	}
	keys := make([]string, 0, len(identities))
	for key := range identities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	units := make([]compilerUnit, 0, len(keys))
	for _, key := range keys {
		identity := identities[key]
		unit := compilerUnit{Primary: append([]*analysis.ParsedFile(nil), primaryByKey[key]...)}
		for _, candidate := range files {
			if candidate == nil {
				continue
			}
			candidateModule, candidateSet := fileModules[candidate.URI], fileSourceSets[candidate.URI]
			accessible := identity.module == nil && candidateModule == nil
			if identity.module != nil && candidateModule != nil {
				accessible = i.moduleCanAccessLocked(identity.module, candidateModule, identity.sourceSet, candidateSet)
			}
			if accessible {
				unit.Inputs = append(unit.Inputs, candidate)
			}
		}
		units = append(units, unit)
	}
	i.mu.RUnlock()
	for unitIndex := range units {
		if len(units[unitIndex].Primary) > 0 {
			units[unitIndex].Classpath, _, _ = i.ClasspathFor(units[unitIndex].Primary[0].URI)
			if module, ok := i.ModuleFor(units[unitIndex].Primary[0].URI); ok {
				units[unitIndex].JavaHome = module.JavaHome
			} else {
				units[unitIndex].JavaHome = i.DefaultJavaHome()
			}
		}
		sort.Slice(units[unitIndex].Primary, func(a, b int) bool { return units[unitIndex].Primary[a].URI < units[unitIndex].Primary[b].URI })
		sort.Slice(units[unitIndex].Inputs, func(a, b int) bool { return units[unitIndex].Inputs[a].URI < units[unitIndex].Inputs[b].URI })
	}
	return units
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
	compiler, ok := findKotlinCompiler()
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

func runKotlinCompiler(ctx context.Context, compiler kotlinCompiler, paths []string, destination string, classpath []string) ([]byte, error) {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, err
	}
	argumentFile := filepath.Join(filepath.Dir(destination), filepath.Base(destination)+"-sources.args")
	var arguments strings.Builder
	for _, path := range paths {
		arguments.WriteString(quoteJavacArgument(path))
		arguments.WriteByte('\n')
	}
	if err := os.WriteFile(argumentFile, []byte(arguments.String()), 0o600); err != nil {
		return nil, err
	}
	commandArgs := append([]string(nil), compiler.prefix...)
	if compiler.embedded {
		commandArgs = append(commandArgs, "-no-stdlib", "-no-reflect")
	}
	// Joint compilation is required for cyclic Java/Kotlin source dependencies:
	// Java sources serve as symbols for K2 and are compiled by javac in the same
	// invocation, making both language outputs available to the follow-up lint.
	commandArgs = append(commandArgs, "-Xcompile-java", "-Xrender-internal-diagnostic-names", "-d", destination)
	if len(classpath) > 0 {
		commandArgs = append(commandArgs, "-classpath", strings.Join(classpath, string(os.PathListSeparator)))
	}
	commandArgs = append(commandArgs, "@"+argumentFile)
	command := exec.CommandContext(ctx, compiler.executable, commandArgs...)
	configureCompilerProcess(command)
	return command.CombinedOutput()
}

// compilerSourcePaths substitutes every open document with an isolated file
// containing its current in-memory text. Disk-backed files remain in place,
// preserving the real module/classpath layout while ensuring unsaved edits are
// exactly what javac/K2 validate.
func (i *Index) compilerSourcePaths(files []*analysis.ParsedFile, temporary string, include func(string) bool) ([]string, map[string]protocol.URI, error) {
	i.mu.RLock()
	open := make(map[protocol.URI]string, len(i.docs))
	for uri, doc := range i.docs {
		if doc != nil {
			open[uri] = doc.Text
		}
	}
	i.mu.RUnlock()
	paths := make([]string, 0, len(files))
	staged := make(map[string]protocol.URI)
	for n, file := range files {
		if file == nil {
			continue
		}
		path, ok := uriutil.Path(file.URI)
		if !ok || !include(path) {
			continue
		}
		if contents, isOpen := open[file.URI]; isOpen {
			directory := filepath.Join(temporary, "snapshots", strconv.Itoa(n))
			if err := os.MkdirAll(directory, 0o700); err != nil {
				return nil, nil, err
			}
			path = filepath.Join(directory, filepath.Base(path))
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				return nil, nil, err
			}
			staged[filepath.Clean(path)] = file.URI
		}
		paths = append(paths, path)
	}
	return paths, staged, nil
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
	if executable, err := exec.LookPath("kotlinc"); err == nil {
		return kotlinCompiler{executable: executable}, true
	}
	cacheRoot := os.Getenv("GRADLE_USER_HOME")
	if cacheRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cacheRoot = filepath.Join(home, ".gradle")
		}
	}
	modules := filepath.Join(cacheRoot, "caches", "modules-2", "files-2.1")
	compilerJar := latestBinaryGlob(filepath.Join(modules, "org.jetbrains.kotlin", "kotlin-compiler-embeddable", "*", "*", "*.jar"))
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
	return kotlinCompiler{
		executable: java, prefix: []string{"-cp", strings.Join(runtimeJars, string(os.PathListSeparator)), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"},
		stdlib: stdlib, embedded: true,
	}, true
}

func latestBinaryGlob(pattern string) string {
	matches, _ := filepath.Glob(pattern)
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

// ScheduleCompilerDiagnostics debounces full javac/K2 validation after saves.
// Compilation remains entirely off the foreground notification/request path;
// only the last requested run is allowed to publish results.
func (i *Index) ScheduleCompilerDiagnostics(parent context.Context) {
	i.compilerCancelMu.Lock()
	if i.compilerCancel != nil {
		i.compilerCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	i.compilerCancel = cancel
	run := i.compilerRun.Add(1)
	i.compilerCancelMu.Unlock()
	generation := i.generation.Load()
	go func() {
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if i.compilerRun.Load() != run || i.generation.Load() != generation {
			return
		}
		i.compilerMu.Lock()
		defer i.compilerMu.Unlock()
		if i.compilerRun.Load() != run || i.generation.Load() != generation {
			return
		}
		i.scanJavaCompilerDiagnostics(ctx, generation)
		i.scanKotlinCompilerDiagnostics(ctx, generation)
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
	for _, lineText := range strings.Split(output, "\n") {
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
		result[uri] = append(result[uri], protocol.Diagnostic{
			Range:    protocol.Range{Start: protocol.Position{Line: line}, End: protocol.Position{Line: line, Character: 1}},
			Severity: severity, Source: "javac", Code: "compiler", Message: match[4],
		})
	}
	return result
}

func parseKotlincDiagnostics(output string) map[protocol.URI][]protocol.Diagnostic {
	result := make(map[protocol.URI][]protocol.Diagnostic)
	for _, lineText := range strings.Split(output, "\n") {
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

func quoteJavacArgument(value string) string {
	if !strings.ContainsAny(value, " \t\r\n\"") {
		return value
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}
