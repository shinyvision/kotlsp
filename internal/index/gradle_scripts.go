package index

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// kotlinDSLImports are what the Kotlin DSL adds to Gradle's own default
// imports for every script.
var kotlinDSLImports = []string{
	"org.gradle.kotlin.dsl.*", "org.gradle.kotlin.dsl.plugins.dsl.*", "java.io.File", "java.util.concurrent.Callable",
	"java.util.concurrent.TimeUnit", "java.math.BigDecimal", "java.math.BigInteger",
}

// fallbackGradleImports stand in for the distribution's list when it cannot
// be read: the packages build scripts use most.
var fallbackGradleImports = []string{
	"org.gradle.*", "org.gradle.api.*", "org.gradle.api.artifacts.*", "org.gradle.api.artifacts.dsl.*", "org.gradle.api.file.*",
	"org.gradle.api.plugins.*", "org.gradle.api.provider.*", "org.gradle.api.tasks.*", "org.gradle.api.tasks.bundling.*",
	"org.gradle.api.tasks.compile.*", "org.gradle.api.tasks.testing.*", "org.gradle.api.initialization.*", "org.gradle.jvm.toolchain.*",
}

var gradleImportCache struct {
	sync.Mutex
	home    string
	imports []analysis.Import
}

// gradleScriptImportsLocked lists the imports every Gradle Kotlin DSL script
// has implicitly: the distribution's own `default-imports.txt` (Project,
// JavaVersion, tasks, ...) and the Kotlin DSL's, as wildcard or single-name
// imports exactly as Gradle declares them.
func gradleScriptImports(home string) []analysis.Import {
	gradleImportCache.Lock()
	defer gradleImportCache.Unlock()
	if gradleImportCache.imports != nil && gradleImportCache.home == home {
		return gradleImportCache.imports
	}
	paths := append(readGradleDefaultImports(home), kotlinDSLImports...)
	imports := make([]analysis.Import, 0, len(paths))
	for _, path := range paths {
		wildcard := strings.HasSuffix(path, ".*")
		imports = append(imports, analysis.Import{Path: strings.TrimSuffix(path, ".*"), Wildcard: wildcard})
	}
	gradleImportCache.home, gradleImportCache.imports = home, imports
	return imports
}

func readGradleDefaultImports(home string) []string {
	if home == "" {
		return fallbackGradleImports
	}
	jars, _ := filepath.Glob(filepath.Join(home, "lib", "gradle-runtime-api-info-*.jar"))
	for _, jar := range jars {
		reader, err := zip.OpenReader(jar)
		if err != nil {
			continue
		}
		read := func(name string) string {
			for _, entry := range reader.File {
				if entry.Name != name {
					continue
				}
				stream, openErr := entry.Open()
				if openErr != nil {
					return ""
				}
				data, _ := io.ReadAll(io.LimitReader(stream, 1<<20))
				stream.Close()
				return string(data)
			}
			return ""
		}
		var out []string
		for _, line := range strings.Split(read("default-imports.txt"), "\n") {
			if path, ok := strings.CutPrefix(strings.TrimSpace(line), "import "); ok && path != "" {
				out = append(out, strings.TrimSpace(path))
			}
		}
		// Two default-imported packages declare `Jar` (and BuildResult, ...);
		// the Kotlin DSL imports the first of each by name, which outranks
		// the star imports, so the name is not ambiguous in a script.
		for _, line := range strings.Split(read("api-mapping.txt"), "\n") {
			_, packages, found := strings.Cut(strings.TrimSpace(line), ":")
			if !found {
				continue
			}
			names := strings.FieldsFunc(packages, func(r rune) bool { return r == ';' })
			if len(names) > 1 {
				out = append(out, names[0])
			}
		}
		reader.Close()
		if len(out) > 0 {
			return out
		}
	}
	if _, err := os.Stat(home); err != nil {
		return fallbackGradleImports
	}
	return fallbackGradleImports
}

// gradleScriptReceiverTypes are the implicit receivers of a Gradle Kotlin DSL
// script, innermost first: the script template (`plugins { }`), then the
// object the script configures (`dependencies`, `tasks`, `rootProject`).
func gradleScriptReceiverTypes(file *analysis.ParsedFile) []string {
	path, ok := uriutil.Path(file.URI)
	if !ok || !isGradleScriptPath(path) {
		return nil
	}
	switch base := strings.ToLower(filepath.Base(path)); {
	case base == "settings.gradle.kts":
		return []string{"org.gradle.kotlin.dsl.KotlinSettingsScriptTemplate", "org.gradle.kotlin.dsl.KotlinSettingsScript", "org.gradle.api.initialization.Settings"}
	case base == "init.gradle.kts" || strings.HasSuffix(base, ".init.gradle.kts"):
		return []string{"org.gradle.kotlin.dsl.KotlinGradleScriptTemplate", "org.gradle.kotlin.dsl.KotlinInitScript", "org.gradle.api.invocation.Gradle"}
	default:
		return []string{"org.gradle.kotlin.dsl.KotlinProjectScriptTemplate", "org.gradle.kotlin.dsl.KotlinBuildScript", "org.gradle.api.Project"}
	}
}

// effectiveImportsLocked is everything a file imports: what it writes, and
// for a Gradle script the imports every script has implicitly.
func (i *Index) effectiveImportsLocked(file *analysis.ParsedFile) []analysis.Import {
	path, ok := uriutil.Path(file.URI)
	if !ok || !isGradleScriptPath(path) {
		return file.Imports
	}
	home := ""
	if module, unique := moduleForURIInModules(file.URI, i.modules); unique && module != nil {
		home = module.GradleHome
	}
	return append(append([]analysis.Import(nil), file.Imports...), gradleScriptImports(home)...)
}

// gradleProjectPathAt returns the Gradle project path in the string literal
// under offset when that literal is the argument of `project(...)`:
// `implementation(project(":database"))`.
func gradleProjectPathAt(text string, offset int) (string, int, int, bool) {
	if offset < 0 || offset > len(text) {
		return "", 0, 0, false
	}
	start := strings.LastIndexByte(text[:offset], '"')
	if start < 0 {
		return "", 0, 0, false
	}
	end := strings.IndexByte(text[offset:], '"')
	if end < 0 {
		return "", 0, 0, false
	}
	end += offset
	path := text[start+1 : end]
	if !strings.HasPrefix(path, ":") && path != "" || strings.ContainsAny(path, "\n\"$") {
		return "", 0, 0, false
	}
	before := strings.TrimRight(text[:start], " \t")
	if !strings.HasSuffix(before, "(") || !strings.HasSuffix(strings.TrimRight(strings.TrimSuffix(before, "("), " \t"), "project") {
		return "", 0, 0, false
	}
	return path, start + 1, end, true
}

// gradleProjectDefinition answers definition on the path in a build
// script's `project(":x")` with that project's build file.
func (i *Index) gradleProjectDefinition(uri protocol.URI, pos protocol.Position) (analysis.Symbol, bool) {
	path, ok := uriutil.Path(uri)
	if !ok || !isGradleScriptPath(path) {
		return analysis.Symbol{}, false
	}
	document, ok := i.Document(uri)
	if !ok {
		return analysis.Symbol{}, false
	}
	projectPath, _, _, ok := gradleProjectPathAt(document.Text, document.Offset(pos))
	if !ok {
		return analysis.Symbol{}, false
	}
	i.mu.RLock()
	modules := append([]ModuleInfo(nil), i.modules...)
	i.mu.RUnlock()
	for _, module := range modules {
		if module.Name != projectPath && !(projectPath == ":" && module.Name == ":") {
			continue
		}
		for _, name := range []string{"build.gradle.kts", "build.gradle"} {
			buildFile := filepath.Join(module.Dir, name)
			if _, err := os.Stat(buildFile); err == nil {
				target := uriutil.File(buildFile)
				return analysis.Symbol{ID: "gradle-project:" + projectPath, Name: projectPath, FQN: projectPath, Kind: analysis.KindPackage, URI: target, Language: analysis.LanguageKotlin}, true
			}
		}
	}
	return analysis.Symbol{}, false
}

// GradleProjectPathCompletion is a project path a build script can name.
type GradleProjectPathCompletion struct {
	Path, Dir  string
	Start, End int
}

// GradleProjectPathCompletions lists the build's project paths when offset is
// inside the string of a build script's `project("...")`, with the span the
// chosen path replaces.
func (i *Index) GradleProjectPathCompletions(uri protocol.URI, text string, offset int) ([]GradleProjectPathCompletion, bool) {
	path, ok := uriutil.Path(uri)
	if !ok || !isGradleScriptPath(path) {
		return nil, false
	}
	typed, start, end, ok := gradleProjectPathAt(text, offset)
	if !ok {
		return nil, false
	}
	typed = typed[:max(0, min(len(typed), offset-start))]
	i.mu.RLock()
	modules := append([]ModuleInfo(nil), i.modules...)
	i.mu.RUnlock()
	var out []GradleProjectPathCompletion
	for _, module := range modules {
		if !strings.HasPrefix(module.Name, ":") || module.Name == ":" || !strings.HasPrefix(module.Name, typed) {
			continue
		}
		out = append(out, GradleProjectPathCompletion{Path: module.Name, Dir: module.Dir, Start: start, End: end})
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Path < out[right].Path })
	return out, true
}
