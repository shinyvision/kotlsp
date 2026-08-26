package index

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// ModuleInfo is the immutable build-model subset needed by foreground
// visibility, launch, and classpath requests.
type ModuleInfo struct {
	Name                    string
	Dir                     string
	Root                    string
	SourceRoots             []string
	SourceSets              map[string][]string
	Classpath               []string
	ClasspathBySourceSet    map[string][]string
	ModulePath              []string
	ModulePathBySourceSet   map[string][]string
	JavaModuleName          string
	JavaHome                string
	Dependencies            []string
	DependenciesBySourceSet map[string][]string
	ExportedBySourceSet     map[string][]string
	DependencyExclusions    map[string][]string
	SourceSetDependsOn      map[string][]string
}

var gradleProjectDependencyPattern = regexp.MustCompile(`project\s*\(\s*(?:path\s*[:=]\s*)?["'](:[^"']+)["']`)
var gradleScopedProjectDependencyPattern = regexp.MustCompile(`(?m)([A-Za-z][A-Za-z0-9_]*)\s*(?:\(\s*)?project\s*\(\s*(?:path\s*[:=]\s*)?["'](:[^"']+)["']`)
var gradleDeclaredSourcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)([A-Za-z][A-Za-z0-9_]*)\s*\{[^{}]{0,1000}?(?:java|kotlin)\s*\.\s*srcDir\s*(?:\(\s*)?["']([^"']+)["']`),
	regexp.MustCompile(`(?s)(?:sourceSets\s*\[\s*["']|sourceSets\s*\.\s*named\s*\(\s*["']|sourceSets\s*\.)([A-Za-z][A-Za-z0-9_]*)(?:["']\s*\]|["']\s*\)|)\s*.{0,1000}?(?:java|kotlin)\s*\.\s*srcDir\s*(?:\(\s*)?["']([^"']+)["']`),
	regexp.MustCompile(`(?s)(?:create|maybeCreate|named)\s*\(\s*["']([A-Za-z][A-Za-z0-9_]*)["']\s*\)\s*\{[^{}]{0,1000}?(?:java|kotlin)\s*\.\s*srcDir\s*(?:\(\s*)?["']([^"']+)["']`),
}
var javaModuleDeclarationPattern = regexp.MustCompile(`(?m)\b(?:open\s+)?module\s+([A-Za-z_$][A-Za-z0-9_$.]*)\s*\{`)

type mavenPOM struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	Properties   mavenProperties `xml:"properties"`
	Dependencies struct {
		Items []mavenDependency `xml:"dependency"`
	} `xml:"dependencies"`
}

type mavenProperties map[string]string

func (properties *mavenProperties) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	if *properties == nil {
		*properties = make(mavenProperties)
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			var text string
			if err := decoder.DecodeElement(&text, &value); err != nil {
				return err
			}
			(*properties)[value.Name.Local] = strings.TrimSpace(text)
		case xml.EndElement:
			if value.Name == start.Name {
				return nil
			}
		}
	}
}

type mavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
	Exclusions struct {
		Items []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
		} `xml:"exclusion"`
	} `xml:"exclusions"`
}

func readMavenPOM(path string) (mavenPOM, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mavenPOM{}, false
	}
	var model mavenPOM
	if err := xml.Unmarshal(data, &model); err != nil {
		return mavenPOM{}, false
	}
	model.GroupID = strings.TrimSpace(model.GroupID)
	model.ArtifactID = strings.TrimSpace(model.ArtifactID)
	model.Version = strings.TrimSpace(model.Version)
	model.Parent.GroupID = strings.TrimSpace(model.Parent.GroupID)
	model.Parent.ArtifactID = strings.TrimSpace(model.Parent.ArtifactID)
	model.Parent.Version = strings.TrimSpace(model.Parent.Version)
	if model.Parent.RelativePath != nil {
		value := strings.TrimSpace(*model.Parent.RelativePath)
		model.Parent.RelativePath = &value
	}
	for index := range model.Dependencies.Items {
		dependency := &model.Dependencies.Items[index]
		dependency.GroupID = strings.TrimSpace(dependency.GroupID)
		dependency.ArtifactID = strings.TrimSpace(dependency.ArtifactID)
		dependency.Scope = strings.TrimSpace(dependency.Scope)
		dependency.Optional = strings.TrimSpace(dependency.Optional)
		for exclusionIndex := range dependency.Exclusions.Items {
			exclusion := &dependency.Exclusions.Items[exclusionIndex]
			exclusion.GroupID = strings.TrimSpace(exclusion.GroupID)
			exclusion.ArtifactID = strings.TrimSpace(exclusion.ArtifactID)
		}
	}
	return model, model.ArtifactID != ""
}

func (m mavenPOM) effectiveGroupID() string {
	if m.GroupID != "" {
		return m.GroupID
	}
	return m.Parent.GroupID
}

func effectiveMavenModels(models map[string]mavenPOM) map[string]mavenPOM {
	coordinates := make(map[string]string, len(models))
	for directory, model := range models {
		coordinates[mavenCoordinate(model.effectiveGroupID(), model.ArtifactID, mavenEffectiveVersion(model))] = directory
	}
	result := make(map[string]mavenPOM, len(models))
	visiting := make(map[string]bool)
	var resolve func(string) mavenPOM
	resolve = func(directory string) mavenPOM {
		if model, ok := result[directory]; ok {
			return model
		}
		model, ok := models[directory]
		if !ok || visiting[directory] {
			return model
		}
		visiting[directory] = true
		parentDirectory := ""
		if model.Parent.ArtifactID != "" {
			relative := "../pom.xml"
			if model.Parent.RelativePath != nil {
				relative = *model.Parent.RelativePath
			}
			if relative != "" {
				candidate := relative
				if !filepath.IsAbs(candidate) {
					candidate = filepath.Join(directory, candidate)
				}
				if info, err := os.Stat(candidate); err == nil && info.IsDir() {
					candidate = filepath.Join(candidate, "pom.xml")
				}
				candidateDirectory := filepath.Dir(filepath.Clean(candidate))
				if _, exists := models[candidateDirectory]; exists {
					parentDirectory = candidateDirectory
				}
			}
			if parentDirectory == "" {
				parentDirectory = coordinates[mavenCoordinate(model.Parent.GroupID, model.Parent.ArtifactID, model.Parent.Version)]
			}
		}
		if parentDirectory != "" && parentDirectory != directory {
			parent := resolve(parentDirectory)
			model = inheritMavenModel(parent, model)
		}
		model = interpolateMavenModel(model)
		visiting[directory] = false
		result[directory] = model
		return model
	}
	for directory := range models {
		resolve(directory)
	}
	return result
}

func mavenCoordinate(groupID, artifactID, version string) string {
	return strings.TrimSpace(groupID) + "\x00" + strings.TrimSpace(artifactID) + "\x00" + strings.TrimSpace(version)
}

func mavenEffectiveVersion(model mavenPOM) string {
	if model.Version != "" {
		return model.Version
	}
	return model.Parent.Version
}

func inheritMavenModel(parent, child mavenPOM) mavenPOM {
	if child.GroupID == "" {
		child.GroupID = parent.effectiveGroupID()
	}
	if child.Version == "" {
		child.Version = mavenEffectiveVersion(parent)
	}
	properties := make(mavenProperties, len(parent.Properties)+len(child.Properties))
	for name, value := range parent.Properties {
		properties[name] = value
	}
	for name, value := range child.Properties {
		properties[name] = value
	}
	child.Properties = properties
	merged := append([]mavenDependency(nil), parent.Dependencies.Items...)
	positions := make(map[string]int, len(merged))
	for index, dependency := range merged {
		positions[dependency.GroupID+"\x00"+dependency.ArtifactID] = index
	}
	for _, dependency := range child.Dependencies.Items {
		key := dependency.GroupID + "\x00" + dependency.ArtifactID
		if index, exists := positions[key]; exists {
			merged[index] = dependency
		} else {
			positions[key] = len(merged)
			merged = append(merged, dependency)
		}
	}
	child.Dependencies.Items = merged
	return child
}

func interpolateMavenModel(model mavenPOM) mavenPOM {
	properties := make(map[string]string, len(model.Properties)+12)
	for name, value := range model.Properties {
		properties[name] = value
	}
	for name, value := range map[string]string{
		"project.groupId": model.effectiveGroupID(), "pom.groupId": model.effectiveGroupID(),
		"project.artifactId": model.ArtifactID, "pom.artifactId": model.ArtifactID,
		"project.version": mavenEffectiveVersion(model), "pom.version": mavenEffectiveVersion(model),
		"project.parent.groupId": model.Parent.GroupID, "parent.groupId": model.Parent.GroupID,
		"project.parent.artifactId": model.Parent.ArtifactID, "parent.artifactId": model.Parent.ArtifactID,
		"project.parent.version": model.Parent.Version, "parent.version": model.Parent.Version,
	} {
		properties[name] = value
	}
	for pass := 0; pass < 20; pass++ {
		changed := false
		for name, value := range properties {
			resolved := interpolateMavenValue(value, properties)
			if resolved != value {
				properties[name], changed = resolved, true
			}
		}
		if !changed {
			break
		}
	}
	model.GroupID = interpolateMavenValue(model.GroupID, properties)
	model.ArtifactID = interpolateMavenValue(model.ArtifactID, properties)
	model.Version = interpolateMavenValue(model.Version, properties)
	for index := range model.Dependencies.Items {
		dependency := &model.Dependencies.Items[index]
		dependency.GroupID = interpolateMavenValue(dependency.GroupID, properties)
		dependency.ArtifactID = interpolateMavenValue(dependency.ArtifactID, properties)
		dependency.Scope = interpolateMavenValue(dependency.Scope, properties)
		dependency.Optional = interpolateMavenValue(dependency.Optional, properties)
		for exclusionIndex := range dependency.Exclusions.Items {
			exclusion := &dependency.Exclusions.Items[exclusionIndex]
			exclusion.GroupID = interpolateMavenValue(exclusion.GroupID, properties)
			exclusion.ArtifactID = interpolateMavenValue(exclusion.ArtifactID, properties)
		}
	}
	return model
}

func interpolateMavenValue(value string, properties map[string]string) string {
	for pass := 0; pass < 20; pass++ {
		start := strings.Index(value, "${")
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			break
		}
		end += start + 2
		name := value[start+2 : end]
		replacement, exists := properties[name]
		if !exists {
			break
		}
		value = value[:start] + replacement + value[end+1:]
	}
	return strings.TrimSpace(value)
}

func discoverModules(roots []string) []ModuleInfo {
	var modules []ModuleInfo
	for _, workspaceRoot := range roots {
		root, err := filepath.Abs(workspaceRoot)
		if err != nil {
			continue
		}
		buildDirs := make(map[string]bool)
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				if path != root && ignoredDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(entry.Name()) {
			case "build.gradle", "build.gradle.kts", "pom.xml":
				buildDirs[filepath.Dir(path)] = true
			}
			return nil
		})
		if len(buildDirs) == 0 {
			buildDirs[root] = true
		}
		dirs := make([]string, 0, len(buildDirs))
		for directory := range buildDirs {
			dirs = append(dirs, directory)
		}
		sort.Slice(dirs, func(a, b int) bool { return len(dirs[a]) < len(dirs[b]) })
		artifactToName := make(map[string]string)
		coordinateToName := make(map[string]string)
		mavenModels := make(map[string]mavenPOM)
		for _, directory := range dirs {
			name := moduleName(root, directory)
			if model, ok := readMavenPOM(filepath.Join(directory, "pom.xml")); ok {
				mavenModels[directory] = model
				artifactToName[model.ArtifactID] = name
				coordinateToName[model.effectiveGroupID()+"\x00"+model.ArtifactID] = name
			}
			sourceSets := moduleSourceSets(directory)
			modules = append(modules, ModuleInfo{
				Name: name, Dir: directory, Root: root,
				SourceRoots: flattenSourceSets(sourceSets), SourceSets: sourceSets,
				ClasspathBySourceSet:    make(map[string][]string),
				ModulePathBySourceSet:   make(map[string][]string),
				DependenciesBySourceSet: make(map[string][]string),
				ExportedBySourceSet:     make(map[string][]string),
				DependencyExclusions:    make(map[string][]string),
				SourceSetDependsOn:      conventionalSourceSetDependencies(sourceSets),
				JavaModuleName:          javaModuleName(directory, sourceSets),
				JavaHome:                moduleJavaHome(directory, root),
			})
		}
		mavenModels = effectiveMavenModels(mavenModels)
		artifactToName = make(map[string]string, len(mavenModels))
		coordinateToName = make(map[string]string, len(mavenModels))
		for directory, model := range mavenModels {
			name := moduleName(root, directory)
			artifactToName[model.ArtifactID] = name
			coordinateToName[model.effectiveGroupID()+"\x00"+model.ArtifactID] = name
		}
		for index := range modules {
			module := &modules[index]
			if module.Dir != root && !strings.HasPrefix(module.Dir, root+string(filepath.Separator)) {
				continue
			}
			dependencies := make(map[string]bool)
			for _, buildName := range []string{"build.gradle", "build.gradle.kts"} {
				if data, err := os.ReadFile(filepath.Join(module.Dir, buildName)); err == nil {
					for _, match := range gradleScopedProjectDependencyPattern.FindAllSubmatch(data, -1) {
						set, compileVisible, exported := gradleDependencyConfiguration(string(match[1]))
						if !compileVisible {
							continue
						}
						dependency := string(match[2])
						dependencies[dependency] = true
						module.DependenciesBySourceSet[set] = appendUniqueString(module.DependenciesBySourceSet[set], dependency)
						if exported {
							module.ExportedBySourceSet[set] = appendUniqueString(module.ExportedBySourceSet[set], dependency)
						}
					}
				}
			}
			if model, ok := mavenModels[module.Dir]; ok {
				for _, declared := range model.Dependencies.Items {
					dependency := coordinateToName[declared.GroupID+"\x00"+declared.ArtifactID]
					if dependency == "" {
						dependency = artifactToName[declared.ArtifactID]
					}
					if dependency == "" {
						continue
					}
					switch declared.Scope {
					case "runtime", "import":
						// These scopes are absent from Java/Kotlin compilation.
						continue
					case "test":
						module.DependenciesBySourceSet["test"] = appendUniqueString(module.DependenciesBySourceSet["test"], dependency)
					default: // compile, provided, system, or Maven's implicit compile
						dependencies[dependency] = true
						module.DependenciesBySourceSet["main"] = appendUniqueString(module.DependenciesBySourceSet["main"], dependency)
						if (declared.Scope == "" || declared.Scope == "compile") && !strings.EqualFold(declared.Optional, "true") {
							module.ExportedBySourceSet["main"] = appendUniqueString(module.ExportedBySourceSet["main"], dependency)
						}
						for _, excluded := range declared.Exclusions.Items {
							excludedName := coordinateToName[excluded.GroupID+"\x00"+excluded.ArtifactID]
							if excludedName == "" {
								excludedName = artifactToName[excluded.ArtifactID]
							}
							if excludedName != "" {
								key := dependencyExclusionKey("main", dependency)
								module.DependencyExclusions[key] = appendUniqueString(module.DependencyExclusions[key], excludedName)
							}
						}
					}
				}
			}
			for dependency := range dependencies {
				module.Dependencies = append(module.Dependencies, dependency)
			}
			sort.Strings(module.Dependencies)
		}
	}
	sort.Slice(modules, func(a, b int) bool {
		if modules[a].Dir == modules[b].Dir {
			return modules[a].Name < modules[b].Name
		}
		return modules[a].Dir < modules[b].Dir
	})
	return modules
}

func moduleJavaHome(directory, workspaceRoot string) string {
	for current := filepath.Clean(directory); ; current = filepath.Dir(current) {
		data, err := os.ReadFile(filepath.Join(current, "gradle.properties"))
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				key, value, found := strings.Cut(strings.TrimSpace(line), "=")
				if found && strings.TrimSpace(key) == "org.gradle.java.home" {
					home := strings.TrimSpace(value)
					if !filepath.IsAbs(home) {
						home = filepath.Join(current, home)
					}
					return filepath.Clean(home)
				}
			}
		}
		if current == filepath.Clean(workspaceRoot) || filepath.Dir(current) == current {
			break
		}
	}
	return ""
}

func javaModuleName(directory string, sourceSets map[string][]string) string {
	candidates := []string{filepath.Join(directory, "module-info.java")}
	for _, roots := range sourceSets {
		for _, root := range roots {
			candidates = append(candidates, filepath.Join(root, "module-info.java"))
		}
	}
	for _, path := range uniqueSortedStrings(candidates) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if match := javaModuleDeclarationPattern.FindSubmatch(data); len(match) == 2 {
			return string(match[1])
		}
	}
	return ""
}

func moduleName(root, directory string) string {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." {
		return ":"
	}
	return ":" + strings.ReplaceAll(filepath.ToSlash(relative), "/", ":")
}

func moduleSourceSets(directory string) map[string][]string {
	sets := make(map[string][]string)
	sourceDir := filepath.Join(directory, "src")
	_ = filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if name == "java" || name == "kotlin" {
			relative, relativeErr := filepath.Rel(sourceDir, path)
			if relativeErr == nil {
				parts := strings.Split(filepath.ToSlash(relative), "/")
				if len(parts) >= 2 {
					set := parts[len(parts)-2]
					sets[set] = append(sets[set], path)
				}
			}
			return filepath.SkipDir
		}
		return nil
	})
	addDeclaredGradleSourceSets(directory, sets)
	addGeneratedSourceSets(directory, sets)
	if len(sets) == 0 {
		sets["main"] = []string{directory}
	}
	for set := range sets {
		sort.Strings(sets[set])
	}
	return sets
}

func addDeclaredGradleSourceSets(directory string, sets map[string][]string) {
	for _, buildName := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(directory, buildName))
		if err != nil {
			continue
		}
		for _, pattern := range gradleDeclaredSourcePatterns {
			for _, match := range pattern.FindAllSubmatch(data, -1) {
				if len(match) != 3 {
					continue
				}
				set, sourceRoot := string(match[1]), string(match[2])
				if strings.Contains(sourceRoot, "${") || strings.Contains(sourceRoot, "$project") || strings.Contains(sourceRoot, "$buildDir") {
					continue
				}
				if !filepath.IsAbs(sourceRoot) {
					sourceRoot = filepath.Join(directory, filepath.FromSlash(sourceRoot))
				}
				if info, statErr := os.Stat(sourceRoot); statErr == nil && info.IsDir() {
					sets[set] = appendUniqueString(sets[set], filepath.Clean(sourceRoot))
				}
			}
		}
	}
}

func addGeneratedSourceSets(directory string, sets map[string][]string) {
	add := func(set, root string) {
		if set == "" {
			set = "main"
		}
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			sets[set] = appendUniqueString(sets[set], filepath.Clean(root))
		}
	}
	for _, pattern := range []string{
		filepath.Join(directory, "build", "generated", "source", "*", "*"),
		filepath.Join(directory, "build", "generated", "sources", "*", "*", "*"),
	} {
		matches, _ := filepath.Glob(pattern)
		for _, root := range matches {
			add(filepath.Base(root), root)
		}
	}
	for _, language := range []string{"java", "kotlin"} {
		matches, _ := filepath.Glob(filepath.Join(directory, "build", "generated", "ksp", "*", language))
		for _, root := range matches {
			add(filepath.Base(filepath.Dir(root)), root)
		}
	}
	// Android Gradle Plugin places generated Java outside the conventional
	// build/generated/source(s) trees. The variant is the directory before the
	// task-specific output directory (usually "out" or "r"). Keep these roots
	// attached to their variant so main/flavor/build-type overlay rules apply.
	for _, output := range []string{
		"data_binding_base_class_source_out",
		"view_binding_base_class_source_out",
		"not_namespaced_r_class_sources",
		"namespaced_r_class_sources",
		"ap_generated_sources",
	} {
		matches, _ := filepath.Glob(filepath.Join(directory, "build", "generated", output, "*", "*"))
		for _, root := range matches {
			add(filepath.Base(filepath.Dir(root)), root)
		}
	}
	add("main", filepath.Join(directory, "target", "generated-sources", "annotations"))
	add("test", filepath.Join(directory, "target", "generated-test-sources", "test-annotations"))
}

func flattenSourceSets(sets map[string][]string) []string {
	var roots []string
	for _, values := range sets {
		roots = append(roots, values...)
	}
	return uniqueSortedStrings(roots)
}

func conventionalSourceSetDependencies(sets map[string][]string) map[string][]string {
	dependencies := make(map[string][]string)
	has := func(name string) bool {
		_, ok := sets[name]
		return ok
	}
	isKMPSet := func(name string) bool {
		if name == "commonMain" || name == "commonTest" || strings.HasSuffix(name, "Main") {
			return true
		}
		if !strings.HasSuffix(name, "Test") {
			return false
		}
		platformMain := strings.TrimSuffix(name, "Test") + "Main"
		return has(platformMain) || has("commonTest")
	}
	for set := range sets {
		platformMain := ""
		if strings.HasSuffix(set, "Test") {
			platformMain = strings.TrimSuffix(set, "Test") + "Main"
		}
		switch {
		case set == "test" && has("main"):
			dependencies[set] = appendUniqueString(dependencies[set], "main")
		case set == "commonTest" && has("commonMain"):
			dependencies[set] = appendUniqueString(dependencies[set], "commonMain")
		case strings.HasSuffix(set, "Test"):
			if has(platformMain) {
				dependencies[set] = appendUniqueString(dependencies[set], platformMain)
			}
			if has("commonTest") {
				dependencies[set] = appendUniqueString(dependencies[set], "commonTest")
			}
		case strings.HasSuffix(set, "Main") && set != "commonMain" && has("commonMain"):
			dependencies[set] = appendUniqueString(dependencies[set], "commonMain")
		}
		// Gradle and Android variant source sets overlay main. Their names are
		// intentionally open-ended (build types and product flavours are user
		// defined), so infer this from the graph instead of a fixed debug/release
		// allow-list. KMP source sets retain their own dependsOn hierarchy.
		if set != "main" && has("main") && !isKMPSet(set) {
			dependencies[set] = appendUniqueString(dependencies[set], "main")
		}
		// A concrete Android variant (for example freeDebug or testFreeDebug)
		// also overlays the shorter build-type/flavour source sets that exist in
		// the project. A title-cased occurrence is a camel-case component boundary.
		if !isKMPSet(set) {
			for candidate := range sets {
				if candidate == set || candidate == "main" || len(candidate) >= len(set) || isKMPSet(candidate) {
					continue
				}
				titleCandidate := strings.ToUpper(candidate[:1]) + candidate[1:]
				if strings.HasPrefix(set, candidate) || strings.Contains(set, titleCandidate) {
					dependencies[set] = appendUniqueString(dependencies[set], candidate)
				}
			}
		}
	}
	return dependencies
}

func (i *Index) setModules(modules []ModuleInfo) {
	i.mu.Lock()
	i.modules = append([]ModuleInfo(nil), modules...)
	i.mu.Unlock()
}

func (i *Index) mergeModuleBuildResolution(root string, resolution classpathResolution) {
	root, _ = filepath.Abs(root)
	i.mu.Lock()
	defer i.mu.Unlock()
	for index := range i.modules {
		module := &i.modules[index]
		if !pathWithin(module.Dir, root) {
			continue
		}
		if module.ClasspathBySourceSet == nil {
			module.ClasspathBySourceSet = make(map[string][]string)
		}
		if module.ModulePathBySourceSet == nil {
			module.ModulePathBySourceSet = make(map[string][]string)
		}
		if module.DependenciesBySourceSet == nil {
			module.DependenciesBySourceSet = make(map[string][]string)
		}
		if module.ExportedBySourceSet == nil {
			module.ExportedBySourceSet = make(map[string][]string)
		}
		if module.DependencyExclusions == nil {
			module.DependencyExclusions = make(map[string][]string)
		}
		if module.SourceSetDependsOn == nil {
			module.SourceSetDependsOn = conventionalSourceSetDependencies(module.SourceSets)
		}
		if values := resolution.ModuleClasspath[module.Name]; len(values) > 0 {
			for _, value := range values {
				if module.JavaModuleName != "" && isModularPath(value) {
					module.ModulePath = append(module.ModulePath, value)
				} else {
					module.Classpath = append(module.Classpath, value)
				}
			}
			module.Classpath = uniqueSortedStrings(module.Classpath)
			module.ModulePath = uniqueSortedStrings(module.ModulePath)
		}
		for sourceSet, values := range resolution.SourceSetClasspath[module.Name] {
			for _, value := range values {
				if module.JavaModuleName != "" && isModularPath(value) {
					module.ModulePathBySourceSet[sourceSet] = append(module.ModulePathBySourceSet[sourceSet], value)
				} else {
					module.ClasspathBySourceSet[sourceSet] = append(module.ClasspathBySourceSet[sourceSet], value)
				}
			}
			module.ClasspathBySourceSet[sourceSet] = uniqueSortedStrings(module.ClasspathBySourceSet[sourceSet])
			module.ModulePathBySourceSet[sourceSet] = uniqueSortedStrings(module.ModulePathBySourceSet[sourceSet])
			for _, value := range values {
				key := filepath.Clean(value)
				if i.libraryAccess[key] == nil {
					i.libraryAccess[key] = make(map[string]bool)
				}
				i.libraryAccess[key][libraryAccessKey(module.Dir, sourceSet)] = true
			}
		}
		if dependencies := resolution.Dependencies[module.Name]; len(dependencies) > 0 {
			module.Dependencies = uniqueSortedStrings(append(module.Dependencies, dependencies...))
		}
		for sourceSet, dependencies := range resolution.SourceSetDependencies[module.Name] {
			module.DependenciesBySourceSet[sourceSet] = uniqueSortedStrings(append(module.DependenciesBySourceSet[sourceSet], dependencies...))
		}
		for sourceSet, dependencies := range resolution.SourceSetExported[module.Name] {
			module.ExportedBySourceSet[sourceSet] = uniqueSortedStrings(append(module.ExportedBySourceSet[sourceSet], dependencies...))
		}
		for sourceSet, dependencies := range resolution.SourceSetDependsOn[module.Name] {
			module.SourceSetDependsOn[sourceSet] = uniqueSortedStrings(append(module.SourceSetDependsOn[sourceSet], dependencies...))
		}
		for sourceSet, roots := range resolution.SourceSetRoots[module.Name] {
			for _, sourceRoot := range roots {
				if info, err := os.Stat(sourceRoot); err == nil && info.IsDir() {
					module.SourceSets[sourceSet] = appendUniqueString(module.SourceSets[sourceSet], filepath.Clean(sourceRoot))
				}
			}
		}
		module.SourceRoots = flattenSourceSets(module.SourceSets)
		for sourceSet, dependencies := range conventionalSourceSetDependencies(module.SourceSets) {
			module.SourceSetDependsOn[sourceSet] = uniqueSortedStrings(append(module.SourceSetDependsOn[sourceSet], dependencies...))
		}
	}
}

func (i *Index) copyLibraryAccess(binary, source string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	access := i.libraryAccess[filepath.Clean(binary)]
	if len(access) == 0 {
		return
	}
	target := make(map[string]bool, len(access))
	for module := range access {
		target[module] = true
	}
	i.libraryAccess[filepath.Clean(source)] = target
}

func uniqueSortedStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value != "" && (len(out) == 0 || out[len(out)-1] != value) {
			out = append(out, value)
		}
	}
	return out
}

func libraryAccessKey(moduleDir, sourceSet string) string {
	return filepath.Clean(moduleDir) + "\x00" + sourceSet
}

func sourceSetFromConfiguration(configuration string) string {
	for _, suffix := range []string{"CompileClasspath", "RuntimeClasspath"} {
		if strings.HasSuffix(configuration, suffix) {
			set := strings.TrimSuffix(configuration, suffix)
			if set == "" {
				return "main"
			}
			return set
		}
	}
	return "main"
}

func sourceSetFromDependencyConfiguration(configuration string) string {
	for _, suffix := range []string{"Implementation", "Api", "CompileOnly", "RuntimeOnly", "Compile", "Runtime"} {
		if strings.HasSuffix(configuration, suffix) {
			set := strings.TrimSuffix(configuration, suffix)
			if set == "" {
				return "main"
			}
			return set
		}
	}
	return "main"
}

func (i *Index) moduleForURILocked(uri protocol.URI) *ModuleInfo {
	path, ok := uriutil.Path(uri)
	if !ok {
		return nil
	}
	path = filepath.Clean(path)
	best := -1
	for index := range i.modules {
		module := &i.modules[index]
		for _, sourceRoot := range module.SourceRoots {
			if pathWithin(path, sourceRoot) && (best < 0 || len(module.Dir) > len(i.modules[best].Dir)) {
				best = index
			}
		}
		if pathWithin(path, module.Dir) && (best < 0 || len(module.Dir) > len(i.modules[best].Dir)) {
			best = index
		}
	}
	if best < 0 {
		return nil
	}
	return &i.modules[best]
}

func (i *Index) sourceSetForURILocked(uri protocol.URI, module *ModuleInfo) string {
	if module == nil {
		return "main"
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		return "main"
	}
	bestSet, bestLength := "main", -1
	for set, roots := range module.SourceSets {
		for _, root := range roots {
			if pathWithin(path, root) && len(root) > bestLength {
				bestSet, bestLength = set, len(root)
			}
		}
	}
	return bestSet
}

func pathWithin(path, directory string) bool {
	path, directory = filepath.Clean(path), filepath.Clean(directory)
	return path == directory || strings.HasPrefix(path, directory+string(filepath.Separator))
}

func (i *Index) moduleCanAccessLocked(from, target *ModuleInfo, sourceSet, targetSourceSet string) bool {
	if from == nil || target == nil {
		return true
	}
	if from.Name == target.Name && from.Dir == target.Dir {
		return sourceSetCanAccess(from, sourceSet, targetSourceSet)
	}
	if targetSourceSet != "main" && targetSourceSet != "commonMain" {
		return false
	}
	byName := make(map[string]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		module := &i.modules[index]
		byName[module.Root+"\x00"+module.Name] = module
	}
	type dependencyPath struct {
		name     string
		excluded map[string]bool
	}
	dependencies := moduleDependenciesForSourceSet(from, sourceSet)
	queue := make([]dependencyPath, 0, len(dependencies))
	for _, dependency := range dependencies {
		queue = append(queue, dependencyPath{name: dependency, excluded: dependencyPathExclusions(nil, from, sourceSet, dependency)})
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		stateKey := path.name + "\x00" + exclusionSetKey(path.excluded)
		if seen[stateKey] {
			continue
		}
		seen[stateKey] = true
		candidate := byName[from.Root+"\x00"+path.name]
		if candidate == nil {
			continue
		}
		if candidate.Name == target.Name && candidate.Dir == target.Dir {
			return true
		}
		// A direct dependency is always visible to its declaring module. Beyond
		// that first edge, only exported Maven compile / Gradle api edges belong
		// on a consumer's compile classpath; implementation and compileOnly do not.
		next := moduleExportedDependenciesForSourceSet(candidate, "main")
		for _, dependency := range next {
			if path.excluded[dependency] {
				continue
			}
			queue = append(queue, dependencyPath{name: dependency, excluded: dependencyPathExclusions(path.excluded, candidate, "main", dependency)})
		}
	}
	return false
}

func dependencyExclusionKey(sourceSet, dependency string) string {
	return sourceSet + "\x00" + dependency
}

func dependencyPathExclusions(parent map[string]bool, module *ModuleInfo, sourceSet, dependency string) map[string]bool {
	values := module.DependencyExclusions[dependencyExclusionKey(sourceSet, dependency)]
	if len(parent) == 0 && len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(parent)+len(values))
	for name := range parent {
		out[name] = true
	}
	for _, name := range values {
		out[name] = true
	}
	return out
}

func exclusionSetKey(excluded map[string]bool) string {
	if len(excluded) == 0 {
		return ""
	}
	values := make([]string, 0, len(excluded))
	for value := range excluded {
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, "\x00")
}

func sourceSetCanAccess(module *ModuleInfo, from, target string) bool {
	return sourceSetAccessDistance(module, from, target) >= 0
}

func sourceSetAccessDistance(module *ModuleInfo, from, target string) int {
	if from == target {
		return 0
	}
	type entry struct {
		name     string
		distance int
	}
	queue := make([]entry, 0)
	for _, dependency := range sourceSetDependencies(module, from) {
		queue = append(queue, entry{name: dependency, distance: 1})
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.name == target {
			return current.distance
		}
		if seen[current.name] {
			continue
		}
		seen[current.name] = true
		for _, dependency := range sourceSetDependencies(module, current.name) {
			queue = append(queue, entry{name: dependency, distance: current.distance + 1})
		}
	}
	return -1
}

func sourceSetDependencies(module *ModuleInfo, sourceSet string) []string {
	if module == nil {
		return nil
	}
	dependencies := append([]string(nil), module.SourceSetDependsOn[sourceSet]...)
	if len(dependencies) == 0 {
		dependencies = append(dependencies, conventionalSourceSetDependencies(module.SourceSets)[sourceSet]...)
	}
	return uniqueSortedStrings(dependencies)
}

func moduleDependenciesForSourceSet(module *ModuleInfo, sourceSet string) []string {
	if module == nil {
		return nil
	}
	if len(module.DependenciesBySourceSet) == 0 {
		return module.Dependencies
	}
	dependencies := append([]string(nil), module.DependenciesBySourceSet[sourceSet]...)
	for _, dependencySet := range sourceSetDependencies(module, sourceSet) {
		dependencies = append(dependencies, moduleDependenciesForSourceSet(module, dependencySet)...)
	}
	if sourceSet != "main" {
		dependencies = append(dependencies, module.DependenciesBySourceSet["main"]...)
	}
	return uniqueSortedStrings(dependencies)
}

func moduleExportedDependenciesForSourceSet(module *ModuleInfo, sourceSet string) []string {
	if module == nil {
		return nil
	}
	// Manually constructed/legacy models predate edge visibility. Preserve
	// their established transitive behavior; discovered build models always
	// initialize ExportedBySourceSet, including an intentionally empty map.
	if module.ExportedBySourceSet == nil {
		return moduleDependenciesForSourceSet(module, sourceSet)
	}
	dependencies := append([]string(nil), module.ExportedBySourceSet[sourceSet]...)
	for _, dependencySet := range sourceSetDependencies(module, sourceSet) {
		dependencies = append(dependencies, moduleExportedDependenciesForSourceSet(module, dependencySet)...)
	}
	if sourceSet != "main" {
		dependencies = append(dependencies, module.ExportedBySourceSet["main"]...)
	}
	return uniqueSortedStrings(dependencies)
}

func (i *Index) ModuleFor(uri protocol.URI) (ModuleInfo, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	module := i.moduleForURILocked(uri)
	if module == nil {
		return ModuleInfo{}, false
	}
	return *module, true
}

func (i *Index) ClasspathFor(uri protocol.URI) (classpath, modulePath []string, moduleName any) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	module := i.moduleForURILocked(uri)
	if module == nil {
		return append([]string(nil), i.classpath...), []string{}, nil
	}
	seen := make(map[string]bool)
	moduleSeen := make(map[string]bool)
	appendPaths := func(paths []string) {
		for _, path := range paths {
			if path != "" && !seen[path] {
				seen[path] = true
				classpath = append(classpath, path)
			}
		}
	}
	appendModulePaths := func(paths []string) {
		for _, path := range paths {
			if path != "" && !moduleSeen[path] {
				moduleSeen[path] = true
				modulePath = append(modulePath, path)
			}
		}
	}
	sourceSet := i.sourceSetForURILocked(uri, module)
	setClasspath := module.ClasspathBySourceSet[sourceSet]
	appendPaths(setClasspath)
	setModulePath := module.ModulePathBySourceSet[sourceSet]
	appendModulePaths(setModulePath)
	for _, dependencySet := range sourceSetDependencyClosure(module, sourceSet) {
		appendPaths(module.ClasspathBySourceSet[dependencySet])
		appendModulePaths(module.ModulePathBySourceSet[dependencySet])
	}
	if len(module.ClasspathBySourceSet) == 0 {
		appendPaths(module.Classpath)
	}
	if len(module.ModulePathBySourceSet) == 0 {
		appendModulePaths(module.ModulePath)
	}
	if len(setClasspath) == 0 && len(module.ClasspathBySourceSet) == 0 && len(module.Classpath) == 0 {
		appendPaths(i.classpath)
	}
	byName := make(map[string]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		candidate := &i.modules[index]
		byName[candidate.Root+"\x00"+candidate.Name] = candidate
	}
	dependencies := moduleDependenciesForSourceSet(module, sourceSet)
	type moduleQueueEntry struct {
		name      string
		sourceSet string
	}
	queue := []moduleQueueEntry{{name: module.Name, sourceSet: sourceSet}}
	for _, dependency := range dependencies {
		queue = append(queue, moduleQueueEntry{name: dependency, sourceSet: "main"})
	}
	visited := make(map[string]bool)
	for len(queue) > 0 {
		entry := queue[0]
		queue = queue[1:]
		key := entry.name + "\x00" + entry.sourceSet
		if visited[key] {
			continue
		}
		visited[key] = true
		candidate := byName[module.Root+"\x00"+entry.name]
		if candidate == nil {
			continue
		}
		outputs := conventionalOutputDirectoriesForSourceSet(candidate.Dir, entry.sourceSet)
		if module.JavaModuleName != "" && candidate.JavaModuleName != "" && candidate.Dir != module.Dir {
			appendModulePaths(outputs)
		} else {
			appendPaths(outputs)
		}
		next := moduleDependenciesForSourceSet(candidate, entry.sourceSet)
		for _, dependency := range next {
			queue = append(queue, moduleQueueEntry{name: dependency, sourceSet: "main"})
		}
	}
	sort.Strings(classpath)
	sort.Strings(modulePath)
	if module.JavaModuleName != "" {
		moduleName = module.JavaModuleName
	}
	return classpath, modulePath, moduleName
}

func sourceSetDependencyClosure(module *ModuleInfo, sourceSet string) []string {
	queue := append([]string(nil), sourceSetDependencies(module, sourceSet)...)
	seen := make(map[string]bool)
	result := make([]string, 0, len(queue))
	for len(queue) > 0 {
		set := queue[0]
		queue = queue[1:]
		if seen[set] {
			continue
		}
		seen[set] = true
		result = append(result, set)
		queue = append(queue, sourceSetDependencies(module, set)...)
	}
	return result
}
