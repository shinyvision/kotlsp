package index

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
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
	Name                           string
	Dir                            string
	Root                           string
	SourceRoots                    []string
	SourceSets                     map[string][]string
	Classpath                      []string
	ClasspathBySourceSet           map[string][]string
	RuntimeClasspathBySourceSet    map[string][]string
	ModulePath                     []string
	ModulePathBySourceSet          map[string][]string
	JavaModuleName                 string
	JavaRequires                   map[string]JavaModuleRequirement
	JavaExports                    map[string][]string
	JavaOpens                      map[string][]string
	JavaHome                       string
	Dependencies                   []string
	DependenciesBySourceSet        map[string][]string
	RuntimeDependenciesBySourceSet map[string][]string
	ExportedBySourceSet            map[string][]string
	DependencyExclusions           map[string][]string
	ExternalDependencyExclusions   map[string][]string
	SourceSetDependsOn             map[string][]string
	BuildImporter                  string
	BuildModelAuthoritative        bool
	// BuildModelSelfContained: no build tool describes this workspace, so the
	// conventional model is complete by construction (see
	// classpathResolution.SelfContained).
	BuildModelSelfContained     bool
	BuildModelFailure           string
	CompilerSettingsBySourceSet map[string]CompilerSettings
}

type JavaModuleRequirement struct {
	Transitive bool
	Static     bool
}

// libraryJavaModule is the binary counterpart of the source module fields on
// ModuleInfo. It is stored once per archive instead of copied onto every
// classfile symbol in what can be a very large dependency.
type libraryJavaModule struct {
	Name      string
	Automatic bool
	Open      bool
	Requires  map[string]JavaModuleRequirement
	Exports   map[string][]string
	Opens     map[string][]string
}

// CompilerSettings is the build-tool-emitted semantic compiler model. Raw
// arguments are retained for audit/export; invocation code applies a narrow
// normalization that replaces source/output/classpath locations owned by the
// language server.
type CompilerSettings struct {
	JavaHome              string
	JavaRelease           string
	JavaSource            string
	JavaTarget            string
	JavaArguments         []string
	KotlinVersion         string
	KotlinLanguageVersion string
	KotlinAPIVersion      string
	KotlinJVMTarget       string
	KotlinArguments       []string
	// IncompleteReason prevents the background compiler from presenting a
	// partial reconstruction as project truth. Fast analysis remains available
	// and status explains which build-tool setting could not be replayed.
	IncompleteReason string
}

type BuildModelStatus struct {
	Module           string
	Directory        string
	Importer         string
	Authoritative    bool
	Failure          string
	CompilerSettings map[string]CompilerSettings
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
	Build mavenBuild `xml:"build"`
}

type mavenBuild struct {
	SourceDirectory     string `xml:"sourceDirectory"`
	TestSourceDirectory string `xml:"testSourceDirectory"`
	Plugins             struct {
		Items []mavenPlugin `xml:"plugin"`
	} `xml:"plugins"`
}

type mavenPlugin struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Config     struct {
		Release         string `xml:"release"`
		Source          string `xml:"source"`
		Target          string `xml:"target"`
		JVMTarget       string `xml:"jvmTarget"`
		LanguageVersion string `xml:"languageVersion"`
		APIVersion      string `xml:"apiVersion"`
		Args            struct {
			Items []string `xml:"arg"`
		} `xml:"args"`
		CompilerArgs struct {
			Items []string `xml:"arg"`
		} `xml:"compilerArgs"`
		CompilerPlugins struct {
			Items []string `xml:"plugin"`
		} `xml:"compilerPlugins"`
		AnnotationProcessorPaths struct {
			Items []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"path"`
		} `xml:"annotationProcessorPaths"`
		Sources struct {
			Items []string `xml:"source"`
		} `xml:"sources"`
	} `xml:"configuration"`
	Executions struct {
		Items []struct {
			Goals struct {
				Items []string `xml:"goal"`
			} `xml:"goals"`
			Config struct {
				Sources struct {
					Items []string `xml:"source"`
				} `xml:"sources"`
			} `xml:"configuration"`
		} `xml:"execution"`
	} `xml:"executions"`
}

func mavenCompilerSettings(model mavenPOM) CompilerSettings {
	settings := CompilerSettings{
		JavaRelease: model.Properties["maven.compiler.release"], JavaSource: model.Properties["maven.compiler.source"], JavaTarget: model.Properties["maven.compiler.target"],
		KotlinVersion: model.Properties["kotlin.version"], KotlinLanguageVersion: model.Properties["kotlin.compiler.languageVersion"],
		KotlinAPIVersion: model.Properties["kotlin.compiler.apiVersion"], KotlinJVMTarget: model.Properties["kotlin.compiler.jvmTarget"],
	}
	for _, plugin := range model.Build.Plugins.Items {
		switch plugin.ArtifactID {
		case "maven-compiler-plugin":
			if plugin.Config.Release != "" {
				settings.JavaRelease = plugin.Config.Release
			}
			if plugin.Config.Source != "" {
				settings.JavaSource = plugin.Config.Source
			}
			if plugin.Config.Target != "" {
				settings.JavaTarget = plugin.Config.Target
			}
			settings.JavaArguments = append(settings.JavaArguments, plugin.Config.CompilerArgs.Items...)
			if len(plugin.Config.AnnotationProcessorPaths.Items) > 0 {
				settings.IncompleteReason = appendIncompleteReason(settings.IncompleteReason, "Maven annotationProcessorPaths require build-tool processor resolution")
			}
		case "kotlin-maven-plugin":
			if plugin.Version != "" {
				settings.KotlinVersion = plugin.Version
			}
			if plugin.Config.JVMTarget != "" {
				settings.KotlinJVMTarget = plugin.Config.JVMTarget
			}
			if plugin.Config.LanguageVersion != "" {
				settings.KotlinLanguageVersion = plugin.Config.LanguageVersion
			}
			if plugin.Config.APIVersion != "" {
				settings.KotlinAPIVersion = plugin.Config.APIVersion
			}
			settings.KotlinArguments = append(settings.KotlinArguments, plugin.Config.Args.Items...)
			if len(plugin.Config.CompilerPlugins.Items) > 0 {
				settings.IncompleteReason = appendIncompleteReason(settings.IncompleteReason, "Maven Kotlin compiler plugins require their build-tool plugin classpath")
			}
		}
	}
	return settings
}

func appendIncompleteReason(current, reason string) string {
	if current == "" {
		return reason
	}
	if strings.Contains(current, reason) {
		return current
	}
	return current + "; " + reason
}

func mavenAdditionalSourceRoots(model mavenPOM, directory string) (main, test []string) {
	for _, plugin := range model.Build.Plugins.Items {
		if plugin.ArtifactID != "build-helper-maven-plugin" {
			continue
		}
		for _, execution := range plugin.Executions.Items {
			isMain, isTest := false, false
			for _, goal := range execution.Goals.Items {
				isMain = isMain || strings.TrimSpace(goal) == "add-source"
				isTest = isTest || strings.TrimSpace(goal) == "add-test-source"
			}
			for _, source := range execution.Config.Sources.Items {
				source = strings.TrimSpace(source)
				if source == "" {
					continue
				}
				if !filepath.IsAbs(source) {
					source = filepath.Join(directory, source)
				}
				if isMain {
					main = appendUniqueString(main, filepath.Clean(source))
				}
				if isTest {
					test = appendUniqueString(test, filepath.Clean(source))
				}
			}
		}
	}
	return main, test
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
			if len(*properties) >= 100_000 {
				return fmt.Errorf("Maven properties exceed their 100000-entry safety limit")
			}
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
	Version    string `xml:"version"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
	Exclusions struct {
		Items []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
		} `xml:"exclusion"`
	} `xml:"exclusions"`
}

func readModuleFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("module input %s exceeds its %d-byte safety limit", path, limit)
	}
	return data, nil
}

func readMavenPOM(path string) (mavenPOM, bool) {
	data, err := readModuleFile(path, 16<<20)
	if err != nil {
		return mavenPOM{}, false
	}
	var model mavenPOM
	if err := xml.Unmarshal(data, &model); err != nil {
		return mavenPOM{}, false
	}
	if validateMavenModel(model) != nil {
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
		dependency.Version = strings.TrimSpace(dependency.Version)
		dependency.Type = strings.TrimSpace(dependency.Type)
		dependency.Classifier = strings.TrimSpace(dependency.Classifier)
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

func validateMavenModel(model mavenPOM) error {
	if len(model.Properties) > 100_000 || len(model.Dependencies.Items) > 100_000 || len(model.Build.Plugins.Items) > 10_000 {
		return fmt.Errorf("Maven model exceeds its properties/dependencies/plugins safety limit")
	}
	totalItems := len(model.Dependencies.Items)
	for _, dependency := range model.Dependencies.Items {
		totalItems += len(dependency.Exclusions.Items)
	}
	for _, plugin := range model.Build.Plugins.Items {
		totalItems += len(plugin.Config.Args.Items) + len(plugin.Config.CompilerArgs.Items) + len(plugin.Config.CompilerPlugins.Items) + len(plugin.Config.AnnotationProcessorPaths.Items) + len(plugin.Config.Sources.Items)
		totalItems += len(plugin.Executions.Items)
		for _, execution := range plugin.Executions.Items {
			totalItems += len(execution.Goals.Items) + len(execution.Config.Sources.Items)
		}
		if totalItems > 500_000 {
			return fmt.Errorf("Maven model exceeds its 500000-item aggregate safety limit")
		}
	}
	return nil
}

func (m mavenPOM) effectiveGroupID() string {
	if m.GroupID != "" {
		return m.GroupID
	}
	return m.Parent.GroupID
}

func effectiveMavenModels(models map[string]mavenPOM) (map[string]mavenPOM, error) {
	coordinates := make(map[string]string, len(models))
	for directory, model := range models {
		coordinates[mavenCoordinate(model.effectiveGroupID(), model.ArtifactID, mavenEffectiveVersion(model))] = directory
	}
	result := make(map[string]mavenPOM, len(models))
	visiting := make(map[string]bool)
	var resolutionErr error
	var resolve func(string, int) mavenPOM
	resolve = func(directory string, depth int) mavenPOM {
		if model, ok := result[directory]; ok {
			return model
		}
		model, ok := models[directory]
		if !ok || visiting[directory] || resolutionErr != nil {
			return model
		}
		if depth > 4096 {
			resolutionErr = fmt.Errorf("Maven parent hierarchy exceeds its 4096-level safety limit")
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
			parent := resolve(parentDirectory, depth+1)
			var inheritErr error
			model, inheritErr = inheritMavenModel(parent, model)
			if inheritErr != nil {
				resolutionErr = inheritErr
				return model
			}
		}
		model = interpolateMavenModel(model)
		if validationErr := validateMavenModel(model); validationErr != nil {
			resolutionErr = validationErr
			return model
		}
		visiting[directory] = false
		result[directory] = model
		return model
	}
	for directory := range models {
		resolve(directory, 0)
		if resolutionErr != nil {
			return nil, resolutionErr
		}
	}
	return result, nil
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

func inheritMavenModel(parent, child mavenPOM) (mavenPOM, error) {
	if child.GroupID == "" {
		child.GroupID = parent.effectiveGroupID()
	}
	if child.Version == "" {
		child.Version = mavenEffectiveVersion(parent)
	}
	if len(parent.Properties)+len(child.Properties) > 100_000 || len(parent.Dependencies.Items)+len(child.Dependencies.Items) > 500_000 {
		return child, fmt.Errorf("effective Maven inheritance exceeds its properties/dependencies safety limit")
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
		positions[mavenDependencyIdentity(dependency)] = index
	}
	for _, dependency := range child.Dependencies.Items {
		key := mavenDependencyIdentity(dependency)
		if index, exists := positions[key]; exists {
			merged[index] = dependency
		} else {
			positions[key] = len(merged)
			merged = append(merged, dependency)
		}
	}
	child.Dependencies.Items = merged
	return child, nil
}

func mavenDependencyIdentity(dependency mavenDependency) string {
	typeName := strings.TrimSpace(dependency.Type)
	if typeName == "" {
		typeName = "jar"
	}
	return strings.TrimSpace(dependency.GroupID) + "\x00" + strings.TrimSpace(dependency.ArtifactID) + "\x00" + typeName + "\x00" + strings.TrimSpace(dependency.Classifier)
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
		dependency.Version = interpolateMavenValue(dependency.Version, properties)
		dependency.Type = interpolateMavenValue(dependency.Type, properties)
		dependency.Classifier = interpolateMavenValue(dependency.Classifier, properties)
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
		if len(value)-((end+1)-start)+len(replacement) > 1<<20 {
			// This discovery model is only a source/dependency hint. Refuse an
			// expansion bomb and leave the placeholder for the authoritative
			// build-tool import to resolve.
			break
		}
		value = value[:start] + replacement + value[end+1:]
	}
	return strings.TrimSpace(value)
}

func discoverModules(roots []string) []ModuleInfo {
	modules, _ := discoverModulesContext(context.Background(), roots)
	return modules
}

func discoverModulesContext(ctx context.Context, roots []string) ([]ModuleInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(roots) > 128 {
		return nil, fmt.Errorf("module discovery exceeds its 128-root safety limit")
	}
	var modules []ModuleInfo
	visitedEntries := 0
	totalSourceSets := 0
	for _, workspaceRoot := range roots {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		root, err := filepath.Abs(workspaceRoot)
		if err != nil {
			continue
		}
		buildDirs := make(map[string]bool)
		moduleLimitExceeded := false
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if walkErr != nil {
				return nil
			}
			visitedEntries++
			if visitedEntries > 1_000_000 {
				return filepath.SkipAll
			}
			if entry.IsDir() {
				if path != root && ignoredDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(entry.Name()) {
			case "build.gradle", "build.gradle.kts", "pom.xml":
				directory := filepath.Dir(path)
				if len(buildDirs) >= 4096 && !buildDirs[directory] {
					moduleLimitExceeded = true
					return filepath.SkipAll
				}
				buildDirs[directory] = true
			}
			return nil
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if visitedEntries > 1_000_000 {
			return nil, fmt.Errorf("module discovery exceeds its 1000000-entry safety limit")
		}
		if moduleLimitExceeded {
			return nil, fmt.Errorf("module discovery exceeds its 4096-module safety limit")
		}
		if len(buildDirs) == 0 {
			buildDirs[root] = true
		}
		dirs := make([]string, 0, len(buildDirs))
		for directory := range buildDirs {
			dirs = append(dirs, directory)
		}
		sort.Slice(dirs, func(a, b int) bool { return len(dirs[a]) < len(dirs[b]) })
		coordinateToName := make(map[string]string)
		gaToNames := make(map[string][]string)
		mavenModels := make(map[string]mavenPOM)
		for _, directory := range dirs {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			name := moduleName(root, directory)
			if model, ok := readMavenPOM(filepath.Join(directory, "pom.xml")); ok {
				mavenModels[directory] = model
				coordinateToName[mavenCoordinate(model.effectiveGroupID(), model.ArtifactID, mavenEffectiveVersion(model))] = name
			}
			sourceSets, sourceSetErr := moduleSourceSets(ctx, directory)
			if sourceSetErr != nil {
				return nil, sourceSetErr
			}
			totalSourceSets += len(sourceSets)
			if totalSourceSets > 100_000 {
				return nil, fmt.Errorf("module discovery exceeds its 100000-source-set aggregate safety limit")
			}
			descriptor := javaModuleDescriptor(directory, sourceSets)
			modules = append(modules, ModuleInfo{
				Name: name, Dir: directory, Root: root,
				SourceRoots: flattenSourceSets(sourceSets), SourceSets: sourceSets,
				ClasspathBySourceSet:           make(map[string][]string),
				RuntimeClasspathBySourceSet:    make(map[string][]string),
				ModulePathBySourceSet:          make(map[string][]string),
				DependenciesBySourceSet:        make(map[string][]string),
				RuntimeDependenciesBySourceSet: make(map[string][]string),
				ExportedBySourceSet:            make(map[string][]string),
				DependencyExclusions:           make(map[string][]string),
				ExternalDependencyExclusions:   make(map[string][]string),
				SourceSetDependsOn:             conventionalSourceSetDependencies(sourceSets),
				JavaModuleName:                 descriptor.Name,
				JavaRequires:                   descriptor.Requires,
				JavaExports:                    descriptor.Exports,
				JavaOpens:                      descriptor.Opens,
				JavaHome:                       moduleJavaHome(directory, root),
			})
			if len(modules) > 4096 {
				return nil, fmt.Errorf("module discovery exceeds its 4096-module safety limit")
			}
		}
		var effectiveErr error
		mavenModels, effectiveErr = effectiveMavenModels(mavenModels)
		if effectiveErr != nil {
			return nil, effectiveErr
		}
		coordinateToName = make(map[string]string, len(mavenModels))
		gaToNames = make(map[string][]string, len(mavenModels))
		for directory, model := range mavenModels {
			name := moduleName(root, directory)
			coordinateToName[mavenCoordinate(model.effectiveGroupID(), model.ArtifactID, mavenEffectiveVersion(model))] = name
			ga := strings.TrimSpace(model.effectiveGroupID()) + "\x00" + strings.TrimSpace(model.ArtifactID)
			gaToNames[ga] = appendUniqueString(gaToNames[ga], name)
		}
		for index := range modules {
			module := &modules[index]
			if module.Dir != root && !strings.HasPrefix(module.Dir, root+string(filepath.Separator)) {
				continue
			}
			dependencies := make(map[string]bool)
			for _, buildName := range []string{"build.gradle", "build.gradle.kts"} {
				if data, err := readModuleFile(filepath.Join(module.Dir, buildName), 8<<20); err == nil {
					matches := gradleScopedProjectDependencyPattern.FindAllSubmatch(data, 100_001)
					if len(matches) > 100_000 {
						return nil, fmt.Errorf("Gradle project dependencies in %s exceed their 100000-match safety limit", module.Dir)
					}
					for _, match := range matches {
						set, compileVisible, runtimeVisible, exported := gradleDependencyConfiguration(string(match[1]))
						if !compileVisible && !runtimeVisible {
							continue
						}
						dependency := string(match[2])
						if compileVisible {
							dependencies[dependency] = true
							module.DependenciesBySourceSet[set] = appendUniqueString(module.DependenciesBySourceSet[set], dependency)
						}
						if runtimeVisible {
							module.RuntimeDependenciesBySourceSet[set] = appendUniqueString(module.RuntimeDependenciesBySourceSet[set], dependency)
						}
						if exported {
							module.ExportedBySourceSet[set] = appendUniqueString(module.ExportedBySourceSet[set], dependency)
						}
					}
				}
			}
			if model, ok := mavenModels[module.Dir]; ok {
				for _, declared := range model.Dependencies.Items {
					dependency := coordinateToName[mavenCoordinate(declared.GroupID, declared.ArtifactID, declared.Version)]
					if dependency == "" {
						continue
					}
					switch declared.Scope {
					case "import":
						continue
					case "runtime":
						module.RuntimeDependenciesBySourceSet["main"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["main"], dependency)
						module.RuntimeDependenciesBySourceSet["test"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["test"], dependency)
					case "test":
						module.DependenciesBySourceSet["test"] = appendUniqueString(module.DependenciesBySourceSet["test"], dependency)
						module.RuntimeDependenciesBySourceSet["test"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["test"], dependency)
					default: // compile, provided, system, or Maven's implicit compile
						dependencies[dependency] = true
						module.DependenciesBySourceSet["main"] = appendUniqueString(module.DependenciesBySourceSet["main"], dependency)
						if declared.Scope == "" || declared.Scope == "compile" {
							module.RuntimeDependenciesBySourceSet["main"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["main"], dependency)
							module.RuntimeDependenciesBySourceSet["test"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["test"], dependency)
						} else if declared.Scope == "provided" || declared.Scope == "system" {
							module.RuntimeDependenciesBySourceSet["test"] = appendUniqueString(module.RuntimeDependenciesBySourceSet["test"], dependency)
						}
						if (declared.Scope == "" || declared.Scope == "compile") && !strings.EqualFold(declared.Optional, "true") {
							module.ExportedBySourceSet["main"] = appendUniqueString(module.ExportedBySourceSet["main"], dependency)
						}
						for _, excluded := range declared.Exclusions.Items {
							for _, excludedName := range gaToNames[strings.TrimSpace(excluded.GroupID)+"\x00"+strings.TrimSpace(excluded.ArtifactID)] {
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
	return modules, nil
}

func moduleJavaHome(directory, workspaceRoot string) string {
	for current := filepath.Clean(directory); ; current = filepath.Dir(current) {
		data, err := readModuleFile(filepath.Join(current, "gradle.properties"), 1<<20)
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

type parsedJavaModuleDescriptor struct {
	Name     string
	Requires map[string]JavaModuleRequirement
	Exports  map[string][]string
	Opens    map[string][]string
}

func javaModuleName(directory string, sourceSets map[string][]string) string {
	return javaModuleDescriptor(directory, sourceSets).Name
}

func javaModuleDescriptor(directory string, sourceSets map[string][]string) parsedJavaModuleDescriptor {
	candidates := []string{filepath.Join(directory, "module-info.java")}
	for _, roots := range sourceSets {
		for _, root := range roots {
			candidates = append(candidates, filepath.Join(root, "module-info.java"))
		}
	}
	for _, path := range uniqueSortedStrings(candidates) {
		data, err := readModuleFile(path, 4<<20)
		if err != nil {
			continue
		}
		if descriptor, ok := parseJavaModuleDescriptor(string(data)); ok {
			return descriptor
		}
	}
	return parsedJavaModuleDescriptor{}
}

var javaModuleRequiresPattern = regexp.MustCompile(`\brequires\s+((?:(?:transitive|static)\s+)*)((?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)\s*;`)
var javaModuleExportsPattern = regexp.MustCompile(`\b(exports|opens)\s+((?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*)(?:\s+to\s+([^;]+))?\s*;`)

func parseJavaModuleDescriptor(source string) (parsedJavaModuleDescriptor, bool) {
	mask := codeMask(source, false)
	clean := []byte(source)
	for index := range clean {
		if !mask[index] {
			clean[index] = ' '
		}
	}
	match := javaModuleDeclarationPattern.FindSubmatch(clean)
	if len(match) != 2 {
		return parsedJavaModuleDescriptor{}, false
	}
	descriptor := parsedJavaModuleDescriptor{Name: string(match[1]), Requires: make(map[string]JavaModuleRequirement), Exports: make(map[string][]string), Opens: make(map[string][]string)}
	requires := javaModuleRequiresPattern.FindAllSubmatch(clean, 100_001)
	if len(requires) > 100_000 {
		return parsedJavaModuleDescriptor{}, false
	}
	for _, match := range requires {
		modifiers := strings.Fields(string(match[1]))
		requirement := JavaModuleRequirement{}
		for _, modifier := range modifiers {
			requirement.Transitive = requirement.Transitive || modifier == "transitive"
			requirement.Static = requirement.Static || modifier == "static"
		}
		descriptor.Requires[string(match[2])] = requirement
	}
	exports := javaModuleExportsPattern.FindAllSubmatch(clean, 100_001)
	if len(exports) > 100_000 {
		return parsedJavaModuleDescriptor{}, false
	}
	for _, match := range exports {
		targets := []string{"*"}
		if len(match[3]) > 0 {
			targets = nil
			for _, target := range strings.Split(string(match[3]), ",") {
				if target = strings.TrimSpace(target); target != "" {
					targets = append(targets, target)
				}
			}
		}
		if string(match[1]) == "exports" {
			descriptor.Exports[string(match[2])] = targets
		} else {
			descriptor.Opens[string(match[2])] = targets
		}
	}
	return descriptor, true
}

func moduleName(root, directory string) string {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." {
		return ":"
	}
	return ":" + strings.ReplaceAll(filepath.ToSlash(relative), "/", ":")
}

func moduleSourceSets(ctx context.Context, directory string) (map[string][]string, error) {
	sets := make(map[string][]string)
	sourceDir := filepath.Join(directory, "src")
	visited := 0
	var inventoryErr error
	_ = filepath.WalkDir(sourceDir, func(path string, entry os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		visited++
		if visited > 100_000 {
			inventoryErr = fmt.Errorf("source-set discovery in %s exceeds its 100000-entry safety limit", directory)
			return filepath.SkipAll
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
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if inventoryErr != nil {
		return nil, inventoryErr
	}
	if err := addDeclaredGradleSourceSets(directory, sets); err != nil {
		return nil, err
	}
	if err := addGeneratedSourceSets(ctx, directory, sets); err != nil {
		return nil, err
	}
	if len(sets) > 512 {
		return nil, fmt.Errorf("source-set discovery in %s exceeds its 512-set safety limit", directory)
	}
	if len(sets) == 0 {
		sets["main"] = []string{directory}
	}
	for set := range sets {
		sort.Strings(sets[set])
	}
	return sets, nil
}

func addDeclaredGradleSourceSets(directory string, sets map[string][]string) error {
	for _, buildName := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := readModuleFile(filepath.Join(directory, buildName), 8<<20)
		if err != nil {
			continue
		}
		for _, pattern := range gradleDeclaredSourcePatterns {
			matches := pattern.FindAllSubmatch(data, 513)
			if len(matches) > 512 {
				return fmt.Errorf("declared Gradle source roots in %s exceed their 512-match safety limit", directory)
			}
			for _, match := range matches {
				if len(match) != 3 {
					continue
				}
				set, sourceRoot := string(match[1]), string(match[2])
				if len(set) > 4096 || len(sourceRoot) > 4096 {
					return fmt.Errorf("declared Gradle source root in %s exceeds its 4096-byte field safety limit", directory)
				}
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
	return nil
}

func addGeneratedSourceSets(ctx context.Context, directory string, sets map[string][]string) error {
	add := func(set, root string) {
		if set == "" {
			set = "main"
		}
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			sets[set] = appendUniqueString(sets[set], filepath.Clean(root))
		}
	}
	generatedRoot := filepath.Join(directory, "build", "generated")
	visited := 0
	var inventoryErr error
	knownAndroidOutput := map[string]bool{
		"data_binding_base_class_source_out": true,
		"view_binding_base_class_source_out": true,
		"not_namespaced_r_class_sources":     true,
		"namespaced_r_class_sources":         true,
		"ap_generated_sources":               true,
	}
	_ = filepath.WalkDir(generatedRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if walkErr != nil {
			return nil
		}
		visited++
		if visited > 50_000 {
			inventoryErr = fmt.Errorf("generated-source discovery in %s exceeds its 50000-entry safety limit", directory)
			return filepath.SkipAll
		}
		if !entry.IsDir() || path == generatedRoot {
			return nil
		}
		relative, err := filepath.Rel(generatedRoot, path)
		if err != nil {
			return filepath.SkipDir
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		set := ""
		switch {
		case len(parts) == 3 && parts[0] == "source":
			set = parts[2]
		case len(parts) == 4 && parts[0] == "sources":
			set = parts[3]
		case len(parts) == 3 && parts[0] == "ksp" && (parts[2] == "java" || parts[2] == "kotlin"):
			set = parts[1]
		case len(parts) == 3 && knownAndroidOutput[parts[0]]:
			set = parts[1]
		}
		if set != "" {
			add(set, path)
			return filepath.SkipDir
		}
		if len(parts) >= 4 {
			return filepath.SkipDir
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if inventoryErr != nil {
		return inventoryErr
	}
	// Android Gradle Plugin places generated Java outside the conventional
	// build/generated/source(s) trees. The variant is the directory before the
	// task-specific output directory (usually "out" or "r"). Keep these roots
	// attached to their variant so main/flavor/build-type overlay rules apply.
	add("main", filepath.Join(directory, "target", "generated-sources", "annotations"))
	add("test", filepath.Join(directory, "target", "generated-test-sources", "test-annotations"))
	return nil
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
	i.semanticEnvironmentVersion++
	i.mu.Unlock()
}

func (i *Index) mergeModuleBuildResolution(root string, resolution classpathResolution) {
	i.recordModuleBuildResolutionHealth(root, resolution)
	root, _ = filepath.Abs(root)
	i.mu.Lock()
	defer i.mu.Unlock()
	applyModuleBuildResolution(i.modules, root, resolution, i.libraryAccess)
	i.semanticEnvironmentVersion++
}

// applyModuleBuildResolution mutates a private module snapshot and its private
// access table. Keeping the transformation independent of Index publication
// lets watched build refreshes prepare a complete replacement before taking
// the foreground lock.
func applyModuleBuildResolution(modules []ModuleInfo, root string, resolution classpathResolution, libraryAccess map[string]map[string]bool) {
	root, _ = filepath.Abs(root)
	for index := range modules {
		module := &modules[index]
		if !pathWithin(module.Dir, root) {
			continue
		}
		module.BuildImporter = resolution.Importer
		module.BuildModelAuthoritative = resolution.Authoritative
		module.BuildModelSelfContained = resolution.SelfContained
		module.BuildModelFailure = resolution.Failure
		if resolution.Authoritative {
			// The importer result replaces degraded script discovery. Appending it
			// to regex-derived roots/dependencies made a module look authoritative
			// while retaining guesses the build tool had contradicted.
			module.Classpath = nil
			module.ModulePath = nil
			module.Dependencies = nil
			module.SourceRoots = nil
			module.SourceSets = make(map[string][]string)
			module.SourceSetDependsOn = make(map[string][]string)
			module.DependenciesBySourceSet = make(map[string][]string)
			module.RuntimeDependenciesBySourceSet = make(map[string][]string)
			module.ExportedBySourceSet = make(map[string][]string)
			module.DependencyExclusions = make(map[string][]string)
			module.ExternalDependencyExclusions = make(map[string][]string)
			module.ClasspathBySourceSet = make(map[string][]string)
			module.RuntimeClasspathBySourceSet = make(map[string][]string)
			module.ModulePathBySourceSet = make(map[string][]string)
			module.CompilerSettingsBySourceSet = make(map[string]CompilerSettings)
		}
		if settings := resolution.CompilerSettings[module.Name]; len(settings) > 0 {
			module.CompilerSettingsBySourceSet = make(map[string]CompilerSettings, len(settings))
			for sourceSet, value := range settings {
				value.JavaArguments = append([]string(nil), value.JavaArguments...)
				value.KotlinArguments = append([]string(nil), value.KotlinArguments...)
				module.CompilerSettingsBySourceSet[sourceSet] = value
				if value.JavaHome != "" {
					module.JavaHome = value.JavaHome
				}
			}
		}
		// A self-contained workspace has no truer model the compiler could
		// contradict; its conventional discovery is reported, not withheld.
		if !resolution.Authoritative && !resolution.SelfContained {
			reason := resolution.Failure
			if reason == "" {
				reason = "build-tool model is not authoritative"
			}
			if module.CompilerSettingsBySourceSet == nil {
				module.CompilerSettingsBySourceSet = make(map[string]CompilerSettings)
			}
			sets := make(map[string]bool)
			for sourceSet := range module.SourceSets {
				sets[sourceSet] = true
			}
			for sourceSet := range module.CompilerSettingsBySourceSet {
				sets[sourceSet] = true
			}
			if len(sets) == 0 {
				sets["main"] = true
			}
			for sourceSet := range sets {
				settings := module.CompilerSettingsBySourceSet[sourceSet]
				settings.IncompleteReason = appendIncompleteReason(settings.IncompleteReason, reason)
				module.CompilerSettingsBySourceSet[sourceSet] = settings
			}
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
		if module.RuntimeDependenciesBySourceSet == nil {
			module.RuntimeDependenciesBySourceSet = make(map[string][]string)
		}
		if module.ExportedBySourceSet == nil {
			module.ExportedBySourceSet = make(map[string][]string)
		}
		if module.DependencyExclusions == nil {
			module.DependencyExclusions = make(map[string][]string)
		}
		if module.ExternalDependencyExclusions == nil {
			module.ExternalDependencyExclusions = make(map[string][]string)
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
				if libraryAccess[key] == nil {
					libraryAccess[key] = make(map[string]bool)
				}
				libraryAccess[key][libraryAccessKey(module.Dir, sourceSet)] = true
			}
		}
		if module.RuntimeClasspathBySourceSet == nil {
			module.RuntimeClasspathBySourceSet = make(map[string][]string)
		}
		for sourceSet, values := range resolution.RuntimeSourceSetClasspath[module.Name] {
			module.RuntimeClasspathBySourceSet[sourceSet] = uniqueSortedStrings(append(module.RuntimeClasspathBySourceSet[sourceSet], values...))
		}
		if dependencies := resolution.Dependencies[module.Name]; len(dependencies) > 0 {
			module.Dependencies = uniqueSortedStrings(append(module.Dependencies, dependencies...))
		}
		for sourceSet, dependencies := range resolution.SourceSetDependencies[module.Name] {
			module.DependenciesBySourceSet[sourceSet] = uniqueSortedStrings(append(module.DependenciesBySourceSet[sourceSet], dependencies...))
		}
		for sourceSet, dependencies := range resolution.RuntimeSourceSetDependencies[module.Name] {
			module.RuntimeDependenciesBySourceSet[sourceSet] = uniqueSortedStrings(append(module.RuntimeDependenciesBySourceSet[sourceSet], dependencies...))
		}
		for sourceSet, dependencies := range resolution.SourceSetExported[module.Name] {
			module.ExportedBySourceSet[sourceSet] = uniqueSortedStrings(append(module.ExportedBySourceSet[sourceSet], dependencies...))
		}
		for key, exclusions := range resolution.DependencyExclusions[module.Name] {
			module.DependencyExclusions[key] = uniqueSortedStrings(append(module.DependencyExclusions[key], exclusions...))
		}
		for key, exclusions := range resolution.ExternalDependencyExclusions[module.Name] {
			module.ExternalDependencyExclusions[key] = uniqueSortedStrings(append(module.ExternalDependencyExclusions[key], exclusions...))
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
		if !resolution.Authoritative {
			for sourceSet, dependencies := range conventionalSourceSetDependencies(module.SourceSets) {
				module.SourceSetDependsOn[sourceSet] = uniqueSortedStrings(append(module.SourceSetDependsOn[sourceSet], dependencies...))
			}
		}
	}
}

func (i *Index) copyLibraryAccess(binary, source string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	binary = filepath.Clean(binary)
	source = filepath.Clean(source)
	i.libraryModuleAliases[source] = binary
	i.semanticEnvironmentVersion++
	access := i.libraryAccess[binary]
	if len(access) == 0 {
		return
	}
	target := make(map[string]bool, len(access))
	for module := range access {
		target[module] = true
	}
	i.libraryAccess[source] = target
	if module, exists := i.libraryModules[binary]; exists {
		i.libraryModules[source] = module
	}
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
	module, unique := moduleForURIInModules(uri, i.modules)
	if !unique {
		return nil
	}
	return module
}

// anyModuleClaimsURI reports whether at least one module's directory or
// source root contains the file, regardless of how many do.
func anyModuleClaimsURI(uri protocol.URI, modules []ModuleInfo) bool {
	path, ok := uriutil.Path(uri)
	if !ok {
		return false
	}
	path = filepath.Clean(path)
	for index := range modules {
		module := &modules[index]
		if pathWithin(path, filepath.Clean(module.Dir)) {
			return true
		}
		for _, sourceRoot := range module.SourceRoots {
			if pathWithin(path, filepath.Clean(sourceRoot)) {
				return true
			}
		}
	}
	return false
}

func moduleForURIInModules(uri protocol.URI, modules []ModuleInfo) (*ModuleInfo, bool) {
	path, ok := uriutil.Path(uri)
	if !ok {
		return nil, false
	}
	path = filepath.Clean(path)
	best, bestSpecificity, ambiguous := -1, -1, false
	for index := range modules {
		module := &modules[index]
		specificity := -1
		for _, sourceRoot := range module.SourceRoots {
			cleanRoot := filepath.Clean(sourceRoot)
			if pathWithin(path, cleanRoot) && len(cleanRoot) > specificity {
				specificity = len(cleanRoot)
			}
		}
		cleanDir := filepath.Clean(module.Dir)
		if pathWithin(path, cleanDir) && len(cleanDir) > specificity {
			specificity = len(cleanDir)
		}
		if specificity < 0 {
			continue
		}
		if specificity > bestSpecificity {
			best, bestSpecificity, ambiguous = index, specificity, false
		} else if specificity == bestSpecificity && best != index {
			ambiguous = true
		}
	}
	if best < 0 || ambiguous {
		return nil, false
	}
	return &modules[best], true
}

func (i *Index) sourceSetForURILocked(uri protocol.URI, module *ModuleInfo) string {
	set, unique := sourceSetForURIInModule(uri, module)
	if !unique {
		return ""
	}
	return set
}

func sourceSetForURIInModule(uri protocol.URI, module *ModuleInfo) (string, bool) {
	if module == nil {
		return "", false
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		return "", false
	}
	bestSet, bestLength, ambiguous := "main", -1, false
	for set, roots := range module.SourceSets {
		for _, root := range roots {
			cleanRoot := filepath.Clean(root)
			if !pathWithin(path, cleanRoot) {
				continue
			}
			if len(cleanRoot) > bestLength {
				bestSet, bestLength, ambiguous = set, len(cleanRoot), false
			} else if len(cleanRoot) == bestLength && set != bestSet {
				ambiguous = true
			}
		}
	}
	if ambiguous {
		return "", false
	}
	return bestSet, true
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
	byName := make(map[string][]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		module := &i.modules[index]
		key := module.Root + "\x00" + module.Name
		byName[key] = append(byName[key], module)
	}
	accessible, complete := moduleAccessSet(from, sourceSet, byName)
	return complete && accessible[moduleAccessIdentity(target)]
}

func moduleAccessIdentity(module *ModuleInfo) string {
	if module == nil {
		return ""
	}
	return module.Root + "\x00" + module.Name + "\x00" + filepath.Clean(module.Dir)
}

func moduleAccessSet(from *ModuleInfo, sourceSet string, byName map[string][]*ModuleInfo) (map[string]bool, bool) {
	const maxDependencyStates = 100_000
	accessible := make(map[string]bool)
	if from == nil {
		return accessible, true
	}
	type dependencyPath struct {
		name     string
		excluded map[string]bool
	}
	dependencies, dependenciesComplete := moduleDependenciesForSourceSetBounded(from, sourceSet)
	if !dependenciesComplete || len(dependencies) > maxDependencyStates {
		return accessible, false
	}
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
		if len(seen) >= maxDependencyStates {
			return accessible, false
		}
		seen[stateKey] = true
		candidates := byName[from.Root+"\x00"+path.name]
		if len(candidates) != 1 {
			// A missing or duplicate identity means the imported dependency graph
			// cannot prove a closure. Returning an incomplete result makes compiler
			// planning fall back to a clean unit instead of compiling an arbitrary
			// prefix which merely happened to have resolvable names.
			return accessible, false
		}
		candidate := candidates[0]
		accessible[moduleAccessIdentity(candidate)] = true
		// A direct dependency is always visible to its declaring module. Beyond
		// that first edge, only exported Maven compile / Gradle api edges belong
		// on a consumer's compile classpath; implementation and compileOnly do not.
		next, nextComplete := moduleExportedDependenciesForSourceSetBounded(candidate, "main")
		if !nextComplete {
			return accessible, false
		}
		for _, dependency := range next {
			if path.excluded[dependency] {
				continue
			}
			if len(queue)+len(seen) >= maxDependencyStates {
				return accessible, false
			}
			queue = append(queue, dependencyPath{name: dependency, excluded: dependencyPathExclusions(path.excluded, candidate, "main", dependency)})
		}
	}
	return accessible, true
}

func (i *Index) javaModuleCanAccessLocked(from, target *ModuleInfo, packageName string) bool {
	if from == nil || target == nil || from.JavaModuleName == "" || target.JavaModuleName == "" || from.JavaModuleName == target.JavaModuleName {
		return true
	}
	readable := target.JavaModuleName == "java.base"
	const maxJavaModuleStates = 100_000
	if len(i.modules) > maxJavaModuleStates || len(from.JavaRequires) > maxJavaModuleStates {
		return false
	}
	byJavaName := make(map[string][]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		module := &i.modules[index]
		if module.JavaModuleName != "" {
			byJavaName[module.JavaModuleName] = append(byJavaName[module.JavaModuleName], module)
		}
	}
	type readableModule struct {
		name       string
		transitive bool
	}
	queue := make([]readableModule, 0, len(from.JavaRequires))
	for name := range from.JavaRequires {
		queue = append(queue, readableModule{name: name, transitive: true})
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current.name] {
			continue
		}
		if len(seen) >= maxJavaModuleStates {
			return false
		}
		seen[current.name] = true
		if current.name == target.JavaModuleName {
			readable = true
			break
		}
		candidates := byJavaName[current.name]
		if len(candidates) != 1 || !current.transitive {
			continue
		}
		module := candidates[0]
		for name, requirement := range module.JavaRequires {
			if requirement.Transitive {
				if len(queue)+len(seen) >= maxJavaModuleStates {
					return false
				}
				queue = append(queue, readableModule{name: name, transitive: true})
			}
		}
	}
	if !readable {
		return false
	}
	targets, exported := target.JavaExports[packageName]
	if !exported {
		return false
	}
	return containsString(targets, "*") || containsString(targets, from.JavaModuleName)
}

func (i *Index) libraryJavaModuleCanAccessLocked(from *ModuleInfo, target libraryJavaModule, packageName string) bool {
	if from == nil || from.JavaModuleName == "" || target.Name == "" || from.JavaModuleName == target.Name {
		return true
	}
	const maxJavaModuleStates = 100_000
	if len(i.modules)+len(i.libraryModules) > maxJavaModuleStates || len(from.JavaRequires) > maxJavaModuleStates {
		return false
	}
	readable := target.Name == "java.base"
	sourceByName := make(map[string][]*ModuleInfo, len(i.modules))
	for moduleIndex := range i.modules {
		module := &i.modules[moduleIndex]
		if module.JavaModuleName != "" {
			sourceByName[module.JavaModuleName] = append(sourceByName[module.JavaModuleName], module)
		}
	}
	libraryByName := make(map[string][]libraryJavaModule, len(i.libraryModules))
	for _, module := range i.libraryModules {
		if module.Name != "" {
			libraryByName[module.Name] = append(libraryByName[module.Name], module)
		}
	}
	queue := make([]string, 0, len(from.JavaRequires))
	for name := range from.JavaRequires {
		queue = append(queue, name)
	}
	seen := make(map[string]bool)
	for len(queue) > 0 && !readable {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		if len(seen) >= maxJavaModuleStates {
			return false
		}
		seen[name] = true
		if name == target.Name {
			readable = true
			break
		}
		if candidates := sourceByName[name]; len(candidates) == 1 && len(libraryByName[name]) == 0 {
			module := candidates[0]
			for dependency, requirement := range module.JavaRequires {
				if requirement.Transitive {
					if len(queue)+len(seen) >= maxJavaModuleStates {
						return false
					}
					queue = append(queue, dependency)
				}
			}
		}
		if candidates := libraryByName[name]; len(candidates) == 1 && len(sourceByName[name]) == 0 {
			module := candidates[0]
			for dependency, requirement := range module.Requires {
				if requirement.Transitive {
					if len(queue)+len(seen) >= maxJavaModuleStates {
						return false
					}
					queue = append(queue, dependency)
				}
			}
		}
	}
	if !readable {
		return false
	}
	if target.Automatic {
		return true
	}
	targets, exported := target.Exports[packageName]
	return exported && (containsString(targets, "*") || containsString(targets, from.JavaModuleName))
}

// javaReadableSetLocked computes JPMS readability once for a foreground
// query. Package exports remain target-local O(1) checks; they must not cause a
// fresh graph traversal for each candidate symbol.
func (i *Index) javaReadableSetLocked(from *ModuleInfo) (map[string]bool, bool) {
	const maxJavaModuleStates = 100_000
	readable := map[string]bool{"java.base": true}
	if from == nil || from.JavaModuleName == "" {
		return readable, true
	}
	if len(i.modules)+len(i.libraryModules) > maxJavaModuleStates || len(from.JavaRequires) > maxJavaModuleStates {
		return nil, false
	}
	sourceByName := make(map[string][]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		module := &i.modules[index]
		if module.JavaModuleName != "" {
			sourceByName[module.JavaModuleName] = append(sourceByName[module.JavaModuleName], module)
		}
	}
	libraryByName := make(map[string][]libraryJavaModule, len(i.libraryModules))
	for _, module := range i.libraryModules {
		if module.Name != "" {
			libraryByName[module.Name] = append(libraryByName[module.Name], module)
		}
	}
	queue := make([]string, 0, len(from.JavaRequires))
	for name := range from.JavaRequires {
		queue = append(queue, name)
	}
	seen := make(map[string]bool)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		if len(seen) >= maxJavaModuleStates {
			return nil, false
		}
		seen[name], readable[name] = true, true
		if candidates := sourceByName[name]; len(candidates) == 1 && len(libraryByName[name]) == 0 {
			for dependency, requirement := range candidates[0].JavaRequires {
				if requirement.Transitive {
					if len(queue)+len(seen) >= maxJavaModuleStates {
						return nil, false
					}
					queue = append(queue, dependency)
				}
			}
		}
		if candidates := libraryByName[name]; len(candidates) == 1 && len(sourceByName[name]) == 0 {
			for dependency, requirement := range candidates[0].Requires {
				if requirement.Transitive {
					if len(queue)+len(seen) >= maxJavaModuleStates {
						return nil, false
					}
					queue = append(queue, dependency)
				}
			}
		}
	}
	return readable, true
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
		if len(seen) >= 100_000 {
			return -1
		}
		seen[current.name] = true
		for _, dependency := range sourceSetDependencies(module, current.name) {
			if len(queue)+len(seen) >= 100_000 {
				return -1
			}
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
	if len(dependencies) == 0 && !module.BuildModelAuthoritative {
		dependencies = append(dependencies, conventionalSourceSetDependencies(module.SourceSets)[sourceSet]...)
	}
	return uniqueSortedStrings(dependencies)
}

func moduleDependenciesForSourceSet(module *ModuleInfo, sourceSet string) []string {
	dependencies, _ := moduleDependenciesForSourceSetBounded(module, sourceSet)
	return dependencies
}

func moduleDependenciesForSourceSetBounded(module *ModuleInfo, sourceSet string) ([]string, bool) {
	if module == nil {
		return nil, true
	}
	if len(module.DependenciesBySourceSet) == 0 {
		if len(module.Dependencies) > 100_000 {
			return nil, false
		}
		return module.Dependencies, true
	}
	closure, complete := sourceSetDependencyClosureBounded(module, sourceSet)
	if !complete {
		return nil, false
	}
	sets := append([]string{sourceSet}, closure...)
	if sourceSet != "main" {
		sets = append(sets, "main")
	}
	var dependencies []string
	for _, dependencySet := range uniqueSortedStrings(sets) {
		if len(module.DependenciesBySourceSet[dependencySet]) > 100_000-len(dependencies) {
			return nil, false
		}
		dependencies = append(dependencies, module.DependenciesBySourceSet[dependencySet]...)
	}
	return uniqueSortedStrings(dependencies), true
}

func moduleExportedDependenciesForSourceSet(module *ModuleInfo, sourceSet string) []string {
	dependencies, _ := moduleExportedDependenciesForSourceSetBounded(module, sourceSet)
	return dependencies
}

func moduleExportedDependenciesForSourceSetBounded(module *ModuleInfo, sourceSet string) ([]string, bool) {
	if module == nil {
		return nil, true
	}
	// Manually constructed/legacy models predate edge visibility. Preserve
	// their established transitive behavior; discovered build models always
	// initialize ExportedBySourceSet, including an intentionally empty map.
	if module.ExportedBySourceSet == nil {
		return moduleDependenciesForSourceSetBounded(module, sourceSet)
	}
	closure, complete := sourceSetDependencyClosureBounded(module, sourceSet)
	if !complete {
		return nil, false
	}
	sets := append([]string{sourceSet}, closure...)
	if sourceSet != "main" {
		sets = append(sets, "main")
	}
	var dependencies []string
	for _, dependencySet := range uniqueSortedStrings(sets) {
		if len(module.ExportedBySourceSet[dependencySet]) > 100_000-len(dependencies) {
			return nil, false
		}
		dependencies = append(dependencies, module.ExportedBySourceSet[dependencySet]...)
	}
	return uniqueSortedStrings(dependencies), true
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

// Modules returns a deep snapshot of the canonical imported module/source-set
// graph for workspace export and diagnostics. Callers cannot mutate index
// state through any of the nested slices or maps.
func (i *Index) Modules() []ModuleInfo {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]ModuleInfo, len(i.modules))
	for position, module := range i.modules {
		out[position] = cloneModuleInfo(module)
	}
	return out
}

func cloneModuleInfo(module ModuleInfo) ModuleInfo {
	cloneStrings := func(values []string) []string { return append([]string(nil), values...) }
	cloneMap := func(values map[string][]string) map[string][]string {
		if values == nil {
			return nil
		}
		result := make(map[string][]string, len(values))
		for key, items := range values {
			result[key] = cloneStrings(items)
		}
		return result
	}
	module.SourceRoots = cloneStrings(module.SourceRoots)
	module.SourceSets = cloneMap(module.SourceSets)
	module.Classpath = cloneStrings(module.Classpath)
	module.ClasspathBySourceSet = cloneMap(module.ClasspathBySourceSet)
	module.RuntimeClasspathBySourceSet = cloneMap(module.RuntimeClasspathBySourceSet)
	module.ModulePath = cloneStrings(module.ModulePath)
	module.ModulePathBySourceSet = cloneMap(module.ModulePathBySourceSet)
	module.JavaExports = cloneMap(module.JavaExports)
	module.JavaOpens = cloneMap(module.JavaOpens)
	if module.JavaRequires != nil {
		requires := make(map[string]JavaModuleRequirement, len(module.JavaRequires))
		for name, requirement := range module.JavaRequires {
			requires[name] = requirement
		}
		module.JavaRequires = requires
	}
	module.Dependencies = cloneStrings(module.Dependencies)
	module.DependenciesBySourceSet = cloneMap(module.DependenciesBySourceSet)
	module.RuntimeDependenciesBySourceSet = cloneMap(module.RuntimeDependenciesBySourceSet)
	module.ExportedBySourceSet = cloneMap(module.ExportedBySourceSet)
	module.DependencyExclusions = cloneMap(module.DependencyExclusions)
	module.ExternalDependencyExclusions = cloneMap(module.ExternalDependencyExclusions)
	module.SourceSetDependsOn = cloneMap(module.SourceSetDependsOn)
	if module.CompilerSettingsBySourceSet != nil {
		settings := make(map[string]CompilerSettings, len(module.CompilerSettingsBySourceSet))
		for sourceSet, value := range module.CompilerSettingsBySourceSet {
			value.JavaArguments = cloneStrings(value.JavaArguments)
			value.KotlinArguments = cloneStrings(value.KotlinArguments)
			settings[sourceSet] = value
		}
		module.CompilerSettingsBySourceSet = settings
	}
	return module
}

func (i *Index) BuildModels() []BuildModelStatus {
	i.mu.RLock()
	defer i.mu.RUnlock()
	models := make([]BuildModelStatus, 0, len(i.modules))
	for _, module := range i.modules {
		models = append(models, BuildModelStatus{
			Module: module.Name, Directory: module.Dir, Importer: module.BuildImporter,
			Authoritative: module.BuildModelAuthoritative, Failure: module.BuildModelFailure,
			CompilerSettings: cloneModuleInfo(module).CompilerSettingsBySourceSet,
		})
	}
	return models
}

func (i *Index) ClasspathFor(uri protocol.URI) (classpath, modulePath []string, moduleName any) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	module := i.moduleForURILocked(uri)
	return classpathForModuleSnapshot(uri, module, i.modules, i.classpath)
}

// classpathForModuleSnapshot derives a compiler path exclusively from one
// immutable module-model snapshot. This keeps background compiler assembly
// from combining a module selected from one generation with dependencies from
// a later generation.
func classpathForModuleSnapshot(uri protocol.URI, module *ModuleInfo, modules []ModuleInfo, fallbackClasspath []string) (classpath, modulePath []string, moduleName any) {
	if module == nil {
		return append([]string(nil), fallbackClasspath...), []string{}, nil
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
	sourceSet := "main"
	if path, ok := uriutil.Path(uri); ok {
		bestLength := -1
		for set, roots := range module.SourceSets {
			for _, root := range roots {
				if pathWithin(path, root) && len(root) > bestLength {
					sourceSet, bestLength = set, len(root)
				}
			}
		}
	}
	setClasspath := module.ClasspathBySourceSet[sourceSet]
	appendPaths(setClasspath)
	setModulePath := module.ModulePathBySourceSet[sourceSet]
	appendModulePaths(setModulePath)
	dependencySets, dependencySetsComplete := sourceSetDependencyClosureBounded(module, sourceSet)
	if !dependencySetsComplete {
		return nil, nil, nil
	}
	for _, dependencySet := range dependencySets {
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
		appendPaths(fallbackClasspath)
	}
	byName := make(map[string][]*ModuleInfo, len(modules))
	for index := range modules {
		candidate := &modules[index]
		key := candidate.Root + "\x00" + candidate.Name
		byName[key] = append(byName[key], candidate)
	}
	dependencies, dependenciesComplete := moduleDependenciesForSourceSetBounded(module, sourceSet)
	if !dependenciesComplete {
		return nil, nil, nil
	}
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
		if len(visited) >= 100_000 {
			return nil, nil, nil
		}
		visited[key] = true
		candidates := byName[module.Root+"\x00"+entry.name]
		// Ambiguous same-name modules are not guessed: the authoritative
		// importer must disambiguate them before their outputs are usable.
		if len(candidates) != 1 {
			continue
		}
		candidate := candidates[0]
		outputs := conventionalOutputDirectoriesForSourceSet(candidate.Dir, entry.sourceSet)
		if module.JavaModuleName != "" && candidate.JavaModuleName != "" && candidate.Dir != module.Dir {
			appendModulePaths(outputs)
		} else {
			appendPaths(outputs)
		}
		next, nextComplete := moduleDependenciesForSourceSetBounded(candidate, entry.sourceSet)
		if !nextComplete {
			return nil, nil, nil
		}
		for _, dependency := range next {
			if len(queue)+len(visited) >= 100_000 {
				return nil, nil, nil
			}
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

// RuntimeClasspathFor returns the runtime classpath entries for the module
// owning uri: the compile classpath misses runtimeOnly dependencies (the JDBC
// driver being the classic example), which makes it wrong for launching a
// debuggee. Compile entries remain the authority for analysis; this is only
// for run/debug.
func (i *Index) RuntimeClasspathFor(uri protocol.URI) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	module := i.moduleForURILocked(uri)
	if module == nil {
		return nil
	}
	sourceSet := i.sourceSetForURILocked(uri, module)
	byName := make(map[string][]*ModuleInfo, len(i.modules))
	for index := range i.modules {
		candidate := &i.modules[index]
		byName[candidate.Root+"\x00"+candidate.Name] = append(byName[candidate.Root+"\x00"+candidate.Name], candidate)
	}
	type runtimePath struct {
		name      string
		sourceSet string
		excluded  map[string]bool
	}
	queue := []runtimePath{{name: module.Name, sourceSet: sourceSet}}
	seen := make(map[string]bool)
	var out []string
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		state := path.name + "\x00" + path.sourceSet + "\x00" + exclusionSetKey(path.excluded)
		if seen[state] {
			continue
		}
		if len(seen) >= 100_000 || len(queue) > 100_000 {
			return nil
		}
		seen[state] = true
		candidates := byName[module.Root+"\x00"+path.name]
		if len(candidates) != 1 {
			return nil
		}
		current := candidates[0]
		sets, complete := sourceSetDependencyClosureBounded(current, path.sourceSet)
		if !complete {
			return nil
		}
		sets = append(sets, path.sourceSet)
		if path.sourceSet != "main" {
			sets = append(sets, "main")
		}
		for _, set := range uniqueSortedStrings(sets) {
			out = append(out, current.RuntimeClasspathBySourceSet[set]...)
		}
		out = append(out, conventionalOutputDirectoriesForSourceSet(current.Dir, path.sourceSet)...)
		dependencies, complete := runtimeModuleDependenciesForSourceSetBounded(current, path.sourceSet)
		if !complete {
			return nil
		}
		for _, dependency := range dependencies {
			if path.excluded[dependency] {
				continue
			}
			if len(queue)+len(seen) >= 100_000 {
				return nil
			}
			queue = append(queue, runtimePath{name: dependency, sourceSet: "main", excluded: dependencyPathExclusions(path.excluded, current, path.sourceSet, dependency)})
		}
	}
	return uniqueSortedStrings(out)
}

func runtimeModuleDependenciesForSourceSetBounded(module *ModuleInfo, sourceSet string) ([]string, bool) {
	if module == nil {
		return nil, true
	}
	if module.RuntimeDependenciesBySourceSet == nil {
		return moduleDependenciesForSourceSetBounded(module, sourceSet)
	}
	sets, complete := sourceSetDependencyClosureBounded(module, sourceSet)
	if !complete {
		return nil, false
	}
	sets = append(sets, sourceSet)
	if sourceSet != "main" {
		sets = append(sets, "main")
	}
	var dependencies []string
	for _, set := range uniqueSortedStrings(sets) {
		values := module.RuntimeDependenciesBySourceSet[set]
		if len(values) > 100_000-len(dependencies) {
			return nil, false
		}
		dependencies = append(dependencies, values...)
	}
	return uniqueSortedStrings(dependencies), true
}

func sourceSetDependencyClosure(module *ModuleInfo, sourceSet string) []string {
	closure, _ := sourceSetDependencyClosureBounded(module, sourceSet)
	return closure
}

func sourceSetDependencyClosureBounded(module *ModuleInfo, sourceSet string) ([]string, bool) {
	queue := append([]string(nil), sourceSetDependencies(module, sourceSet)...)
	if len(queue) > 100_000 {
		return nil, false
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(queue))
	for len(queue) > 0 {
		set := queue[0]
		queue = queue[1:]
		if seen[set] {
			continue
		}
		if len(seen) >= 100_000 {
			return nil, false
		}
		seen[set] = true
		result = append(result, set)
		next := sourceSetDependencies(module, set)
		if len(queue)+len(seen)+len(next) > 100_000 {
			return nil, false
		}
		queue = append(queue, next...)
	}
	return result, true
}
