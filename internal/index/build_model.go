package index

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func resolveClasspath(ctx context.Context, root string) []string {
	return resolveClasspathModel(ctx, root).Classpath
}

type classpathResolution struct {
	Classpath             []string
	ModuleClasspath       map[string][]string
	Dependencies          map[string][]string
	SourceSetClasspath    map[string]map[string][]string
	SourceSetDependencies map[string]map[string][]string
	SourceSetExported     map[string]map[string][]string
	SourceSetDependsOn    map[string]map[string][]string
	SourceSetRoots        map[string]map[string][]string
}

const buildModelCacheVersion = 4

type cachedBuildModel struct {
	Version     int
	Fingerprint [sha256.Size]byte
	Resolution  classpathResolution
}

var modularPathCache sync.Map

func isModularPath(path string) bool {
	path = filepath.Clean(path)
	if cached, ok := modularPathCache.Load(path); ok {
		return cached.(bool)
	}
	modular := false
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			for _, name := range []string{"module-info.class", "module-info.java"} {
				if _, statErr := os.Stat(filepath.Join(path, name)); statErr == nil {
					modular = true
					break
				}
			}
		} else if strings.HasSuffix(strings.ToLower(path), ".jar") {
			if archive, openErr := zip.OpenReader(path); openErr == nil {
				for _, file := range archive.File {
					name := filepath.ToSlash(file.Name)
					if name == "module-info.class" || strings.HasPrefix(name, "META-INF/versions/") && strings.HasSuffix(name, "/module-info.class") {
						modular = true
						break
					}
					if strings.EqualFold(name, "META-INF/MANIFEST.MF") {
						reader, readErr := file.Open()
						if readErr == nil {
							manifest, _ := io.ReadAll(reader)
							_ = reader.Close()
							for _, line := range strings.Split(strings.ReplaceAll(string(manifest), "\r\n ", ""), "\n") {
								if strings.HasPrefix(strings.ToLower(line), "automatic-module-name:") && strings.TrimSpace(strings.TrimPrefix(line, line[:strings.IndexByte(line, ':')+1])) != "" {
									modular = true
									break
								}
							}
						}
					}
				}
				_ = archive.Close()
			}
		}
	}
	modularPathCache.Store(path, modular)
	return modular
}

func newClasspathResolution() classpathResolution {
	return classpathResolution{
		ModuleClasspath:       make(map[string][]string),
		Dependencies:          make(map[string][]string),
		SourceSetClasspath:    make(map[string]map[string][]string),
		SourceSetDependencies: make(map[string]map[string][]string),
		SourceSetExported:     make(map[string]map[string][]string),
		SourceSetDependsOn:    make(map[string]map[string][]string),
		SourceSetRoots:        make(map[string]map[string][]string),
	}
}

func resolveClasspathModel(ctx context.Context, root string) classpathResolution {
	fingerprint := buildModelFingerprint(root)
	if cached, ok := loadBuildModelCache(root, fingerprint); ok {
		cached.Classpath = uniqueSortedStrings(append(cached.Classpath, conventionalOutputDirectories(root)...))
		return cached
	}
	resolution := newClasspathResolution()
	paths := make([]string, 0)
	resolvedByBuildTool := false
	if gradle := gradleLauncher(root); gradle != "" {
		gradleResolution := gradleClasspathModel(ctx, root, gradle)
		paths = append(paths, gradleResolution.Classpath...)
		resolvedByBuildTool = len(gradleResolution.Classpath) > 0
		resolution.ModuleClasspath = gradleResolution.ModuleClasspath
		resolution.Dependencies = gradleResolution.Dependencies
		resolution.SourceSetClasspath = gradleResolution.SourceSetClasspath
		resolution.SourceSetDependencies = gradleResolution.SourceSetDependencies
		resolution.SourceSetExported = gradleResolution.SourceSetExported
		resolution.SourceSetDependsOn = gradleResolution.SourceSetDependsOn
		resolution.SourceSetRoots = gradleResolution.SourceSetRoots
	}
	if len(paths) == 0 {
		if maven := mavenLauncher(root); maven != "" {
			for _, module := range discoverModules([]string{root}) {
				if _, err := os.Stat(filepath.Join(module.Dir, "pom.xml")); err != nil {
					continue
				}
				mainPaths := mavenClasspathForScope(ctx, module.Dir, maven, "compile")
				testPaths := mavenClasspathForScope(ctx, module.Dir, maven, "test")
				modulePaths := uniqueSortedStrings(append(append([]string(nil), mainPaths...), testPaths...))
				resolution.ModuleClasspath[module.Name] = uniqueSortedStrings(append(resolution.ModuleClasspath[module.Name], modulePaths...))
				if resolution.SourceSetClasspath[module.Name] == nil {
					resolution.SourceSetClasspath[module.Name] = make(map[string][]string)
				}
				resolution.SourceSetClasspath[module.Name]["main"] = mainPaths
				resolution.SourceSetClasspath[module.Name]["test"] = testPaths
				paths = append(paths, modulePaths...)
				if len(modulePaths) > 0 {
					resolvedByBuildTool = true
				}
			}
			if len(paths) == 0 {
				paths = append(paths, mavenClasspath(ctx, root, maven)...)
				resolvedByBuildTool = len(paths) > 0
			}
		}
	}
	if len(paths) == 0 {
		paths = append(paths, directJarReferences(root)...)
	}
	paths = append(paths, conventionalOutputDirectories(root)...)
	sort.Strings(paths)
	out := paths[:0]
	for _, path := range paths {
		if len(out) == 0 || out[len(out)-1] != path {
			out = append(out, path)
		}
	}
	resolution.Classpath = out
	// Never turn a transient Gradle/Maven failure into a persistent model that
	// contains only wrapper JARs or stale output directories.
	if len(out) > 0 && resolvedByBuildTool {
		_ = saveBuildModelCache(root, fingerprint, resolution)
	}
	return resolution
}

func buildModelFingerprint(root string) [sha256.Size]byte {
	hash := sha256.New()
	root, _ = filepath.Abs(root)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != root && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(entry.Name())
		buildInput := name == "build.gradle" || name == "build.gradle.kts" || name == "settings.gradle" || name == "settings.gradle.kts" || name == "pom.xml" || name == "gradle.properties" || name == "libs.versions.toml" || name == "gradle-wrapper.properties"
		lowerPath := strings.ToLower(path)
		libraryInput := strings.HasSuffix(name, ".jar") && !strings.HasSuffix(name, "-sources.jar") && !strings.HasSuffix(name, "-javadoc.jar") && !strings.Contains(lowerPath, string(filepath.Separator)+"build"+string(filepath.Separator))
		if !buildInput && !libraryInput {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write([]byte{0})
		if buildInput {
			if data, readErr := os.ReadFile(path); readErr == nil {
				_, _ = hash.Write(data)
			}
		} else if info, statErr := entry.Info(); statErr == nil {
			_, _ = io.WriteString(hash, itoa64(info.Size()))
			_, _ = io.WriteString(hash, info.ModTime().UTC().Format(time.RFC3339Nano))
		}
		_, _ = hash.Write([]byte{0})
		return nil
	})
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hash.Sum(nil))
	return fingerprint
}

func buildModelCachePath(root string) (string, bool) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(filepath.Clean(absolute)))
	dir := filepath.Join(cacheRoot, "kotlsp", "build-model")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	return filepath.Join(dir, hex.EncodeToString(sum[:16])+".gob"), true
}

func loadBuildModelCache(root string, fingerprint [sha256.Size]byte) (classpathResolution, bool) {
	path, ok := buildModelCachePath(root)
	if !ok {
		return classpathResolution{}, false
	}
	file, err := os.Open(path)
	if err != nil {
		return classpathResolution{}, false
	}
	defer file.Close()
	var cached cachedBuildModel
	if err := gob.NewDecoder(file).Decode(&cached); err != nil || cached.Version != buildModelCacheVersion || cached.Fingerprint != fingerprint {
		return classpathResolution{}, false
	}
	for _, path := range cached.Resolution.Classpath {
		if _, err := os.Stat(path); err != nil {
			return classpathResolution{}, false
		}
	}
	return cached.Resolution, true
}

func saveBuildModelCache(root string, fingerprint [sha256.Size]byte, resolution classpathResolution) error {
	path, ok := buildModelCachePath(root)
	if !ok {
		return os.ErrInvalid
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".build-model-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	_ = tmp.Chmod(0o600)
	if err := gob.NewEncoder(tmp).Encode(cachedBuildModel{Version: buildModelCacheVersion, Fingerprint: fingerprint, Resolution: resolution}); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func gradleLauncher(root string) string {
	for _, name := range []string{"gradlew", "gradlew.bat"} {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath("gradle")
	return path
}

func gradleClasspath(parent context.Context, root, gradle string) []string {
	return gradleClasspathModel(parent, root, gradle).Classpath
}

func gradleClasspathModel(parent context.Context, root, gradle string) classpathResolution {
	resolution := newClasspathResolution()
	tmp, err := os.CreateTemp("", "kotlsp-*.init.gradle")
	if err != nil {
		return resolution
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = io.Copy(tmp, bytes.NewBufferString(gradleInitScript)); err != nil {
		_ = tmp.Close()
		return resolution
	}
	_ = tmp.Close()
	cmd := exec.CommandContext(parent, gradle, "--quiet", "--no-daemon", "--init-script", name, "kotlspClasspath")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GRADLE_OPTS=-Dorg.gradle.daemon=false")
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "kotlsp: Gradle classpath resolution failed in %s: %v: %s\n", root, err, strings.TrimSpace(string(exit.Stderr)))
		} else {
			fmt.Fprintf(os.Stderr, "kotlsp: Gradle classpath resolution failed in %s: %v\n", root, err)
		}
		return resolution
	}
	var paths []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "KOTLSP_CLASSPATH="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if absolute, err := filepath.Abs(parts[2]); err == nil {
					paths = append(paths, absolute)
					resolution.ModuleClasspath[parts[0]] = append(resolution.ModuleClasspath[parts[0]], absolute)
					if resolution.SourceSetClasspath[parts[0]] == nil {
						resolution.SourceSetClasspath[parts[0]] = make(map[string][]string)
					}
					set := sourceSetFromConfiguration(parts[1])
					resolution.SourceSetClasspath[parts[0]][set] = append(resolution.SourceSetClasspath[parts[0]][set], absolute)
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				resolution.Dependencies[parts[0]] = appendUniqueString(resolution.Dependencies[parts[0]], parts[2])
				set, compileVisible, exported := gradleDependencyConfiguration(parts[1])
				if !compileVisible {
					continue
				}
				if resolution.SourceSetDependencies[parts[0]] == nil {
					resolution.SourceSetDependencies[parts[0]] = make(map[string][]string)
				}
				resolution.SourceSetDependencies[parts[0]][set] = appendUniqueString(resolution.SourceSetDependencies[parts[0]][set], parts[2])
				if exported {
					if resolution.SourceSetExported[parts[0]] == nil {
						resolution.SourceSetExported[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetExported[parts[0]][set] = appendUniqueString(resolution.SourceSetExported[parts[0]][set], parts[2])
				}
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCESET_DEPENDENCY="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				if resolution.SourceSetDependsOn[parts[0]] == nil {
					resolution.SourceSetDependsOn[parts[0]] = make(map[string][]string)
				}
				resolution.SourceSetDependsOn[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetDependsOn[parts[0]][parts[1]], parts[2])
			}
		}
		if value, ok := strings.CutPrefix(line, "KOTLSP_SOURCE_ROOT="); ok {
			parts := strings.SplitN(value, "\t", 3)
			if len(parts) == 3 {
				absolute, absoluteErr := filepath.Abs(parts[2])
				if absoluteErr == nil {
					if resolution.SourceSetRoots[parts[0]] == nil {
						resolution.SourceSetRoots[parts[0]] = make(map[string][]string)
					}
					resolution.SourceSetRoots[parts[0]][parts[1]] = appendUniqueString(resolution.SourceSetRoots[parts[0]][parts[1]], absolute)
				}
			}
		}
	}
	resolution.Classpath = paths
	return resolution
}

func gradleDependencyConfiguration(configuration string) (sourceSet string, compileVisible, exported bool) {
	lower := strings.ToLower(configuration)
	for _, suffix := range []string{"runtimeonly", "runtime", "developmentonly"} {
		if strings.HasSuffix(lower, suffix) {
			set := configuration[:len(configuration)-len(suffix)]
			if set == "" {
				set = "main"
			}
			return set, false, false
		}
	}
	for _, suffix := range []struct {
		name     string
		exported bool
	}{
		{"implementation", false}, {"compileonly", false}, {"api", true}, {"compile", true},
	} {
		if strings.HasSuffix(lower, suffix.name) {
			set := configuration[:len(configuration)-len(suffix.name)]
			if set == "" {
				set = "main"
			}
			return set, true, suffix.exported
		}
	}
	return "main", false, false
}

func mavenLauncher(root string) string {
	for _, name := range []string{"mvnw", "mvnw.cmd"} {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath("mvn")
	return path
}

func mavenClasspath(parent context.Context, root, maven string) []string {
	return mavenClasspathForScope(parent, root, maven, "test")
}

func mavenClasspathForScope(parent context.Context, root, maven, scope string) []string {
	tmp, err := os.CreateTemp("", "kotlsp-maven-classpath-*.txt")
	if err != nil {
		return nil
	}
	name := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(name)
	cmd := exec.CommandContext(parent, maven, "-q", "dependency:build-classpath", "-Dmdep.includeScope="+scope, "-Dmdep.outputAbsoluteArtifactFilename=true", "-Dmdep.outputFile="+name)
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		return nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil
	}
	var paths []string
	for _, path := range filepath.SplitList(strings.TrimSpace(string(data))) {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func conventionalOutputDirectories(root string) []string {
	candidates := []string{
		"build/classes/java/main", "build/classes/java/test",
		"build/classes/kotlin/main", "build/classes/kotlin/test",
		"build/resources/main", "build/resources/test",
		"target/classes", "target/test-classes", "out/production", "out/test",
	}
	paths := make([]string, 0, len(candidates))
	for _, relative := range candidates {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			paths = append(paths, path)
		}
	}
	return paths
}

func conventionalOutputDirectoriesForSourceSet(root, sourceSet string) []string {
	if sourceSet == "" {
		sourceSet = "main"
	}
	candidates := []string{
		filepath.Join("build", "classes", "java", sourceSet),
		filepath.Join("build", "classes", "kotlin", sourceSet),
		filepath.Join("build", "resources", sourceSet),
	}
	if sourceSet == "main" {
		candidates = append(candidates, "target/classes", "out/production")
	}
	if sourceSet == "test" {
		candidates = append(candidates, "target/test-classes", "target/classes", "out/test", "out/production")
	}
	var paths []string
	for _, relative := range candidates {
		path := filepath.Join(root, relative)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			paths = append(paths, path)
		}
	}
	return uniqueSortedStrings(paths)
}

func directJarReferences(root string) []string {
	var paths []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != root && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, "-sources.jar") && !strings.HasSuffix(lower, "-javadoc.jar") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

func sourceJarsFor(binary string) []string {
	if strings.HasSuffix(binary, "-sources.jar") {
		return []string{binary}
	}
	versionDir := filepath.Dir(filepath.Dir(binary))
	var sources []string
	_ = filepath.WalkDir(versionDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), "-sources.jar") {
			sources = append(sources, path)
		}
		return nil
	})
	return sources
}

func jdkSources() string {
	return jdkSourcesForHome("")
}

func jdkSourcesForHome(configuredHome string) string {
	candidates := make([]string, 0, 5)
	if configuredHome != "" {
		candidates = append(candidates, filepath.Join(configuredHome, "lib", "src.zip"), filepath.Join(configuredHome, "src.zip"))
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
		return ""
	}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, "lib", "src.zip"))
	}
	if java, err := exec.LookPath("java"); err == nil {
		if real, err := filepath.EvalSymlinks(java); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Dir(real)), "lib", "src.zip"))
		}
	}
	candidates = append(candidates, "/usr/lib/jvm/default/lib/src.zip", "/usr/lib/jvm/java-21-openjdk/lib/src.zip")
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func jdkBinaryArchives(configuredHome string) []sourceArchive {
	home := configuredHome
	if home == "" {
		home = os.Getenv("JAVA_HOME")
	}
	if home == "" {
		if java, err := exec.LookPath("java"); err == nil {
			if resolved, resolveErr := filepath.EvalSymlinks(java); resolveErr == nil {
				home = filepath.Dir(filepath.Dir(resolved))
			}
		}
	}
	if home == "" {
		return nil
	}
	paths, _ := filepath.Glob(filepath.Join(home, "jmods", "*.jmod"))
	sort.Strings(paths)
	release := javaHomeRelease(home)
	archives := make([]sourceArchive, 0, len(paths))
	for _, path := range paths {
		module := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		archive := sourceArchive{path: path, jdk: true, binary: true, module: module, release: release}
		if module == "java.base" {
			archives = append([]sourceArchive{archive}, archives...)
		} else {
			archives = append(archives, archive)
		}
	}
	return archives
}

func sourceEntry(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "/module-info.java") || strings.HasSuffix(lower, "/package-info.java") {
		return false
	}
	return strings.HasSuffix(lower, ".java") || strings.HasSuffix(lower, ".kt") || strings.HasSuffix(lower, ".kts")
}

func archiveAccepts(archive sourceArchive, file *zip.File) bool {
	if archive.binary {
		name := strings.ToLower(file.Name)
		return strings.HasSuffix(name, ".class") && !strings.HasSuffix(name, "module-info.class")
	}
	return sourceEntry(file.Name)
}

func selectedArchiveFiles(archive sourceArchive, files []*zip.File) []*zip.File {
	if !archive.binary {
		selected := make([]*zip.File, 0, len(files))
		for _, file := range files {
			if archiveAccepts(archive, file) {
				selected = append(selected, file)
			}
		}
		return selected
	}
	multiRelease := false
	for _, file := range files {
		if strings.EqualFold(filepath.ToSlash(file.Name), "META-INF/MANIFEST.MF") {
			reader, err := file.Open()
			if err != nil {
				break
			}
			manifest, readErr := io.ReadAll(reader)
			_ = reader.Close()
			if readErr == nil {
				unfolded := strings.ReplaceAll(strings.ReplaceAll(string(manifest), "\r\n ", ""), "\n ", "")
				for _, line := range strings.Split(unfolded, "\n") {
					name, value, found := strings.Cut(line, ":")
					if found && strings.EqualFold(strings.TrimSpace(name), "Multi-Release") && strings.EqualFold(strings.TrimSpace(value), "true") {
						multiRelease = true
						break
					}
				}
			}
			break
		}
	}
	type choice struct {
		version int
		file    *zip.File
	}
	choices := make(map[string]choice)
	for _, file := range files {
		if !archiveAccepts(archive, file) {
			continue
		}
		name := filepath.ToSlash(file.Name)
		logical, version := name, 0
		if strings.HasPrefix(strings.ToLower(name), "meta-inf/versions/") {
			if !multiRelease {
				continue
			}
			remainder := name[len("META-INF/versions/"):]
			slash := strings.IndexByte(remainder, '/')
			if slash <= 0 {
				continue
			}
			parsed, err := strconv.Atoi(remainder[:slash])
			if err != nil || parsed > archive.release {
				continue
			}
			version, logical = parsed, remainder[slash+1:]
		}
		if previous, ok := choices[logical]; !ok || version > previous.version {
			choices[logical] = choice{version: version, file: file}
		}
	}
	names := make([]string, 0, len(choices))
	for name := range choices {
		names = append(names, name)
	}
	sort.Strings(names)
	selected := make([]*zip.File, 0, len(names))
	for _, name := range names {
		selected = append(selected, choices[name].file)
	}
	return selected
}

var defaultJavaReleaseCache struct {
	sync.Once
	value int
}

func defaultJavaRelease() int {
	defaultJavaReleaseCache.Do(func() {
		if executable, err := exec.LookPath("java"); err == nil {
			if executable, err = filepath.EvalSymlinks(executable); err == nil {
				defaultJavaReleaseCache.value = javaHomeRelease(filepath.Dir(filepath.Dir(executable)))
			}
		}
		if defaultJavaReleaseCache.value == 0 {
			defaultJavaReleaseCache.value = 8
		}
	})
	return defaultJavaReleaseCache.value
}

func javaHomeRelease(home string) int {
	if home == "" {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(home, "release"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "JAVA_VERSION" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		majorText := value
		if strings.HasPrefix(value, "1.") {
			majorText = strings.TrimPrefix(value, "1.")
		}
		if dot := strings.IndexByte(majorText, '.'); dot >= 0 {
			majorText = majorText[:dot]
		}
		major, _ := strconv.Atoi(majorText)
		return major
	}
	return 0
}

func (i *Index) javaReleaseForLibrary(path string) int {
	path = filepath.Clean(path)
	i.mu.RLock()
	defer i.mu.RUnlock()
	release := 0
	access := i.libraryAccess[path]
	for index := range i.modules {
		module := &i.modules[index]
		if len(access) > 0 && !access[module.Dir] {
			matched := false
			for key := range access {
				if strings.HasPrefix(key, filepath.Clean(module.Dir)+"\x00") {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if value := javaHomeRelease(module.JavaHome); value > release {
			release = value
		}
	}
	if release == 0 {
		release = javaHomeRelease(i.defaultJavaHome)
	}
	if release == 0 {
		release = defaultJavaRelease()
	}
	return release
}

func languageForEntry(name string) string {
	if strings.HasSuffix(strings.ToLower(name), ".java") {
		return "java"
	}
	return "kotlin"
}
