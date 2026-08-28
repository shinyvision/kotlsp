package index

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func TestMavenEffectiveModelInheritsParentDependenciesAndProperties(t *testing.T) {
	root := t.TempDir()
	for _, module := range []string{"lib", "app"} {
		if err := os.MkdirAll(filepath.Join(root, module, "src", "main", "java"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, text string) {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging><properties><reactor.group>example</reactor.group><reactor.lib>lib</reactor.lib></properties><dependencies><dependency><groupId>${reactor.group}</groupId><artifactId>${reactor.lib}</artifactId><version>${project.version}</version></dependency></dependencies></project>`)
	for _, module := range []string{"lib", "app"} {
		write(filepath.Join(root, module, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>../pom.xml</relativePath></parent><artifactId>`+module+`</artifactId></project>`)
	}
	modules := discoverModules([]string{root})
	var app *ModuleInfo
	for index := range modules {
		if modules[index].Name == ":app" {
			app = &modules[index]
		}
	}
	if app == nil || !containsString(app.DependenciesBySourceSet["main"], ":lib") || !containsString(app.ExportedBySourceSet["main"], ":lib") {
		t.Fatalf("inherited Maven dependency model = %#v", app)
	}
}

func TestMavenEffectiveModelExportsBuildHelperRootsAndAbstainsOnUnresolvedPlugins(t *testing.T) {
	var model mavenPOM
	data := []byte(`<project><build><plugins>
<plugin><artifactId>build-helper-maven-plugin</artifactId><executions>
<execution><goals><goal>add-source</goal></goals><configuration><sources><source>generated/main</source></sources></configuration></execution>
<execution><goals><goal>add-test-source</goal></goals><configuration><sources><source>generated/test</source></sources></configuration></execution>
</executions></plugin>
<plugin><artifactId>maven-compiler-plugin</artifactId><configuration><annotationProcessorPaths><path><groupId>sample</groupId><artifactId>processor</artifactId><version>1</version></path></annotationProcessorPaths></configuration></plugin>
</plugins></build></project>`)
	if err := xml.Unmarshal(data, &model); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	main, test := mavenAdditionalSourceRoots(model, directory)
	if len(main) != 1 || main[0] != filepath.Join(directory, "generated", "main") || len(test) != 1 || test[0] != filepath.Join(directory, "generated", "test") {
		t.Fatalf("build-helper roots = main %#v, test %#v", main, test)
	}
	if settings := mavenCompilerSettings(model); settings.IncompleteReason == "" {
		t.Fatal("unresolved annotation-processor classpath was presented as compiler truth")
	}
}

func TestDeclaredGradleCustomSourceRootIsIsolatedFromMain(t *testing.T) {
	root := t.TempDir()
	mainRoot := filepath.Join(root, "src", "main", "java")
	integrationRoot := filepath.Join(root, "customIntegration", "java")
	for _, directory := range []string{mainRoot, integrationRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	build := "plugins { id 'java' }\nsourceSets {\n integrationTest { java.srcDir 'customIntegration/java' }\n}\n"
	if err := os.WriteFile(filepath.Join(root, "build.gradle"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
	modules := discoverModules([]string{root})
	if len(modules) != 1 || !containsString(modules[0].SourceSets["integrationTest"], integrationRoot) {
		t.Fatalf("custom Gradle source roots = %#v", modules)
	}
	if sourceSetCanAccess(&modules[0], "main", "integrationTest") {
		t.Fatalf("main can access integrationTest: %#v", modules[0].SourceSetDependsOn)
	}
	if !sourceSetCanAccess(&modules[0], "integrationTest", "main") {
		t.Fatalf("integrationTest cannot access main: %#v", modules[0].SourceSetDependsOn)
	}
}

func TestEffectiveMavenGraphReplacesDegradedDiscoveryEdges(t *testing.T) {
	resolution := newClasspathResolution()
	resolution.Dependencies[":app"] = []string{":guessed"}
	resolution.SourceSetDependencies[":app"] = map[string][]string{"main": {":guessed"}}
	models := make(map[string]mavenPOM)
	for _, module := range []string{":app", ":lib", ":excluded"} {
		model := mavenPOM{GroupID: "example", ArtifactID: module[1:], Version: "1"}
		models[module] = model
	}
	app := models[":app"]
	if err := xml.Unmarshal([]byte(`<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>lib</artifactId><version>1</version><exclusions><exclusion><groupId>example</groupId><artifactId>excluded</artifactId></exclusion></exclusions></dependency></dependencies></project>`), &app); err != nil {
		t.Fatal(err)
	}
	models[":app"] = app
	if err := replaceWithEffectiveMavenGraph(&resolution, models); err != nil {
		t.Fatal(err)
	}
	if !containsString(resolution.Dependencies[":app"], ":lib") || containsString(resolution.Dependencies[":app"], ":guessed") {
		t.Fatalf("effective Maven dependencies = %#v", resolution.Dependencies)
	}
	key := dependencyExclusionKey("main", ":lib")
	if !containsString(resolution.DependencyExclusions[":app"][key], ":excluded") {
		t.Fatalf("effective Maven exclusions = %#v", resolution.DependencyExclusions)
	}
	if !containsString(resolution.SourceSetDependsOn[":app"]["test"], "main") {
		t.Fatalf("effective Maven source-set graph = %#v", resolution.SourceSetDependsOn)
	}
}

func TestEffectiveMavenGraphUsesGAVAndPreservesRuntimeAndExternalExclusions(t *testing.T) {
	resolution := newClasspathResolution()
	models := map[string]mavenPOM{
		":app":    {GroupID: "example", ArtifactID: "app", Version: "1"},
		":lib-v1": {GroupID: "example", ArtifactID: "lib", Version: "1"},
		":lib-v2": {GroupID: "example", ArtifactID: "lib", Version: "2"},
	}
	app := models[":app"]
	if err := xml.Unmarshal([]byte(`<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies>
<dependency><groupId>example</groupId><artifactId>lib</artifactId><version>2</version><scope>runtime</scope></dependency>
<dependency><groupId>external</groupId><artifactId>driver</artifactId><version>4</version><exclusions><exclusion><groupId>logging</groupId><artifactId>legacy</artifactId></exclusion></exclusions></dependency>
</dependencies></project>`), &app); err != nil {
		t.Fatal(err)
	}
	models[":app"] = app
	if err := replaceWithEffectiveMavenGraph(&resolution, models); err != nil {
		t.Fatal(err)
	}
	if got := resolution.RuntimeSourceSetDependencies[":app"]["main"]; len(got) != 1 || got[0] != ":lib-v2" {
		t.Fatalf("runtime GAV edge = %#v", got)
	}
	if !containsString(resolution.SourceSetDependencies[":app"]["test"], ":lib-v2") {
		t.Fatalf("Maven runtime dependency missing from test compile graph: %#v", resolution.SourceSetDependencies)
	}
	if containsString(resolution.SourceSetDependencies[":app"]["main"], ":lib-v2") || containsString(resolution.Dependencies[":app"], ":lib-v1") {
		t.Fatalf("runtime or wrong-version edge leaked into compile graph: %#v", resolution)
	}
	key := dependencyExclusionKey("main", "maven:external:driver:4")
	if !containsString(resolution.ExternalDependencyExclusions[":app"][key], "logging:legacy") {
		t.Fatalf("external exclusion coordinates = %#v", resolution.ExternalDependencyExclusions)
	}
}

func TestAuthoritativeSourceSetGraphNeverUsesConventionalEdges(t *testing.T) {
	module := &ModuleInfo{
		BuildModelAuthoritative: true,
		SourceSets: map[string][]string{
			"main": {"/src/main"},
			"test": {"/src/test"},
		},
		SourceSetDependsOn: map[string][]string{},
	}
	if sourceSetCanAccess(module, "test", "main") {
		t.Fatal("an authoritative empty graph acquired a conventional test-to-main edge")
	}
}

func TestGradleDependencyConfigurationSeparatesCompileAndRuntime(t *testing.T) {
	cases := []struct {
		configuration              string
		set                        string
		compile, runtime, exported bool
	}{
		{configuration: "implementation", set: "main", compile: true, runtime: true},
		{configuration: "testCompileOnly", set: "test", compile: true},
		{configuration: "runtimeOnly", set: "main", runtime: true},
		{configuration: "integrationApi", set: "integration", compile: true, runtime: true, exported: true},
	}
	for _, test := range cases {
		set, compileVisible, runtimeVisible, exported := gradleDependencyConfiguration(test.configuration)
		if set != test.set || compileVisible != test.compile || runtimeVisible != test.runtime || exported != test.exported {
			t.Fatalf("%s = (%s,%t,%t,%t), want (%s,%t,%t,%t)", test.configuration, set, compileVisible, runtimeVisible, exported, test.set, test.compile, test.runtime, test.exported)
		}
	}
}

func TestCompileClasspathEntriesIncludesSourceSetOnlyBuildModels(t *testing.T) {
	resolution := newClasspathResolution()
	resolution.SourceSetClasspath[":app"] = map[string][]string{
		"main": {"/deps/spring-core.jar", "/deps/spring-web.jar"},
		"test": {"/deps/spring-core.jar", "/deps/junit.jar"},
	}
	resolution.RuntimeSourceSetClasspath[":app"] = map[string][]string{
		"main": {"/runtime/database-driver.jar"},
	}

	entries, complete := compileClasspathEntries(resolution)
	if !complete {
		t.Fatal("small source-set classpath was reported as truncated")
	}
	want := []string{"/deps/spring-core.jar", "/deps/spring-web.jar", "/deps/junit.jar"}
	if len(entries) != len(want) {
		t.Fatalf("compile classpath = %#v, want %#v", entries, want)
	}
	for index := range want {
		if entries[index] != want[index] {
			t.Fatalf("compile classpath = %#v, want %#v", entries, want)
		}
	}
}

func TestLibraryScanConsumesSourceSetOnlyClasspath(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	class := compileTestClass(t, "dependency", "Service", "package dependency; public class Service { public String run() { return \"ok\"; } }")
	archive := writeTestArchive(t, "dependency.jar", map[string]string{"dependency/Service.class": class})
	root := t.TempDir()
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	resolution := newClasspathResolution()
	resolution.SourceSetClasspath[":"] = map[string][]string{"main": {archive}}

	previousSkip, previousFilter := skipLibraryScan, libraryArchiveFilter
	skipLibraryScan = false
	libraryArchiveFilter = func(candidate sourceArchive) bool {
		return filepath.Clean(candidate.path) == filepath.Clean(archive)
	}
	t.Cleanup(func() {
		skipLibraryScan, libraryArchiveFilter = previousSkip, previousFilter
	})

	idx := New(nil)
	defer idx.Close()
	ready := false
	idx.scanLibraries(context.Background(), []string{cleanRoot}, idx.generation.Load(), func() { ready = true }, map[string]classpathResolution{filepath.Clean(cleanRoot): resolution})
	if !ready || !idx.librariesScanned.Load() {
		t.Fatalf("source-set-only library scan did not complete: progress=%+v health=%+v", idx.Progress(), idx.Health())
	}
	if symbols := idx.SymbolsByFQN("dependency.Service.run"); len(symbols) != 1 {
		t.Fatalf("source-set-only dependency method was not indexed: %#v", symbols)
	}
	if classpath := idx.Classpath(); !containsString(classpath, archive) {
		t.Fatalf("published classpath = %#v, want it to contain %s", classpath, archive)
	}
}

func TestBuildModelCacheAllowsUnbuiltOutputsButRejectsMissingArchives(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	fingerprint, err := buildModelFingerprint(root, false)
	if err != nil {
		t.Fatal(err)
	}
	resolution := newClasspathResolution()
	resolution.Importer = "gradle"
	resolution.Classpath = []string{filepath.Join(root, "build", "classes", "kotlin", "main")}
	if err := saveBuildModelCache(root, fingerprint, resolution); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadBuildModelCache(root, fingerprint); !ok {
		t.Fatal("an output directory which has not been built invalidated the model cache")
	}
	resolution.Classpath = append(resolution.Classpath, filepath.Join(root, "missing-dependency.jar"))
	if err := saveBuildModelCache(root, fingerprint, resolution); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadBuildModelCache(root, fingerprint); ok {
		t.Fatal("a missing archive dependency was accepted from the model cache")
	}
}
