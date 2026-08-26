package index

import (
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
