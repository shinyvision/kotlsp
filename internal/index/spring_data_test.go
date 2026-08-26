package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestSpringDataDerivedQueryNavigationAndDiagnostics(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	ctx := context.Background()
	open := func(uri protocol.URI, language, source string) {
		idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: language, Version: 1, Text: source})
	}
	open("file:///workspace/spring/Repository.java", "java", "package org.springframework.data.repository; public interface Repository<T, ID> {}")
	open("file:///workspace/spring/JpaRepository.java", "java", "package org.springframework.data.jpa.repository; import org.springframework.data.repository.Repository; public interface JpaRepository<T, ID> extends Repository<T, ID> {}")
	addressURI := protocol.URI("file:///workspace/p/Address.java")
	noteURI := protocol.URI("file:///workspace/p/Note.java")
	repositoryURI := protocol.URI("file:///workspace/p/NoteRepository.java")
	open(addressURI, "java", "package p; public class Address { String zipCode; }")
	open(noteURI, "java", "package p; public class Note { String title; Address address; }")
	source := "package p; import org.springframework.data.jpa.repository.JpaRepository; interface NoteRepository extends JpaRepository<Note, Long> { Note findByTitle(String title); Note findByAddressZipCode(String zip); Note findByUnknown(String value); }"
	open(repositoryURI, "java", source)
	document := textdoc.NewDocument(repositoryURI, "java", 1, source)

	definitions := idx.Definitions(repositoryURI, document.Position(strings.Index(source, "Title")+1))
	if !containsSymbol(definitions, "title", analysis.KindField, noteURI) {
		t.Fatalf("derived property definition = %#v", definitions)
	}
	nested := idx.Definitions(repositoryURI, document.Position(strings.Index(source, "ZipCode")+1))
	if !containsSymbol(nested, "zipCode", analysis.KindField, addressURI) {
		t.Fatalf("nested derived property definition = %#v", nested)
	}
	if definitions := idx.Definitions(repositoryURI, document.Position(strings.Index(source, "Unknown")+1)); len(definitions) != 0 {
		t.Fatalf("unknown property navigated to declaration: %#v", definitions)
	}
	var invalid bool
	for _, diagnostic := range idx.Diagnostics(repositoryURI) {
		if diagnostic.Code == "spring-data-invalid-property" && strings.Contains(diagnostic.Message, "unknown") {
			invalid = true
		}
	}
	if !invalid {
		t.Fatalf("missing invalid derived property diagnostic: %#v", idx.Diagnostics(repositoryURI))
	}
}

func TestSpringDataOperatorsOrderByAndExplicitQuery(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	ctx := context.Background()
	open := func(uri protocol.URI, language, source string) {
		idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: language, Version: 1, Text: source})
	}
	open("file:///workspace/Repository.java", "java", "package org.springframework.data.repository; public interface Repository<T, ID> {}")
	entityURI := protocol.URI("file:///workspace/p/Person.kt")
	open(entityURI, "kotlin", "package p\nclass Person(val name: String, val age: Int)")
	repositoryURI := protocol.URI("file:///workspace/p/People.kt")
	source := "package p\nimport org.springframework.data.repository.Repository\ninterface People : Repository<Person, Long> {\n fun findByNameContainingIgnoreCaseAndAgeGreaterThanOrderByNameDesc(name: String, age: Int): List<Person>\n @Query(\"select p from Person p\") fun findByMissing(): List<Person>\n}"
	open(repositoryURI, "kotlin", source)
	document := textdoc.NewDocument(repositoryURI, "kotlin", 1, source)
	for _, occurrence := range []int{strings.Index(source, "NameContaining"), strings.LastIndex(source, "NameDesc"), strings.Index(source, "AgeGreater")} {
		definitions := idx.Definitions(repositoryURI, document.Position(occurrence+1))
		if len(definitions) != 1 || definitions[0].URI != entityURI {
			t.Fatalf("operator/order property definition at %d = %#v", occurrence, definitions)
		}
	}
	for _, diagnostic := range idx.Diagnostics(repositoryURI) {
		if diagnostic.Code == "spring-data-invalid-property" && strings.Contains(strings.ToLower(diagnostic.Message), "missing") {
			t.Fatalf("explicit @Query method was parsed as derived: %#v", diagnostic)
		}
	}
}
