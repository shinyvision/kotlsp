package analysis

import (
	"context"
	"strings"
	"testing"

	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func referenceRoles(file *ParsedFile) map[string][]ReferenceRole {
	roles := make(map[string][]ReferenceRole, len(file.References))
	for _, reference := range file.References {
		roles[reference.Name] = append(roles[reference.Name], reference.Role)
	}
	return roles
}

func containsRole(roles []ReferenceRole, want ReferenceRole) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

// A name in backticks is one identifier whose quotes are not part of it. The
// declaration owns that span and a call spells the same name, so neither may
// reach the index quoted: every backticked test function and every `when` from
// Mockito would otherwise be reported as an unresolved reference.
func TestKotlinBacktickedNamesReachTheIndexUnquoted(t *testing.T) {
	source := "package demo\n" +
		"\n" +
		"import org.mockito.Mockito.*\n" +
		"\n" +
		"class Suite {\n" +
		"    fun `verifies the mailbox flow`() {\n" +
		"        `when`(value()).thenReturn(1)\n" +
		"    }\n" +
		"\n" +
		"    fun value(): Int = 1\n" +
		"}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///Suite.kt", "kotlin", 1, source))
	if !hasSymbol(file, "verifies the mailbox flow", KindMethod) {
		t.Fatalf("backticked declaration missing; symbols: %s", symbolSummary(file.Symbols))
	}
	for _, reference := range file.References {
		if strings.Contains(reference.Name, "`") {
			t.Errorf("reference %q keeps its backticks", reference.Name)
		}
		if reference.Name == "verifies the mailbox flow" {
			t.Errorf("the declaration's own name was also emitted as a reference (role %v)", reference.Role)
		}
	}
	if !hasReference(file, "when", RoleCall) {
		t.Fatalf("missing unquoted `when` call; references: %#v", file.References)
	}
}

// Kotlin allows any single segment of an import path to be quoted. The quotes
// are syntax, so the path must reach the index spelled the way the declaration
// is: keeping them made `import org.mockito.Mockito.`when“ match nothing, and
// every use of that member was reported as an undefined name.
func TestKotlinImportSegmentsReachTheIndexUnquoted(t *testing.T) {
	source := "package demo\n" +
		"\n" +
		"import org.mockito.Mockito.`when`\n" +
		"import org.mockito.Mockito.mock as `mock it`\n" +
		"\n" +
		"class Suite {\n" +
		"    fun run() {\n" +
		"        `when`(1)\n" +
		"    }\n" +
		"}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///Imports.kt", "kotlin", 1, source))
	for _, imported := range file.Imports {
		if strings.Contains(imported.Path, "`") || strings.Contains(imported.Alias, "`") {
			t.Errorf("import keeps its backticks: path=%q alias=%q", imported.Path, imported.Alias)
		}
	}
	local := make(map[string]bool, len(file.Imports))
	for _, imported := range file.Imports {
		local[imported.LocalName()] = true
	}
	if !local["when"] {
		t.Fatalf("no import declares `when`; imports: %#v", file.Imports)
	}
	if !local["mock it"] {
		t.Fatalf("no import declares the quoted alias; imports: %#v", file.Imports)
	}
}

// Both sides of an assignment are children of the same node, so a role taken
// from the parent alone marks the value being read as the thing written. That
// made `account.email = address` report "'val' cannot be reassigned" against
// the local `address`.
func TestAssignmentMarksOnlyItsTargetAsAWrite(t *testing.T) {
	kotlin := "package demo\n" +
		"\n" +
		"class Account {\n" +
		"    var email: String = \"\"\n" +
		"}\n" +
		"\n" +
		"fun update(account: Account) {\n" +
		"    val address = \"a@b\"\n" +
		"    var cached = \"\"\n" +
		"    cached = address\n" +
		"    account.email = address\n" +
		"}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///Roles.kt", "kotlin", 1, kotlin))
	roles := referenceRoles(file)
	if len(roles["address"]) == 0 || containsRole(roles["address"], RoleWrite) {
		t.Errorf("kotlin: the assigned value must be read, not written: %v", roles["address"])
	}
	if !containsRole(roles["cached"], RoleWrite) {
		t.Errorf("kotlin: the assigned local must be written: %v", roles["cached"])
	}
	if !containsRole(roles["email"], RoleWrite) {
		t.Errorf("kotlin: the assigned member must be written: %v", roles["email"])
	}
	if containsRole(roles["account"], RoleWrite) {
		t.Errorf("kotlin: the receiver of an assigned member is read: %v", roles["account"])
	}

	java := "package demo;\n" +
		"\n" +
		"class Account {\n" +
		"    String email;\n" +
		"\n" +
		"    void update(Account other) {\n" +
		"        String address = \"a@b\";\n" +
		"        String cached;\n" +
		"        cached = address;\n" +
		"        other.email = address;\n" +
		"    }\n" +
		"}\n"
	javaFile := Parse(context.Background(), textdoc.NewDocument("file:///Roles.java", "java", 1, java))
	javaRoles := referenceRoles(javaFile)
	if len(javaRoles["address"]) == 0 || containsRole(javaRoles["address"], RoleWrite) {
		t.Errorf("java: the assigned value must be read, not written: %v", javaRoles["address"])
	}
	if !containsRole(javaRoles["cached"], RoleWrite) {
		t.Errorf("java: the assigned local must be written: %v", javaRoles["cached"])
	}
	if !containsRole(javaRoles["email"], RoleWrite) {
		t.Errorf("java: the assigned field must be written: %v", javaRoles["email"])
	}
	if containsRole(javaRoles["other"], RoleWrite) {
		t.Errorf("java: the receiver of an assigned field is read: %v", javaRoles["other"])
	}
}
