package index

import "testing"

// Gradle reports a Kotlin JVM target as its enum constant. kotlinc answers an
// unknown spelling with a sourceless error, and a finding with no source fails
// the whole pass, so this mapping decides whether a project gets compiler
// diagnostics at all.
func TestKotlinJVMTargetValueMatchesCompilerSpelling(t *testing.T) {
	for value, want := range map[string]string{
		"JVM_21":     "21",
		"jvm_21":     "21",
		"JVM_1_8":    "1.8",
		"JVM_11":     "11",
		"21":         "21",
		"1.8":        "1.8",
		"":           "",
		"latest":     "",
		"JVM_LATEST": "",
	} {
		if got := kotlinJVMTargetValue(value); got != want {
			t.Errorf("kotlinJVMTargetValue(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestKotlinCompilerArgumentsCarryTheNormalizedTarget(t *testing.T) {
	arguments := normalizedKotlinCompilerArguments(CompilerSettings{KotlinJVMTarget: "JVM_21"})
	for index, argument := range arguments {
		if argument != "-jvm-target" {
			continue
		}
		if index+1 >= len(arguments) || arguments[index+1] != "21" {
			t.Fatalf("-jvm-target is not followed by the compiler spelling: %v", arguments)
		}
		return
	}
	t.Fatalf("-jvm-target missing from %v", arguments)
}
