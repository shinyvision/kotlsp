package index

import (
	"os"
	"os/exec"
	"strings"
)

func limitCompilerEnvironment(command *exec.Cmd) {
	environment := command.Env
	if environment == nil {
		environment = os.Environ()
	}
	const option = "-Xmx768m -XX:+ExitOnOutOfMemoryError -Duser.language=en -Duser.country=US"
	foundLocale, foundLanguage := false, false
	for index, value := range environment {
		if strings.HasPrefix(value, "LC_ALL=") {
			environment[index], foundLocale = "LC_ALL=C", true
		}
		if strings.HasPrefix(value, "LANG=") {
			environment[index], foundLanguage = "LANG=C", true
		}
		if strings.HasPrefix(value, "JAVA_TOOL_OPTIONS=") {
			environment[index] = value + " " + option
			command.Env = environment
		}
	}
	if !foundLocale {
		environment = append(environment, "LC_ALL=C")
	}
	if !foundLanguage {
		environment = append(environment, "LANG=C")
	}
	for _, value := range environment {
		if strings.HasPrefix(value, "JAVA_TOOL_OPTIONS=") {
			command.Env = environment
			return
		}
	}
	command.Env = append(environment, "JAVA_TOOL_OPTIONS="+option)
}
