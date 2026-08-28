package lsp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shinyvision/kotlsp/internal/jsonrpc"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (s *Server) interpolateFileTemplate(args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) != 2 {
		return nil, invalidParams(fmt.Errorf("expected document URI and template text"))
	}
	var uri protocol.URI
	var template string
	if json.Unmarshal(args[0], &uri) != nil || json.Unmarshal(args[1], &template) != nil {
		return nil, invalidParams(fmt.Errorf("expected document URI and template text"))
	}
	path, ok := uriutil.Path(uri)
	if !ok {
		return nil, nil
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		// OpenKotlin requires a VirtualFile, PsiFile, and containing directory;
		// a URI alone is not enough to establish a template context.
		return nil, nil
	}
	now := time.Now()
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	values := map[string]string{
		"NAME": name, "FILE_NAME": filepath.Base(path), "FILE_PATH": path,
		"DIR_PATH": filepath.Dir(path), "PROJECT_NAME": filepath.Base(s.rootPath()),
		"DATE": now.Format("2006-01-02"), "TIME": now.Format("15:04"),
		"YEAR": now.Format("2006"), "MONTH": now.Format("01"), "DAY": now.Format("02"),
		"HOUR": now.Format("15"), "MINUTE": now.Format("04"),
		"USER": os.Getenv("USER"),
	}
	if parsed, ok := s.index.Parsed(uri); ok {
		values["PACKAGE_NAME"] = parsed.Package
	}
	if err := validateFileTemplateDialect(template); err != nil {
		return nil, invalidParams(err)
	}
	return interpolateFileTemplateText(template, values), nil
}

func (s *Server) exportWorkspace(ctx context.Context, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if responseErr := canceledResponse(ctx); responseErr != nil {
		return nil, responseErr
	}
	if len(args) != 1 {
		return nil, invalidParams(fmt.Errorf("expected one workspace export directory"))
	}
	var destination string
	if json.Unmarshal(args[0], &destination) != nil || destination == "" {
		return nil, invalidParams(fmt.Errorf("expected a workspace export directory"))
	}
	info, err := os.Stat(destination)
	if err != nil || !info.IsDir() {
		return nil, invalidParams(fmt.Errorf("workspace export directory does not exist: %s", destination))
	}
	importedModules := s.index.Modules()
	classpath := s.index.Classpath()
	for _, module := range importedModules {
		classpath = append(classpath, module.Classpath...)
		classpath = append(classpath, module.ModulePath...)
	}
	classpath = uniqueCommandStrings(classpath)
	libraries := make([]map[string]any, 0, len(classpath))
	libraryNames := make(map[string]string, len(classpath))
	for n, path := range classpath {
		if n&255 == 0 {
			if responseErr := canceledResponse(ctx); responseErr != nil {
				return nil, responseErr
			}
		}
		name := filepath.Base(path) + "-" + strconv.Itoa(n)
		libraryNames[path] = name
		libraries = append(libraries, map[string]any{
			"name": name, "level": "project", "module": nil, "type": nil,
			"roots":         []any{map[string]any{"path": path, "type": "CLASSES", "inclusionOptions": "root_itself"}},
			"excludedRoots": []string{}, "properties": nil,
		})
	}
	modules := make([]map[string]any, 0, len(importedModules))
	kotlinSettings := make([]any, 0, len(importedModules))
	javaSettings := make([]any, 0, len(importedModules))
	for moduleIndex, module := range importedModules {
		if moduleIndex&31 == 0 {
			if responseErr := canceledResponse(ctx); responseErr != nil {
				return nil, responseErr
			}
		}
		sourceRoots := make([]map[string]any, 0)
		for sourceSet, roots := range module.SourceSets {
			kind := "java-source"
			if strings.Contains(strings.ToLower(sourceSet), "test") {
				kind = "java-test"
			}
			for _, root := range roots {
				sourceRoots = append(sourceRoots, map[string]any{"path": root, "type": kind, "sourceSet": sourceSet,
					"generated": strings.Contains(filepath.ToSlash(root), "/generated/")})
			}
		}
		sort.Slice(sourceRoots, func(left, right int) bool {
			return fmt.Sprint(sourceRoots[left]["path"]) < fmt.Sprint(sourceRoots[right]["path"])
		})
		dependencies := []map[string]any{{"type": "moduleSource"}, {"type": "inheritedSdk"}}
		for _, dependency := range module.Dependencies {
			dependencies = append(dependencies, map[string]any{"type": "module", "name": dependency, "scope": "COMPILE", "isExported": false})
		}
		for _, path := range module.Classpath {
			if name := libraryNames[path]; name != "" {
				dependencies = append(dependencies, map[string]any{"type": "library", "name": name, "scope": "COMPILE", "isExported": false})
			}
		}
		modules = append(modules, map[string]any{
			"name": module.Name, "type": "JAVA_MODULE", "coordinate": nil,
			"dependencies": dependencies,
			"contentRoots": []any{map[string]any{"path": module.Dir, "excludedPatterns": []string{}, "excludedUrls": []string{}, "sourceRoots": sourceRoots}},
			"facets":       []string{}, "externalProjectPath": module.Dir,
			"sourceSets": module.SourceSets, "sourceSetDependsOn": module.SourceSetDependsOn,
			"dependenciesBySourceSet": module.DependenciesBySourceSet, "runtimeDependenciesBySourceSet": module.RuntimeDependenciesBySourceSet, "exportedBySourceSet": module.ExportedBySourceSet,
			"dependencyExclusions": module.DependencyExclusions, "externalDependencyExclusions": module.ExternalDependencyExclusions,
			"classpathBySourceSet": module.ClasspathBySourceSet, "runtimeClasspathBySourceSet": module.RuntimeClasspathBySourceSet,
			"modulePathBySourceSet": module.ModulePathBySourceSet, "javaModuleName": nullableString(module.JavaModuleName),
			"javaRequires": module.JavaRequires, "javaExports": module.JavaExports, "javaOpens": module.JavaOpens,
			"compilerSettingsBySourceSet": module.CompilerSettingsBySourceSet,
			"buildModel":                  map[string]any{"importer": module.BuildImporter, "authoritative": module.BuildModelAuthoritative, "failure": nullableString(module.BuildModelFailure)},
		})
		for sourceSet, settings := range module.CompilerSettingsBySourceSet {
			kotlinSettings = append(kotlinSettings, map[string]any{
				"module": module.Name, "sourceSet": sourceSet, "sourceSetDependsOn": module.SourceSetDependsOn[sourceSet],
				"version": settings.KotlinVersion, "languageVersion": settings.KotlinLanguageVersion,
				"apiVersion": settings.KotlinAPIVersion, "jvmTarget": settings.KotlinJVMTarget,
				"arguments": settings.KotlinArguments, "incompleteReason": nullableString(settings.IncompleteReason),
			})
			javaHome := settings.JavaHome
			if javaHome == "" {
				javaHome = module.JavaHome
			}
			javaSettings = append(javaSettings, map[string]any{
				"module": module.Name, "sourceSet": sourceSet, "javaHome": nullableString(javaHome),
				"moduleName": nullableString(module.JavaModuleName), "modulePath": module.ModulePathBySourceSet[sourceSet],
				"release": settings.JavaRelease, "source": settings.JavaSource, "target": settings.JavaTarget,
				"arguments": settings.JavaArguments, "incompleteReason": nullableString(settings.IncompleteReason),
			})
		}
		if len(module.CompilerSettingsBySourceSet) == 0 {
			kotlinSettings = append(kotlinSettings, map[string]any{"module": module.Name, "sourceSetDependsOn": module.SourceSetDependsOn})
			javaSettings = append(javaSettings, map[string]any{"module": module.Name, "javaHome": nullableString(module.JavaHome), "moduleName": nullableString(module.JavaModuleName), "modulePath": module.ModulePath})
		}
	}
	sort.Slice(kotlinSettings, func(left, right int) bool {
		return fmt.Sprint(kotlinSettings[left]) < fmt.Sprint(kotlinSettings[right])
	})
	sort.Slice(javaSettings, func(left, right int) bool { return fmt.Sprint(javaSettings[left]) < fmt.Sprint(javaSettings[right]) })
	s.rootMu.RLock()
	javaHome := s.defaultJavaHome
	s.rootMu.RUnlock()
	if javaHome == "" {
		javaHome = os.Getenv("JAVA_HOME")
	}
	workspace := map[string]any{
		"modules": modules, "libraries": libraries,
		"sdks":           []any{map[string]any{"name": "kotlsp-jdk", "type": "JavaSDK", "version": runtime.Version(), "homePath": nullableString(javaHome), "roots": nil, "additionalData": ""}},
		"kotlinSettings": kotlinSettings, "javaSettings": javaSettings,
	}
	payload, err := json.Marshal(workspace)
	if err != nil {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: "encode workspace: " + err.Error()}
	}
	if len(payload) > 64<<20 {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.RequestCanceled, Message: "workspace export exceeds its 64 MiB safety limit"}
	}
	if err = writeWorkspaceExportAtomic(ctx, destination, payload); err != nil {
		if ctx.Err() != nil {
			return nil, canceledResponse(ctx)
		}
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: "write workspace.json: " + err.Error()}
	}
	return nil, nil
}

func writeWorkspaceExportAtomic(ctx context.Context, destination string, payload []byte) error {
	temporary, err := os.CreateTemp(destination, ".workspace-*.tmp")
	if err != nil {
		return err
	}
	path := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return err
	}
	for start := 0; start < len(payload); {
		if err = ctx.Err(); err != nil {
			return err
		}
		end := min(start+(1<<20), len(payload))
		written, writeErr := temporary.Write(payload[start:end])
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 {
			return fmt.Errorf("workspace export made no write progress")
		}
		start += written
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Rename(path, filepath.Join(destination, "workspace.json")); err != nil {
		return err
	}
	committed = true
	return nil
}

func uniqueCommandStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func interpolateVariables(template string, values map[string]string) string {
	var out strings.Builder
	for i := 0; i < len(template); {
		if template[i] == '\\' && i+1 < len(template) && template[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if template[i] != '$' {
			out.WriteByte(template[i])
			i++
			continue
		}
		start, end := i+1, i+1
		braced := start < len(template) && template[start] == '{'
		if braced {
			start++
			end = start
			for end < len(template) && template[end] != '}' {
				end++
			}
			if end >= len(template) {
				out.WriteByte(template[i])
				i++
				continue
			}
		} else {
			for end < len(template) && (template[end] == '_' || template[end] >= 'A' && template[end] <= 'Z' || template[end] >= 'a' && template[end] <= 'z' || template[end] >= '0' && template[end] <= '9') {
				end++
			}
		}
		key := template[start:end]
		if value, ok := values[key]; ok {
			out.WriteString(value)
		}
		if braced {
			i = end + 1
		} else if end > start {
			i = end
		} else {
			out.WriteByte('$')
			i++
		}
	}
	return strings.ReplaceAll(out.String(), "\r\n", "\n")
}

func interpolateFileTemplateText(template string, values map[string]string) string {
	// CustomFileTemplate delegates to IntelliJ's Velocity-compatible engine.
	// File templates primarily use conditional blocks and #set; implement those
	// directives with nesting before expanding the standard context variables.
	type conditional struct {
		parentActive bool
		matched      bool
	}
	stack := make([]conditional, 0, 4)
	active := true
	var out strings.Builder
	for index := 0; index < len(template); {
		if strings.HasPrefix(template[index:], "##") {
			end := strings.IndexByte(template[index:], '\n')
			if end < 0 {
				break
			}
			index += end
			continue
		}
		if strings.HasPrefix(template[index:], "#*") {
			end := strings.Index(template[index+2:], "*#")
			if end < 0 {
				break
			}
			index += end + 4
			continue
		}
		if template[index] == '#' {
			handled := false
			for _, directive := range []string{"elseif", "if", "set"} {
				prefix := "#" + directive
				if !strings.HasPrefix(template[index:], prefix) {
					continue
				}
				argument, next, ok := templateDirectiveArgument(template, index+len(prefix))
				if !ok {
					continue
				}
				switch directive {
				case "if":
					matched := templateCondition(argument, values)
					stack = append(stack, conditional{parentActive: active, matched: matched})
					active = active && matched
				case "elseif":
					if len(stack) == 0 {
						continue
					}
					frame := &stack[len(stack)-1]
					matched := !frame.matched && templateCondition(argument, values)
					frame.matched = frame.matched || matched
					active = frame.parentActive && matched
				case "set":
					if active {
						templateSet(argument, values)
					}
				}
				index, handled = next, true
				break
			}
			if handled {
				continue
			}
			if strings.HasPrefix(template[index:], "#else") && templateWordBoundary(template, index+len("#else")) && len(stack) > 0 {
				frame := &stack[len(stack)-1]
				active = frame.parentActive && !frame.matched
				frame.matched = true
				index += len("#else")
				continue
			}
			if strings.HasPrefix(template[index:], "#end") && templateWordBoundary(template, index+len("#end")) && len(stack) > 0 {
				frame := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				active = frame.parentActive
				index += len("#end")
				continue
			}
		}
		if active {
			out.WriteByte(template[index])
		}
		index++
	}
	return interpolateVariables(out.String(), values)
}

// validateFileTemplateDialect makes the compatibility boundary explicit.
// Silently half-rendering a Velocity macro/include/loop is substantially worse
// than returning a useful protocol error because it can create corrupt source.
func validateFileTemplateDialect(template string) error {
	depth := 0
	for index := 0; index < len(template); {
		if strings.HasPrefix(template[index:], "##") {
			if newline := strings.IndexByte(template[index:], '\n'); newline >= 0 {
				index += newline + 1
				continue
			}
			return nil
		}
		if strings.HasPrefix(template[index:], "#*") {
			end := strings.Index(template[index+2:], "*#")
			if end < 0 {
				return fmt.Errorf("unterminated file-template block comment")
			}
			index += end + 4
			continue
		}
		if template[index] == '#' {
			end := index + 1
			for end < len(template) && (template[end] == '_' || template[end] >= 'a' && template[end] <= 'z' || template[end] >= 'A' && template[end] <= 'Z') {
				end++
			}
			if end > index+1 {
				directive := template[index+1 : end]
				switch directive {
				case "if":
					depth++
				case "elseif", "else":
					if depth == 0 {
						return fmt.Errorf("file-template #%s has no matching #if", directive)
					}
				case "end":
					if depth == 0 {
						return fmt.Errorf("file-template #end has no matching #if")
					}
					depth--
				case "set":
				default:
					return fmt.Errorf("unsupported IntelliJ file-template directive #%s; supported directives are #if, #elseif, #else, #end, and #set", directive)
				}
				index = end
				continue
			}
		}
		if template[index] == '$' {
			end := index + 1
			if end < len(template) && template[end] == '{' {
				close := strings.IndexByte(template[end+1:], '}')
				if close < 0 {
					return fmt.Errorf("unterminated file-template variable at byte %d", index)
				}
				value := template[end+1 : end+1+close]
				if value == "" || !templateIdentifier(value) {
					return fmt.Errorf("unsupported file-template expression ${%s}; only context variables are supported", value)
				}
				index = end + close + 2
				continue
			}
			for end < len(template) && (template[end] == '_' || template[end] >= 'a' && template[end] <= 'z' || template[end] >= 'A' && template[end] <= 'Z' || template[end] >= '0' && template[end] <= '9') {
				end++
			}
			if end > index+1 && end < len(template) && strings.ContainsRune(".([", rune(template[end])) {
				return fmt.Errorf("unsupported file-template method/property expression after %s", template[index:end])
			}
			index = max(end, index+1)
			continue
		}
		index++
	}
	if depth != 0 {
		return fmt.Errorf("unterminated file-template #if block")
	}
	return nil
}

func templateIdentifier(value string) bool {
	for index := 0; index < len(value); index++ {
		if !(value[index] == '_' || value[index] >= 'a' && value[index] <= 'z' || value[index] >= 'A' && value[index] <= 'Z' || index > 0 && value[index] >= '0' && value[index] <= '9') {
			return false
		}
	}
	return value != ""
}

func templateDirectiveArgument(template string, after int) (string, int, bool) {
	for after < len(template) && (template[after] == ' ' || template[after] == '\t') {
		after++
	}
	if after >= len(template) || template[after] != '(' {
		return "", after, false
	}
	depth, quote, escaped := 1, byte(0), false
	for index := after + 1; index < len(template); index++ {
		value := template[index]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		switch value {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return template[after+1 : index], index + 1, true
			}
		}
	}
	return "", after, false
}

func templateCondition(expression string, values map[string]string) bool {
	expression = strings.TrimSpace(expression)
	if parts := strings.SplitN(expression, "||", 2); len(parts) == 2 {
		return templateCondition(parts[0], values) || templateCondition(parts[1], values)
	}
	if parts := strings.SplitN(expression, "&&", 2); len(parts) == 2 {
		return templateCondition(parts[0], values) && templateCondition(parts[1], values)
	}
	if strings.HasPrefix(expression, "!") {
		return !templateCondition(strings.TrimSpace(expression[1:]), values)
	}
	for _, operator := range []string{"!=", "=="} {
		if parts := strings.SplitN(expression, operator, 2); len(parts) == 2 {
			equal := templateValue(parts[0], values) == templateValue(parts[1], values)
			return equal == (operator == "==")
		}
	}
	value := strings.ToLower(strings.TrimSpace(templateValue(expression, values)))
	return value != "" && value != "false" && value != "0" && value != "null"
}

func templateValue(expression string, values map[string]string) string {
	expression = strings.TrimSpace(expression)
	if len(expression) >= 2 && (expression[0] == '"' && expression[len(expression)-1] == '"' || expression[0] == '\'' && expression[len(expression)-1] == '\'') {
		return expression[1 : len(expression)-1]
	}
	key := strings.TrimPrefix(expression, "$")
	key = strings.TrimPrefix(key, "{")
	key = strings.TrimSuffix(key, "}")
	if value, ok := values[key]; ok {
		return value
	}
	if strings.HasPrefix(expression, "$") {
		return ""
	}
	return expression
}

func templateSet(argument string, values map[string]string) {
	parts := strings.SplitN(argument, "=", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(strings.TrimPrefix(parts[0], "$"))
	key = strings.TrimSuffix(strings.TrimPrefix(key, "{"), "}")
	if key != "" {
		values[key] = templateValue(parts[1], values)
	}
}

func templateWordBoundary(template string, after int) bool {
	if after >= len(template) {
		return true
	}
	value := template[after]
	return !(value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9')
}

func (s *Server) applyModCommand(ctx context.Context, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) != 1 {
		return nil, invalidParams(fmt.Errorf("expected one ModCommandData argument"))
	}
	var command map[string]any
	if err := json.Unmarshal(args[0], &command); err != nil {
		return nil, invalidParams(fmt.Errorf("invalid ModCommandData: %w", err))
	}
	if err := s.executeModCommandState(ctx, command, make(map[string]string)); err != nil {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
	}
	return true, nil
}

func (s *Server) executeModCommand(ctx context.Context, command map[string]any) error {
	return s.executeModCommandState(ctx, command, make(map[string]string))
}

func (s *Server) executeModCommandState(ctx context.Context, command map[string]any, changedFiles map[string]string) error {
	kind := commandKind(command)
	switch {
	case strings.Contains(kind, "nothing"):
		return nil
	case strings.Contains(kind, "composite"):
		commands, _ := command["commands"].([]any)
		for _, value := range commands {
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid composite ModCommandData")
			}
			if err := s.executeModCommandState(ctx, child, changedFiles); err != nil {
				return err
			}
		}
		return nil
	case strings.Contains(kind, "updatefiletext"):
		uri := lspURI(stringValue(command, "fileUrl"))
		oldText, newText := stringValue(command, "oldText"), stringValue(command, "newText")
		changedFiles[stringValue(command, "fileUrl")] = newText
		doc := textdoc.NewDocument(uri, uriutil.LanguageID(string(uri)), 0, oldText)
		return s.applyWorkspaceEdit(ctx, "Update "+string(uri), protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: {{Range: doc.Range(0, len(oldText)), NewText: newText}}}})
	case strings.Contains(kind, "createfile"):
		uri := lspURI(stringValue(command, "fileUrl"))
		content, _ := command["content"].(map[string]any)
		contentKind := commandKind(content)
		if strings.Contains(contentKind, "directory") {
			path, ok := uriutil.Path(uri)
			if !ok {
				return fmt.Errorf("directory ModCreateFile requires a file URI")
			}
			return os.MkdirAll(path, 0o755)
		}
		changes := []any{map[string]any{"kind": "create", "uri": uri}}
		if strings.Contains(contentKind, "text") {
			if !s.clientSupportsResourceOperation("create") {
				return fmt.Errorf("client does not support create resource operations")
			}
			changes = append(changes, protocol.TextDocumentEdit{TextDocument: protocol.OptionalVersionedTextDocumentIdentifier{URI: uri}, Edits: []protocol.TextEdit{{Range: protocol.Range{}, NewText: stringValue(content, "text")}}})
		} else if strings.Contains(contentKind, "binary") {
			data, err := base64.StdEncoding.DecodeString(stringValue(content, "base64"))
			if err != nil {
				return fmt.Errorf("invalid binary create-file payload: %w", err)
			}
			path, ok := uriutil.Path(uri)
			if !ok {
				return fmt.Errorf("binary ModCreateFile requires a file URI")
			}
			if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			if _, err = file.Write(data); err != nil {
				_ = file.Close()
				return err
			}
			return file.Close()
		}
		return s.applyWorkspaceEdit(ctx, "Create "+string(uri), protocol.WorkspaceEdit{DocumentChanges: changes})
	case strings.Contains(kind, "deletefile"):
		if !s.clientSupportsResourceOperation("delete") {
			return fmt.Errorf("client does not support delete resource operations")
		}
		uri := lspURI(stringValue(command, "fileUrl"))
		return s.applyWorkspaceEdit(ctx, "Delete "+string(uri), protocol.WorkspaceEdit{DocumentChanges: []any{map[string]any{"kind": "delete", "uri": uri}}})
	case strings.Contains(kind, "movefile"):
		if !s.clientSupportsResourceOperation("rename") {
			return fmt.Errorf("client does not support rename resource operations")
		}
		oldURI, newURI := lspURI(stringValue(command, "fileUrl")), lspURI(stringValue(command, "targetUrl"))
		return s.applyWorkspaceEdit(ctx, "Move "+string(oldURI), protocol.WorkspaceEdit{DocumentChanges: []any{protocol.RenameFile{Kind: "rename", OldURI: oldURI, NewURI: newURI}}})
	case strings.Contains(kind, "navigate"):
		uri := lspURI(stringValue(command, "fileUrl"))
		params := map[string]any{"uri": uri, "takeFocus": false}
		if doc, ok := s.index.DocumentContext(ctx, uri); ok {
			start, end := intValue(command, "selectionStart"), intValue(command, "selectionEnd")
			if start < 0 {
				start = intValue(command, "caret")
			}
			if end < 0 {
				end = start
			}
			if start >= 0 && end >= start {
				params["selection"] = doc.Range(start, end)
			}
		}
		return s.clientRequest(ctx, "window/showDocument", params)
	case strings.Contains(kind, "displaymessage"):
		messageType := 3
		if strings.Contains(strings.ToLower(fmt.Sprint(command["messageKind"])), "error") {
			messageType = 1
		}
		if s.conn != nil {
			return s.conn.Notify("window/showMessage", map[string]any{"type": messageType, "message": stringValue(command, "message")})
		}
		return nil
	case strings.Contains(kind, "copytoclipboard"):
		if s.conn != nil {
			return s.conn.Notify("intellij/copyToClipboard", map[string]any{"content": stringValue(command, "content")})
		}
		return nil
	case strings.Contains(kind, "chooseaction"):
		sessionID := int64(intValue(command, "sessionId"))
		if sessionID >= 0 {
			rawActions, hasActions := command["actions"].([]any)
			rawEntries, _ := command["entries"].([]any)
			maxIndex := len(rawActions) - 1
			for _, rawEntry := range rawEntries {
				if entry, ok := rawEntry.(map[string]any); ok && intValue(entry, "index") > maxIndex {
					maxIndex = intValue(entry, "index")
				}
			}
			actions := make([]map[string]any, maxIndex+1)
			for _, rawAction := range rawActions {
				if action, valid := rawAction.(map[string]any); valid {
					for index := range actions {
						if actions[index] == nil {
							actions[index] = action
							break
						}
					}
				}
			}
			// In the real protocol actions are retained server-side when the DTO
			// is created, and are intentionally absent from the JSON.  Preserve an
			// already registered session; for externally replayed DTOs, register
			// advertised entries as safe no-ops so the protocol remains one-shot.
			for index := range actions {
				if actions[index] == nil {
					actions[index] = map[string]any{"type": "Nothing"}
				}
			}
			s.modMu.Lock()
			s.pruneModSessionsLocked(time.Now())
			if _, exists := s.modSessions[sessionID]; !exists || hasActions {
				s.modSessions[sessionID] = actions
				s.modSessionCreated[sessionID] = time.Now()
			}
			s.modMu.Unlock()
		}
		if s.conn != nil {
			return s.conn.Notify("intellij/chooseAction", map[string]any{"sessionId": command["sessionId"], "title": command["title"], "entries": command["entries"]})
		}
		return nil
	case strings.Contains(kind, "snippet"):
		return s.executeSnippet(ctx, command, changedFiles)
	default:
		return fmt.Errorf("unsupported ModCommandData kind %q", kind)
	}
}

func (s *Server) chooseModCommandAction(ctx context.Context, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) < 2 {
		return nil, invalidParams(fmt.Errorf("expected session id and action index"))
	}
	var sessionID int64
	var actionIndex int
	if json.Unmarshal(args[0], &sessionID) != nil || json.Unmarshal(args[1], &actionIndex) != nil || actionIndex < 0 {
		return nil, invalidParams(fmt.Errorf("expected numeric session id and action index"))
	}
	s.modMu.Lock()
	s.pruneModSessionsLocked(time.Now())
	actions, exists := s.modSessions[sessionID]
	if exists {
		delete(s.modSessions, sessionID)
		delete(s.modSessionCreated, sessionID)
	}
	s.modMu.Unlock()
	if !exists || actionIndex >= len(actions) {
		return nil, &jsonrpc.ResponseError{Code: -32803, Message: "mod-command choice session has expired"}
	}
	if err := s.executeModCommandState(ctx, actions[actionIndex], make(map[string]string)); err != nil {
		return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
	}
	return true, nil
}

func (s *Server) executeSnippet(ctx context.Context, command map[string]any, changedFiles map[string]string) error {
	fileURL := stringValue(command, "fileUrl")
	uri := lspURI(fileURL)
	text := changedFiles[fileURL]
	if text == "" {
		doc, ok := s.index.DocumentContext(ctx, uri)
		if !ok {
			return nil
		}
		text = doc.Text
	}
	type snippetVariable struct {
		start, end, name int
		choices          []string
	}
	rawVariables, _ := command["vars"].([]any)
	variables := make([]snippetVariable, 0, len(rawVariables))
	for _, rawVariable := range rawVariables {
		value, ok := rawVariable.(map[string]any)
		if !ok {
			continue
		}
		variable := snippetVariable{start: intValue(value, "start"), end: intValue(value, "end"), name: intValue(value, "name")}
		if rawChoices, ok := value["choices"].([]any); ok {
			for _, choice := range rawChoices {
				if stringChoice, valid := choice.(string); valid {
					variable.choices = append(variable.choices, stringChoice)
				}
			}
		}
		if variable.start >= 0 && variable.end >= variable.start && variable.end <= len(text) && variable.name >= 0 {
			variables = append(variables, variable)
		}
	}
	if len(variables) == 0 {
		return nil
	}
	sort.SliceStable(variables, func(a, b int) bool { return variables[a].start < variables[b].start })
	editStart, editEnd := variables[0].start, variables[0].end
	for _, variable := range variables[1:] {
		if variable.start < editStart {
			editStart = variable.start
		}
		if variable.end > editEnd {
			editEnd = variable.end
		}
	}
	doc := textdoc.NewDocument(uri, uriutil.LanguageID(string(uri)), 0, text)
	if doc.Position(editStart).Line != doc.Position(editEnd).Line {
		editStart = lineStart(text, editStart)
	}
	var snippet strings.Builder
	cursor := editStart
	for _, variable := range variables {
		if variable.start < cursor {
			continue
		}
		snippet.WriteString(escapeSnippet(text[cursor:variable.start], false))
		snippet.WriteString("${")
		snippet.WriteString(strconv.Itoa(variable.name))
		if len(variable.choices) > 0 {
			snippet.WriteByte('|')
			for index, choice := range variable.choices {
				if index > 0 {
					snippet.WriteByte(',')
				}
				snippet.WriteString(escapeSnippet(choice, true))
			}
			snippet.WriteByte('|')
		} else if variable.start != variable.end {
			snippet.WriteByte(':')
			snippet.WriteString(escapeSnippet(text[variable.start:variable.end], false))
		}
		snippet.WriteByte('}')
		cursor = variable.end
	}
	snippet.WriteString(escapeSnippet(text[cursor:editEnd], false))
	if !s.clientCapabilityBool("workspace", "workspaceEdit", "snippetEditSupport") {
		return s.applyWorkspaceEdit(ctx, "Run snippet in "+fileURL, protocol.WorkspaceEdit{Changes: map[protocol.URI][]protocol.TextEdit{uri: {{Range: doc.Range(editStart, editEnd), NewText: text[editStart:editEnd]}}}})
	}
	edit := protocol.TextEdit{Range: doc.Range(editStart, editEnd), NewText: text[editStart:editEnd], Snippet: snippet.String()}
	return s.applyWorkspaceEdit(ctx, "Run snippet in "+fileURL, protocol.WorkspaceEdit{DocumentChanges: []any{protocol.TextDocumentEdit{TextDocument: protocol.OptionalVersionedTextDocumentIdentifier{URI: uri}, Edits: []protocol.TextEdit{edit}}}})
}

func escapeSnippet(value string, choice bool) string {
	replacer := strings.NewReplacer("\\", "\\\\", "}", "\\}", "$", "\\$")
	value = replacer.Replace(value)
	if choice {
		value = strings.NewReplacer(",", "\\,", "|", "\\|").Replace(value)
	}
	return value
}

func (s *Server) applyCompletionCommand(ctx context.Context, command string, args []json.RawMessage) (any, *jsonrpc.ResponseError) {
	if len(args) != 1 {
		return nil, invalidParams(fmt.Errorf("missing completion application data"))
	}
	if command == "jetbrains.kotlin.completion.apply" {
		var id int64
		if json.Unmarshal(args[0], &id) != nil || id <= 0 {
			return nil, invalidParams(fmt.Errorf("Kotlin completion requires one numeric CompletionItemId"))
		}
		s.completionMu.Lock()
		application, ok := s.completionSessions[id]
		if ok && !application.Created.IsZero() && time.Since(application.Created) > transientSessionTTL {
			ok = false
		}
		if ok {
			delete(s.completionSessions, id)
		}
		s.completionMu.Unlock()
		if !ok {
			return nil, &jsonrpc.ResponseError{Code: -32803, Message: "completion session has expired"}
		}
		if application.Edit != nil {
			if err := s.applyWorkspaceEdit(ctx, "Apply Kotlin completion", *application.Edit); err != nil {
				return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
			}
		}
		return true, nil
	}
	var data map[string]any
	if json.Unmarshal(args[0], &data) != nil {
		return nil, invalidParams(fmt.Errorf("invalid completion application data"))
	}
	// Java's extension argument is exactly a ModCommandData DTO.
	if commandKind(data) != "" {
		if err := s.executeModCommandState(ctx, data, make(map[string]string)); err != nil {
			return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
		}
		return true, nil
	}
	// Compatibility with pre-v3 clients which embedded a workspace edit.
	if rawEdit, ok := data["edit"]; ok {
		encoded, _ := json.Marshal(rawEdit)
		var edit protocol.WorkspaceEdit
		if json.Unmarshal(encoded, &edit) == nil {
			if err := s.applyWorkspaceEdit(ctx, "Apply completion", edit); err != nil {
				return nil, &jsonrpc.ResponseError{Code: jsonrpc.InternalError, Message: err.Error()}
			}
		}
	}
	return true, nil
}

func (s *Server) pruneModSessionsLocked(now time.Time) {
	for id, created := range s.modSessionCreated {
		if now.Sub(created) > transientSessionTTL {
			delete(s.modSessionCreated, id)
			delete(s.modSessions, id)
		}
	}
	for len(s.modSessions) > 256 {
		oldestID, oldest := int64(0), now
		for id := range s.modSessions {
			created := s.modSessionCreated[id]
			if created.IsZero() || !created.After(oldest) {
				oldestID, oldest = id, created
			}
		}
		delete(s.modSessions, oldestID)
		delete(s.modSessionCreated, oldestID)
	}
}

func (s *Server) applyWorkspaceEdit(ctx context.Context, label string, edit protocol.WorkspaceEdit) error {
	var response struct {
		Applied       bool   `json:"applied"`
		FailureReason string `json:"failureReason"`
	}
	if err := s.callClient(ctx, "workspace/applyEdit", map[string]any{"label": label, "edit": edit}, &response); err != nil {
		return err
	}
	if !response.Applied {
		return fmt.Errorf("client rejected workspace edit: %s", response.FailureReason)
	}
	return nil
}

func (s *Server) clientRequest(ctx context.Context, method string, params any) error {
	return s.callClient(ctx, method, params, nil)
}

func (s *Server) callClient(ctx context.Context, method string, params, result any) error {
	if s.clientCall != nil {
		return s.clientCall(ctx, method, params, result)
	}
	if s.conn == nil {
		return fmt.Errorf("client request %s requires an active JSON-RPC connection", method)
	}
	return s.conn.Request(ctx, method, params, result)
}

func commandKind(command map[string]any) string {
	for _, key := range []string{"type", "kind", "command"} {
		if value, ok := command[key].(string); ok {
			return strings.ToLower(value)
		}
	}
	return ""
}

func stringValue(value map[string]any, key string) string {
	text, _ := value[key].(string)
	return text
}

func intValue(value map[string]any, key string) int {
	switch number := value[key].(type) {
	case float64:
		return int(number)
	case int:
		return number
	case json.Number:
		v, _ := strconv.Atoi(string(number))
		return v
	default:
		return -1
	}
}

func lspURI(value string) protocol.URI {
	if strings.HasPrefix(value, "file:") || strings.HasPrefix(value, "jar:") || strings.HasPrefix(value, "jrt:") {
		return protocol.URI(value)
	}
	if runtime.GOOS == "windows" && len(value) >= 2 && value[1] == ':' {
		return uriutil.File(value)
	}
	return uriutil.File(value)
}
