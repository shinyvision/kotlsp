package index

import (
	"archive/zip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// builtinSources holds the declarations of Kotlin's built-in types. The
// compiler keeps them in .kotlin_builtins resources, so no class file declares
// Any, Enum, String, the numeric types, arrays or the collection interfaces;
// the only place their source exists is the stdlib sources jar. A project that
// never downloaded that jar would otherwise have none of them -- no members on
// a List, an Int or an enum -- so a copy ships inside the server.
//
//go:embed builtins/kotlin/*.kt
var builtinSources embed.FS

// builtinSourcesArchive writes the embedded declarations as a sources jar in
// the user cache and returns its path. The file name carries a content hash, so
// an upgrade writes a new jar and the old one is never read half-replaced. The
// "kotlin-stdlib" in the name is what routes it through the same builtin
// selection a real stdlib sources jar goes through.
func builtinSourcesArchive() (string, error) {
	names, err := fs.Glob(builtinSources, "builtins/kotlin/*.kt")
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	digest := sha256.New()
	contents := make(map[string][]byte, len(names))
	for _, name := range names {
		data, readErr := builtinSources.ReadFile(name)
		if readErr != nil {
			return "", readErr
		}
		contents[name] = data
		digest.Write([]byte(name))
		digest.Write(data)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(cacheRoot, "kotlsp", "builtins")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	archivePath := filepath.Join(directory, "kotlin-stdlib-builtins-"+hex.EncodeToString(digest.Sum(nil))[:12]+"-sources.jar")
	if info, statErr := os.Stat(archivePath); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
		return archivePath, nil
	}
	temporary, err := os.CreateTemp(directory, "builtins-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(temporary.Name())
	writer := zip.NewWriter(temporary)
	for _, name := range names {
		entry, createErr := writer.Create("kotlin/" + path.Base(name))
		if createErr != nil {
			temporary.Close()
			return "", createErr
		}
		if _, writeErr := entry.Write(contents[name]); writeErr != nil {
			temporary.Close()
			return "", writeErr
		}
	}
	if err := writer.Close(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporary.Name(), archivePath); err != nil {
		return "", err
	}
	return archivePath, nil
}

// hasKotlinStdlibSources reports whether a real stdlib sources archive is
// already among the source archives.
func hasKotlinStdlibSources(archives []sourceArchive) bool {
	for _, archive := range archives {
		if kotlinBuiltinSourceArchive(archive) {
			return true
		}
	}
	return false
}
