package uri

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func Path(value protocol.URI) (string, bool) {
	u, err := url.Parse(string(value))
	if err != nil || u.Scheme != "file" {
		return "", false
	}
	p, err := url.PathUnescape(u.Path)
	if err != nil {
		return "", false
	}
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

func File(path string) protocol.URI {
	path, _ = filepath.Abs(path)
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	return protocol.URI(u.String())
}

func LanguageID(path string) string {
	path = strings.ToLower(path)
	if strings.HasSuffix(path, ".kt") || strings.HasSuffix(path, ".kts") {
		return "kotlin"
	}
	if strings.HasSuffix(path, ".java") {
		return "java"
	}
	return ""
}

func Base(value protocol.URI) string {
	if p, ok := Path(value); ok {
		return filepath.Base(p)
	}
	s := string(value)
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}
