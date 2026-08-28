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
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		if runtime.GOOS != "windows" || strings.ContainsAny(u.Host, "/\\") {
			return "", false
		}
		p = "//" + u.Host + "/" + strings.TrimPrefix(p, "/")
	}
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

func File(path string) protocol.URI {
	path, _ = filepath.Abs(path)
	slashed := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && strings.HasPrefix(slashed, "//") {
		rest := strings.TrimPrefix(slashed, "//")
		if cut := strings.IndexByte(rest, '/'); cut > 0 {
			u := url.URL{Scheme: "file", Host: rest[:cut], Path: "/" + rest[cut+1:]}
			return protocol.URI(u.String())
		}
	}
	u := url.URL{Scheme: "file", Path: slashed}
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
