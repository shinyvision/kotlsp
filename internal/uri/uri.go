package uri

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Path converts a file URI to a filesystem path. Resolution does this for the
// same few thousand URIs millions of times, and parsing and unescaping each
// time was a visible share of a project-wide query, so results are kept
// (bounded).
func Path(value protocol.URI) (string, bool) {
	pathCache.RLock()
	cached, ok := pathCache.values[value]
	pathCache.RUnlock()
	if ok {
		return cached.path, cached.ok
	}
	path, valid := parsePath(value)
	pathCache.Lock()
	if pathCache.values == nil || len(pathCache.values) >= 100_000 {
		pathCache.values = make(map[protocol.URI]cachedPath)
	}
	pathCache.values[value] = cachedPath{path, valid}
	pathCache.Unlock()
	return path, valid
}

type cachedPath struct {
	path string
	ok   bool
}

var pathCache struct {
	sync.RWMutex
	values map[protocol.URI]cachedPath
}

func parsePath(value protocol.URI) (string, bool) {
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
