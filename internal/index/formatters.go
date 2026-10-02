package index

import (
	"strings"

	"github.com/shinyvision/kotlsp/internal/protocol"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// FormatterFor returns the build's formatter for a document: the module's
// Spotless "kotlin" step for sources, its "kotlinGradle" step for build
// scripts. false means the build declares none, and the server's own
// formatter is the only option.
func (i *Index) FormatterFor(uri protocol.URI) (FormatterSpec, bool) {
	path, ok := uriutil.Path(uri)
	if !ok {
		return FormatterSpec{}, false
	}
	format := "kotlin"
	switch {
	case strings.HasSuffix(path, ".kts"):
		format = "kotlinGradle"
	case !strings.HasSuffix(path, ".kt"):
		return FormatterSpec{}, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	module := i.moduleForURILocked(uri)
	if module == nil {
		return FormatterSpec{}, false
	}
	for _, spec := range module.Formatters {
		if spec.Format == format && len(spec.Classpath) > 0 {
			return spec, true
		}
	}
	return FormatterSpec{}, false
}
