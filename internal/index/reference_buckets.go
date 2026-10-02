package index

import (
	"sort"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// referenceBuckets indexes references by a key (a name or a resolved target),
// grouped by the file that holds them. An edit replaces one file's
// references, and with one flat slice per key every replacement scanned all
// the workspace's references of that name -- `it`, `map`, `name` -- while the
// write lock held every request back. Grouped by file, replacing a reference
// looks only at its own file's references of that key.
type referenceBuckets map[string]map[protocol.URI][]analysis.Reference

func (b referenceBuckets) add(key string, reference analysis.Reference) {
	files := b[key]
	if files == nil {
		files = make(map[protocol.URI][]analysis.Reference, 1)
		b[key] = files
	}
	files[reference.URI] = append(files[reference.URI], reference)
}

func (b referenceBuckets) position(key string, wanted analysis.Reference) int {
	for index, candidate := range b[key][wanted.URI] {
		if candidate.StartByte == wanted.StartByte && candidate.EndByte == wanted.EndByte && candidate.Name == wanted.Name {
			return index
		}
	}
	return -1
}

func (b referenceBuckets) remove(key string, wanted analysis.Reference) {
	files := b[key]
	references := files[wanted.URI]
	position := b.position(key, wanted)
	if position < 0 {
		return
	}
	references = append(references[:position:position], references[position+1:]...)
	if len(references) == 0 {
		delete(files, wanted.URI)
		if len(files) == 0 {
			delete(b, key)
		}
		return
	}
	files[wanted.URI] = references
}

func (b referenceBuckets) replace(key string, old, replacement analysis.Reference) {
	if position := b.position(key, old); position >= 0 && old.URI == replacement.URI {
		b[key][old.URI][position] = replacement
		return
	}
	b.remove(key, old)
	b.add(key, replacement)
}

// get returns every reference under key, ordered by file. The slice is the
// caller's to keep.
func (b referenceBuckets) get(key string) []analysis.Reference {
	files := b[key]
	if len(files) == 0 {
		return nil
	}
	uris := make([]protocol.URI, 0, len(files))
	total := 0
	for uri, references := range files {
		uris = append(uris, uri)
		total += len(references)
	}
	sort.Slice(uris, func(left, right int) bool { return uris[left] < uris[right] })
	out := make([]analysis.Reference, 0, total)
	for _, uri := range uris {
		out = append(out, files[uri]...)
	}
	return out
}

func (b referenceBuckets) count(key string) int {
	total := 0
	for _, references := range b[key] {
		total += len(references)
	}
	return total
}

// take removes and returns every reference under key.
func (b referenceBuckets) take(key string) []analysis.Reference {
	out := b.get(key)
	delete(b, key)
	return out
}

// dropFile removes a file's references under key.
func (b referenceBuckets) dropFile(key string, uri protocol.URI) {
	files := b[key]
	if files == nil {
		return
	}
	delete(files, uri)
	if len(files) == 0 {
		delete(b, key)
	}
}
