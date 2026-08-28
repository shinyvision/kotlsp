package index

import (
	"sort"
	"strings"
)

// nameIndex is the shared string-index machinery behind the workspace-symbol
// and completion families: a name -> values map plus the satellites that keep
// candidate scans cheap -- the first-use name registration (known/names), an
// initial-letter and short-prefix bucket, and, when trackChars is set, an
// any-position character bucket for fuzzy queries.
//
// Locking follows the package's Locked convention: every method expects the
// caller to hold Index.mu, so none carry the suffix themselves.
type nameIndex[T any] struct {
	byName     map[string][]T
	known      map[string]bool
	names      []string
	byInitial  map[byte][]string
	byPrefix   map[string][]string
	trackChars bool
	byChar     map[byte][]string
	deadNames  map[string]bool
	deadCount  int
}

func newNameIndex[T any](trackChars bool) nameIndex[T] {
	n := nameIndex[T]{trackChars: trackChars}
	n.clear()
	return n
}

func (n *nameIndex[T]) clear() {
	n.byName = make(map[string][]T)
	n.known = make(map[string]bool)
	n.names = nil
	n.byInitial = make(map[byte][]string)
	n.byPrefix = make(map[string][]string)
	n.byChar = make(map[byte][]string)
	n.deadNames = make(map[string]bool)
	n.deadCount = 0
}

// insert appends value under name, registering name and its satellites the
// first time the bucket is filled.
func (n *nameIndex[T]) insert(name string, value T) {
	if name == "" || len(name) > 4096 {
		return
	}
	if len(n.byName[name]) == 0 {
		n.add(name)
	}
	n.byName[name] = append(n.byName[name], value)
}

func (n *nameIndex[T]) add(name string) {
	if n.known[name] {
		return
	}
	if n.deadNames[name] {
		delete(n.deadNames, name)
		n.deadCount--
		n.known[name] = true
		return
	}
	n.known[name] = true
	n.names = append(n.names, name)
	lower := strings.ToLower(name)
	if len(lower) > 0 && lower[0] < 128 {
		n.byInitial[lower[0]] = append(n.byInitial[lower[0]], name)
		for length := 1; length <= 3 && length <= len(lower); length++ {
			key, ok := asciiPrefix(lower, length)
			if !ok {
				break
			}
			n.byPrefix[key] = append(n.byPrefix[key], name)
		}
	}
	if !n.trackChars {
		return
	}
	var seen [128]bool
	for k := 0; k < len(lower); k++ {
		char := lower[k]
		if char >= 128 || seen[char] {
			continue
		}
		seen[char] = true
		n.byChar[char] = append(n.byChar[char], name)
	}
}

// removeValues drops the values removed reports true for from the buckets
// named by keys, deleting buckets left empty.
func (n *nameIndex[T]) removeValues(keys map[string]bool, removed func(T) bool) {
	for key := range keys {
		bucket := n.byName[key]
		out := bucket[:0]
		for _, value := range bucket {
			if !removed(value) {
				out = append(out, value)
			}
		}
		if len(out) == 0 {
			delete(n.byName, key)
			if n.known[key] {
				delete(n.known, key)
				n.deadNames[key] = true
				n.deadCount++
			}
		} else {
			n.byName[key] = out
		}
	}
	if n.deadCount > 1024 && n.deadCount*4 > len(n.names) {
		n.rebuildSatellites()
	}
}

func (n *nameIndex[T]) rebuildSatellites() {
	names := make([]string, 0, len(n.byName))
	for name, values := range n.byName {
		if len(values) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	n.known = make(map[string]bool, len(names))
	n.names = nil
	n.byInitial = make(map[byte][]string)
	n.byPrefix = make(map[string][]string)
	n.byChar = make(map[byte][]string)
	n.deadNames = make(map[string]bool)
	n.deadCount = 0
	for _, name := range names {
		n.add(name)
	}
}

// get returns the values indexed under name.
func (n *nameIndex[T]) get(name string) []T {
	return n.byName[name]
}

// allNames returns every registered name in registration order.
func (n *nameIndex[T]) allNames() []string {
	return n.names
}

// charBucket returns the registered names containing the byte c at any
// position. It is populated only when trackChars is set.
func (n *nameIndex[T]) charBucket(c byte) []string {
	return n.byChar[c]
}

// initialBucket returns the registered names whose lowercase form starts with
// the byte c.
func (n *nameIndex[T]) initialBucket(c byte) []string {
	return n.byInitial[c]
}

// prefixBucket returns the registered names whose lowercase form starts with
// the (1-3 byte ASCII) key.
func (n *nameIndex[T]) prefixBucket(key string) []string {
	return n.byPrefix[key]
}
