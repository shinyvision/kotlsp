package lsp

import (
	"sort"
	"sync"
	"sync/atomic"
)

var requestCounts sync.Map // method -> *atomic.Int64

func countRequest(method string) {
	counter, _ := requestCounts.LoadOrStore(method, new(atomic.Int64))
	counter.(*atomic.Int64).Add(1)
}

// RequestCounts returns how many requests and notifications of each method the
// server has received, for diagnosing a client that keeps asking for something.
func RequestCounts() (methods []string, counts map[string]int64) {
	counts = make(map[string]int64)
	requestCounts.Range(func(key, value any) bool {
		counts[key.(string)] = value.(*atomic.Int64).Load()
		methods = append(methods, key.(string))
		return true
	})
	sort.Slice(methods, func(a, b int) bool { return counts[methods[a]] > counts[methods[b]] })
	return methods, counts
}
