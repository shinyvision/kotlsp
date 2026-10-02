package index

import (
	"context"
	"runtime"
	"sort"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

const (
	// Sampling costs a stop-the-world ReadMemStats, and pressure builds over
	// minutes rather than milliseconds.
	memoryPressureInterval = 15 * time.Second
	// Act before the collector starts fighting the limit rather than after.
	memoryPressureHighWater = 0.85
	// A bounded sweep keeps the index write lock for a predictable time; the
	// next tick continues if pressure remains.
	memoryPressureEvictionBudget = 512
)

// startMemoryPressureWatch drops cold library caches when the heap approaches
// the limit the runtime is actually enforcing.
//
// Only two kinds of state are evictable, because each has a proven path that
// rebuilds it on next use, so eviction costs a reload rather than a wrong
// answer: libraryDocs, which DocumentContext reloads from the archive, and a
// library file's References, which ensureLibraryReferencesContext re-parses
// whenever it finds them empty.
//
// Symbols are deliberately never evicted. Nothing re-indexes an archive when a
// name lookup misses, so dropping them would make go-to-definition answer "no
// locations found" until something unrelated happened to rebuild that archive.
// That is a worse failure than the memory it would reclaim.
func (i *Index) startMemoryPressureWatch() {
	ctx, finish, started := i.beginBackground(context.Background())
	if !started {
		return
	}
	go func() {
		defer i.recoverBackground("startMemoryPressureWatch")
		defer finish()
		ticker := time.NewTicker(memoryPressureInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if i.closed.Load() {
					return
				}
				i.relieveMemoryPressure()
			}
		}
	}()
}

// heapPressure measures the live heap against the limit in force, which is the
// coordinator's effective limit rather than the configured ceiling: a child JVM
// holding its reservation lowers the real limit while it runs.
func heapPressure() (float64, uint64, int64) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	limit := resourcebudget.Current().EffectiveGoSoftLimit
	if limit <= 0 {
		return 0, stats.HeapInuse, limit
	}
	return float64(stats.HeapInuse) / float64(limit), stats.HeapInuse, limit
}

func (i *Index) relieveMemoryPressure() {
	before, _, _ := heapPressure()
	if before < memoryPressureHighWater {
		return
	}
	dropped := i.evictColdLibraryCaches(memoryPressureEvictionBudget)
	if dropped == 0 {
		// Nothing cheap left to drop: what is resident is the symbol index,
		// which this sweep never touches.
		i.recordHealth("memory-pressure", "library cache", "the heap is at "+percentText(before)+" of its enforced limit and no evictable library cache entry remains; the resident cost is the symbol index, which is never evicted because no path re-indexes an archive on a missed lookup")
		return
	}
	// The sweep only unlinks; the collector returns the memory, and the report
	// should describe the result rather than the state before it.
	runtime.GC()
	after, heap, limit := heapPressure()
	i.recordHealth("memory-pressure", "library cache", "evicted "+itoa(dropped)+" cold library cache entries at "+percentText(before)+" of the enforced heap limit; now "+percentText(after)+" ("+itoa64(int64(heap))+" of "+itoa64(limit)+" bytes)")
}

func percentText(value float64) string {
	return itoa(int(value*100+0.5)) + "%"
}

// evictColdLibraryCaches drops the least recently used library documents and
// their reference lists, oldest first, returning how many entries it unlinked.
// An entry with no recorded use is maximally cold: it was never read, or last
// read before the current recency epoch.
func (i *Index) evictColdLibraryCaches(budget int) int {
	if budget <= 0 {
		return 0
	}
	type candidate struct {
		uri  protocol.URI
		used int64
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	candidates := make([]candidate, 0, len(i.libraryDocs))
	for uri := range i.libraryDocs {
		if i.docs[uri] != nil {
			// An open buffer is never cold, whatever its provenance.
			continue
		}
		used := int64(0)
		if value, ok := i.libraryCacheUse.Load(uri); ok {
			used, _ = value.(int64)
		}
		candidates = append(candidates, candidate{uri: uri, used: used})
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].used < candidates[right].used })
	dropped := 0
	for _, entry := range candidates {
		if dropped >= budget {
			break
		}
		delete(i.libraryDocs, entry.uri)
		i.libraryCacheUse.Delete(entry.uri)
		dropped++
	}
	if dropped > 0 {
		// A library file's references rebuild from its document, so they are
		// dropped on the same schedule. The working-set order keeps whatever
		// still has a resident document.
		retained := i.libraryReferenceOrder[:0]
		for _, uri := range i.libraryReferenceOrder {
			if _, live := i.libraryDocs[uri]; live {
				retained = append(retained, uri)
				continue
			}
			if file := i.files[uri]; file != nil && len(file.References) > 0 {
				file.References = nil
				i.fileCursorSpans[uri] = buildCursorSpans(file)
			}
		}
		i.libraryReferenceOrder = retained
	}
	return dropped
}

// noteLibraryCacheUse records that a library document was read. Every caller
// holds the index lock in read mode, so this must not touch index state: the
// side table is lock-free and the clock is atomic. A lost update only makes an
// entry look slightly colder than it is, which costs a reload and nothing else.
func (i *Index) noteLibraryCacheUse(uri protocol.URI) {
	i.libraryCacheUse.Store(uri, i.libraryCacheClock.Add(1))
}
