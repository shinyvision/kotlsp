package index

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
)

// checkInvariantsLocked verifies that every secondary map refers only to
// symbols that exist. The maps are maintained by hand alongside i.symbols; an
// entry left behind by a mutation is a nil dereference waiting for whichever
// feature reads it next. Tests call this after mutations; it is not on any
// request path.
func (i *Index) checkInvariantsLocked() []string {
	var problems []string
	// Every library file is grouped under its archive, and only there.
	grouped := 0
	for archive, uris := range i.libraryURIsByArchive {
		for uri := range uris {
			grouped++
			if source, ok := i.librarySources[uri]; !ok || filepath.Clean(source.Archive) != archive {
				problems = append(problems, "libraryURIsByArchive["+archive+"] lists "+string(uri)+", which is not that archive's")
			}
		}
	}
	if grouped != len(i.librarySources) {
		problems = append(problems, "libraryURIsByArchive groups "+strconv.Itoa(grouped)+" library files of "+strconv.Itoa(len(i.librarySources)))
	}
	buckets := []struct {
		name  string
		index map[string][]string
	}{
		{"byName", i.byName}, {"byFQN", i.byFQN}, {"bySuper", i.bySuper}, {"bySuperID", i.bySuperID},
		{"byContainerName", i.byContainerName}, {"byContainerMember", i.byContainerMember},
		{"byReceiver", i.byReceiver}, {"byReceiverMember", i.byReceiverMember},
		{"byGenericReceiverMember", i.byGenericReceiverMember}, {"byOrigin", i.byOrigin}, {"byPackage", i.byPackage},
	}
	for _, bucket := range buckets {
		keys := make([]string, 0, len(bucket.index))
		for key := range bucket.index {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			for _, id := range bucket.index[key] {
				if i.symbols[id] == nil {
					problems = append(problems, fmt.Sprintf("%s[%q] holds %q, which is not a symbol", bucket.name, key, id))
					if len(problems) >= 20 {
						return problems
					}
				}
			}
		}
	}
	// A member is filed under its own container only. An entry under any
	// other key is stale: it outlives the symbol's move and dangles once the
	// symbol is removed.
	for key, ids := range i.byContainerName {
		for _, id := range ids {
			if symbol := i.symbols[id]; symbol != nil && symbol.ContainerID != key && symbol.ContainerName != key {
				problems = append(problems, fmt.Sprintf("byContainerName[%q] holds %q, whose containers are %q and %q", key, id, symbol.ContainerID, symbol.ContainerName))
				if len(problems) >= 20 {
					return problems
				}
			}
		}
	}
	for key, ids := range i.byContainerMember {
		for _, id := range ids {
			if symbol := i.symbols[id]; symbol != nil && key != memberKey(symbol.ContainerID, symbol.Name) && key != memberKey(symbol.ContainerName, symbol.Name) {
				problems = append(problems, fmt.Sprintf("byContainerMember[%q] holds %q, which is not that member", key, id))
				if len(problems) >= 20 {
					return problems
				}
			}
		}
	}
	return problems
}
