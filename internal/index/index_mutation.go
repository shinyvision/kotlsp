package index

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) AddLibraryBatch(files []LibraryFile) {
	if i.closed.Load() {
		return
	}
	i.addLibraryBatch(files, i.generation.Load())
}

// stabilizeFileSymbolIDs preserves declaration identities across edits which
// move byte offsets but leave the declaration's semantic shape unchanged.
// Ambiguous duplicate shapes deliberately keep fresh parser IDs: guessing
// would be worse than invalidating that small family.
func stabilizeFileSymbolIDs(old, replacement *analysis.ParsedFile) {
	if old == nil || replacement == nil {
		return
	}
	oldByKey := make(map[string][]string)
	newByKey := make(map[string][]int)
	for _, symbol := range old.Symbols {
		oldByKey[stableSymbolShape(symbol)] = append(oldByKey[stableSymbolShape(symbol)], symbol.ID)
	}
	for index, symbol := range replacement.Symbols {
		newByKey[stableSymbolShape(symbol)] = append(newByKey[stableSymbolShape(symbol)], index)
	}
	freshIDOwner := make(map[string]int, len(replacement.Symbols))
	for index, symbol := range replacement.Symbols {
		freshIDOwner[symbol.ID] = index
	}
	remapped := make(map[string]string)
	for key, newIndexes := range newByKey {
		oldIDs := oldByKey[key]
		// Multiple declarations with the same semantic shape have no stable
		// pairing proof. Preserve neither rather than assigning IDs by incidental
		// parser order.
		if len(oldIDs) != 1 || len(newIndexes) != 1 {
			continue
		}
		index := newIndexes[0]
		freshID, stableID := replacement.Symbols[index].ID, oldIDs[0]
		if owner, occupied := freshIDOwner[stableID]; occupied && owner != index {
			// A newly inserted declaration may naturally receive the old byte-based
			// ID. Do not create duplicate IDs while stabilizing a moved symbol.
			continue
		}
		replacement.Symbols[index].ID = stableID
		remapped[freshID] = stableID
	}
	for index := range replacement.Symbols {
		symbol := &replacement.Symbols[index]
		if stable, ok := remapped[symbol.ContainerID]; ok {
			symbol.ContainerID = stable
		}
		if stable, ok := remapped[symbol.OriginID]; ok {
			symbol.OriginID = stable
		}
	}
	for index := range replacement.References {
		reference := &replacement.References[index]
		if stable, ok := remapped[reference.ContainerID]; ok {
			reference.ContainerID = stable
		}
		if stable, ok := remapped[reference.ResolvedID]; ok {
			reference.ResolvedID = stable
		}
	}
}

func stableSymbolShape(symbol analysis.Symbol) string {
	var value strings.Builder
	write := func(part string) {
		value.WriteString(part)
		value.WriteByte(0)
	}
	write(strconv.Itoa(int(symbol.Kind)))
	write(symbol.Name)
	write(symbol.FQN)
	write(symbol.ContainerName)
	write(symbol.Type)
	write(symbol.ReceiverType)
	write(symbol.Signature)
	write(strings.Join(symbol.TypeParameters, ","))
	write(strings.Join(symbol.Supertypes, ","))
	write(strings.Join(symbol.Modifiers, ","))
	for _, parameter := range symbol.Parameters {
		write(parameter.Name)
		write(parameter.Type)
		write(strconv.FormatBool(parameter.Variadic))
	}
	boundNames := make([]string, 0, len(symbol.TypeParameterBounds))
	for name := range symbol.TypeParameterBounds {
		boundNames = append(boundNames, name)
	}
	sort.Strings(boundNames)
	for _, name := range boundNames {
		write(name)
		write(strings.Join(symbol.TypeParameterBounds[name], ","))
	}
	return value.String()
}

func symbolBucketShape(symbol analysis.Symbol) string {
	var value strings.Builder
	// A declaration may retain the same byte-derived ID while its callable or
	// type shape changes. Treating that as an unchanged bucket leaves external
	// references resolved to a declaration which no longer accepts the call.
	// Start with the complete semantic shape used by stable-ID matching, then
	// append index-visibility fields which do not participate in ID stability.
	value.WriteString(stableSymbolShape(symbol))
	value.WriteString(symbol.OriginID)
	value.WriteByte(0)
	value.WriteString(symbol.Package)
	value.WriteByte(0)
	value.WriteString(symbol.JVMName)
	value.WriteByte(0)
	value.WriteString(symbol.JVMDescriptor)
	value.WriteByte(0)
	value.WriteString(strconv.Itoa(int(symbol.InteropLanguage)))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(symbol.Synthetic))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(symbol.Library))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(symbol.Provisional))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(symbol.Deprecated))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(isLexicalSymbol(symbol)))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(isWorkspaceSymbol(symbol)))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(isUnqualifiedCompletionSymbol(symbol)))
	return value.String()
}

func (i *Index) replaceFileDeltaLocked(old, replacement *analysis.ParsedFile) {
	oldSymbols := make(map[string]analysis.Symbol, len(old.Symbols))
	newSymbols := make(map[string]*analysis.Symbol, len(replacement.Symbols))
	for _, symbol := range old.Symbols {
		oldSymbols[symbol.ID] = symbol
	}
	for index := range replacement.Symbols {
		symbol := &replacement.Symbols[index]
		newSymbols[symbol.ID] = symbol
	}
	var removals []analysis.Symbol
	for id, symbol := range oldSymbols {
		replacementSymbol := newSymbols[id]
		if replacementSymbol == nil || symbolBucketShape(symbol) != symbolBucketShape(*replacementSymbol) {
			removals = append(removals, symbol)
		}
	}
	batch := newBucketRemoval(removals)
	for _, symbol := range removals {
		i.removeSymbolIndicesBatchLocked(symbol, replacement.URI, batch)
	}
	// Publish the replacement file pointer inside the already-exclusive
	// mutation transaction before deriving new hierarchy/type identities. The
	// old value remains available through the caller's `old` snapshot for the
	// removal phase above.
	i.files[replacement.URI] = replacement
	// Hierarchy and receiver indices resolve same-file declarations while each
	// new symbol is added. Publish the replacement's lexical inventory first;
	// otherwise those lookups observe the removed snapshot and miss edges when
	// a parent and child are introduced by the same edit.
	i.rebuildFileLocalIndicesLocked(replacement)
	for id, symbol := range newSymbols {
		oldSymbol, existed := oldSymbols[id]
		if !existed || symbolBucketShape(oldSymbol) != symbolBucketShape(*symbol) {
			i.addSymbolIndicesLocked(symbol)
		} else {
			i.symbols[id] = symbol
		}
	}

	i.fileCursorSpans[replacement.URI] = buildCursorSpans(replacement)
	i.prepareFileReferencesLocked(replacement)
	i.replaceReferenceDeltaLocked(old, replacement)
	i.replaceImportDeltaLocked(old, replacement)
}

func (i *Index) rebuildFileLocalIndicesLocked(file *analysis.ParsedFile) {
	if _, library := i.librarySources[file.URI]; library {
		delete(i.fileSymbolsByName, file.URI)
		delete(i.fileAnonymousByName, file.URI)
		delete(i.fileSmartCastsByName, file.URI)
		return
	}
	fileSymbols := make(map[string][]*analysis.Symbol)
	fileAnonymous := make(map[string][]*analysis.Symbol)
	for index := range file.Symbols {
		symbol := &file.Symbols[index]
		fileSymbols[symbol.Name] = append(fileSymbols[symbol.Name], symbol)
		if strings.HasPrefix(strings.TrimSpace(symbol.Initializer), "object") {
			fileAnonymous[symbol.Name] = append(fileAnonymous[symbol.Name], symbol)
		}
	}
	for name := range fileSymbols {
		sort.SliceStable(fileSymbols[name], func(left, right int) bool {
			return fileSymbols[name][left].StartByte < fileSymbols[name][right].StartByte
		})
	}
	for name := range fileAnonymous {
		sort.SliceStable(fileAnonymous[name], func(left, right int) bool {
			return fileAnonymous[name][left].StartByte < fileAnonymous[name][right].StartByte
		})
	}
	i.fileSymbolsByName[file.URI] = fileSymbols
	i.fileAnonymousByName[file.URI] = fileAnonymous
	fileSmartCasts := make(map[string][]analysis.SmartCast)
	for _, smartCast := range file.SmartCasts {
		fileSmartCasts[smartCast.Name] = append(fileSmartCasts[smartCast.Name], smartCast)
	}
	i.fileSmartCastsByName[file.URI] = fileSmartCasts
}

// bucketRemoval batches the bucket edits of removing many identities at once.
// Removing a large file's declarations one identity at a time rescanned each
// shared spelling/container bucket per identity, which is quadratic in the
// bucket size; a batch filters every touched bucket exactly once.
type bucketRemoval struct {
	removed map[string]bool
	visited map[string]bool
}

func newBucketRemoval(symbols []analysis.Symbol) *bucketRemoval {
	batch := &bucketRemoval{removed: make(map[string]bool, len(symbols)), visited: make(map[string]bool)}
	for _, symbol := range symbols {
		batch.removed[symbol.ID] = true
	}
	return batch
}

func (i *Index) removeSymbolIndicesLocked(symbol analysis.Symbol, replacing protocol.URI) {
	i.removeSymbolIndicesBatchLocked(symbol, replacing, nil)
}

func (i *Index) removeSymbolIndicesBatchLocked(symbol analysis.Symbol, replacing protocol.URI, batch *bucketRemoval) {
	remove := func(name string, index map[string][]string, key string) {
		if batch == nil {
			removeStringID(index, key, symbol.ID)
			return
		}
		visit := name + "\x00" + key
		if batch.visited[visit] {
			return
		}
		batch.visited[visit] = true
		removeStringIDs(index, key, batch.removed)
	}
	directSuperIDs := i.directSupertypeIDsLocked(symbol)
	receiverIDs := i.receiverTypeIDsLocked(symbol)
	i.semanticVersion++
	i.semanticSymbolVersion[symbol.ID] = i.semanticVersion
	i.semanticNameVersion[symbol.Name] = i.semanticVersion
	delete(i.symbols, symbol.ID)
	if !isLexicalSymbol(symbol) {
		i.invalidateResolvedTargetLocked(symbol.ID, symbol.Name, replacing)
	}
	if symbol.Synthetic && symbol.OriginID == "" && symbol.InteropLanguage == analysis.LanguageUnknown || isLexicalSymbol(symbol) {
		return
	}
	remove("byName", i.byName, symbol.Name)
	if symbol.OriginID != "" {
		remove("byOrigin", i.byOrigin, symbol.OriginID)
	}
	if symbol.FQN != "" {
		remove("byFQN", i.byFQN, symbol.FQN)
	}
	if symbol.ContainerName != "" {
		remove("byContainerName", i.byContainerName, symbol.ContainerName)
		remove("byContainerMember", i.byContainerMember, memberKey(symbol.ContainerName, symbol.Name))
	}
	if symbol.ContainerID != "" {
		remove("byContainerName", i.byContainerName, symbol.ContainerID)
		remove("byContainerMember", i.byContainerMember, memberKey(symbol.ContainerID, symbol.Name))
	}
	if symbol.ReceiverType != "" {
		receiver := simpleType(symbol.ReceiverType)
		remove("byReceiver", i.byReceiver, receiver)
		remove("byReceiverMember", i.byReceiverMember, memberKey(receiver, symbol.Name))
		if typeContainsAnyParameter(symbol.ReceiverType, symbol.TypeParameters) {
			remove("byGenericReceiverMember", i.byGenericReceiverMember, symbol.Name)
		}
	}
	for _, receiverID := range receiverIDs {
		remove("byReceiver", i.byReceiver, receiverID)
		remove("byReceiverMember", i.byReceiverMember, memberKey(receiverID, symbol.Name))
	}
	if symbol.ContainerID == "" && symbol.Package != "" {
		remove("byPackage", i.byPackage, symbol.Package)
	}
	if isWorkspaceSymbol(symbol) {
		i.workspaceIndex.removeValues(map[string]bool{symbol.Name: true}, func(id string) bool { return id == symbol.ID })
	}
	if isUnqualifiedCompletionSymbol(symbol) {
		i.completionIndex.removeValues(map[string]bool{symbol.Name: true}, func(id string) bool { return id == symbol.ID })
	}
	for _, supertype := range symbol.Supertypes {
		simple := simpleType(supertype)
		remove("bySuper", i.bySuper, simple)
		if simple != supertype {
			remove("bySuper", i.bySuper, supertype)
		}
	}
	for _, superID := range directSuperIDs {
		remove("bySuperID", i.bySuperID, superID)
	}
	// If the removed declaration was itself a supertype, its identity cannot
	// remain a live hierarchy key. Children reconnect when that exact identity
	// is indexed again; raw spellings are never returned as semantic edges.
	delete(i.bySuperID, symbol.ID)
	delete(i.byReceiver, symbol.ID)
}

func (i *Index) addSymbolIndicesLocked(symbol *analysis.Symbol) {
	i.semanticVersion++
	i.semanticSymbolVersion[symbol.ID] = i.semanticVersion
	i.semanticNameVersion[symbol.Name] = i.semanticVersion
	// removeSymbolIndicesLocked clears every bucket entry of a removed
	// identity, so an identity absent from i.symbols cannot already sit in a
	// bucket. Scanning the bucket anyway made indexing a large file quadratic
	// in the size of its biggest spelling/container bucket.
	_, known := i.symbols[symbol.ID]
	appendID := func(values []string, value string) []string {
		if known {
			return appendUniqueString(values, value)
		}
		return append(values, value)
	}
	i.symbols[symbol.ID] = symbol
	if symbol.Synthetic && symbol.OriginID == "" && symbol.InteropLanguage == analysis.LanguageUnknown || isLexicalSymbol(*symbol) {
		return
	}
	i.byName[symbol.Name] = appendID(i.byName[symbol.Name], symbol.ID)
	if symbol.OriginID != "" {
		i.byOrigin[symbol.OriginID] = appendID(i.byOrigin[symbol.OriginID], symbol.ID)
	}
	if symbol.FQN != "" {
		i.byFQN[symbol.FQN] = appendID(i.byFQN[symbol.FQN], symbol.ID)
	}
	if symbol.ContainerName != "" {
		i.byContainerName[symbol.ContainerName] = appendID(i.byContainerName[symbol.ContainerName], symbol.ID)
		key := memberKey(symbol.ContainerName, symbol.Name)
		i.byContainerMember[key] = appendID(i.byContainerMember[key], symbol.ID)
	}
	if symbol.ContainerID != "" {
		i.byContainerName[symbol.ContainerID] = appendID(i.byContainerName[symbol.ContainerID], symbol.ID)
		key := memberKey(symbol.ContainerID, symbol.Name)
		i.byContainerMember[key] = appendID(i.byContainerMember[key], symbol.ID)
	}
	if symbol.ReceiverType != "" {
		receiver := simpleType(symbol.ReceiverType)
		i.byReceiver[receiver] = appendID(i.byReceiver[receiver], symbol.ID)
		key := memberKey(receiver, symbol.Name)
		i.byReceiverMember[key] = appendID(i.byReceiverMember[key], symbol.ID)
		if typeContainsAnyParameter(symbol.ReceiverType, symbol.TypeParameters) {
			i.byGenericReceiverMember[symbol.Name] = appendID(i.byGenericReceiverMember[symbol.Name], symbol.ID)
		}
	}
	for _, receiverID := range i.receiverTypeIDsLocked(*symbol) {
		i.byReceiver[receiverID] = appendID(i.byReceiver[receiverID], symbol.ID)
		i.byReceiverMember[memberKey(receiverID, symbol.Name)] = appendID(i.byReceiverMember[memberKey(receiverID, symbol.Name)], symbol.ID)
	}
	if symbol.ContainerID == "" && symbol.Package != "" {
		i.byPackage[symbol.Package] = appendID(i.byPackage[symbol.Package], symbol.ID)
	}
	if isWorkspaceSymbol(*symbol) {
		i.workspaceIndex.insert(symbol.Name, symbol.ID)
	}
	if isUnqualifiedCompletionSymbol(*symbol) {
		i.completionIndex.insert(symbol.Name, symbol.ID)
	}
	for _, supertype := range symbol.Supertypes {
		simple := simpleType(supertype)
		i.bySuper[simple] = appendID(i.bySuper[simple], symbol.ID)
		if simple != supertype {
			i.bySuper[supertype] = appendID(i.bySuper[supertype], symbol.ID)
		}
	}
	i.connectHierarchyIdentityLocked(*symbol)
}

func (i *Index) directSupertypeIDsLocked(symbol analysis.Symbol) []string {
	file := i.files[symbol.URI]
	if file == nil || len(symbol.Supertypes) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var result []string
	for _, declared := range symbol.Supertypes {
		for _, resolved := range i.resolveTypeSymbolsForOwnerLocked(file, declared, symbol) {
			if resolved.ID != "" && resolved.ID != symbol.ID && !seen[resolved.ID] {
				seen[resolved.ID] = true
				result = append(result, resolved.ID)
			}
		}
	}
	return result
}

func (i *Index) connectHierarchyIdentityLocked(symbol analysis.Symbol) {
	i.connectReceiverIdentityLocked(symbol)
	if len(symbol.Supertypes) > 0 {
		for _, superID := range i.directSupertypeIDsLocked(symbol) {
			i.bySuperID[superID] = appendUniqueString(i.bySuperID[superID], symbol.ID)
		}
	}
	if !analysis.IsTypeKind(symbol.Kind) {
		return
	}
	// A parent can be indexed after its children. The spelling bucket is only
	// a bounded candidate accelerator; every edge is proven against the exact
	// parent ID before entering the semantic hierarchy.
	candidates := append([]string(nil), i.bySuper[symbol.Name]...)
	if symbol.FQN != "" && symbol.FQN != symbol.Name {
		candidates = append(candidates, i.bySuper[symbol.FQN]...)
	}
	if len(candidates) > maxResolutionCandidates {
		i.recordHealth("hierarchy", symbol.FQN, "subtype spelling inventory exceeded its 512-symbol publication safety limit; unresolved edges were withheld")
		return
	}
	for _, childID := range candidates {
		child := i.symbols[childID]
		if child != nil && child.ID != symbol.ID && i.directSupertypeMatchesLocked(*child, symbol.ID) {
			i.bySuperID[symbol.ID] = appendUniqueString(i.bySuperID[symbol.ID], child.ID)
		}
	}
}

func (i *Index) receiverTypeIDsLocked(symbol analysis.Symbol) []string {
	if symbol.ReceiverType == "" {
		return nil
	}
	file := i.files[symbol.URI]
	if file == nil {
		return nil
	}
	base, _ := splitInstantiatedType(strings.TrimSuffix(strings.TrimSpace(symbol.ReceiverType), "?"))
	seen := make(map[string]bool)
	var ids []string
	for _, receiver := range i.resolveTypeSymbolsForOwnerLocked(file, base, symbol) {
		if receiver.ID != "" && !seen[receiver.ID] {
			seen[receiver.ID] = true
			ids = append(ids, receiver.ID)
		}
	}
	return ids
}

func (i *Index) connectReceiverIdentityLocked(symbol analysis.Symbol) {
	if symbol.ReceiverType != "" {
		for _, receiverID := range i.receiverTypeIDsLocked(symbol) {
			i.byReceiver[receiverID] = appendUniqueString(i.byReceiver[receiverID], symbol.ID)
			i.byReceiverMember[memberKey(receiverID, symbol.Name)] = appendUniqueString(i.byReceiverMember[memberKey(receiverID, symbol.Name)], symbol.ID)
		}
	}
	if !analysis.IsTypeKind(symbol.Kind) {
		return
	}
	candidates := append([]string(nil), i.byReceiver[symbol.Name]...)
	if symbol.FQN != "" && symbol.FQN != symbol.Name {
		candidates = append(candidates, i.byReceiver[symbol.FQN]...)
	}
	if len(candidates) > maxResolutionCandidates {
		i.recordHealth("receiver-index", symbol.FQN, "extension receiver spelling inventory exceeded its 512-symbol publication safety limit; unresolved edges were withheld")
		return
	}
	for _, extensionID := range candidates {
		extension := i.symbols[extensionID]
		if extension == nil {
			continue
		}
		for _, receiverID := range i.receiverTypeIDsLocked(*extension) {
			if receiverID == symbol.ID {
				i.byReceiver[symbol.ID] = appendUniqueString(i.byReceiver[symbol.ID], extension.ID)
				i.byReceiverMember[memberKey(symbol.ID, extension.Name)] = appendUniqueString(i.byReceiverMember[memberKey(symbol.ID, extension.Name)], extension.ID)
			}
		}
	}
}

// removeStringIDs drops every identity in removed from one bucket in a single
// pass, preserving the order of the survivors.
func removeStringIDs(index map[string][]string, key string, removed map[string]bool) {
	bucket := index[key]
	kept := bucket[:0]
	for _, value := range bucket {
		if !removed[value] {
			kept = append(kept, value)
		}
	}
	if len(kept) == 0 {
		delete(index, key)
	} else {
		index[key] = kept
	}
}

func removeStringID(index map[string][]string, key, id string) {
	bucket := index[key]
	for position, value := range bucket {
		if value != id {
			continue
		}
		copy(bucket[position:], bucket[position+1:])
		bucket = bucket[:len(bucket)-1]
		break
	}
	if len(bucket) == 0 {
		delete(index, key)
	} else {
		index[key] = bucket
	}
}

func (i *Index) prepareFileReferencesLocked(file *analysis.ParsedFile) {
	type lexicalKey struct{ container, name string }
	lexicalByContainer := make(map[lexicalKey]analysis.Symbol)
	lexicalDuplicates := make(map[lexicalKey][]analysis.Symbol)
	lexicalNames := make(map[string]bool)
	for _, symbol := range file.Symbols {
		if !isLexicalSymbol(symbol) {
			continue
		}
		lexicalNames[symbol.Name] = true
		if symbol.ContainerID == "" {
			continue
		}
		key := lexicalKey{symbol.ContainerID, symbol.Name}
		if previous, exists := lexicalByContainer[key]; exists {
			if len(lexicalDuplicates[key]) == 0 {
				lexicalDuplicates[key] = append(lexicalDuplicates[key], previous)
			}
			lexicalDuplicates[key] = append(lexicalDuplicates[key], symbol)
		} else {
			lexicalByContainer[key] = symbol
		}
	}
	for referenceIndex := range file.References {
		reference := &file.References[referenceIndex]
		if reference.ResolvedID != "" && i.symbols[reference.ResolvedID] == nil {
			reference.ResolvedID = ""
		}
		unqualified := reference.Qualifier == ""
		if unqualified {
			unqualified = expressionQualifierBefore(i.documentTextLocked(file.URI), reference.StartByte) == ""
		}
		if reference.ResolvedID == "" && !reference.ArgumentLabel && unqualified {
			key := lexicalKey{reference.ContainerID, reference.Name}
			if candidates := lexicalDuplicates[key]; len(candidates) > 0 {
				reference.ResolvedID = lexicalBinding(file, *reference, candidates)
			} else if candidate, exists := lexicalByContainer[key]; exists && lexicalCandidateMatches(*reference, candidate) {
				reference.ResolvedID = candidate.ID
			} else if lexicalNames[reference.Name] {
				reference.ResolvedID = lexicalBinding(file, *reference, file.Symbols)
			}
		}
		if reference.ResolvedID == "" && i.Progress().Ready {
			if resolved := i.resolveLocked(file, *reference); len(resolved) == 1 {
				reference.ResolvedID = resolved[0].ID
			}
		}
	}
}

func referenceStableShape(reference analysis.Reference) string {
	var value strings.Builder
	value.WriteString(reference.Name)
	value.WriteByte(0)
	value.WriteString(reference.Qualifier)
	value.WriteByte(0)
	value.WriteString(reference.ContainerID)
	value.WriteByte(0)
	value.WriteString(reference.ResolvedID)
	value.WriteByte(0)
	value.WriteString(strconv.Itoa(int(reference.Role)))
	value.WriteByte(0)
	value.WriteString(strconv.Itoa(reference.Arity))
	value.WriteByte(0)
	value.WriteString(strconv.FormatBool(reference.ArgumentLabel))
	return value.String()
}

func (i *Index) replaceReferenceDeltaLocked(old, replacement *analysis.ParsedFile) {
	oldByShape := make(map[string][]int)
	for index, reference := range old.References {
		shape := referenceStableShape(reference)
		oldByShape[shape] = append(oldByShape[shape], index)
	}
	consumed := make(map[string]int)
	matchedOld := make(map[int]bool)
	for _, reference := range replacement.References {
		shape := referenceStableShape(reference)
		position := consumed[shape]
		candidates := oldByShape[shape]
		if position < len(candidates) {
			oldIndex := candidates[position]
			consumed[shape] = position + 1
			matchedOld[oldIndex] = true
			i.replaceReferenceBucketsLocked(old.References[oldIndex], reference)
			continue
		}
		i.addReferenceBucketsLocked(reference)
	}
	for index, reference := range old.References {
		if !matchedOld[index] {
			i.removeReferenceBucketsLocked(reference)
		}
	}
}

func (i *Index) addReferenceBucketsLocked(reference analysis.Reference) {
	i.refsByName[reference.Name] = append(i.refsByName[reference.Name], reference)
	if reference.ResolvedID != "" {
		i.refsByTarget[reference.ResolvedID] = append(i.refsByTarget[reference.ResolvedID], reference)
	} else {
		i.unresolvedRefsByName[reference.Name] = append(i.unresolvedRefsByName[reference.Name], reference)
	}
}

func (i *Index) removeReferenceBucketsLocked(reference analysis.Reference) {
	removeExactReference(i.refsByName, reference.Name, reference)
	if reference.ResolvedID != "" {
		removeExactReference(i.refsByTarget, reference.ResolvedID, reference)
	} else {
		removeExactReference(i.unresolvedRefsByName, reference.Name, reference)
	}
}

func (i *Index) replaceReferenceBucketsLocked(old, replacement analysis.Reference) {
	replaceExactReference(i.refsByName, old.Name, old, replacement)
	if old.ResolvedID != "" {
		replaceExactReference(i.refsByTarget, old.ResolvedID, old, replacement)
	} else {
		replaceExactReference(i.unresolvedRefsByName, old.Name, old, replacement)
	}
}

func exactReferencePosition(bucket []analysis.Reference, wanted analysis.Reference) int {
	for index, candidate := range bucket {
		if candidate.URI == wanted.URI && candidate.StartByte == wanted.StartByte && candidate.EndByte == wanted.EndByte && candidate.Name == wanted.Name {
			return index
		}
	}
	return -1
}

func removeExactReference(index map[string][]analysis.Reference, key string, wanted analysis.Reference) {
	bucket := index[key]
	position := exactReferencePosition(bucket, wanted)
	if position < 0 {
		return
	}
	copy(bucket[position:], bucket[position+1:])
	bucket = bucket[:len(bucket)-1]
	if len(bucket) == 0 {
		delete(index, key)
	} else {
		index[key] = bucket
	}
}

func replaceExactReference(index map[string][]analysis.Reference, key string, old, replacement analysis.Reference) {
	bucket := index[key]
	if position := exactReferencePosition(bucket, old); position >= 0 {
		bucket[position] = replacement
		index[key] = bucket
		return
	}
	index[key] = append(bucket, replacement)
}

func (i *Index) replaceImportDeltaLocked(old, replacement *analysis.ParsedFile) {
	if _, workspace := uriutil.Path(replacement.URI); !workspace {
		return
	}
	oldPrefixes := make(map[string]bool)
	newPrefixes := make(map[string]bool)
	for _, imported := range old.Imports {
		for _, prefix := range importPrefixes(imported.Path) {
			oldPrefixes[prefix] = true
		}
	}
	for _, imported := range replacement.Imports {
		for _, prefix := range importPrefixes(imported.Path) {
			newPrefixes[prefix] = true
		}
	}
	for prefix := range oldPrefixes {
		if !newPrefixes[prefix] {
			i.importersByPrefix[prefix] = withoutURI(i.importersByPrefix[prefix], replacement.URI)
		}
	}
	for prefix := range newPrefixes {
		if !oldPrefixes[prefix] {
			i.importersByPrefix[prefix] = appendUniqueURI(i.importersByPrefix[prefix], replacement.URI)
		}
	}
}

func (i *Index) invalidateResolvedTargetLocked(target, name string, replacing protocol.URI) {
	references := i.refsByTarget[target]
	delete(i.refsByTarget, target)
	for _, reference := range references {
		if reference.URI == replacing {
			continue
		}
		unresolved := reference
		unresolved.ResolvedID = ""
		replaceExactReference(i.refsByName, name, reference, unresolved)
		i.unresolvedRefsByName[name] = append(i.unresolvedRefsByName[name], unresolved)
		if file := i.files[reference.URI]; file != nil {
			replacement := *file
			replacement.References = append([]analysis.Reference(nil), file.References...)
			for index := range replacement.References {
				candidate := &replacement.References[index]
				if candidate.StartByte == reference.StartByte && candidate.EndByte == reference.EndByte && candidate.Name == reference.Name {
					candidate.ResolvedID = ""
					i.files[reference.URI] = &replacement
					break
				}
			}
		}
	}
}

func (i *Index) addLibraryBatch(files []LibraryFile, generation uint64) {
	// A short run of files per critical section bounds reader wait time even
	// when a cached archive contains tens of thousands of classes. Library
	// loading is background work; foreground completion/navigation wins a
	// scheduling opportunity every few files, while the lock is not taken a
	// hundred thousand times per scan.
	for index := range files {
		if len(files[index].Parsed.Symbols)+len(files[index].Parsed.References) > maxPublishedFileOccurrences {
			i.recordHealth("library-index", files[index].Source.Archive, "library member exceeds the 32768-occurrence publication safety limit and was withheld")
			return
		}
	}
	i.libraryCommitMu.Lock()
	defer i.libraryCommitMu.Unlock()
	if i.closed.Load() || i.generation.Load() != generation {
		return
	}
	for start := 0; start < len(files); {
		end, work := start, 0
		for end < len(files) {
			weight := max(1, len(files[end].Parsed.Symbols)+len(files[end].Parsed.References))
			if end > start && work+weight > maxPublishedFileOccurrences {
				break
			}
			work += weight
			end++
		}
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			return
		}
		for n := start; n < end; n++ {
			i.addLibraryFileLocked(&files[n], generation)
		}
		i.mu.Unlock()
		start = end
	}
	i.signalSemanticProgress()
}

// addLibraryArchiveTransaction publishes a fully prepared archive in short
// critical sections. The archive commit mutex preserves archive order, while
// refreshIncomplete/readiness keep absence-based diagnostics disabled until
// the complete staged generation lands. Parsing and validation have already
// succeeded, so the only abort is a superseding generation or Close.
func (i *Index) addLibraryArchiveTransaction(archivePath string, files []LibraryFile, generation uint64, accessSnapshots ...map[string]bool) bool {
	for index := range files {
		if len(files[index].Parsed.Symbols)+len(files[index].Parsed.References) > maxPublishedFileOccurrences {
			i.recordHealth("library-index", archivePath, "archive member exceeds the 32768-occurrence publication safety limit; previous archive snapshot retained")
			return false
		}
	}
	i.libraryCommitMu.Lock()
	defer i.libraryCommitMu.Unlock()
	if i.closed.Load() || i.generation.Load() != generation {
		return false
	}
	archivePath = filepath.Clean(archivePath)
	if len(accessSnapshots) > 0 {
		i.mu.Lock()
		access := make(map[string]bool, len(accessSnapshots[0]))
		for key := range accessSnapshots[0] {
			access[key] = true
		}
		i.libraryAccess[archivePath] = access
		i.mu.Unlock()
	}
	wanted := make(map[protocol.URI]bool, len(files))
	for index := range files {
		wanted[files[index].Parsed.URI] = true
	}
	for start := 0; start < len(files); {
		end, work := start, 0
		for end < len(files) {
			weight := max(1, len(files[end].Parsed.Symbols)+len(files[end].Parsed.References))
			if end > start && work+weight > maxPublishedFileOccurrences {
				break
			}
			work += weight
			end++
		}
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			return false
		}
		for index := start; index < end; index++ {
			i.addLibraryFileLocked(&files[index], generation)
		}
		i.mu.Unlock()
		start = end
	}
	var stale []protocol.URI
	i.mu.RLock()
	for uri, source := range i.librarySources {
		if filepath.Clean(source.Archive) == archivePath && !wanted[uri] {
			stale = append(stale, uri)
		}
	}
	i.mu.RUnlock()
	for start := 0; start < len(stale); start += 32 {
		end := min(start+32, len(stale))
		i.mu.Lock()
		if i.closed.Load() {
			i.mu.Unlock()
			return false
		}
		for index := start; index < end; index++ {
			uri := stale[index]
			if source, exists := i.librarySources[uri]; exists && filepath.Clean(source.Archive) == archivePath && !wanted[uri] {
				i.removeLocked(uri)
			}
		}
		i.mu.Unlock()
	}
	complete := !i.closed.Load() && i.generation.Load() == generation
	if complete {
		i.signalSemanticProgress()
	}
	return complete
}

func (i *Index) addLibraryFileLocked(file *LibraryFile, generation uint64) {
	for symbol := range file.Parsed.Symbols {
		file.Parsed.Symbols[symbol].Library = true
	}
	i.librarySources[file.Parsed.URI] = file.Source
	matched := i.attachLibrarySourceLocked(file)
	if len(matched) > 0 {
		retainLibrarySourceOnlySymbols(&file.Parsed, matched)
	}
	if file.Content != "" {
		i.libraryDocs[file.Parsed.URI] = textdoc.NewDocument(file.Parsed.URI, file.Source.LanguageID, 0, file.Content)
	}
	i.replaceLocked(&file.Parsed)
	i.fileGeneration[file.Parsed.URI] = generation
}

func (i *Index) attachLibrarySourceLocked(file *LibraryFile) map[string]bool {
	if file == nil || file.Source.Archive == "" || file.Source.Binary {
		return nil
	}
	matched := make(map[string]bool)
	for symbolIndex := range file.Parsed.Symbols {
		incoming := &file.Parsed.Symbols[symbolIndex]
		if incoming.FQN == "" {
			continue
		}
		var best *analysis.Symbol
		bestScore := -1
		bestCount := 0
		binaryArchive := i.libraryModuleAliases[filepath.Clean(file.Source.Archive)]
		for _, existingID := range i.byFQN[incoming.FQN] {
			existing := i.symbols[existingID]
			if existing == nil {
				continue
			}
			existingSource, ok := i.librarySources[existing.URI]
			if !ok || !existingSource.Binary {
				continue
			}
			if binaryArchive != "" && filepath.Clean(existingSource.Archive) != binaryArchive {
				continue
			}
			if score := i.libraryDeclarationMatchScoreLocked(&file.Parsed, *existing, *incoming); score > bestScore {
				best, bestScore, bestCount = existing, score, 1
			} else if score == bestScore && score >= 0 {
				bestCount++
			}
		}
		if best == nil || bestScore < 0 || bestCount != 1 {
			continue
		}
		best.SourceURI = incoming.URI
		best.SourceRange = incoming.SelectionRange
		if incoming.Documentation != "" {
			best.Documentation = incoming.Documentation
		}
		matched[incoming.ID] = true
	}
	return matched
}

func (i *Index) libraryDeclarationMatchScoreLocked(file *analysis.ParsedFile, first, second analysis.Symbol) int {
	if first.FQN != second.FQN || first.Name != second.Name {
		return -1
	}
	if analysis.IsCallableKind(first.Kind) || analysis.IsCallableKind(second.Kind) {
		if !analysis.IsCallableKind(first.Kind) || !analysis.IsCallableKind(second.Kind) {
			return -1
		}
		if (first.Kind == analysis.KindConstructor) != (second.Kind == analysis.KindConstructor) {
			return -1
		}
		if first.JVMDescriptor == "" || file == nil {
			return -1
		}
		descriptor, ok := i.sourceJvmDescriptorLocked(file, second)
		if !ok || descriptor != first.JVMDescriptor {
			return -1
		}
		firstName := first.JVMName
		if firstName == "" {
			firstName = first.Name
		}
		secondName := second.JVMName
		if secondName == "" {
			secondName = second.Name
		}
		if first.Kind == analysis.KindConstructor {
			firstName, secondName = "<init>", "<init>"
		}
		if firstName != secondName {
			return -1
		}
		return 200
	}
	if first.Kind != second.Kind {
		return -1
	}
	return 100
}

// sourceJvmDescriptorLocked derives the exact erased descriptor of a source
// callable. It deliberately abstains when any type is unresolved/ambiguous;
// attaching no source is safer than navigating one overload to another.
func (i *Index) sourceJvmDescriptorLocked(file *analysis.ParsedFile, symbol analysis.Symbol) (string, bool) {
	if file == nil || !analysis.IsCallableKind(symbol.Kind) {
		return "", false
	}
	var out strings.Builder
	out.WriteByte('(')
	if symbol.ReceiverType != "" {
		descriptor, ok := i.sourceJvmTypeDescriptorLocked(file, symbol, symbol.ReceiverType, false)
		if !ok {
			return "", false
		}
		out.WriteString(descriptor)
	}
	for _, parameter := range symbol.Parameters {
		typeName := parameter.Type
		if parameter.Variadic && !strings.HasSuffix(strings.TrimSpace(typeName), "[]") {
			typeName = strings.TrimSpace(typeName) + "[]"
		}
		descriptor, ok := i.sourceJvmTypeDescriptorLocked(file, symbol, typeName, false)
		if !ok {
			return "", false
		}
		out.WriteString(descriptor)
	}
	if containsString(symbol.Modifiers, "suspend") {
		out.WriteString("Lkotlin/coroutines/Continuation;")
		out.WriteString(")Ljava/lang/Object;")
		return out.String(), true
	}
	out.WriteByte(')')
	if symbol.Kind == analysis.KindConstructor {
		out.WriteByte('V')
		return out.String(), true
	}
	result, ok := i.sourceJvmTypeDescriptorLocked(file, symbol, symbol.Type, true)
	if !ok {
		return "", false
	}
	out.WriteString(result)
	return out.String(), true
}

func (i *Index) sourceJvmTypeDescriptorLocked(file *analysis.ParsedFile, owner analysis.Symbol, value string, result bool) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "out "), "in "))
	nullable := strings.HasSuffix(value, "?")
	value = strings.TrimSpace(strings.TrimSuffix(value, "?"))
	arrays := 0
	for strings.HasSuffix(value, "[]") || strings.HasSuffix(value, "...") {
		arrays++
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(value, "[]"), "..."))
	}
	base, arguments := splitInstantiatedType(value)
	base = strings.TrimSpace(base)
	if base == "Array" || base == "kotlin.Array" {
		if len(arguments) != 1 {
			return "", false
		}
		// Kotlin Array<T> always stores references; unlike IntArray, Array<Int>
		// uses boxed Integer elements.
		component, ok := i.sourceJvmTypeDescriptorLocked(file, owner, strings.TrimSuffix(strings.TrimSpace(arguments[0]), "?")+"?", false)
		if !ok || component == "V" {
			return "", false
		}
		return "[" + component, true
	}
	primitiveArrays := map[string]string{"BooleanArray": "Z", "ByteArray": "B", "CharArray": "C", "ShortArray": "S", "IntArray": "I", "LongArray": "J", "FloatArray": "F", "DoubleArray": "D"}
	if component := primitiveArrays[base]; component != "" {
		return strings.Repeat("[", arrays+1) + component, true
	}
	primitive := map[string]string{"boolean": "Z", "byte": "B", "char": "C", "short": "S", "int": "I", "long": "J", "float": "F", "double": "D"}
	if file.Language == analysis.LanguageKotlin {
		primitive = map[string]string{"Boolean": "Z", "kotlin.Boolean": "Z", "Byte": "B", "kotlin.Byte": "B", "Char": "C", "kotlin.Char": "C", "Short": "S", "kotlin.Short": "S", "Int": "I", "kotlin.Int": "I", "Long": "J", "kotlin.Long": "J", "Float": "F", "kotlin.Float": "F", "Double": "D", "kotlin.Double": "D"}
	}
	if code := primitive[base]; code != "" && !nullable {
		return strings.Repeat("[", arrays) + code, true
	}
	if result && arrays == 0 && (base == "void" || file.Language == analysis.LanguageKotlin && (base == "Unit" || base == "kotlin.Unit")) {
		return "V", true
	}
	if bounds, parameter := sourceTypeParameterBounds(file, owner, base); parameter {
		if len(bounds) == 0 {
			return strings.Repeat("[", arrays) + "Ljava/lang/Object;", true
		}
		descriptor, ok := i.sourceJvmTypeDescriptorLocked(file, owner, bounds[0], false)
		if !ok {
			return "", false
		}
		return strings.Repeat("[", arrays) + descriptor, true
	}
	known := map[string]string{
		"String": "java.lang.String", "kotlin.String": "java.lang.String",
		"Any": "java.lang.Object", "kotlin.Any": "java.lang.Object",
		"Unit": "kotlin.Unit", "kotlin.Unit": "kotlin.Unit",
		"Boolean": "java.lang.Boolean", "kotlin.Boolean": "java.lang.Boolean",
		"Byte": "java.lang.Byte", "kotlin.Byte": "java.lang.Byte",
		"Char": "java.lang.Character", "kotlin.Char": "java.lang.Character",
		"Short": "java.lang.Short", "kotlin.Short": "java.lang.Short",
		"Int": "java.lang.Integer", "kotlin.Int": "java.lang.Integer",
		"Long": "java.lang.Long", "kotlin.Long": "java.lang.Long",
		"Float": "java.lang.Float", "kotlin.Float": "java.lang.Float",
		"Double": "java.lang.Double", "kotlin.Double": "java.lang.Double",
	}
	fqn := known[base]
	if fqn == "" {
		resolved := i.resolveTypeSymbolsForOwnerLocked(file, base, owner)
		if len(resolved) != 1 || resolved[0].FQN == "" {
			return "", false
		}
		fqn = i.jvmBinaryFQNLocked(resolved[0])
	}
	return strings.Repeat("[", arrays) + "L" + strings.ReplaceAll(fqn, ".", "/") + ";", true
}

func sourceTypeParameterBounds(file *analysis.ParsedFile, owner analysis.Symbol, name string) ([]string, bool) {
	current := owner
	for {
		if containsString(current.TypeParameters, name) {
			return current.TypeParameterBounds[name], true
		}
		if current.ContainerID == "" {
			return nil, false
		}
		found := false
		for _, candidate := range file.Symbols {
			if candidate.ID == current.ContainerID {
				current, found = candidate, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
}

func (i *Index) jvmBinaryFQNLocked(symbol analysis.Symbol) string {
	if symbol.ContainerID == "" {
		return symbol.FQN
	}
	owner := i.symbols[symbol.ContainerID]
	if owner == nil || !analysis.IsTypeKind(owner.Kind) {
		return symbol.FQN
	}
	return i.jvmBinaryFQNLocked(*owner) + "$" + symbol.Name
}

// Matching source declarations are navigation metadata for the authoritative
// bytecode symbols, not a second semantic universe. Retain only declarations
// absent from bytecode, plus any matched containers they require.
func retainLibrarySourceOnlySymbols(parsed *analysis.ParsedFile, matched map[string]bool) {
	if parsed == nil || len(matched) == 0 {
		return
	}
	byID := make(map[string]analysis.Symbol, len(parsed.Symbols))
	needed := make(map[string]bool)
	for _, symbol := range parsed.Symbols {
		byID[symbol.ID] = symbol
		if !matched[symbol.ID] {
			needed[symbol.ID] = true
		}
	}
	for id := range needed {
		for container := byID[id].ContainerID; container != "" && !needed[container]; container = byID[container].ContainerID {
			needed[container] = true
		}
	}
	kept := parsed.Symbols[:0]
	for _, symbol := range parsed.Symbols {
		if !matched[symbol.ID] || needed[symbol.ID] {
			kept = append(kept, symbol)
		}
	}
	parsed.Symbols = kept
}

// prepareInterop drops stale derived symbols and appends the JVM-view ones.
// It touches only the file, so it may run before the index lock is taken.
func prepareInterop(file *analysis.ParsedFile) {
	if file.InteropPrepared {
		return
	}
	base := file.Symbols[:0]
	for _, symbol := range file.Symbols {
		if !symbol.Synthetic || symbol.OriginID == "" {
			base = append(base, symbol)
		}
	}
	file.Symbols = base
	interop := interopSymbols(file)
	if len(interop) > 0 {
		combined := make([]analysis.Symbol, len(file.Symbols)+len(interop))
		copy(combined, file.Symbols)
		copy(combined[len(file.Symbols):], interop)
		file.Symbols = combined
	}
	file.InteropPrepared = true
}

// reserveLibraryCapacityLocked grows the global maps ahead of a library scan
// so a million symbols do not arrive into maps that rehash at every doubling
// while the lock is held.
func (i *Index) reserveLibraryCapacityLocked(files int64) {
	// Pre-sizing the complete theoretical classpath can itself be the largest
	// allocation in the scan. Grow for the common prefix and let maps expand
	// incrementally beyond it within the global archive budget.
	if files > 125_000 {
		files = 125_000
	}
	if files <= 0 {
		return
	}
	expected := int(files) * 8
	if expected < 1<<16 || len(i.symbols) >= expected/2 {
		return
	}
	grow := func(m map[string][]string) map[string][]string {
		out := make(map[string][]string, expected)
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	symbols := make(map[string]*analysis.Symbol, expected)
	for k, v := range i.symbols {
		symbols[k] = v
	}
	i.symbols = symbols
	i.byName = grow(i.byName)
	i.byFQN = grow(i.byFQN)
	i.byContainerName = grow(i.byContainerName)
	i.byContainerMember = grow(i.byContainerMember)
}

func (i *Index) replaceLocked(file *analysis.ParsedFile) {
	// Every semantic replacement invalidates compiler work captured before this
	// lock acquisition. The run token is checked at transaction publication,
	// so even mutation paths which are not initiated by an editor notification
	// cannot publish diagnostics for the previous index snapshot.
	i.compilerRun.Add(1)
	i.invalidateCompilerDiagnosticsLocked()
	old := i.files[file.URI]
	if old != nil {
		preserveLibraryAttachments(old, file)
	}
	prepareInterop(file)
	if old != nil && old.Package == file.Package {
		stabilizeFileSymbolIDs(old, file)
		i.replaceFileDeltaLocked(old, file)
		return
	}
	if old != nil {
		i.removeFileContentsLocked(old)
	}
	i.files[file.URI] = file
	i.fileCursorSpans[file.URI] = buildCursorSpans(file)
	libraryFile := false
	if _, exists := i.librarySources[file.URI]; exists {
		libraryFile = true
	}
	if !libraryFile {
		fileSymbols := make(map[string][]*analysis.Symbol)
		fileAnonymous := make(map[string][]*analysis.Symbol)
		for symbolIndex := range file.Symbols {
			symbol := &file.Symbols[symbolIndex]
			fileSymbols[symbol.Name] = append(fileSymbols[symbol.Name], symbol)
			if strings.HasPrefix(strings.TrimSpace(symbol.Initializer), "object") {
				fileAnonymous[symbol.Name] = append(fileAnonymous[symbol.Name], symbol)
			}
		}
		for name := range fileSymbols {
			sort.SliceStable(fileSymbols[name], func(left, right int) bool {
				return fileSymbols[name][left].StartByte < fileSymbols[name][right].StartByte
			})
		}
		for name := range fileAnonymous {
			sort.SliceStable(fileAnonymous[name], func(left, right int) bool {
				return fileAnonymous[name][left].StartByte < fileAnonymous[name][right].StartByte
			})
		}
		i.fileSymbolsByName[file.URI] = fileSymbols
		i.fileAnonymousByName[file.URI] = fileAnonymous
		fileSmartCasts := make(map[string][]analysis.SmartCast)
		for _, smartCast := range file.SmartCasts {
			fileSmartCasts[smartCast.Name] = append(fileSmartCasts[smartCast.Name], smartCast)
		}
		i.fileSmartCastsByName[file.URI] = fileSmartCasts
	}
	i.addPackageLocked(file)
	i.addCompletionPackageLocked(file.Package)
	for symbolIndex := range file.Symbols {
		i.addSymbolIndicesLocked(&file.Symbols[symbolIndex])
	}
	// addSymbolIndicesLocked connects each new child to an already indexed
	// parent, and each new parent to earlier children in the spelling bucket.
	// A second full-file pass duplicated that global bucket work under the
	// mutation lock without adding an edge the two directional cases miss.
	type lexicalKey struct{ container, name string }
	lexicalByContainer := make(map[lexicalKey]analysis.Symbol)
	lexicalDuplicates := make(map[lexicalKey][]analysis.Symbol)
	lexicalNames := make(map[string]bool)
	for _, symbol := range file.Symbols {
		if !isLexicalSymbol(symbol) {
			continue
		}
		lexicalNames[symbol.Name] = true
		if symbol.ContainerID == "" {
			continue
		}
		key := lexicalKey{symbol.ContainerID, symbol.Name}
		if previous, exists := lexicalByContainer[key]; exists {
			if len(lexicalDuplicates[key]) == 0 {
				lexicalDuplicates[key] = append(lexicalDuplicates[key], previous)
			}
			lexicalDuplicates[key] = append(lexicalDuplicates[key], symbol)
		} else {
			lexicalByContainer[key] = symbol
		}
	}
	for referenceIndex := range file.References {
		reference := &file.References[referenceIndex]
		unqualified := reference.Qualifier == ""
		if unqualified {
			unqualified = expressionQualifierBefore(i.documentTextLocked(file.URI), reference.StartByte) == ""
		}
		// Lexical bindings cannot be invalidated by another file being indexed.
		// Resolve them once at snapshot insertion instead of repeating the same
		// scope search for every definition/reference/semantic-token request.
		if reference.ResolvedID == "" && !reference.ArgumentLabel && unqualified {
			key := lexicalKey{reference.ContainerID, reference.Name}
			if candidates := lexicalDuplicates[key]; len(candidates) > 0 {
				reference.ResolvedID = lexicalBinding(file, *reference, candidates)
			} else if candidate, exists := lexicalByContainer[key]; exists && lexicalCandidateMatches(*reference, candidate) {
				reference.ResolvedID = candidate.ID
			} else if lexicalNames[reference.Name] {
				reference.ResolvedID = lexicalBinding(file, *reference, file.Symbols)
			}
		}
		if reference.ResolvedID == "" && i.Progress().Ready {
			if resolved := i.resolveLocked(file, *reference); len(resolved) == 1 {
				reference.ResolvedID = resolved[0].ID
			}
		}
		i.refsByName[reference.Name] = append(i.refsByName[reference.Name], *reference)
		if reference.ResolvedID != "" {
			i.refsByTarget[reference.ResolvedID] = append(i.refsByTarget[reference.ResolvedID], *reference)
		} else {
			i.unresolvedRefsByName[reference.Name] = append(i.unresolvedRefsByName[reference.Name], *reference)
		}
	}
	if _, workspace := uriutil.Path(file.URI); workspace {
		for _, imported := range file.Imports {
			for _, prefix := range importPrefixes(imported.Path) {
				i.importersByPrefix[prefix] = appendUniqueURI(i.importersByPrefix[prefix], file.URI)
			}
		}
	}
}

func preserveLibraryAttachments(old, replacement *analysis.ParsedFile) {
	if old == nil || replacement == nil {
		return
	}
	attached := make(map[string][]analysis.Symbol)
	for _, symbol := range old.Symbols {
		if symbol.SourceURI != "" {
			attached[symbol.FQN] = append(attached[symbol.FQN], symbol)
		}
	}
	for index := range replacement.Symbols {
		symbol := &replacement.Symbols[index]
		bestScore := -1
		bestCount := 0
		var best analysis.Symbol
		for _, candidate := range attached[symbol.FQN] {
			if score := binaryDeclarationIdentityScore(candidate, *symbol); score > bestScore {
				best, bestScore, bestCount = candidate, score, 1
			} else if score == bestScore && score >= 0 {
				bestCount++
			}
		}
		if bestScore >= 0 && bestCount == 1 {
			symbol.SourceURI = best.SourceURI
			symbol.SourceRange = best.SourceRange
			if best.Documentation != "" {
				symbol.Documentation = best.Documentation
			}
		}
	}
}

func binaryDeclarationIdentityScore(first, second analysis.Symbol) int {
	if first.FQN != second.FQN || first.Name != second.Name || first.Kind != second.Kind {
		return -1
	}
	if analysis.IsCallableKind(first.Kind) {
		if first.JVMDescriptor == "" || first.JVMDescriptor != second.JVMDescriptor || first.JVMName != second.JVMName {
			return -1
		}
	}
	return 100
}

func (i *Index) removeFileContentsLocked(file *analysis.ParsedFile) {
	delete(i.fileSymbolsByName, file.URI)
	delete(i.fileSmartCastsByName, file.URI)
	delete(i.fileAnonymousByName, file.URI)
	i.removePackageLocked(file)
	i.removeCompletionPackageLocked(file.Package)
	removed := make(map[string]bool, len(file.Symbols))
	byNameKeys, byOriginKeys, byFQNKeys := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	byContainerNameKeys, byContainerMemberKeys := make(map[string]bool), make(map[string]bool)
	byReceiverKeys, byReceiverMemberKeys := make(map[string]bool), make(map[string]bool)
	byPackageKeys, workspaceKeys, completionKeys, bySuperKeys := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, s := range file.Symbols {
		delete(i.symbols, s.ID)
		removed[s.ID] = true
		if isLexicalSymbol(s) {
			continue
		}
		i.invalidateResolvedTargetLocked(s.ID, s.Name, file.URI)
		byNameKeys[s.Name] = true
		if s.OriginID != "" {
			byOriginKeys[s.OriginID] = true
		}
		byFQNKeys[s.FQN] = true
		if s.ContainerName != "" {
			byContainerNameKeys[s.ContainerName] = true
			byContainerMemberKeys[memberKey(s.ContainerName, s.Name)] = true
		}
		if s.ContainerID != "" {
			byContainerNameKeys[s.ContainerID] = true
			byContainerMemberKeys[memberKey(s.ContainerID, s.Name)] = true
		}
		if s.ReceiverType != "" {
			receiver := simpleType(s.ReceiverType)
			byReceiverKeys[receiver] = true
			byReceiverMemberKeys[memberKey(receiver, s.Name)] = true
		}
		if s.ContainerID == "" && s.Package != "" {
			byPackageKeys[s.Package] = true
		}
		if isWorkspaceSymbol(s) {
			workspaceKeys[s.Name] = true
		}
		if isUnqualifiedCompletionSymbol(s) {
			completionKeys[s.Name] = true
		}
		for _, supertype := range s.Supertypes {
			simple := simpleType(supertype)
			bySuperKeys[simple] = true
			if simple != supertype {
				bySuperKeys[supertype] = true
			}
		}
	}
	filterStringIndexBuckets(i.byName, byNameKeys, removed)
	filterStringIndexBuckets(i.byOrigin, byOriginKeys, removed)
	filterStringIndexBuckets(i.byFQN, byFQNKeys, removed)
	filterStringIndexBuckets(i.byContainerName, byContainerNameKeys, removed)
	filterStringIndexBuckets(i.byContainerMember, byContainerMemberKeys, removed)
	filterStringIndexBuckets(i.byReceiver, byReceiverKeys, removed)
	filterStringIndexBuckets(i.byReceiverMember, byReceiverMemberKeys, removed)
	for key, bucket := range i.byReceiver {
		if removed[key] {
			delete(i.byReceiver, key)
			continue
		}
		kept := bucket[:0]
		for _, id := range bucket {
			if !removed[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) == 0 {
			delete(i.byReceiver, key)
		} else {
			i.byReceiver[key] = kept
		}
	}
	for key, bucket := range i.byReceiverMember {
		container, _, _ := strings.Cut(key, "\x00")
		if removed[container] {
			delete(i.byReceiverMember, key)
			continue
		}
		kept := bucket[:0]
		for _, id := range bucket {
			if !removed[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) == 0 {
			delete(i.byReceiverMember, key)
		} else {
			i.byReceiverMember[key] = kept
		}
	}
	filterStringIndexBuckets(i.byPackage, byPackageKeys, removed)
	i.workspaceIndex.removeValues(workspaceKeys, func(id string) bool { return removed[id] })
	i.completionIndex.removeValues(completionKeys, func(id string) bool { return removed[id] })
	filterStringIndexBuckets(i.bySuper, bySuperKeys, removed)
	for superID, children := range i.bySuperID {
		if removed[superID] {
			delete(i.bySuperID, superID)
			continue
		}
		kept := children[:0]
		for _, childID := range children {
			if !removed[childID] {
				kept = append(kept, childID)
			}
		}
		if len(kept) == 0 {
			delete(i.bySuperID, superID)
		} else {
			i.bySuperID[superID] = kept
		}
	}
	referenceNames := make(map[string]bool)
	for _, r := range file.References {
		referenceNames[r.Name] = true
	}
	for name := range referenceNames {
		filterReferenceBucket(i.refsByName, name, file.URI)
		filterReferenceBucket(i.unresolvedRefsByName, name, file.URI)
	}
	targets := make(map[string]bool)
	for _, reference := range file.References {
		if reference.ResolvedID != "" {
			targets[reference.ResolvedID] = true
		}
	}
	for target := range targets {
		filterReferenceBucket(i.refsByTarget, target, file.URI)
	}
	if _, workspace := uriutil.Path(file.URI); workspace {
		prefixes := make(map[string]bool)
		for _, imported := range file.Imports {
			for _, prefix := range importPrefixes(imported.Path) {
				prefixes[prefix] = true
			}
		}
		for prefix := range prefixes {
			i.importersByPrefix[prefix] = withoutURI(i.importersByPrefix[prefix], file.URI)
		}
	}
}

func filterReferenceBucket(index map[string][]analysis.Reference, key string, uri protocol.URI) {
	bucket := index[key]
	out := bucket[:0]
	for _, reference := range bucket {
		if reference.URI != uri {
			out = append(out, reference)
		}
	}
	if len(out) == 0 {
		delete(index, key)
	} else {
		index[key] = out
	}
}

func filterStringIndexBuckets(index map[string][]string, keys, removed map[string]bool) {
	for key := range keys {
		bucket := index[key]
		out := bucket[:0]
		for _, id := range bucket {
			if !removed[id] {
				out = append(out, id)
			}
		}
		if len(out) == 0 {
			delete(index, key)
		} else {
			index[key] = out
		}
	}
}

func (i *Index) addPackageLocked(file *analysis.ParsedFile) {
	if file.Package == "" {
		return
	}
	path, ok := uriutil.Path(file.URI)
	if !ok { // IntelliJ's package-definition providers exclude libraries.
		return
	}
	directory := uriutil.File(filepath.Dir(path))
	for _, existing := range i.packages[file.Package] {
		if existing == directory {
			return
		}
	}
	i.packages[file.Package] = append(i.packages[file.Package], directory)
}

func (i *Index) removePackageLocked(file *analysis.ParsedFile) {
	if file.Package == "" {
		return
	}
	path, ok := uriutil.Path(file.URI)
	if !ok {
		return
	}
	directory := uriutil.File(filepath.Dir(path))
	// Retain a directory while another file in that directory declares the
	// same package.
	for uri, candidate := range i.files {
		if uri == file.URI || candidate.Package != file.Package {
			continue
		}
		candidatePath, fileURI := uriutil.Path(uri)
		if fileURI && uriutil.File(filepath.Dir(candidatePath)) == directory {
			return
		}
	}
	i.packages[file.Package] = withoutURI(i.packages[file.Package], directory)
}

func (i *Index) addCompletionPackageLocked(packageName string) {
	if packageName == "" {
		return
	}
	if i.packageCounts[packageName] == 0 {
		parts := strings.Split(packageName, ".")
		parent := ""
		for _, child := range parts {
			i.packageChildren[parent] = appendUniqueString(i.packageChildren[parent], child)
			if parent == "" {
				parent = child
			} else {
				parent += "." + child
			}
		}
	}
	i.packageCounts[packageName]++
}

func (i *Index) removeCompletionPackageLocked(packageName string) {
	if packageName == "" || i.packageCounts[packageName] <= 0 {
		return
	}
	i.packageCounts[packageName]--
	if i.packageCounts[packageName] > 0 {
		return
	}
	delete(i.packageCounts, packageName)
	parts := strings.Split(packageName, ".")
	parent := ""
	for _, child := range parts {
		full := child
		if parent != "" {
			full = parent + "." + child
		}
		used := false
		for candidate, count := range i.packageCounts {
			if count > 0 && (candidate == full || strings.HasPrefix(candidate, full+".")) {
				used = true
				break
			}
		}
		if !used {
			i.packageChildren[parent] = without(i.packageChildren[parent], child)
		}
		parent = full
	}
}
