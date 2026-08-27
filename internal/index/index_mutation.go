package index

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/shinyvision/kotlsp/internal/analysis"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func (i *Index) AddLibraryBatch(files []LibraryFile) {
	i.addLibraryBatch(files, i.generation.Load())
}

func (i *Index) addLibraryBatch(files []LibraryFile, generation uint64) {
	// A short run of files per critical section bounds reader wait time even
	// when a cached archive contains tens of thousands of classes. Library
	// loading is background work; foreground completion/navigation wins a
	// scheduling opportunity every few files, while the lock is not taken a
	// hundred thousand times per scan.
	const chunkSize = 16
	for start := 0; start < len(files); start += chunkSize {
		if i.generation.Load() != generation {
			return
		}
		end := start + chunkSize
		if end > len(files) {
			end = len(files)
		}
		i.mu.Lock()
		if i.generation.Load() != generation {
			i.mu.Unlock()
			return
		}
		for n := start; n < end; n++ {
			file := &files[n]
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
		}
		i.mu.Unlock()
	}
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
		for _, existingID := range i.byFQN[incoming.FQN] {
			existing := i.symbols[existingID]
			if existing == nil {
				continue
			}
			existingSource, ok := i.librarySources[existing.URI]
			if !ok || !existingSource.Binary {
				continue
			}
			if score := libraryDeclarationMatchScore(*existing, *incoming); score > bestScore {
				best, bestScore = existing, score
			}
		}
		if best == nil || bestScore < 0 {
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

func libraryDeclarationMatchScore(first, second analysis.Symbol) int {
	if first.FQN != second.FQN || first.Name != second.Name {
		return -1
	}
	if analysis.IsCallableKind(first.Kind) || analysis.IsCallableKind(second.Kind) {
		if !analysis.IsCallableKind(first.Kind) || !analysis.IsCallableKind(second.Kind) || len(first.Parameters) != len(second.Parameters) {
			return -1
		}
		score := 100
		for parameter := range first.Parameters {
			left, right := first.Parameters[parameter].Type, second.Parameters[parameter].Type
			if left == "" || right == "" {
				continue
			}
			if !sameJvmType(left, right) {
				return -1
			}
			score += 10
		}
		return score
	}
	if first.Kind != second.Kind {
		return -1
	}
	return 100
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
	if old := i.files[file.URI]; old != nil {
		preserveLibraryAttachments(old, file)
		i.removeFileContentsLocked(old)
	}
	prepareInterop(file)
	i.files[file.URI] = file
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
		s := &file.Symbols[symbolIndex]
		i.symbols[s.ID] = s
		if s.Synthetic && s.OriginID == "" && s.InteropLanguage == analysis.LanguageUnknown {
			continue
		}
		if isLexicalSymbol(*s) {
			// Lexical declarations are resolved from their immutable file scope
			// and direct ResolvedID bindings. Keeping thousands of parameters in
			// every global name/container index wastes both update time and memory.
			continue
		}
		i.byName[s.Name] = append(i.byName[s.Name], s.ID)
		if s.OriginID != "" {
			i.byOrigin[s.OriginID] = append(i.byOrigin[s.OriginID], s.ID)
		}
		if s.FQN != "" {
			i.byFQN[s.FQN] = append(i.byFQN[s.FQN], s.ID)
		}
		if s.ContainerName != "" {
			i.byContainerName[s.ContainerName] = append(i.byContainerName[s.ContainerName], s.ID)
			i.byContainerMember[memberKey(s.ContainerName, s.Name)] = append(i.byContainerMember[memberKey(s.ContainerName, s.Name)], s.ID)
		}
		if s.ReceiverType != "" {
			receiver := simpleType(s.ReceiverType)
			i.byReceiver[receiver] = append(i.byReceiver[receiver], s.ID)
			i.byReceiverMember[memberKey(receiver, s.Name)] = append(i.byReceiverMember[memberKey(receiver, s.Name)], s.ID)
		}
		if s.ContainerID == "" && s.Package != "" {
			i.byPackage[s.Package] = append(i.byPackage[s.Package], s.ID)
		}
		if isWorkspaceSymbol(*s) {
			i.workspaceIndex.insert(s.Name, s.ID)
		}
		if isUnqualifiedCompletionSymbol(*s) {
			i.completionIndex.insert(s.Name, s.ID)
		}
		for _, supertype := range s.Supertypes {
			simple := simpleType(supertype)
			i.bySuper[simple] = append(i.bySuper[simple], s.ID)
			if simple != supertype {
				i.bySuper[supertype] = append(i.bySuper[supertype], s.ID)
			}
		}
	}
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
		i.refsByName[reference.Name] = append(i.refsByName[reference.Name], *reference)
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
		var best analysis.Symbol
		for _, candidate := range attached[symbol.FQN] {
			if score := libraryDeclarationMatchScore(candidate, *symbol); score > bestScore {
				best, bestScore = candidate, score
			}
		}
		if bestScore >= 0 {
			symbol.SourceURI = best.SourceURI
			symbol.SourceRange = best.SourceRange
			if best.Documentation != "" {
				symbol.Documentation = best.Documentation
			}
		}
	}
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
		byNameKeys[s.Name] = true
		if s.OriginID != "" {
			byOriginKeys[s.OriginID] = true
		}
		byFQNKeys[s.FQN] = true
		if s.ContainerName != "" {
			byContainerNameKeys[s.ContainerName] = true
			byContainerMemberKeys[memberKey(s.ContainerName, s.Name)] = true
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
	filterStringIndexBuckets(i.byPackage, byPackageKeys, removed)
	i.workspaceIndex.removeValues(workspaceKeys, func(id string) bool { return removed[id] })
	i.completionIndex.removeValues(completionKeys, func(id string) bool { return removed[id] })
	filterStringIndexBuckets(i.bySuper, bySuperKeys, removed)
	referenceNames := make(map[string]bool)
	for _, r := range file.References {
		referenceNames[r.Name] = true
	}
	for name := range referenceNames {
		bucket := i.refsByName[name]
		out := bucket[:0]
		for _, reference := range bucket {
			if reference.URI != file.URI {
				out = append(out, reference)
			}
		}
		if len(out) == 0 {
			delete(i.refsByName, name)
		} else {
			i.refsByName[name] = out
		}
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
