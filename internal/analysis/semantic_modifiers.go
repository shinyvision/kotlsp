package analysis

// LSP semantic-token modifier bits, in the legend order the server advertises:
// declaration, definition, readonly, static, deprecated, abstract, async,
// modification, documentation, defaultLibrary. Definition and documentation
// are included for completeness even where the parser does not set them.
const (
	SemanticModifierDeclaration uint32 = 1 << iota
	SemanticModifierDefinition
	SemanticModifierReadonly
	SemanticModifierStatic
	SemanticModifierDeprecated
	SemanticModifierAbstract
	SemanticModifierAsync
	SemanticModifierModification
	SemanticModifierDocumentation
	SemanticModifierDefaultLibrary
)
