package analysis

/*
#cgo CFLAGS: -std=c11
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

static void kotlsp_release_native_heap(void) {
#if defined(__GLIBC__)
	malloc_trim(0);
#endif
}

// These declarations are the stable public tree-sitter ABI. Keeping the
// traversal in C avoids a cgo round trip for every node property and sibling
// in large generated source files.
typedef struct {
	uint32_t context[4];
	const void *id;
	const void *tree;
} TSNode;

typedef struct {
	const void *tree;
	const void *id;
	uint32_t context[3];
} TSTreeCursor;

typedef uint16_t TSSymbol;
typedef uint16_t TSFieldId;

extern TSTreeCursor ts_tree_cursor_new(TSNode node);
extern void ts_tree_cursor_delete(TSTreeCursor *self);
extern bool ts_tree_cursor_goto_first_child(TSTreeCursor *self);
extern bool ts_tree_cursor_goto_next_sibling(TSTreeCursor *self);
extern TSNode ts_tree_cursor_current_node(const TSTreeCursor *self);
extern TSFieldId ts_tree_cursor_current_field_id(const TSTreeCursor *self);
extern bool ts_node_is_named(TSNode self);
extern bool ts_node_is_error(TSNode self);
extern bool ts_node_is_missing(TSNode self);
extern bool ts_node_has_error(TSNode self);
extern TSSymbol ts_node_symbol(TSNode self);
extern uint32_t ts_node_start_byte(TSNode self);
extern uint32_t ts_node_end_byte(TSNode self);

typedef struct {
	TSNode node;
	uint32_t parent;
	uint32_t first_child;
	uint32_t next_sibling;
	uint32_t start_byte;
	uint32_t end_byte;
	uint16_t symbol;
	uint16_t field;
	uint8_t flags;
} KotlspSyntaxNode;

typedef struct {
	KotlspSyntaxNode *nodes;
	uint32_t count;
	uint32_t capacity;
	bool failed;
} KotlspSyntaxBuffer;

static bool kotlsp_syntax_reserve(KotlspSyntaxBuffer *buffer) {
	if (buffer->count < buffer->capacity) return true;
	uint32_t capacity = buffer->capacity == 0 ? 1024 : buffer->capacity * 2;
	KotlspSyntaxNode *nodes = (KotlspSyntaxNode *)realloc(buffer->nodes, (size_t)capacity * sizeof(KotlspSyntaxNode));
	if (nodes == NULL) {
		buffer->failed = true;
		return false;
	}
	buffer->nodes = nodes;
	buffer->capacity = capacity;
	return true;
}

static uint32_t kotlsp_syntax_visit(KotlspSyntaxBuffer *buffer, TSNode node, uint32_t parent, uint16_t field) {
	if (!kotlsp_syntax_reserve(buffer)) return UINT32_MAX;
	uint32_t index = buffer->count++;
	KotlspSyntaxNode *entry = &buffer->nodes[index];
	entry->node = node;
	entry->parent = parent;
	entry->first_child = UINT32_MAX;
	entry->next_sibling = UINT32_MAX;
	entry->start_byte = ts_node_start_byte(node);
	entry->end_byte = ts_node_end_byte(node);
	entry->symbol = ts_node_symbol(node);
	entry->field = field;
	entry->flags = (ts_node_is_error(node) ? 1 : 0) |
		(ts_node_is_missing(node) ? 2 : 0) |
		(ts_node_has_error(node) ? 4 : 0) |
		(ts_node_is_named(node) ? 8 : 0);

	TSTreeCursor cursor = ts_tree_cursor_new(node);
	uint32_t previous = UINT32_MAX;
	if (ts_tree_cursor_goto_first_child(&cursor)) {
		do {
			TSNode child = ts_tree_cursor_current_node(&cursor);
			uint32_t child_index = kotlsp_syntax_visit(buffer, child, index, ts_tree_cursor_current_field_id(&cursor));
			if (child_index == UINT32_MAX) break;
			if (previous == UINT32_MAX) {
				buffer->nodes[index].first_child = child_index;
			} else {
				buffer->nodes[previous].next_sibling = child_index;
			}
			previous = child_index;
		} while (ts_tree_cursor_goto_next_sibling(&cursor));
	}
	ts_tree_cursor_delete(&cursor);
	return buffer->failed ? UINT32_MAX : index;
}

static KotlspSyntaxNode *kotlsp_syntax_snapshot(
	uint32_t c0, uint32_t c1, uint32_t c2, uint32_t c3,
	uintptr_t id, uintptr_t tree, uint32_t *count
) {
	TSNode root = {{c0, c1, c2, c3}, (const void *)id, (const void *)tree};
	KotlspSyntaxBuffer buffer = {0};
	kotlsp_syntax_visit(&buffer, root, UINT32_MAX, 0);
	if (buffer.failed) {
		free(buffer.nodes);
		*count = 0;
		return NULL;
	}
	*count = buffer.count;
	return buffer.nodes;
}
*/
import "C"

import (
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// releaseLargeParseMemory returns tree-sitter's released native arenas to the
// OS. Do not call debug.FreeOSMemory here: a large editor buffer can be parsed
// while workspace/JDK indexing owns a large live Go heap, and forcing a global
// collection/OS scavenging cycle on the notification path stalls didOpen for
// tens of seconds. Go's pacer already sees all Go traversal allocations; only
// the C allocator needs the explicit trim.
func releaseLargeParseMemory() {
	C.kotlsp_release_native_heap()
}

const noSyntaxNode = ^uint32(0)

// rawSitterNode mirrors tree-sitter's public TSNode and the sole field in the
// Go binding's sitter.Node. It lets the single C traversal return ordinary Go
// binding nodes without calling back through cgo for each one.
type rawSitterNode struct {
	context [4]uint32
	id      uintptr
	tree    uintptr
}

type syntaxNode struct {
	node        sitter.Node
	kind        string
	parent      uint32
	firstChild  uint32
	nextSibling uint32
	start       int
	end         int
	field       uint16
	flags       uint8
}

type syntaxSnapshot struct {
	nodes []syntaxNode
	byID  map[uintptr]uint32
}

func syntaxKindNames(language *sitter.Language) []string {
	names := make([]string, language.NodeKindCount())
	for index := range names {
		names[index] = language.NodeKindForId(uint16(index))
	}
	return names
}

var (
	javaSyntaxKindNames   = syntaxKindNames(javaLanguage)
	kotlinSyntaxKindNames = syntaxKindNames(kotlinLanguage)
)

func newSyntaxSnapshot(root *sitter.Node, language Language) *syntaxSnapshot {
	if root == nil {
		return nil
	}
	raw := *(*rawSitterNode)(unsafe.Pointer(root))
	var count C.uint32_t
	items := C.kotlsp_syntax_snapshot(
		C.uint32_t(raw.context[0]), C.uint32_t(raw.context[1]),
		C.uint32_t(raw.context[2]), C.uint32_t(raw.context[3]),
		C.uintptr_t(raw.id), C.uintptr_t(raw.tree), &count,
	)
	if items == nil || count == 0 {
		return nil
	}
	defer C.free(unsafe.Pointer(items))
	cItems := unsafe.Slice(items, int(count))
	names := javaSyntaxKindNames
	if language == LanguageKotlin {
		names = kotlinSyntaxKindNames
	}
	snapshot := &syntaxSnapshot{
		nodes: make([]syntaxNode, len(cItems)),
		byID:  make(map[uintptr]uint32, len(cItems)),
	}
	for index := range cItems {
		item := &cItems[index]
		node := *(*sitter.Node)(unsafe.Pointer(&item.node))
		symbol := int(item.symbol)
		kind := ""
		if symbol >= 0 && symbol < len(names) {
			kind = names[symbol]
		}
		snapshot.nodes[index] = syntaxNode{
			node: node, kind: kind, parent: uint32(item.parent),
			firstChild: uint32(item.first_child), nextSibling: uint32(item.next_sibling),
			start: int(item.start_byte), end: int(item.end_byte), field: uint16(item.field),
			flags: uint8(item.flags),
		}
		snapshot.byID[node.Id()] = uint32(index)
	}
	return snapshot
}

func (s *syntaxSnapshot) record(node *sitter.Node) (*syntaxNode, uint32) {
	if s == nil || node == nil {
		return nil, noSyntaxNode
	}
	index, ok := s.byID[node.Id()]
	if !ok || int(index) >= len(s.nodes) {
		return nil, noSyntaxNode
	}
	return &s.nodes[index], index
}

func (s *syntaxSnapshot) node(index uint32) *sitter.Node {
	if s == nil || index == noSyntaxNode || int(index) >= len(s.nodes) {
		return nil
	}
	return &s.nodes[index].node
}
