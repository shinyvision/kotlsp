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
*/
import "C"

import (
	"context"

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

func newSyntaxSnapshot(ctx context.Context, root *sitter.Node, language Language) *syntaxSnapshot {
	if root == nil {
		return nil
	}
	fieldIDs := javaFieldIDs
	if language == LanguageKotlin {
		fieldIDs = kotlinFieldIDs
	}
	snapshot := &syntaxSnapshot{
		nodes: make([]syntaxNode, 0, 4096),
		byID:  make(map[uintptr]uint32, 4096),
	}
	appendNode := func(node sitter.Node, parent uint32, field uint16) uint32 {
		flags := uint8(0)
		if node.IsError() {
			flags |= 1
		}
		if node.IsMissing() {
			flags |= 2
		}
		if node.HasError() {
			flags |= 4
		}
		if node.IsNamed() {
			flags |= 8
		}
		index := uint32(len(snapshot.nodes))
		snapshot.nodes = append(snapshot.nodes, syntaxNode{
			node: node, kind: node.Kind(), parent: parent,
			firstChild: noSyntaxNode, nextSibling: noSyntaxNode,
			start: int(node.StartByte()), end: int(node.EndByte()), field: field, flags: flags,
		})
		snapshot.byID[node.Id()] = index
		return index
	}
	type frame struct {
		index, next, count, last uint32
	}
	rootIndex := appendNode(*root, noSyntaxNode, 0)
	stack := []frame{{index: rootIndex, count: uint32(root.ChildCount()), last: noSyntaxNode}}
	const maxSnapshotNodes = 1_000_000
	for len(stack) > 0 {
		if len(snapshot.nodes)&255 == 0 && ctx.Err() != nil {
			return nil
		}
		current := &stack[len(stack)-1]
		if current.next >= current.count {
			stack = stack[:len(stack)-1]
			continue
		}
		parent := &snapshot.nodes[current.index].node
		childPosition := current.next
		current.next++
		child := parent.Child(uint(childPosition))
		if child == nil {
			continue
		}
		field := uint16(0)
		for _, candidate := range fieldIDs {
			if candidate == 0 {
				continue
			}
			if fieldChild := parent.ChildByFieldId(candidate); fieldChild != nil && fieldChild.Id() == child.Id() {
				field = candidate
				break
			}
		}
		if len(snapshot.nodes) >= maxSnapshotNodes || len(stack) >= 65_536 {
			return nil
		}
		childIndex := appendNode(*child, current.index, field)
		if current.last == noSyntaxNode {
			snapshot.nodes[current.index].firstChild = childIndex
		} else {
			snapshot.nodes[current.last].nextSibling = childIndex
		}
		current.last = childIndex
		stack = append(stack, frame{index: childIndex, count: uint32(child.ChildCount()), last: noSyntaxNode})
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
