// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hbird

import (
	"fmt"
	"testing"
)

// isBitSet is a small helper to check if a particular color bit is set in a Node.
func isBitSet(n *Node, color uint32) bool {
	chunkIdx := color / wordSize
	bitIdx := color % wordSize
	if chunkIdx >= uint32(len(n.colorBits)) {
		return false
	}
	mask := uint64(1) << (wordSize - 1 - bitIdx)
	return (n.colorBits[chunkIdx] & mask) != 0
}

func (n *Node) String() (out string) {
	for _, cb := range n.colorBits {
		out += fmt.Sprintf("%064b", cb)
	}
	return
}

// TestMarkUsedColorBasic tests a few single bits in small ranges.
func TestMarkUsedColorBasic(t *testing.T) {
	var node Node

	// Check that nothing is set initially.
	if isBitSet(&node, 0) {
		t.Error("Expected bit 0 to be clear before marking")
	}

	// Mark color=0 and verify it's set
	node.markUsedColor(0)
	if !isBitSet(&node, 0) {
		t.Error("Bit 0 should be set after markUsedColor(0)")
	}

	// Mark color=1 and verify it's set, and color=0 is still set
	node.markUsedColor(1)
	if !isBitSet(&node, 1) {
		t.Error("Bit 1 should be set after markUsedColor(1)")
	}
	if !isBitSet(&node, 0) {
		t.Error("Bit 0 should remain set after marking bit 1")
	}
}

// TestMarkUsedColorEdgeChunkBoundaries tests marking colors near 63, 64, and beyond.
func TestMarkUsedColorEdgeChunkBoundaries(t *testing.T) {
	var node Node

	// Mark color=63 (last bit of chunk 0) and check
	node.markUsedColor(63)
	if !isBitSet(&node, 63) {
		t.Error("Bit 63 (last bit in first 64-bit chunk) should be set")
	}

	// Mark color=64 (first bit of chunk 1) and check
	node.markUsedColor(64)
	if !isBitSet(&node, 64) {
		t.Error("Bit 64 (first bit in second 64-bit chunk) should be set")
	}

	// Also verify that 63 remains set
	if !isBitSet(&node, 63) {
		t.Error("Bit 63 should still be set")
	}

	// Mark color=127 (last bit of chunk 1)
	node.markUsedColor(127)
	if !isBitSet(&node, 127) {
		t.Error("Bit 127 should be set (last bit in second 64-bit chunk)")
	}
}

// TestMarkUsedColorHighValue tests marking large color indices.
func TestMarkUsedColorHighValue(t *testing.T) {
	var node Node

	// Mark a color well beyond the first two chunks.
	const colorIndex = 300
	node.markUsedColor(colorIndex)

	// Confirm it's set
	if !isBitSet(&node, colorIndex) {
		t.Errorf("Expected bit %d to be set", colorIndex)
	}
	// Confirm that smaller bits are not spuriously set
	if isBitSet(&node, 0) {
		t.Error("Bit 0 should not be set unless explicitly marked")
	}
	if isBitSet(&node, 64) {
		t.Error("Bit 64 should not be set unless explicitly marked")
	}
}

// TestMarkUsedColorRepeated verifies that marking a bit is idempotent.
func TestMarkUsedColorRepeated(t *testing.T) {
	var node Node

	node.markUsedColor(10)
	node.markUsedColor(10)
	node.markUsedColor(10)

	if !isBitSet(&node, 10) {
		t.Error("Bit 10 should still be set after multiple markings")
	}
}
