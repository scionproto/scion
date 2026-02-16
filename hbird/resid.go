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
	"errors"
	"fmt"
	"math"
)

// Node stores the used colors in colorBits.
type Node struct {
	// colorBits stores indicator bits in big-endian form inside each uint64 chunk,
	// i.e. the highest-order bit of colorBits[i] corresponds to color = i*(wordSize) + 0
	colorBits []uint64
}

// wordSize, size in bits per entry in colorBits
const wordSize = 64

// markUsedColor sets the bit for the given color index in this node's colorBits.
func (n *Node) markUsedColor(color uint32) {
	chunkIdx := color / wordSize
	bitIdx := color % wordSize
	if uint32(len(n.colorBits)) <= chunkIdx {
		n.colorBits = append(n.colorBits, make([]uint64, chunkIdx-uint32(len(n.colorBits))+1)...)
	}
	n.colorBits[chunkIdx] |= 1 << (wordSize - 1 - bitIdx)
}

// IntervalColorMap allows marking and looking up the colors used in an interval, in a chunked bitvector,
// allowing direct lookup of the first free color.
type IntervalColorMap struct {
	nodes          []Node
	NUnitIntervals int
}

// NewIntervalColorMap initializes a new IntervalColorMap
func NewIntervalColorMap(nUnitIntervals int) *IntervalColorMap {
	nInnerNodes := nextPowerOfTwo(nUnitIntervals) - 1
	nodes := make([]Node, nInnerNodes+nUnitIntervals)
	return &IntervalColorMap{
		nodes:          nodes,
		NUnitIntervals: nUnitIntervals,
	}
}

// height returns the height of the tree
func (icm *IntervalColorMap) height() uint32 {
	return ilog2(nextPowerOfTwo(icm.NUnitIntervals)) + 1
}

// nodesForInterval returns the nodes covering [low..high].
func (icm *IntervalColorMap) nodesForInterval(low, high int) ([]*Node, error) {
	if low > high || high >= icm.NUnitIntervals {
		return nil, fmt.Errorf("invalid interval query on color tree: [%d..%d]", low, high)
	}
	iter := NewNodeIter(icm, low, high)
	var nodes []*Node
	for {
		idx, ok := iter.Next()
		if !ok {
			break
		}
		nodes = append(nodes, &icm.nodes[idx])
	}
	return nodes, nil
}

// markUsedColor marks the color as used in the [low, high] interval
func (icm *IntervalColorMap) markUsedColor(color uint32, low, high int) error {
	if low > high || high >= icm.NUnitIntervals {
		return fmt.Errorf("invalid interval when marking colors in color tree: [%d..%d]", low, high)
	}
	// For each node index discovered by NodeIdxIter, mark in the entire subtree and ancestors.
	iter := NewNodeIdxIter(icm, low, high)
	for {
		idx, ok := iter.Next()
		if !ok {
			break
		}
		if err := icm.markSubTree(int(idx), color); err != nil {
			return err
		}
		if err := icm.markAncestors(int(idx), color); err != nil {
			return err
		}
	}
	return nil
}

func (icm *IntervalColorMap) markSubTree(index int, color uint32) error {
	if index < 0 || index >= len(icm.nodes) {
		return errors.New("trying to mark color for invalid index in markSubTree")
	}
	icm.nodes[index].markUsedColor(color)
	left := index*2 + 1
	right := index*2 + 2
	if left < len(icm.nodes) {
		if err := icm.markSubTree(left, color); err != nil {
			return err
		}
	}
	if right < len(icm.nodes) {
		if err := icm.markSubTree(right, color); err != nil {
			return err
		}
	}
	return nil
}

func (icm *IntervalColorMap) markAncestors(index int, color uint32) error {
	for index > 0 {
		index = (index - 1) / 2
		if index < 0 || index >= len(icm.nodes) {
			return errors.New("trying to mark color for invalid index in markAncestors")
		}
		icm.nodes[index].markUsedColor(color)
	}
	return nil
}

// AssignColor assigns and returns the first free color in the interval low, high;
// this corresponds to the interval (start_time, expiration_time).
func (icm *IntervalColorMap) AssignColor(low, high int) (uint32, error) {
	color, err := icm.firstFreeColor(low, high)
	if err != nil {
		return 0, err
	}
	if err := icm.markUsedColor(color, low, high); err != nil {
		return 0, err
	}
	return color, nil
}

// firstFreeColor is a helper function calling an iterator over the combined chunked data.
func (icm *IntervalColorMap) firstFreeColor(low, high int) (uint32, error) {
	// Obtain an iterator with node references covering [low..high].
	nodeIter, err := icm.nodesForInterval(low, high)
	if err != nil {
		return 0, err
	}
	// Each Node has a colorBits slice of uint. We want to combine them with | (bitwise OR).
	// Then find the first free bit using firstFreeFromChunkIter.
	chunks := []uint64{0}

	// Collect union of node colorBits by OR-ing across them.
	// The maximum length of colorBits among all nodes might differ, so we gather them.
	for _, nodeRef := range nodeIter {
		// nodeRef: pointer to Node
		// We gather its colorBits by OR-ing them into a final slice.
		nbits := len(nodeRef.colorBits)
		if len(chunks) < nbits {
			// Extend our main chunk slice
			oldLen := len(chunks)
			chunks = append(chunks, make([]uint64, nbits-oldLen)...)
		}
		for i := 0; i < nbits; i++ {
			// OR them in
			chunks[i] |= nodeRef.colorBits[i]
		}
	}
	// Now use firstFreeFromChunkIter to pick the first free color bit
	return firstFreeFromChunkIter(chunks)
}

// firstFreeFromChunkIter scans the slice for the first chunk != MAX.
func firstFreeFromChunkIter(chunks []uint64) (uint32, error) {
	// We look for the first chunk which is not all 1 bits
	allOnes := ^uint64(0)
	for i, val := range chunks {
		if val != allOnes {
			// find first bit that is 0 in val
			for bitIdx := uint32(0); bitIdx < wordSize; bitIdx++ {
				mask := uint64(1) << (wordSize - 1 - bitIdx)
				if (val & mask) == 0 {
					// The color is i*wordSize + bitIdx
					return uint32(i)*wordSize + bitIdx, nil
				}
			}
		}
	}
	// If none found, we fail
	return 0, errors.New("all bits used, no free color found")
}

// NodeIdxIter iterates over the indices in the tree covering [low..high].
type NodeIdxIter struct {
	low, high   int
	level       uint32
	totalHeight uint32
	finished    bool
}

// NewNodeIdxIter constructs the iterator from an IntervalColorMap, low, high.
func NewNodeIdxIter(colorMap *IntervalColorMap, low, high int) *NodeIdxIter {
	return &NodeIdxIter{
		low:         low,
		high:        high,
		level:       colorMap.height() - 1,
		totalHeight: colorMap.height(),
		finished:    false,
	}
}

// Next returns (nodeIndex, ok).
func (ni *NodeIdxIter) Next() (idx uint32, ok bool) {
	if ni.finished || ni.low >= (1<<ni.totalHeight) {
		return idx, false
	}
	for {
		subintervalExp := ni.totalHeight - ni.level - 1
		subintervalSize := 1 << subintervalExp

		// Condition for the "low" alignment case
		if ni.low%subintervalSize == 0 &&
			ni.low%(2*subintervalSize) != 0 &&
			ni.high >= ni.low+subintervalSize-1 {
			idx = uint32((1<<ni.level - 1) + ni.low/subintervalSize)
			ni.low += subintervalSize
			return idx, true
		}

		// Condition for the "high" alignment case
		if (ni.high+1)%subintervalSize == 0 &&
			(ni.high+1)%(2*subintervalSize) != 0 &&
			ni.high >= ni.low+subintervalSize-1 {
			idx = uint32((1<<ni.level - 1) + ni.high/subintervalSize)
			if subintervalSize <= ni.high {
				ni.high -= subintervalSize
			} else {
				ni.high = 0
			}
			ok = true
		}

		if ni.level == 0 {
			ni.finished = true
			return idx, ok
		}
		ni.level--
		if ok {
			return idx, ok
		}
	}
}

// NodeIter returns the node indices for [low..high].
type NodeIter struct {
	idxIter *NodeIdxIter
	done    bool
}

// NewNodeIter constructs a NodeIter from IntervalColorMap, low, high.
func NewNodeIter(colorMap *IntervalColorMap, low, high int) *NodeIter {
	return &NodeIter{
		idxIter: NewNodeIdxIter(colorMap, low, high),
		done:    false,
	}
}

// Next returns (index, ok) of the next node covering [low..high].
func (niter *NodeIter) Next() (int, bool) {
	if niter.done {
		return 0, false
	}
	idx, ok := niter.idxIter.Next()
	if !ok {
		niter.done = true
		return 0, false
	}
	return int(idx), true
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	pow := 1
	for pow < n {
		pow <<= 1
	}
	return pow
}

func ilog2(n int) uint32 {
	return uint32(math.Log2(float64(n)))
}
