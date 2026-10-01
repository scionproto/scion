// Copyright 2026 SCION Association
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

package lfring

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests reach into [Ring]'s unexported fields and therefore live with
// the implementation. Everything reachable through the exported API is
// tested from the parent queue package instead.

// TestLenEdges tests that Len clamps to [0, Cap] when
// the enq/deq snapshot is momentarily skewed.
func TestLenEdges(t *testing.T) {
	r := NewRing[int](4)
	// enq behind deq can happen mid-op between two atomic loads; Len must report 0.
	r.enq.Store(5)
	r.deq.Store(7)
	require.Equal(t, 0, r.Len())
	// enq far ahead of deq; Len must clamp to Cap.
	r.enq.Store(100)
	r.deq.Store(0)
	require.Equal(t, r.Cap(), r.Len())
}

// TestRoundUpPow2Clamps tests the capacity clamp at both ends.
// The upper clamp is checked here rather than through NewRing:
// a ring of MaxCapacity cells is far too large to allocate in a test.
func TestRoundUpPow2Clamps(t *testing.T) {
	require.Equal(t, uint32(2), roundUpPow2(math.MinInt), "most negative")
	require.Equal(t, uint32(2), roundUpPow2(-1))
	require.Equal(t, uint32(2), roundUpPow2(0))
	require.Equal(t, uint32(MaxCapacity), roundUpPow2(MaxCapacity))
	require.Equal(t, uint32(MaxCapacity), roundUpPow2(MaxCapacity+1), "above the max")
	require.Equal(t, uint32(MaxCapacity), roundUpPow2(math.MaxInt), "far above the max")
}

// TestPopClearsCell tests that after a pop the slot holds
// no reference to the value. *T can then be collected.
func TestPopClearsCell(t *testing.T) {
	r := NewRing[*int](4)
	x := new(int)
	require.True(t, r.TryPush(x))
	_, ok := r.TryPop()
	require.True(t, ok)
	for i := range r.cells {
		require.Nil(t, r.cells[i].val, "cell %d still references a popped value", i)
	}
}
