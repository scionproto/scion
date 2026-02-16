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
	"strings"
	"testing"
)

// TestIntervalColorMapNodesForInterval test if the correct nodes of the IntervalColorMap cover the range
func TestIntervalColorMapNodesForInterval(t *testing.T) {
	icm := NewIntervalColorMap(8)

	cases := []struct {
		name        string
		low, high   int
		wantIndices []int
	}{
		{
			name:        "single",
			low:         2,
			high:        2,
			wantIndices: []int{9},
		},
		{
			name:        "first",
			low:         0,
			high:        0,
			wantIndices: []int{7},
		},
		{
			name:        "last",
			low:         7,
			high:        7,
			wantIndices: []int{14},
		},
		{
			name:        "paired",
			low:         4,
			high:        5,
			wantIndices: []int{5},
		},
		{
			name:        "two_unpaired",
			low:         3,
			high:        4,
			wantIndices: []int{10, 11},
		},
		{
			name:        "full",
			low:         0,
			high:        7,
			wantIndices: []int{0},
		},
		{
			name:        "almost_full",
			low:         1,
			high:        6,
			wantIndices: []int{8, 13, 4, 5},
		},
		{
			name:        "almost_full2",
			low:         1,
			high:        7,
			wantIndices: []int{8, 4, 2},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := icm.nodesForInterval(tc.low, tc.high)
			if err != nil {
				t.Fatalf("nodesForInterval(%d,%d) error: %v", tc.low, tc.high, err)
			}
			var gotIndices []int
			for i, _ := range nodes {
				for j, _ := range icm.nodes {
					if nodes[i] == &icm.nodes[j] {
						gotIndices = append(gotIndices, j)
						break
					}
				}
			}
			//fmt.Println(tc.name, ": gotIndices =", gotIndices)
			if len(gotIndices) != len(tc.wantIndices) {
				t.Fatalf("got len=%d, want len=%d", len(gotIndices), len(tc.wantIndices))
			}
			// We'll compare slices ignoring order if needed, but the original test expects the same order.
			for i := range tc.wantIndices {
				if gotIndices[i] != tc.wantIndices[i] {
					t.Fatalf("node index mismatch at %d: got %d, want %d",
						i, gotIndices[i], tc.wantIndices[i])
				}
			}
		})
	}

	// Test invalid intervals

	eCases := []struct {
		name      string
		low, high int
		wantError error
	}{
		{
			name:      "flipped",
			low:       7,
			high:      0,
			wantError: fmt.Errorf("invalid interval query on color tree: "),
		},
		{
			name:      "outOfBound",
			low:       0,
			high:      8,
			wantError: fmt.Errorf("invalid interval query on color tree: "),
		},
	}
	for _, tc := range eCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := icm.nodesForInterval(tc.low, tc.high)
			if err == nil {
				t.Fatalf("nodesForInterval(%d,%d) does not error: %v, expected: %v", tc.low, tc.high, err, tc.wantError)
			} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
				t.Fatalf("nodesForInterval(%d,%d) incorrect error: %v, expected: %v", tc.low, tc.high, err, tc.wantError)
			}
		})
	}
}

// TestColorAssignment tests the color assignment for various intervals
func TestColorAssignment(t *testing.T) {
	intervals := []struct {
		low, high int
	}{
		{0, 0},
		{2, 2},
		{4, 4},
		{6, 6},
		{0, 1},
		{5, 6},
		{1, 3},
		{3, 5},
	}
	var assignedColors []uint32
	colorTree := NewIntervalColorMap(7)

	for _, itv := range intervals {
		c, err := colorTree.firstFreeColor(itv.low, itv.high)
		if err != nil {
			t.Fatalf("firstFreeColor(%d..%d) failed: %v", itv.low, itv.high, err)
		}
		if err := colorTree.markUsedColor(c, itv.low, itv.high); err != nil {
			t.Fatalf("markUsedColor(%d, %d..%d) failed: %v", c, itv.low, itv.high, err)
		}
		assignedColors = append(assignedColors, c)
	}

	want := []uint32{0, 0, 0, 0, 1, 1, 2, 3}
	if len(assignedColors) != len(want) {
		t.Fatalf("got len=%d, want len=%d", len(assignedColors), len(want))
	}
	for i := range assignedColors {
		if assignedColors[i] != want[i] {
			t.Errorf("color at %d: got %d, want %d", i, assignedColors[i], want[i])
		}
	}

	colorTree = NewIntervalColorMap(7)
	assignedColors = []uint32{}
	for _, itv := range intervals {
		c, err := colorTree.AssignColor(itv.low, itv.high)
		if err != nil {
			t.Fatalf("AssignColor(%d..%d) failed: %v", itv.low, itv.high, err)
		}
		assignedColors = append(assignedColors, c)
	}
	for i := range assignedColors {
		if assignedColors[i] != want[i] {
			t.Errorf("color at %d: got %d, want %d", i, assignedColors[i], want[i])
		}
	}

	// Test invalid assignments
	eCases := []struct {
		name      string
		low, high int
		color     uint32
		wantError error
	}{
		{
			name:      "flipped",
			low:       6,
			high:      0,
			color:     0,
			wantError: fmt.Errorf("invalid interval when marking colors in color tree: "),
		},
		{
			name:      "subtreeOutOfBound",
			low:       0,
			high:      6,
			color:     14,
			wantError: fmt.Errorf("trying to mark color for invalid index in markSubTree"),
		},
		{
			name:      "ancestorOutOfBound",
			low:       0,
			high:      6,
			color:     14,
			wantError: fmt.Errorf("trying to mark color for invalid index in markAncestors"),
		},
		{
			name:      "variableSize",
			low:       0,
			high:      1,
			color:     65,
			wantError: nil,
		},
		{
			name:      "allUsed",
			low:       0,
			high:      6,
			color:     0,
			wantError: fmt.Errorf("all bits used, no free color found"),
		},
		{
			name:      "invalidAssignColorInterval",
			low:       5,
			high:      0,
			color:     0,
			wantError: fmt.Errorf("invalid interval query on color tree"),
		},
		{
			name:      "invalidIdxIterator",
			low:       2,
			high:      2,
			color:     0,
			wantError: fmt.Errorf("false"),
		},
		{
			name:      "invalidNodeIterator",
			low:       2,
			high:      2,
			color:     0,
			wantError: fmt.Errorf("false"),
		},
	}

	for _, tc := range eCases {
		switch tc.name {
		case "flipped":
			t.Run(tc.name, func(t *testing.T) {
				err := colorTree.markUsedColor(tc.color, tc.low, tc.high)
				if err == nil {
					t.Fatalf("markUsedColor(%d, %d..%d) does not error: %v, expected: %v",
						tc.color, tc.low, tc.high, err, tc.wantError)
				} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
					t.Fatalf("markUsedColor(%d, %d..%d) incorrect error: %v, expected: %v",
						tc.color, tc.low, tc.high, err, tc.wantError)
				}
			})
		case "subtreeOutOfBound":
			t.Run(tc.name, func(t *testing.T) {
				err := colorTree.markSubTree(tc.high*2+2, tc.color)
				if err == nil {
					t.Fatalf("markSubTree(%d, %d) does not error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
					t.Fatalf("markSubTree(%d, %d) incorrect error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				}
			})
		case "ancestorOutOfBound":
			t.Run(tc.name, func(t *testing.T) {
				err := colorTree.markAncestors(tc.high*4+6, tc.color)
				if err == nil {
					t.Fatalf("markAncestors(%d, %d) does not error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
					t.Fatalf("markAncestors(%d, %d) incorrect error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				}
			})
		case "variableSize":
			for i := 0; i < 65; i++ {
				_ = colorTree.markUsedColor(uint32(i), tc.low, tc.low)
			}
			t.Run(tc.name, func(t *testing.T) {
				_, err := colorTree.firstFreeColor(tc.low, tc.high)
				if err != tc.wantError {
					t.Fatalf("firstFreeColor((%d..%d) failed: %v",
						tc.low, tc.high, err)
				}
			})
		case "allUsed":
			colorTree.nodes[7].colorBits[0] = ^uint64(0)
			colorTree.nodes[7].colorBits[1] = ^uint64(0)
			t.Run(tc.name, func(t *testing.T) {
				_, err := colorTree.firstFreeColor(tc.low, tc.low)
				if err == nil {
					t.Fatalf("firstFreeColor(%d, %d) does not error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
					t.Fatalf("firstFreeColor(%d, %d) incorrect error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				}
			})
		case "invalidAssignColorInterval":
			t.Run(tc.name, func(t *testing.T) {
				icm := NewIntervalColorMap(2)
				_, err := icm.AssignColor(tc.low, tc.high)
				if err == nil {
					t.Fatalf("AssignColor(%d, %d) does not error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				} else if !strings.Contains(err.Error(), tc.wantError.Error()) {
					t.Fatalf("AssignColor(%d, %d) incorrect error: %v, expected: %v",
						tc.high+1, tc.color, err, tc.wantError)
				}
			})
		case "invalidIdxIterator":
			t.Run(tc.name, func(t *testing.T) {
				icm := NewIntervalColorMap(1)
				iter := NewNodeIdxIter(icm, tc.low, tc.high)
				idx, ok := iter.Next()
				if ok {
					t.Fatalf("idx, ok := iter.Next(), got idx=%d, ok=%v, expected: %v",
						idx, ok, tc.wantError)
				}
				_, ok2 := iter.Next()
				if ok2 {
					t.Fatalf("idx, ok2 := iter.Next(), got idx=%d, ok2=%v, expected: %v",
						idx, ok, tc.wantError)
				}
			})
		case "invalidNodeIterator":
			t.Run(tc.name, func(t *testing.T) {
				icm := NewIntervalColorMap(1)
				iter := NewNodeIter(icm, tc.low, tc.high)
				idx, ok := iter.Next()
				if ok {
					t.Fatalf("idx, ok := iter.Next(), got idx=%d, ok=%v, expected: %v",
						idx, ok, tc.wantError)
				}
				_, ok2 := iter.Next()
				if ok2 {
					t.Fatalf("idx, ok2 := iter.Next(), got idx=%d, ok2=%v, expected: %v",
						idx, ok, tc.wantError)
				}
			})
		}
	}
}
