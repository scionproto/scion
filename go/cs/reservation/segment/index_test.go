// Copyright 2020 ETH Zurich, Anapaya Systems
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

// package segment_test
package segment_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

func TestIndicesSort(t *testing.T) {
	indices := newIndices(2, 3, 1)
	indices.Sort()
	require.Len(t, indices, 3)
	checkIndicesSorted(t, indices)
	// one element
	indices = newIndices(2)
	indices.Sort()
	require.Len(t, indices, 1)
	require.Equal(t, 2, int(indices[0].Idx))
	// empty
	indices = segment.Indices{}
	indices.Sort()
	require.Len(t, indices, 0)
	// wrap around
	indices = newIndices(0, 1, 15)
	indices.Sort()
	require.Len(t, indices, 3)
	checkIndicesSorted(t, indices)
	// full 16 elements
	indices = newIndices(14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
	indices.Sort()
	require.Len(t, indices, 16)
	checkIndicesSorted(t, indices)
}

func newIndices(idxs ...int) segment.Indices {
	indices := make(segment.Indices, len(idxs))
	for i, idx := range idxs {
		idx := segment.NewIndex(reservation.IndexNumber(idx), time.Unix(1, 0), segment.IndexPending,
			reservation.BWCls(1), reservation.BWCls(1), reservation.BWCls(1), &reservation.Token{})
		indices[i] = *idx
	}
	return indices
}

func checkIndicesSorted(t *testing.T, idxs segment.Indices) {
	t.Helper()
	if len(idxs) < 2 {
		return
	}
	for i := 1; i < len(idxs); i++ {
		require.Equal(t, idxs[i-1].Idx.Add(1), idxs[i].Idx)
	}
}
