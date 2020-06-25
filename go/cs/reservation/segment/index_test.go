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

package segment_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/cs/reservation"
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
		expTime := time.Unix(int64(i/3+1), 0)
		idx := segment.NewIndex(reservation.IndexNumber(idx), expTime,
			segment.IndexPending, reservation.BWCls(1), reservation.BWCls(1), reservation.BWCls(1),
			nil)
		indices[i] = *idx
	}
	return indices
}

func checkIndicesSorted(t *testing.T, idxs segment.Indices) {
	t.Helper()
	// validate according to valid indices criteria
	err := base.ValidateIndices(idxs)
	require.NoError(t, err)
}
