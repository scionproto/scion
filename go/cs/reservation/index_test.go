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

package reservation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

func TestValidateIndices(t *testing.T) {
	idxs := make(Indices, 0)
	// up to 3 indices per expiration time
	expTime := time.Unix(1, 0)
	idx, err := idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, reservation.IndexNumber(0), idx)
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, reservation.IndexNumber(1), idx)
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, reservation.IndexNumber(2), idx)
	idxs = idxs[:1]
	// exp time is less
	_, err = idxs.NewIndex(expTime.Add(-1 * time.Millisecond))
	require.Error(t, err)
	require.Len(t, idxs, 1)
	// exp time is same
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, idxs, 2)
	require.True(t, idxs[1].Idx == idx)
	require.True(t, idxs[1].Expiration == expTime)
	require.Equal(t, reservation.IndexNumber(1), idx)
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, idxs, 3)
	require.True(t, idxs[2].Idx == idx)
	require.True(t, idxs[2].Expiration == expTime)
	require.Equal(t, reservation.IndexNumber(2), idx)
	// too many indices for the same exp time
	_, err = idxs.NewIndex(expTime)
	require.Error(t, err)
	require.Len(t, idxs, 3)
	// exp time is greater
	expTime = expTime.Add(time.Second)
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, idxs, 4)
	require.True(t, idxs[3].Idx == idx)
	require.True(t, idxs[3].Expiration == expTime)
	require.Equal(t, reservation.IndexNumber(3), idx)
	// index number rollover
	idxs = Indices{}
	idxs.NewIndex(expTime)
	require.Len(t, idxs, 1)
	idxs[0].Idx = idxs[0].Idx.Sub(1)
	idx, err = idxs.NewIndex(expTime)
	require.NoError(t, err)
	require.True(t, idxs[1].Idx == idx)
	require.True(t, idxs[1].Expiration == expTime)
	require.Equal(t, reservation.IndexNumber(0), idx)
	// more than 16 indices
	idxs = Indices{}
	for i := 0; i < 16; i++ {
		expTime := time.Unix(int64(i), 0)
		_, err = idxs.NewIndex(expTime)
		require.NoError(t, err)
	}
	require.Len(t, idxs, 16)
	_, err = idxs.NewIndex(expTime.Add(time.Hour))
	require.Error(t, err)
	// exp time is before
	idxs = Indices{}
	expTime = time.Unix(1, 0)
	idxs.NewIndex(expTime)
	idxs.NewIndex(expTime)
	idxs[1].Expiration = expTime.Add(-1 * time.Second)
	err = ValidateIndices(idxs)
	require.Error(t, err)
	// non consecutive indices
	idxs = Indices{}
	expTime = time.Unix(1, 0)
	idxs.NewIndex(expTime)
	idxs.NewIndex(expTime)
	idxs[1].Idx = 2
	err = ValidateIndices(idxs)
	require.Error(t, err)
	// more than three indices per exp time
	idxs = Indices{}
	idxs.NewIndex(expTime)
	idxs.NewIndex(expTime)
	idxs.NewIndex(expTime)
	require.Len(t, idxs, 3)
	err = ValidateIndices(idxs)
	require.NoError(t, err)
	_, err = idxs.NewIndex(expTime)
	require.Error(t, err)
}

type Index struct {
	Idx        reservation.IndexNumber
	Expiration time.Time
}

type Indices []Index

var _ IndicesInterface = (*Indices)(nil)

func (idxs Indices) Len() int                                     { return len(idxs) }
func (idxs Indices) GetIndexNumber(i int) reservation.IndexNumber { return idxs[i].Idx }
func (idxs Indices) GetExpiration(i int) time.Time                { return idxs[i].Expiration }
func (idxs Indices) GetAllocBW(i int) reservation.BWCls           { return reservation.BWCls(0) }
func (idxs Indices) GetToken(i int) *reservation.Token            { return nil }

func (idxs *Indices) NewIndex(expTime time.Time) (reservation.IndexNumber, error) {
	idx := reservation.IndexNumber(0)
	if len(*idxs) > 0 {
		idx = (*idxs)[len(*idxs)-1].Idx.Add(1)
	}
	index := Index{
		Idx:        idx,
		Expiration: expTime,
	}
	newIndices := make(Indices, len(*idxs)+1)
	copy(newIndices, *idxs)
	newIndices[len(newIndices)-1] = index
	err := ValidateIndices(newIndices)
	if err != nil {
		return reservation.IndexNumber(0), err
	}
	*idxs = newIndices
	return idx, nil
}
