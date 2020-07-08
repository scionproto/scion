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
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

type IndicesInterface interface {
	Len() int
	GetIndexNumber(i int) reservation.IndexNumber
	GetExpiration(i int) time.Time
	GetAllocBW(i int) reservation.BWCls
	GetToken(i int) *reservation.Token
	Rotate(i int) IndicesInterface
}

// ValidateIndices checks that the indices follow consecutive index numbers, their expiration
// times are greater or equal, and no more than three indices per expiration time. Also no more
// than 16 indices are allowed.
func ValidateIndices(indices IndicesInterface) error {
	lastExpiration := util.SecsToTime(0)
	lastIndexNumber := reservation.IndexNumber(0).Sub(1)
	if indices.Len() > 0 {
		lastIndexNumber = indices.GetIndexNumber(0).Sub(1)
		if indices.Len() > 16 {
			// with only 4 bits to represent the index number, we cannot have more than 16 indices
			return serrors.New("too many indices", "index_count", indices.Len())
		}
	}
	indicesPerExpTime := 0
	for i := 0; i < indices.Len(); i++ {
		if indices.GetExpiration(i).Before(lastExpiration) {
			return serrors.New("index expires before than a previous one",
				"idx", indices.GetIndexNumber(i),
				"expiration", indices.GetExpiration(i), "previous_exp", lastExpiration)
		}
		if indices.GetExpiration(i).Equal(lastExpiration) {
			indicesPerExpTime++
			if indicesPerExpTime > 3 {
				return serrors.New("more than three indices per expiration time",
					"expiration", indices.GetExpiration(i))
			}
		} else {
			indicesPerExpTime = 1
		}
		if indices.GetIndexNumber(i).Sub(lastIndexNumber) != reservation.IndexNumber(1) {
			return serrors.New("non consecutive indices", "prev_index_number", lastIndexNumber,
				"index_number", indices.GetIndexNumber(i))
		}
		lastExpiration = indices.GetExpiration(i)
		lastIndexNumber = indices.GetIndexNumber(i)
		token := indices.GetToken(i)
		if token != nil {
			if token.Idx != lastIndexNumber {
				return serrors.New("inconsistent token", "token_index_number", token.Idx,
					"expected", lastIndexNumber)
			}
			if token.ExpirationTick != reservation.TickFromTime(lastExpiration) {
				return serrors.New("inconsistent token", "token_expiration_tick",
					token.ExpirationTick, "expected", reservation.TickFromTime(lastExpiration))
			}
			if token.BWCls != indices.GetAllocBW(i) {
				return serrors.New("inconsistent token", "token_bw_class", token.BWCls,
					"expected", indices.GetAllocBW(i))
			}
		}
	}
	return nil
}

// FindIndex returns the slice index for the passed IndexNumber.
func FindIndex(indices IndicesInterface, idx reservation.IndexNumber) (int, error) {
	var firstIdx reservation.IndexNumber = 0
	if indices.Len() > 0 {
		firstIdx = indices.GetIndexNumber(0)
	}
	sliceIndex := int(idx.Sub(firstIdx))
	if sliceIndex > indices.Len()-1 {
		return 0, serrors.New("index not found in this reservation", "index_number", idx,
			"indices length", indices.Len())
	}
	return sliceIndex, nil
}

// SortIndices sorts these Indices according to their index number modulo 16, e.g. [14, 15, 0, 1].
func SortIndices(idxs IndicesInterface) {
	if idxs.Len() < 2 {
		return
	}
	sort.Slice(idxs, func(i, j int) bool {
		ae, be := idxs.GetExpiration(i), idxs.GetExpiration(j)
		ai, bi := idxs.GetIndexNumber(i), idxs.GetIndexNumber(j)
		distance := bi.Sub(ai)
		return ae.Before(be) || (ae.Equal(be) && distance < 3)
	})
	// find a discontinuity and rotate
	i := 1
	for ; i < idxs.Len(); i++ {
		if idxs.GetIndexNumber(i-1).Add(1) != idxs.GetIndexNumber(i).Add(0) {
			break
		}
	}
	idxs = idxs.Rotate(i)
}
