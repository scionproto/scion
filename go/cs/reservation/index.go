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
	"time"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

type IndicesInterface interface {
	Len() int
	GetIndexNumber(i int) reservation.IndexNumber
	GetExpiration(i int) time.Time
}

// ValidateIndices checks that the indices follow consecutive index numbers, their expiration
// times are greater or equal, and no more than three indices per expiration time. Also no more
// than 16 indices are allowed.
func ValidateIndices(indices IndicesInterface) error {
	lastExpiration := time.Unix(0, 0)
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
	}
	return nil
}
