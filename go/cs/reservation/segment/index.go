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

package segment

import (
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

type IndexState uint8

// possible states of a segment reservation index.
const (
	IndexTemporary IndexState = iota
	IndexPending              // the index is confirmed, but not yet activated.
	IndexActive
)

// Index is a segment reservation index.
type Index struct {
	Idx        reservation.IndexNumber
	Expiration time.Time
	state      IndexState
	MinBW      reservation.BWCls
	MaxBW      reservation.BWCls
	AllocBW    reservation.BWCls
	Token      *reservation.Token
}

// NewIndex creates a new Index without yet linking it to any reservation.
func NewIndex(idx reservation.IndexNumber, expiration time.Time, state IndexState,
	minBW, maxBW, allocBW reservation.BWCls, token *reservation.Token) *Index {
	return &Index{
		Idx:        idx,
		Expiration: expiration,
		state:      state,
		MinBW:      minBW,
		MaxBW:      maxBW,
		AllocBW:    allocBW,
		Token:      token,
	}
}

// State returns the read-only state.
func (index *Index) State() IndexState {
	return index.state
}

// Indices is a collection of Index that implements IndicesInterface.
type Indices []Index

var _ base.IndicesInterface = (*Indices)(nil)

func (idxs Indices) Len() int                                     { return len(idxs) }
func (idxs Indices) GetIndexNumber(i int) reservation.IndexNumber { return idxs[i].Idx }
func (idxs Indices) GetExpiration(i int) time.Time                { return idxs[i].Expiration }
func (idxs Indices) GetAllocBW(i int) reservation.BWCls           { return idxs[i].AllocBW }
func (idxs Indices) GetToken(i int) *reservation.Token            { return idxs[i].Token }
func (idxs Indices) Rotate(i int) base.IndicesInterface {
	return append(idxs[i:], idxs[:i]...)
}
