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
	"sort"
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

type IndexState uint8

// possible states of a segment reservation index.
const (
	IndexTemporary IndexState = iota
	IndexPending              // the index is confirmed, but not yet activated.
	IndexActive
)

// NewIndexStateFromCtrlMsg converts a proto reservation index state into its application type.
func NewIndexStateFromCtrlMsg(st proto.ReservationIndexState) (IndexState, error) {
	var state IndexState
	switch st {
	case proto.ReservationIndexState_pending:
		state = IndexPending
	case proto.ReservationIndexState_active:
		state = IndexActive
	default:
		return 0, serrors.New("unknown index_state in ctrl variable", "index_state", st)
	}
	return state, nil
}

// ToCtrlMsg converts this IndexState to its control message counterpart.
func (s IndexState) ToCtrlMsg() (proto.ReservationIndexState, error) {
	var st proto.ReservationIndexState
	switch s {
	case IndexPending:
		st = proto.ReservationIndexState_pending
	case IndexActive:
		st = proto.ReservationIndexState_active
	default:
		return 0, serrors.New("cannot convert index state to control message", "state", s)
	}
	return st, nil
}

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

// Sort sorts these Indices according to their index number modulo 16, e.g. [14, 15, 0, 1].
func (idxs *Indices) Sort() {
	if len(*idxs) < 2 {
		return
	}
	sort.Slice(*idxs, func(i, j int) bool {
		a, b := (*idxs)[i], (*idxs)[j]
		distance := b.Idx.Sub(a.Idx)
		return a.Expiration.Before(b.Expiration) ||
			(a.Expiration.Equal(b.Expiration) && distance < 3)
	})
	// find a discontinuity and rotate
	i := 1
	for ; i < len(*idxs); i++ {
		if (*idxs)[i-1].Idx.Add(1) != (*idxs)[i].Idx.Add(0) {
			break
		}
	}
	*idxs = append((*idxs)[i:], (*idxs)[:i]...)
}
