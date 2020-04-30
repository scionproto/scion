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
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

type IndexState uint8

const (
	IndexTemporary IndexState = iota
	IndexPending              // the index is confirmed, but not yet activated.
	IndexActive
)

type Index struct {
	reservation.IndexID
	state   IndexState
	MinBW   reservation.BWCls
	MaxBW   reservation.BWCls
	AllocBW reservation.BWCls
	Token   reservation.Token
}

// State returns the read-only state.
func (idx *Index) State() IndexState {
	return idx.state
}
