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

package e2e

import (
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

// Index represents an E2E index. These are interpreted as "active", so the reservation initiator
// must cleanup indices along the path when the setup didn't finish correctly.
type Index struct {
	Idx        reservation.IndexNumber
	Expiration time.Time
	AllocBW    reservation.BWCls // also present in the token
	Token      *reservation.Token
}

type Indices []Index

var _ base.IndicesInterface = (*Indices)(nil)

func (idxs Indices) Len() int                                     { return len(idxs) }
func (idxs Indices) GetIndexNumber(i int) reservation.IndexNumber { return idxs[i].Idx }
func (idxs Indices) GetExpiration(i int) time.Time                { return idxs[i].Expiration }
func (idxs Indices) GetAllocBW(i int) reservation.BWCls           { return idxs[i].AllocBW }
func (idxs Indices) GetToken(i int) *reservation.Token            { return idxs[i].Token }
