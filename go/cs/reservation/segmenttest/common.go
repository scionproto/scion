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

package segmenttest

import (
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

func NewPathFromComponents(chain ...interface{}) segment.ReservationTransparentPath {
	if len(chain)%3 != 0 {
		panic("wrong number of arguments")
	}
	p := segment.ReservationTransparentPath{}
	for i := 0; i < len(chain); i += 3 {
		p = append(p, segment.PathStepWithIA{
			PathStep: segment.PathStep{
				Ingress: uint16(chain[i].(int)),
				Egress:  uint16(chain[i+2].(int)),
			},
			IA: xtest.MustParseIA(chain[i+1].(string)),
		})
	}
	return p
}

func NewReservation() *segment.Reservation {
	segID, err := reservation.NewSegmentID(xtest.MustParseAS("ff00:0:1"),
		xtest.MustParseHexString("beefcafe"))
	if err != nil {
		panic(err)
	}
	r := segment.NewReservation()
	r.ID = *segID
	r.Path = NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	return r
}
