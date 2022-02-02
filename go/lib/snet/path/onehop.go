// Copyright 2021 ETH Zurich
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

package path

import (
	"crypto/rand"
	"hash"
	"math/big"
	"time"

	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/util"
)

type OneHop struct {
	Info      path.InfoField
	FirstHop  path.HopField
	SecondHop path.HopField
}

func (p OneHop) SetPath(s *slayers.SCION) error {
	ohp := &onehop.Path{
		Info:      p.Info,
		FirstHop:  p.FirstHop,
		SecondHop: p.SecondHop,
	}
	s.Path, s.PathType = ohp, ohp.Type()
	return nil
}

// NewOneHop creates a onehop path that has the first hopfield initialized.
func NewOneHop(
	egress uint16,
	timestamp time.Time,
	expiration uint8,
	mac hash.Hash,
) (OneHop, error) {

	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return OneHop{}, err
	}
	ohp := OneHop{
		Info: path.InfoField{
			ConsDir:   true,
			Timestamp: util.TimeToSecs(timestamp),
			SegID:     uint16(segID.Uint64()),
		},
		FirstHop: path.HopField{
			ConsEgress: egress,
			ExpTime:    expiration,
		},
	}
	ohp.FirstHop.Mac = path.MAC(mac, ohp.Info, ohp.FirstHop, nil)
	return ohp, nil
}
