// Copyright 2017 ETH Zurich
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

// This file contains the Go representation of a hop entry in a AS entry

package seg

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

type HopEntry struct {
	RawInIA     addr.IAInt `capnp:"inIA"`
	RemoteInIF  common.IFIDType
	InMTU       uint16     `capnp:"inMTU"`
	RawOutIA    addr.IAInt `capnp:"outIA"`
	RemoteOutIF common.IFIDType
	HopField    HopField `capnp:"hopField"`

	// Deprecated: This is only used for legacy path header
	RawHopField []byte `capnp:"hopF"`
}

func (e *HopEntry) InIA() addr.IA {
	return e.RawInIA.IA()
}

func (e *HopEntry) OutIA() addr.IA {
	return e.RawOutIA.IA()
}

type HopField struct {
	ExpTime     uint8  `capnp:"expTime"`
	ConsIngress uint16 `capnp:"consIngress"`
	ConsEgress  uint16 `capnp:"consEgress"`
	MAC         []byte `capnp:"mac"`
}
