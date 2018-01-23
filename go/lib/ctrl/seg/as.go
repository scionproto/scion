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

// This file contains the Go representation of an AS entry in a path segment

package seg

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
)

type ASEntry struct {
	RawIA        addr.IAInt `capnp:"isdas"`
	TrcVer       uint32
	CertVer      uint32
	IfIDSize     uint8
	HopEntries   []*HopEntry `capnp:"pcbms"`
	HashTreeRoot []byte
	Sig          []byte
	MTU          uint16 `capnp:"mtu"`
	Exts         struct {
		RoutingPolicy []byte `capnp:"-"` // Omit routing policy extension for now.
	}
}

func (e *ASEntry) IA() *addr.ISD_AS {
	return e.RawIA.IA()
}
