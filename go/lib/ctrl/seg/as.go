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
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*ASEntry)(nil)

type ASEntry struct {
	RawIA        addr.IAInt `capnp:"isdas"`
	TrcVer       uint64
	CertVer      uint64
	IfIDSize     uint8
	HopEntries   []*HopEntry `capnp:"hops"`
	HashTreeRoot common.RawBytes
	MTU          uint16 `capnp:"mtu"`
	Exts         struct {
		RoutingPolicy common.RawBytes `capnp:"-"` // Not supported yet
		Sibra         common.RawBytes `capnp:"-"` // Not supported yet
	}
}

func newASEntryFromRaw(b common.RawBytes) (*ASEntry, error) {
	ase := &ASEntry{}
	return ase, proto.ParseFromRaw(ase, ase.ProtoId(), b)
}

func (ase *ASEntry) IA() *addr.ISD_AS {
	return ase.RawIA.IA()
}

func (ase *ASEntry) Pack() (common.RawBytes, error) {
	return proto.PackRoot(ase)
}

func (ase *ASEntry) ProtoId() proto.ProtoIdType {
	return proto.ASEntry_TypeID
}

func (ase *ASEntry) String() string {
	return fmt.Sprintf("%s Trc: %d Cert: %d Ifid size: %d Hops: %d MTU: %d",
		ase.IA(), ase.TrcVer, ase.CertVer, ase.IfIDSize, len(ase.HopEntries), ase.MTU)
}
