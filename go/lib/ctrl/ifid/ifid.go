// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// Package ifid contains the Go representation of an IFID keepalive packet.
//
// IFID keepalive messages are sent from the beacon server on all links to the
// neighboring ASes using a one-hop path. The keepalive contains origin IFID
// which specifies the interface it was sent on. This allows beacon servers to
// discover the remote IFIDs of links, a crucial information for the beaconing
// process.
package ifid

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*IFID)(nil)

// IFID is the ifid keepalive message.
type IFID struct {
	// OrigiIfid is the egress interface a keepalive was sent on.
	OrigIfID common.IFIDType `capnp:"origIF"`
}

func NewFromRaw(b common.RawBytes) (*IFID, error) {
	i := &IFID{}
	return i, proto.ParseFromRaw(i, b)
}

func (i *IFID) ProtoId() proto.ProtoIdType {
	return proto.IFID_TypeID
}

func (i *IFID) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(i, b)
}

func (i *IFID) String() string {
	return fmt.Sprintf("OrigIfID: %d", i.OrigIfID)
}
