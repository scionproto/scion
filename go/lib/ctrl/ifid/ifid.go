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

// This file contains the Go representation of an IFID packet

package ifid

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*IFID)(nil)

type IFID struct {
	OrigIfID  uint64 `capnp:"origIF"`
	RelayIfID uint64 `capnp:"relayIF"`
}

func NewIFIDFromRaw(b common.RawBytes) (*IFID, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	pkt := &IFID{}
	err = pogs.Extract(pkt, proto.IFID_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	return pkt, nil
}

func (i *IFID) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (i *IFID) Copy() (common.Payload, *common.Error) {
	rawPld, err := i.Pack()
	if err != nil {
		return nil, err
	}
	return NewIFIDFromRaw(rawPld)
}

func (i *IFID) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	if err := pogs.Insert(proto.IFID_TypeID, root.Struct, i); err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	return packed, nil
}

func (i *IFID) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := i.Pack()
	if err != nil {
		return 0, nil
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (i *IFID) String() string {
	return fmt.Sprintf("OrigIfID: %d, RelayIfID: %d", i.OrigIfID, i.RelayIfID)
}
