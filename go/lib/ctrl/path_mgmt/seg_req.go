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

// This file contains the Go representation of segment requests.

package path_mgmt

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*SegReq)(nil)

type SegReq struct {
	RawSrcIA uint32 `capnp:"srcIA"`
	RawDstIA uint32 `capnp:"dstIA"`
	Flags    struct {
		Sibra     bool
		CacheOnly bool
	}
}

func NewSegReqFromRaw(b common.RawBytes) (*SegReq, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse SegReq", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse SegReq", "err", err)
	}
	req := &SegReq{}
	err = pogs.Extract(req, proto.SegReq_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse SegReq", "err", err)
	}
	return req, nil
}

func (s *SegReq) SrcIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawSrcIA))
}

func (s *SegReq) DstIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawDstIA))
}

func (s *SegReq) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (s *SegReq) Copy() (common.Payload, *common.Error) {
	rawPld, err := s.Pack()
	if err != nil {
		return nil, err
	}
	return NewSegReqFromRaw(rawPld)
}

func (s *SegReq) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack SegReq", "err", err)
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack SegReq", "err", err)
	}
	if err := pogs.Insert(proto.SegReq_TypeID, root.Struct, s); err != nil {
		return nil, common.NewError("Failed to pack SegReq", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack SegReq", "err", err)
	}
	return packed, nil
}

func (s *SegReq) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := s.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write SegReq", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (s *SegReq) String() string {
	return fmt.Sprintf("SrcIA: %v, DstIA: %d, Flags: %v", s.SrcIA(), s.DstIA(), s.Flags)
}
