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
	ctrl_cmn "github.com/netsec-ethz/scion/go/lib/ctrl/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ PathMgmtPld = (*SegReq)(nil)

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

func NewSegReqFromProto(msg proto.SegReq) (*SegReq, *common.Error) {
	s := &SegReq{}
	if err := pogs.Extract(s, proto.SegReq_TypeID, msg.Struct); err != nil {
		return nil, common.NewError("Failed to extract SegReq struct", "err", err)
	}
	return s, nil
}

func (s *SegReq) SrcIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawSrcIA))
}

func (s *SegReq) DstIA() *addr.ISD_AS {
	return addr.IAFromInt(int(s.RawDstIA))
}

func (s *SegReq) PldClass() proto.SCION_Which {
	return proto.SCION_Which_pathMgmt
}

func (s *SegReq) PldType() proto.PathMgmt_Which {
	return proto.PathMgmt_Which_segReg
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

func (s *SegReq) WritePld(b common.RawBytes) (int, *common.Error) {
	return ctrl_cmn.WritePld(b, s.CtrlWrite)
}

func (s *SegReq) CtrlWrite(scion *proto.SCION) *common.Error {
	mgmt, err := scion.NewPathMgmt()
	if err != nil {
		return common.NewError("Failed to allocate PathMgmt payload", "err", err)
	}
	if err := s.PathMgmtWrite(&mgmt); err != nil {
		return common.NewError("Failed to write SegReq payload", "err", err)
	}
	return nil
}

func (s *SegReq) PathMgmtWrite(mgmt *proto.PathMgmt) *common.Error {
	req, err := mgmt.NewSegReq()
	if err != nil {
		return common.NewError("Failed to allocate SegReq struct", "err", err)
	}
	if err := pogs.Insert(proto.SegReq_TypeID, req.Struct, s); err != nil {
		return common.NewError("Failed to insert SegReq struct", "err", err)
	}
	return nil
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
