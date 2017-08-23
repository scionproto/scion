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

package path_mgmt

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*PathMgmt)(nil)

type PathMgmt struct {
	Which        proto.PathMgmt_Which
	SegReq       *SegReq
	SegReply     *SegRecs
	SegReg       *SegRecs
	SegSync      *SegRecs
	RevInfo      *RevInfo
	IFStateReq   *IFStateReq   `capnp:"ifStateReq"`
	IFStateInfos *IFStateInfos `capnp:"ifStateInfos"`
}

func NewPathMgmt(val interface{}, which proto.PathMgmt_Which) (*PathMgmt, *common.Error) {
	pathMgmt := &PathMgmt{Which: which}
	var ok bool
	switch which {
	case proto.PathMgmt_Which_segReq:
		pathMgmt.SegReq, ok = val.(*SegReq)
	case proto.PathMgmt_Which_segReply:
		pathMgmt.SegReply, ok = val.(*SegRecs)
	case proto.PathMgmt_Which_segReg:
		pathMgmt.SegReg, ok = val.(*SegRecs)
	case proto.PathMgmt_Which_segSync:
		pathMgmt.SegSync, ok = val.(*SegRecs)
	case proto.PathMgmt_Which_revInfo:
		pathMgmt.RevInfo, ok = val.(*RevInfo)
	case proto.PathMgmt_Which_ifStateReq:
		pathMgmt.IFStateReq, ok = val.(*IFStateReq)
	case proto.PathMgmt_Which_ifStateInfos:
		pathMgmt.IFStateInfos, ok = val.(*IFStateInfos)
	default:
		return nil, common.NewError("Unsupported payload type: %v", which)
	}
	if !ok {
		return nil, common.NewError("Provided value does not match the type",
			"provided", fmt.Sprintf("%T", val), "expected", which)
	}
	return pathMgmt, nil
}

func NewPathMgmtFromRaw(b common.RawBytes) (*PathMgmt, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	pkt := &PathMgmt{}
	err = pogs.Extract(pkt, proto.PathMgmt_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse IFID packet", "err", err)
	}
	return pkt, nil
}

func (p *PathMgmt) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (p *PathMgmt) Copy() (common.Payload, *common.Error) {
	rawPld, err := p.Pack()
	if err != nil {
		return nil, err
	}
	return NewPathMgmtFromRaw(rawPld)
}

func (p *PathMgmt) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	root, err := proto.NewRootPathMgmt(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	if err := pogs.Insert(proto.PathMgmt_TypeID, root.Struct, p); err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack IFID packet", "err", err)
	}
	return packed, nil
}

func (p *PathMgmt) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := p.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write PathMgmt", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (p *PathMgmt) String() string {
	switch p.Which {
	case proto.PathMgmt_Which_unset:
		return "unset"
	case proto.PathMgmt_Which_segReq:
		return fmt.Sprintf("SegRequest: %v", p.SegReq)
	case proto.PathMgmt_Which_segReply:
		return fmt.Sprintf("SegReply: %v", p.SegReply)
	case proto.PathMgmt_Which_segReg:
		return fmt.Sprintf("SegRegistration: %v", p.SegReg)
	case proto.PathMgmt_Which_segSync:
		return fmt.Sprintf("SeqSync: %v", p.SegSync)
	case proto.PathMgmt_Which_revInfo:
		return fmt.Sprintf("RevInfo: %v", p.RevInfo)
	case proto.PathMgmt_Which_ifStateReq:
		return fmt.Sprintf("IFStateReq: %v", p.IFStateReq)
	case proto.PathMgmt_Which_ifStateInfos:
		return fmt.Sprintf("IFStateInfos: %v", p.IFStateInfos)
	default:
		return "unknown"
	}
}
