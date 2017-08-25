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

// This file contains the Go representation of IFState requests.

package path_mgmt

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	ctrl_cmn "github.com/netsec-ethz/scion/go/lib/ctrl/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ PathMgmtPld = (*IFStateReq)(nil)

type IFStateReq struct {
	IfID uint64
}

func NewIFStateReqFromRaw(b common.RawBytes) (*IFStateReq, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateReq", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateReq", "err", err)
	}
	req := &IFStateReq{}
	err = pogs.Extract(req, proto.IFStateReq_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateReq", "err", err)
	}
	return req, nil
}

func NewIFStateReqFromProto(msg proto.IFStateReq) (*IFStateReq, *common.Error) {
	i := &IFStateReq{}
	if err := pogs.Extract(i, proto.IFStateReq_TypeID, msg.Struct); err != nil {
		return nil, common.NewError("Failed to extract IFStateReq struct", "err", err)
	}
	return i, nil
}

func (i *IFStateReq) PldClass() proto.SCION_Which {
	return proto.SCION_Which_pathMgmt
}

func (i *IFStateReq) PldType() proto.PathMgmt_Which {
	return proto.PathMgmt_Which_ifStateReq
}

func (i *IFStateReq) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (i *IFStateReq) Copy() (common.Payload, *common.Error) {
	rawPld, err := i.Pack()
	if err != nil {
		return nil, err
	}
	return NewIFStateReqFromRaw(rawPld)
}

func (i *IFStateReq) WritePld(b common.RawBytes) (int, *common.Error) {
	return ctrl_cmn.WritePld(b, i.CtrlWrite)
}

func (i *IFStateReq) CtrlWrite(scion *proto.SCION) *common.Error {
	mgmt, err := scion.NewPathMgmt()
	if err != nil {
		return common.NewError("Failed to allocate PathMgmt payload", "err", err)
	}
	if err := i.PathMgmtWrite(&mgmt); err != nil {
		return common.NewError("Failed to write IFStateReq payload", "err", err)
	}
	return nil
}

func (i *IFStateReq) PathMgmtWrite(mgmt *proto.PathMgmt) *common.Error {
	req, err := mgmt.NewIfStateReq()
	if err != nil {
		return common.NewError("Failed to allocate IFStateReq struct", "err", err)
	}
	if err := pogs.Insert(proto.IFStateReq_TypeID, req.Struct, i); err != nil {
		return common.NewError("Failed to insert IFStateReq struct", "err", err)
	}
	return nil
}

func (i *IFStateReq) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateReq", "err", err)
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateReq", "err", err)
	}
	if err := pogs.Insert(proto.IFStateReq_TypeID, root.Struct, i); err != nil {
		return nil, common.NewError("Failed to pack IFStateReq", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateReq", "err", err)
	}
	return packed, nil
}

func (i *IFStateReq) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := i.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write IFStateReq", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (i *IFStateReq) String() string {
	return fmt.Sprintf("IfID: %v", i.IfID)
}
