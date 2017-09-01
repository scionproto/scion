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

// This file contains the Go representation of segment records.

package path_mgmt

import (
	"bytes"
	"strings"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	ctrl_cmn "github.com/netsec-ethz/scion/go/lib/ctrl/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ PathMgmtPld = (*SegRecs)(nil)

type SegRecs struct {
	Recs     []*seg.Meta
	RevInfos []*RevInfo
	pldType  proto.PathMgmt_Which
}

func NewSegRecsFromRaw(b common.RawBytes, pldType proto.PathMgmt_Which) (*SegRecs, *common.Error) {
	recs := &SegRecs{pldType: pldType}
	if !recs.validatePldType() {
		return nil, common.NewError("Invalid payload type", "type", pldType)
	}
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse SegRecs", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse SegRecs", "err", err)
	}
	err = pogs.Extract(recs, proto.SegRecs_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse SegRecs", "err", err)
	}
	return recs, nil
}

func NewSegRecsFromProto(msg proto.SegRecs, pldType proto.PathMgmt_Which) (*SegRecs, *common.Error) {
	recs := &SegRecs{pldType: pldType}
	if !recs.validatePldType() {
		return nil, common.NewError("Invalid payload type", "type", pldType)
	}
	if err := pogs.Extract(recs, proto.SegRecs_TypeID, msg.Struct); err != nil {
		return nil, common.NewError("PathMgmt payload parsing failed", "err", err)
	}
	return recs, nil
}

func (s *SegRecs) PldClass() proto.SCION_Which {
	return proto.SCION_Which_pathMgmt
}

func (s *SegRecs) PldType() proto.PathMgmt_Which {
	return s.pldType
}

func (s *SegRecs) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (s *SegRecs) Copy() (common.Payload, *common.Error) {
	rawPld, err := s.Pack()
	if err != nil {
		return nil, err
	}
	return NewSegReqFromRaw(rawPld)
}

func (s *SegRecs) WritePld(b common.RawBytes) (int, *common.Error) {
	return ctrl_cmn.WritePld(b, s.CtrlWrite)
}

func (s *SegRecs) CtrlWrite(scion *proto.SCION) *common.Error {
	mgmt, err := scion.NewPathMgmt()
	if err != nil {
		return common.NewError("Failed to allocate PathMgmt payload", "err", err)
	}
	if err := s.PathMgmtWrite(&mgmt); err != nil {
		return common.NewError("Failed to write SegRecs payload", "err", err)
	}
	return nil
}

func (s *SegRecs) PathMgmtWrite(mgmt *proto.PathMgmt) *common.Error {
	var err error
	var recs proto.SegRecs
	switch s.pldType {
	case proto.PathMgmt_Which_segReply:
		recs, err = mgmt.NewSegReply()
	case proto.PathMgmt_Which_segReg:
		recs, err = mgmt.NewSegReg()
	case proto.PathMgmt_Which_segSync:
		recs, err = mgmt.NewSegSync()
	}
	if err != nil {
		return common.NewError("Failed to allocate SegRecs struct", "err", err)
	}
	if err := pogs.Insert(proto.SegRecs_TypeID, recs.Struct, s); err != nil {
		return common.NewError("Failed to insert SegRecs struct", "err", err)
	}
	return nil
}

func (s *SegRecs) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack SegRecs", "err", err)
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack SegRecs", "err", err)
	}
	if err := pogs.Insert(proto.SegRecs_TypeID, root.Struct, s); err != nil {
		return nil, common.NewError("Failed to pack SegRecs", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack SegRecs", "err", err)
	}
	return packed, nil
}

func (s *SegRecs) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := s.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write SegRecs", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (s *SegRecs) String() string {
	desc := []string{"Recs:"}
	for _, m := range s.Recs {
		desc = append(desc, m.String())
	}
	if len(s.RevInfos) > 0 {
		desc = append(desc, "RevInfos")
		for _, info := range s.RevInfos {
			desc = append(desc, info.String())
		}
	}
	return strings.Join(desc, "\n")
}

func (s *SegRecs) validatePldType() bool {
	switch s.pldType {
	case proto.PathMgmt_Which_segReply, proto.PathMgmt_Which_segReg, proto.PathMgmt_Which_segSync:
		return true
	}
	return false
}
