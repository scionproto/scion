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
	"strings"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*IFStateInfos)(nil)

type IFStateInfos struct {
	Infos []*IFStateInfo
}

func NewIFStateInfosFromRaw(b common.RawBytes) (*IFStateInfos, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateInfos", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateInfos", "err", err)
	}
	req := &IFStateInfos{}
	err = pogs.Extract(req, proto.IFStateInfos_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse IFStateInfos", "err", err)
	}
	return req, nil
}

func (i *IFStateInfos) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (i *IFStateInfos) Copy() (common.Payload, *common.Error) {
	rawPld, err := i.Pack()
	if err != nil {
		return nil, err
	}
	return NewIFStateInfosFromRaw(rawPld)
}

func (i *IFStateInfos) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateInfos", "err", err)
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateInfos", "err", err)
	}
	if err := pogs.Insert(proto.IFStateInfos_TypeID, root.Struct, i); err != nil {
		return nil, common.NewError("Failed to pack IFStateInfos", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack IFStateInfos", "err", err)
	}
	return packed, nil
}

func (i *IFStateInfos) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := i.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write IFStateInfos", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (i *IFStateInfos) String() string {
	desc := []string{"Infos"}
	for _, info := range i.Infos {
		desc = append(desc, info.String())
	}
	return strings.Join(desc, "\n")
}

type IFStateInfo struct {
	IfID    uint64
	Active  bool
	RevInfo *RevInfo
}

func (i *IFStateInfo) String() string {
	desc := fmt.Sprintf("IfID: %v, Active: %v", i.IfID, i.Active)
	if i.RevInfo != nil {
		desc += fmt.Sprintf(", RevInfo: %v", i.RevInfo)
	}
	return desc
}
