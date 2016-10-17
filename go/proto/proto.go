// Copyright 2016 ETH Zurich
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

package proto

import (
	"bytes"

	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
)

func NewMessage() (*capnp.Message, *capnp.Segment, *common.Error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, nil, common.NewError("Unable to allocate new capnp message", "err", err)
	}
	return msg, seg, nil
}

func NewSCIONMsg() (*SCION, *common.Error) {
	_, seg, err := NewMessage()
	if err != nil {
		return nil, err
	}
	scion, cerr := NewRootSCION(seg)
	if cerr != nil {
		return nil, common.NewError("Unable to create new SCION capnp struct", "err", err)
	}
	return &scion, nil
}

func NewIFIDMsg() (*SCION, *IFID, *common.Error) {
	scion, err := NewSCIONMsg()
	if err != nil {
		return nil, nil, err
	}
	ifid, cerr := scion.NewIfid()
	if cerr != nil {
		return nil, nil, common.NewError("Unable to create IFID struct", "err", err)
	}
	return scion, &ifid, nil
}

func NewPathMgmtMsg() (*SCION, *PathMgmt, *common.Error) {
	scion, err := NewSCIONMsg()
	if err != nil {
		return nil, nil, err
	}
	pathMgmt, cerr := scion.NewPathMgmt()
	if cerr != nil {
		return nil, nil, common.NewError("Unable to create PathMgmt struct", "err", err)
	}
	return scion, &pathMgmt, nil
}

func StructPack(s capnp.Struct) (common.RawBytes, *common.Error) {
	msg, _, err := NewMessage()
	if err != nil {
		return nil, err
	}
	msg.SetRootPtr(s.ToPtr())
	buf := &bytes.Buffer{}
	enc := capnp.NewPackedEncoder(buf)
	if err := enc.Encode(msg); err != nil {
		return nil, common.NewError("Capnp struct encoding failed", "err", err)
	}
	return buf.Bytes(), nil
}
