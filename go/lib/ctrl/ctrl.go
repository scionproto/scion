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

package ctrl

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*CtrlPld)(nil)

type CtrlPld struct {
	Which       proto.SCION_Which
	PathSegment *seg.PathSegment `capnp:"pcb"`
	IfID        *ifid.IFID       `capnp:"ifid"`
	CertMgmt    []byte           `capnp:"-"` // Omit for now
	PathMgmt    *path_mgmt.PathMgmt
	Sibra       []byte `capnp:"-"` // Omit for now
	DRKeyMgmt   []byte `capnp:"-"` // Omit for now
	Sig         []byte `capnp:"-"` // Omit for now
}

func NewCtrlPldFromRaw(b common.RawBytes) (*CtrlPld, *common.Error) {
	rawPld := b
	pldLen := common.Order.Uint32(rawPld)
	rawPld = rawPld[4:]
	if int(pldLen) != len(rawPld) {
		return nil, common.NewError("Ctrl payload length incorrect",
			"expected", pldLen, "actual", len(rawPld))
	}
	buf := bytes.NewBuffer(rawPld)
	msg, err := capnp.NewPackedDecoder(buf).Decode()
	if err != nil {
		return nil, common.NewError("Ctrl payload decoding failed", "err", err)
	}
	// Handle any panics while parsing
	defer func() *common.Error {
		if err := recover(); err != nil {
			return common.NewError("Ctrl payload parsing failed", "err", err)
		}
		return nil
	}()
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Ctrl payload decoding failed", "err", err)
	}
	pld := &CtrlPld{}
	if err := pogs.Extract(pld, proto.SCION_TypeID, rootPtr.Struct()); err != nil {
		return nil, common.NewError("Ctrl payload parsing failed", "err", err)
	}
	return pld, nil
}

func NewCtrlPld(val interface{}, which proto.SCION_Which) (*CtrlPld, *common.Error) {
	pld := &CtrlPld{Which: which}
	var ok bool
	switch which {
	case proto.SCION_Which_pcb:
		pld.PathSegment, ok = val.(*seg.PathMgmt)
	case proto.SCION_Which_ifid:
		pld.IfID, ok = val.(*ifid.IFID)
	case proto.SCION_Which_pathMgmt:
		pld.PathMgmt, ok = val.(*path_mgmt.PathMgmt)
	case proto.SCION_Which_certMgmt:
		fallthrough
	case proto.SCION_Which_sibra:
		fallthrough
	case proto.SCION_Which_drkeyMgmt:
		fallthrough
	case proto.SCION_Which_sig:
		fallthrough
	default:
		return nil, common.NewError("Unsupported payload type: %v", which)
	}
	if !ok {
		return nil, common.NewError("Provided value does not match the type",
			"provided", fmt.Sprintf("%T", val), "expected", which)
	}
	return pld, nil
}

func (c *CtrlPld) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (c *CtrlPld) Copy() (common.Payload, *common.Error) {
	rawPld, err := c.Pack()
	if err != nil {
		return nil, err
	}
	return NewCtrlPldFromRaw(rawPld)
}

func (c *CtrlPld) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := c.Pack()
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

func (c *CtrlPld) Pack() (common.RawBytes, *common.Error) {
	buf := bytes.NewBuffer(make(common.RawBytes, 4))
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}
	root, err := proto.NewRootIFID(arena)
	if err != nil {
		return nil, err
	}
	if err := pogs.Insert(proto.SCION_TypeID, root.Struct, s); err != nil {
		return nil, err
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, err
	}
	// Copy packed message into buffer and prepend length of data.
	pld = make(common.RawBytes, len(packed)+4)
	common.Order.PutUint32(rawPld, uint32(len(packed)))
	copy(pld[4:], packed)

	return pld, nil
}

func (c *CtrlPld) String() string {
	switch c.Which {
	case proto.SCION_Which_unset:
		return "unset"
	case proto.SCION_Which_pcb:
		return fmt.Sprintf("PathSegment: %s", c.PathSegment.String())
	case proto.SCION_Which_ifid:
		return fmt.Sprintf("IFID: %s", c.IfID.String())
	case proto.SCION_Which_certMgmt:
		return "CertMgmt"
	case proto.SCION_Which_pathMgmt:
		return fmt.Sprintf("PathMgmt: %s", c.PathMgmt.String())
	case proto.SCION_Which_sibra:
		return "Sibra"
	case proto.SCION_Which_sig:
		return "SIG"
	default:
		return "unknown"
	}
}
