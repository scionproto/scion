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

package ctrl

import (
	"bytes"
	//"fmt"

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"
	//"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*Pld)(nil)

type Pld struct {
	proto.CerealBase
}

func NewPld(c proto.Cerealizable) *Pld {
	return &Pld{CerealBase: proto.NewCerealBase(c)}
}

func NewPldFromRaw(b common.RawBytes) (*Pld, *common.Error) {
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
	scion, err := proto.ReadRootSCION(msg)
	if err != nil {
		return nil, common.NewError("Ctrl payload decoding failed", "err", err)
	}
	p := &Pld{}
	var s capnp.Struct
	switch scion.Which() {
	case proto.SCION_Which_pathMgmt:
		// path_mgmt implements its own sub-messages, so handle it differently.
		m, _ := scion.PathMgmt()
		pmgmt, cerr := path_mgmt.NewPathMgmtPldFromProto(m)
		if cerr != nil {
			return nil, cerr
		}
		p.CerealBase = proto.NewCerealBase(pmgmt)
		return p, nil
	case proto.SCION_Which_ifid:
		m, _ := scion.Ifid()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&ifid.IFID{})
	case proto.SCION_Which_pcb:
		m, _ := scion.Pcb()
		s = m.Struct
		p.CerealBase = proto.NewCerealBase(&seg.PathSegment{})
	default:
		return nil, common.NewError("Unsupported CtrlPld type", "type", scion.Which())
	}
	if cerr := p.ParseProto(s); cerr != nil {
		return nil, cerr
	}
	return p, nil
}

func (p *Pld) WritePld(b common.RawBytes) (int, *common.Error) {
	var cerr *common.Error
	var err error
	var scion proto.SCION
	var s capnp.Struct
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return 0, common.NewError("Failed to create new ctrl capnp message",
			"type", p.ProtoType(), "err", err)
	}
	if scion, err = proto.NewRootSCION(arena); cerr != nil {
		return 0, common.NewError("Failed to create new ctrl capnp struct", "err", err)
	}
	// Call NewStruct on the immediate contents. If this is a container like
	// path_mgmt.Pld, it will recursively call NewStruct on its own contents.
	if s, cerr = p.CerealBase.Cerealizable.NewStruct(scion); cerr != nil {
		return 0, cerr
	}
	raw := &util.Raw{B: b, Offset: 4}
	// Call Insert on the inner contents, if any.
	switch contents := p.CerealBase.Cerealizable.(type) {
	case *path_mgmt.Pld:
		cerr = contents.Insert(s)
	default:
		cerr = p.Insert(s)
	}
	if cerr != nil {
		return 0, cerr
	}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(msg); err != nil {
		return 0, common.NewError("Ctrl payload encoding failed", "err", err)
	}
	// Set payload length
	common.Order.PutUint32(b, uint32(raw.Offset-4))
	return raw.Offset, nil
}

func (p *Pld) Contents() proto.Cerealizable {
	type container interface {
		Contents() proto.Cerealizable
	}
	oldv := p.CerealBase.Cerealizable
	for {
		newv, ok := oldv.(container)
		if !ok {
			return oldv
		}
		oldv = newv.Contents()
	}
}
