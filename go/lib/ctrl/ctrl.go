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

// Package ctrl handles SCION control-plane payloads, which are encoded as capnp proto messages.
// Each ctrl payload has a 4B length field prefixed to the start of the capnp message.
package ctrl

import (
	"fmt"
	"strings"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/cert_mgmt"
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
	sigmgmt "github.com/netsec-ethz/scion/go/sig/mgmt"
)

const LenSize = 4

var _ common.Payload = (*PldOuter)(nil)
var _ proto.Cerealizable = (*PldOuter)(nil)

type PldOuter struct {
	Blob common.RawBytes
	Sign *proto.SignS
}

func NewPldOuter() *PldOuter {
	return &PldOuter{Sign: &proto.SignS{}}
}

func NewPldOuterFromRaw(b common.RawBytes) (*PldOuter, error) {
	po := &PldOuter{}
	n := common.Order.Uint32(b)
	if int(n)+4 != len(b) {
		return nil, common.NewCError("Invalid ctrl payload length",
			"expected", n+4, "actual", len(b))
	}
	return po, proto.ParseFromRaw(po, proto.CtrlPldOuter_TypeID, b[4:])
}

func (po *PldOuter) Pld() (*Pld, error) {
	return NewPldFromRaw(po.Blob)
}

func (po *PldOuter) SetPld(p *Pld) error {
	var err error
	po.Blob, err = proto.PackRoot(p)
	return err
}

func (po *PldOuter) Len() int {
	return -1
}

func (po *PldOuter) Copy() (common.Payload, error) {
	return &PldOuter{Blob: append(common.RawBytes(nil), po.Blob...), Sign: po.Sign.Copy()}, nil
}

func (po *PldOuter) WritePld(b common.RawBytes) (int, error) {
	n, err := proto.WriteRoot(po, b[4:])
	common.Order.PutUint32(b, uint32(n))
	return n + 4, err
}

func (po *PldOuter) PackPld() (common.RawBytes, error) {
	b, err := proto.PackRoot(po)
	if err != nil {
		return nil, err
	}
	// Make a larger buffer, to allow pre-pending of the length field.
	full := make(common.RawBytes, LenSize+len(b))
	// Write length field
	common.Order.PutUint32(full, uint32(len(b)))
	// Copy the encoded proto into the full buffer
	copy(full[LenSize:], b)
	return full, err
}

func (po *PldOuter) ProtoId() proto.ProtoIdType {
	return proto.CtrlPldOuter_TypeID
}

func (po *PldOuter) String() string {
	return fmt.Sprintf("CtrlPldOuter: %s %s", po.Blob, po.Sign)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
}

// NewPld creates a new control payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
	return p, p.union.set(u)
}

// NewPathMgmtPld creates a new control payload, containing a new path_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewPathMgmtPld(u proto.Cerealizable) (*Pld, error) {
	ppld, err := path_mgmt.NewPld(u)
	if err != nil {
		return nil, err
	}
	return NewPld(ppld)
}

// NewCertMgmtPld creates a new control payload, containing a new cert_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewCertMgmtPld(u proto.Cerealizable) (*Pld, error) {
	cpld, err := cert_mgmt.NewPld(u)
	if err != nil {
		return nil, err
	}
	return NewPld(cpld)
}

func NewPldFromRaw(b common.RawBytes) (*Pld, error) {
	p := &Pld{}
	return p, proto.ParseFromRaw(p, proto.CtrlPld_TypeID, b)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

func (p *Pld) Len() int {
	return -1
}

func (p *Pld) Copy() (common.Payload, error) {
	raw, err := proto.PackRoot(p)
	if err != nil {
		return nil, err
	}
	return NewPldFromRaw(raw)
}

func (p *Pld) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(p, b)
}

func (p *Pld) NewOuter() (*PldOuter, error) {
	po := NewPldOuter()
	err := po.SetPld(p)
	return po, err
}

func (p *Pld) WritePld(b common.RawBytes) (int, error) {
	po, err := p.NewOuter()
	if err != nil {
		return 0, err
	}
	return po.WritePld(b)
}

func (p *Pld) PackPld() (common.RawBytes, error) {
	po, err := p.NewOuter()
	if err != nil {
		return nil, err
	}
	return po.PackPld()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.CtrlPld_TypeID
}

func (p *Pld) String() string {
	desc := []string{"Ctrl: Union:"}
	u, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u))
	}
	return strings.Join(desc, " ")
}

// union represents the contents of the unnamed capnp union.
type union struct {
	Which       proto.CtrlPld_Which
	PathSegment *seg.PathSegment `capnp:"pcb"`
	IfID        *ifid.IFID       `capnp:"ifid"`
	CertMgmt    *cert_mgmt.Pld
	PathMgmt    *path_mgmt.Pld
	Sibra       []byte `capnp:"-"` // Omit for now
	DRKeyMgmt   []byte `capnp:"-"` // Omit for now
	Sig         *sigmgmt.Pld
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *seg.PathSegment:
		u.Which = proto.CtrlPld_Which_pcb
		u.PathSegment = p
	case *ifid.IFID:
		u.Which = proto.CtrlPld_Which_ifid
		u.IfID = p
	case *path_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_pathMgmt
		u.PathMgmt = p
	case *sigmgmt.Pld:
		u.Which = proto.CtrlPld_Which_sig
		u.Sig = p
	case *cert_mgmt.Pld:
		u.Which = proto.CtrlPld_Which_certMgmt
		u.CertMgmt = p
	default:
		return common.NewCError("Unsupported ctrl union type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.CtrlPld_Which_pcb:
		return u.PathSegment, nil
	case proto.CtrlPld_Which_ifid:
		return u.IfID, nil
	case proto.CtrlPld_Which_pathMgmt:
		return u.PathMgmt, nil
	case proto.CtrlPld_Which_sig:
		return u.Sig, nil
	case proto.CtrlPld_Which_certMgmt:
		return u.CertMgmt, nil
	}
	return nil, common.NewCError("Unsupported ctrl union type (get)", "type", u.Which)
}
