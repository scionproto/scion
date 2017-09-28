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
	"github.com/netsec-ethz/scion/go/lib/ctrl/ifid"
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/proto"
)

// contents represents the contents of the unnamed capnp union.
type contents struct {
	Which       proto.CtrlPld_Which
	PathSegment *seg.PathSegment `capnp:"pcb"`
	IfID        *ifid.IFID       `capnp:"ifid"`
	CertMgmt    []byte           `capnp:"-"` // Omit for now
	PathMgmt    *path_mgmt.Pld
	Sibra       []byte `capnp:"-"` // Omit for now
	DRKeyMgmt   []byte `capnp:"-"` // Omit for now
	Sig         []byte `capnp:"-"` // Omit for now
}

func (cts *contents) set(c proto.Cerealizable) error {
	switch u := c.(type) {
	case *seg.PathSegment:
		cts.Which = proto.CtrlPld_Which_pcb
		cts.PathSegment = u
	case *ifid.IFID:
		cts.Which = proto.CtrlPld_Which_ifid
		cts.IfID = u
	case *path_mgmt.Pld:
		cts.Which = proto.CtrlPld_Which_pathMgmt
		cts.PathMgmt = u
	default:
		return common.NewCError("Unsupported ctrl contents type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (cts *contents) get() (proto.Cerealizable, error) {
	switch cts.Which {
	case proto.CtrlPld_Which_pcb:
		return cts.PathSegment, nil
	case proto.CtrlPld_Which_ifid:
		return cts.IfID, nil
	case proto.CtrlPld_Which_pathMgmt:
		return cts.PathMgmt, nil
	}
	return nil, common.NewCError("Unsupported ctrl contents type (get)", "type", cts.Which)
}

var _ common.Payload = (*Pld)(nil)
var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	contents
}

// NewPld creates a new control payload, containing the supplied Cerealizable instance.
func NewPld(cts proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
	return p, p.contents.set(cts)
}

// NewPathMgmtPld creates a new control payload, containing a new path_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewPathMgmtPld(cts proto.Cerealizable) (*Pld, error) {
	ppld, err := path_mgmt.NewPld(cts)
	if err != nil {
		return nil, err
	}
	return NewPld(ppld)
}

func NewPldFromRaw(b common.RawBytes) (*Pld, error) {
	p := &Pld{}
	n := common.Order.Uint32(b)
	if int(n)+4 != len(b) {
		return nil, common.NewCError("Invalid ctrl payload length",
			"expected", n+4, "actual", len(b))
	}
	return p, proto.ParseFromRaw(p, proto.CtrlPld_TypeID, b[4:])
}

func (p *Pld) Contents() (proto.Cerealizable, error) {
	return p.contents.get()
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

func (p *Pld) WritePld(b common.RawBytes) (int, error) {
	n, err := proto.WriteRoot(p, b[4:])
	common.Order.PutUint32(b, uint32(n))
	return n + 4, err
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.CtrlPld_TypeID
}

func (p *Pld) String() string {
	desc := []string{"Ctrl: Contents:"}
	cts, err := p.Contents()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", cts))
	}
	return strings.Join(desc, " ")
}
