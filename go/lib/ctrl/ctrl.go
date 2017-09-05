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

// union0 represents the contents of the capnp union that starts at field @0.
type union0 struct {
	Which       proto.SCION_Which
	PathSegment *seg.PathSegment `capnp:"pcb"`
	IfID        *ifid.IFID       `capnp:"ifid"`
	CertMgmt    []byte           `capnp:"-"` // Omit for now
	PathMgmt    *path_mgmt.Pld
	Sibra       []byte `capnp:"-"` // Omit for now
	DRKeyMgmt   []byte `capnp:"-"` // Omit for now
	Sig         []byte `capnp:"-"` // Omit for now
}

func (u0 *union0) set(c proto.Cerealizable) error {
	switch u := c.(type) {
	case *seg.PathSegment:
		u0.Which = proto.SCION_Which_pcb
		u0.PathSegment = u
	case *ifid.IFID:
		u0.Which = proto.SCION_Which_ifid
		u0.IfID = u
	case *path_mgmt.Pld:
		u0.Which = proto.SCION_Which_pathMgmt
		u0.PathMgmt = u
	default:
		return common.NewCError("Unsupported ctrl union0 type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u0 *union0) get() (proto.Cerealizable, error) {
	switch u0.Which {
	case proto.SCION_Which_pcb:
		return u0.PathSegment, nil
	case proto.SCION_Which_ifid:
		return u0.IfID, nil
	case proto.SCION_Which_pathMgmt:
		return u0.PathMgmt, nil
	}
	return nil, common.NewCError("Unsupported ctrl union0 type (get)", "type", u0.Which)
}

var _ common.Payload = (*Pld)(nil)
var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union0
}

// NewPld creates a new control payload, containing the supplied Cerealizable instance.
func NewPld(u0 proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
	return p, p.union0.set(u0)
}

// NewPathMgmtPld creates a new control payload, containing a new path_mgmt payload,
// which in turn contains the supplied Cerealizable instance.
func NewPathMgmtPld(u0 proto.Cerealizable) (*Pld, error) {
	ppld, err := path_mgmt.NewPld(u0)
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
	return p, proto.ParseFromRaw(p, proto.SCION_TypeID, b[4:])
}

func (p *Pld) Union0() (proto.Cerealizable, error) {
	return p.union0.get()
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
	return proto.SCION_TypeID
}

func (p *Pld) String() string {
	desc := []string{"Ctrl: Union0:"}
	u0, err := p.Union0()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u0))
	}
	return strings.Join(desc, " ")
}
