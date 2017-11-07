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
	"github.com/netsec-ethz/scion/go/lib/ctrl/path_mgmt"
	"github.com/netsec-ethz/scion/go/proto"
)

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

func (p *Pld) SignedPld() (*SignedPld, error) {
	return NewSignedPld(p)
}

func (p *Pld) WritePld(b common.RawBytes) (int, error) {
	sp, err := p.SignedPld()
	if err != nil {
		return 0, err
	}
	return sp.WritePld(b)
}

func (p *Pld) PackPld() (common.RawBytes, error) {
	sp, err := p.SignedPld()
	if err != nil {
		return nil, err
	}
	return sp.PackPld()
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
