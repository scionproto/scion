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

package cert_mgmt

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

type union struct {
	Which       proto.CertMgmt_Which
	ChainReq    *ChainReq    `capnp:"certChainReq"`
	ChainRep    *Chain       `capnp:"certChain"`
	ChainIssReq *ChainIssReq `capnp:"certChainIssReq"`
	ChainIssRep *ChainIssRep `capnp:"certChainIssRep"`
	TRCReq      *TRCReq      `capnp:"trcReq"`
	TRCRep      *TRC         `capnp:"trc"`
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *ChainReq:
		u.Which = proto.CertMgmt_Which_certChainReq
		u.ChainReq = p
	case *Chain:
		u.Which = proto.CertMgmt_Which_certChain
		u.ChainRep = p
	case *ChainIssReq:
		u.Which = proto.CertMgmt_Which_certChainIssReq
		u.ChainIssReq = p
	case *ChainIssRep:
		u.Which = proto.CertMgmt_Which_certChainIssRep
		u.ChainIssRep = p
	case *TRCReq:
		u.Which = proto.CertMgmt_Which_trcReq
		u.TRCReq = p
	case *TRC:
		u.Which = proto.CertMgmt_Which_trc
		u.TRCRep = p
	default:
		return common.NewBasicError("Unsupported cert mgmt union type (set)", nil,
			"type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.CertMgmt_Which_certChainReq:
		return u.ChainReq, nil
	case proto.CertMgmt_Which_certChain:
		return u.ChainRep, nil
	case proto.CertMgmt_Which_certChainIssReq:
		return u.ChainIssReq, nil
	case proto.CertMgmt_Which_certChainIssRep:
		return u.ChainIssRep, nil
	case proto.CertMgmt_Which_trcReq:
		return u.TRCReq, nil
	case proto.CertMgmt_Which_trc:
		return u.TRCRep, nil
	}
	return nil, common.NewBasicError("Unsupported cert mgmt union type (get)", nil, "type", u.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
	*Data
}

// NewPld creates a new cert mgmt payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable, d *Data) (*Pld, error) {
	p := &Pld{Data: d}
	return p, p.union.set(u)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.CertMgmt_TypeID
}

func (p *Pld) String() string {
	desc := []string{"CertMgmt: Union:"}
	u, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u))
	}
	return strings.Join(desc, " ")
}

type Data struct {
	// For passing any future non-union data.
}
