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
	"math"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

const NewestVersion = math.MaxUint64

type union struct {
	Which    proto.CertMgmt_Which
	ChainReq *ChainReq `capnp:"certChainReq"`
	ChainRep *Chain    `capnp:"certChain"`
	TRCReq   *TRCReq   `capnp:"trcReq"`
	TRCRep   *TRC      `capnp:"trc"`
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *ChainReq:
		u.Which = proto.CertMgmt_Which_certChainReq
		u.ChainReq = p
	case *Chain:
		u.Which = proto.CertMgmt_Which_certChain
		u.ChainRep = p
	case *TRCReq:
		u.Which = proto.CertMgmt_Which_trcReq
		u.TRCReq = p
	case *TRC:
		u.Which = proto.CertMgmt_Which_trc
		u.TRCRep = p
	default:
		return common.NewCError("Unsupported cert mgmt union type (set)", "type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.CertMgmt_Which_certChainReq:
		return u.ChainReq, nil
	case proto.CertMgmt_Which_certChain:
		return u.ChainRep, nil
	case proto.CertMgmt_Which_trcReq:
		return u.TRCReq, nil
	case proto.CertMgmt_Which_trc:
		return u.TRCRep, nil
	}
	return nil, common.NewCError("Unsupported cert mgmt union type (get)", "type", u.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	union
}

// NewPld creates a new cert mgmt payload, containing the supplied Cerealizable instance.
func NewPld(u proto.Cerealizable) (*Pld, error) {
	p := &Pld{}
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
