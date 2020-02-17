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

package sig_mgmt

import (
	"fmt"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

type MsgIdType uint64

func (m MsgIdType) String() string {
	return fmt.Sprintf("0x%016x", uint64(m))
}

func (m MsgIdType) Time() time.Time {
	return time.Unix(int64(m)/1000000000, int64(m)%1000000000)
}

// union represents the contents of the unnamed capnp union.
type union struct {
	Which   proto.SIGCtrl_Which
	PollReq *PollReq
	PollRep *PollRep
}

func (u *union) set(c proto.Cerealizable) error {
	switch p := c.(type) {
	case *PollReq:
		u.Which = proto.SIGCtrl_Which_pollReq
		u.PollReq = p
	case *PollRep:
		u.Which = proto.SIGCtrl_Which_pollRep
		u.PollRep = p
	default:
		return common.NewBasicError("Unsupported SIG ctrl union type (set)", nil,
			"type", common.TypeOf(c))
	}
	return nil
}

func (u *union) get() (proto.Cerealizable, error) {
	switch u.Which {
	case proto.SIGCtrl_Which_pollReq:
		return u.PollReq, nil
	case proto.SIGCtrl_Which_pollRep:
		return u.PollRep, nil
	}
	return nil, common.NewBasicError("Unsupported SIG ctrl union type (get)", nil,
		"type", u.Which)
}

var _ proto.Cerealizable = (*Pld)(nil)

type Pld struct {
	Id MsgIdType
	union
}

// NewPld creates a new SIG ctrl payload, containing the supplied Cerealizable instance.
func NewPld(id MsgIdType, u proto.Cerealizable) (*Pld, error) {
	p := &Pld{Id: id}
	return p, p.union.set(u)
}

func (p *Pld) Union() (proto.Cerealizable, error) {
	return p.union.get()
}

func (p *Pld) ProtoId() proto.ProtoIdType {
	return proto.SIGCtrl_TypeID
}

func (p *Pld) String() string {
	desc := []string{fmt.Sprintf("SIGCtrl: Id: %s Union:", p.Id)}
	u, err := p.Union()
	if err != nil {
		desc = append(desc, err.Error())
	} else {
		desc = append(desc, fmt.Sprintf("%+v", u))
	}
	return strings.Join(desc, " ")
}
