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

package mgmt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*poll)(nil)

type poll struct {
	Addr    *Addr
	Session SessionType
}

func newPoll(a *Addr, s SessionType) *poll {
	return &poll{Addr: a, Session: s}
}

func (p *poll) ProtoId() proto.ProtoIdType {
	return proto.SIGPoll_TypeID
}

func (p *poll) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(p, b)
}

func (p *poll) String() string {
	return fmt.Sprintf("%s Session: %s", p.Addr, p.Session)
}

type PollReq struct {
	*poll
}

func NewPollReq(a *Addr, s SessionType) *PollReq {
	return &PollReq{newPoll(a, s)}
}

type PollRep struct {
	*poll
}

func NewPollRep(a *Addr, s SessionType) *PollRep {
	return &PollRep{newPoll(a, s)}
}
