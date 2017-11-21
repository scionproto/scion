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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*Addr)(nil)

type Addr struct {
	Ctrl      *sciond.HostInfo
	EncapPort uint16
}

func NewAddr(host addr.HostAddr, ctrlPort, encapPort uint16) *Addr {
	return &Addr{
		Ctrl:      sciond.HostInfoFromHostAddr(host, ctrlPort),
		EncapPort: encapPort,
	}
}

func newAddrFromRaw(b common.RawBytes) (*Addr, error) {
	a := &Addr{}
	return a, proto.ParseFromRaw(a, a.ProtoId(), b)
}

func (a *Addr) ProtoId() proto.ProtoIdType {
	return proto.SIGAddr_TypeID
}

func (a *Addr) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(a, b)
}

func (a *Addr) String() string {
	return fmt.Sprintf("Host: %s CtrlPort: %d EncapPort: %d",
		a.Ctrl.Host(), a.Ctrl.Port, a.EncapPort)
}
