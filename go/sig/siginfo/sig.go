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

package siginfo

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type Sig struct {
	IA          addr.IA
	Host        addr.HostAddr
	CtrlL4Port  int
	EncapL4Port int
}

func (s *Sig) CtrlSnetAddr() *snet.Addr {
	l4 := addr.NewL4UDPInfo(uint16(s.CtrlL4Port))
	return &snet.Addr{IA: s.IA, Host: &addr.AppAddr{L3: s.Host, L4: l4}}
}

func (s *Sig) EncapSnetAddr() *snet.Addr {
	l4 := addr.NewL4UDPInfo(uint16(s.EncapL4Port))
	return &snet.Addr{IA: s.IA, Host: &addr.AppAddr{L3: s.Host, L4: l4}}
}

func (s *Sig) Equal(x *Sig) bool {
	if s == nil || x == nil {
		return s == x
	}
	return s.IA == x.IA &&
		s.Host.Equal(x.Host) &&
		s.CtrlL4Port == x.CtrlL4Port &&
		s.EncapL4Port == x.EncapL4Port
}

func (s *Sig) String() string {
	return fmt.Sprintf("%s,[%s]:%d:%d", s.IA, s.Host, s.CtrlL4Port, s.EncapL4Port)
}
