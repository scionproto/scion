// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

type Sig struct {
	IA          addr.IA
	Host        addr.HostAddr
	CtrlL4Port  int
	EncapL4Port int
}

func (s *Sig) CtrlSnetAddr(path spath.Path, nextHop *net.UDPAddr) net.Addr {
	switch s.Host.(type) {
	case addr.HostSVC:
		return &snet.SVCAddr{
			IA:      s.IA,
			Path:    path,
			NextHop: nextHop,
			SVC:     addr.SvcSIG,
		}
	default:
		return &snet.UDPAddr{
			IA:      s.IA,
			Path:    path,
			NextHop: nextHop,
			Host: &net.UDPAddr{
				IP:   s.Host.IP(),
				Port: s.CtrlL4Port,
			},
		}
	}
}

func (s *Sig) EncapSnetAddr() *snet.UDPAddr {
	return &snet.UDPAddr{
		IA: s.IA,
		Host: &net.UDPAddr{
			IP:   s.Host.IP(),
			Port: s.EncapL4Port,
		},
	}
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

func (s *Sig) Copy() *Sig {
	if s == nil {
		return nil
	}
	res := &Sig{}
	*res = *s
	res.Host = s.Host.Copy()
	return res
}

func (s *Sig) String() string {
	return fmt.Sprintf("%s,[%s]:%d:%d", s.IA, s.Host, s.CtrlL4Port, s.EncapL4Port)
}
