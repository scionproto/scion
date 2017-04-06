// Copyright 2016 ETH Zurich
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

package spkt

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// SCION Packet structure.
type ScnPkt struct {
	DstIA   *addr.ISD_AS
	SrcIA   *addr.ISD_AS
	DstHost addr.HostAddr
	SrcHost addr.HostAddr
	Path    *spath.Path
	HBHExt  []common.Extension
	E2EExt  []common.Extension
	L4      l4.L4Header
	Pld     common.Payload
}

func (s *ScnPkt) Copy() *ScnPkt {
	c := &ScnPkt{}
	if s.DstIA != nil {
		c.DstIA = s.DstIA.Copy()
	}
	if s.SrcIA != nil {
		c.SrcIA = s.SrcIA.Copy()
	}
	if s.DstHost != nil {
		c.DstHost = s.DstHost.Copy()
	}
	if s.SrcHost != nil {
		c.SrcHost = s.SrcHost.Copy()
	}
	if s.Path != nil {
		c.Path = s.Path.Copy()
	}
	for _, e := range s.HBHExt {
		c.HBHExt = append(c.HBHExt, e.Copy())
	}
	for _, e := range s.E2EExt {
		c.E2EExt = append(c.E2EExt, e.Copy())
	}
	if s.L4 != nil {
		c.L4 = s.L4.Copy()
	}
	// TODO(kormat): define payload interface, with Copy()
	return c
}

func (s *ScnPkt) Reverse() *common.Error {
	s.DstIA, s.SrcIA = s.SrcIA, s.DstIA
	s.DstHost, s.SrcHost = s.SrcHost, s.DstHost
	if s.Path != nil {
		if err := s.Path.Reverse(); err != nil {
			return err
		}
	}
	// FIXME(kormat): handle reversing extensions
	if s.L4 != nil {
		s.L4.Reverse()
	}
	return nil
}

func (s *ScnPkt) AddrLen() int {
	addrLen := addr.IABytes*2 + s.DstHost.Size() + s.SrcHost.Size()
	return addrLen + util.CalcPadding(addrLen, common.LineLen)
}

func (s *ScnPkt) HdrLen() int {
	l := CmnHdrLen + s.AddrLen()
	if s.Path != nil {
		l += len(s.Path.Raw)
	}
	return l
}

func (s *ScnPkt) TotalLen() int {
	l := s.HdrLen()
	for _, h := range s.HBHExt {
		l += h.Len()
	}
	for _, e := range s.E2EExt {
		l += e.Len()
	}
	if s.L4 != nil {
		l += s.L4.L4Len()
	}
	if s.Pld != nil {
		l += s.Pld.Len()
	}
	return l
}
