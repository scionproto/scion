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

package packet

import (
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

func CreateCtrlPacket(dirTo Dir, srcHost addr.HostAddr, dstIA *addr.ISD_AS,
	dstHost addr.HostAddr) (*Packet, *util.Error) {
	addrLen := addr.IABytes*2 + srcHost.Size() + dstHost.Size()
	addrPad := util.CalcPadding(addrLen, spkt.LineLen)
	hdrLen := spkt.CmnHdrLen + addrLen + addrPad
	p := &Packet{}
	p.Raw = make(util.RawBytes, hdrLen)
	p.TimeIn = time.Now()
	p.Logger = log.New("pkt", logext.RandId(4))
	p.DirFrom = DirSelf
	p.DirTo = dirTo
	// Fill in common header and write it out
	p.CmnHdr.SrcType = srcHost.Type()
	p.CmnHdr.DstType = dstHost.Type()
	p.CmnHdr.HdrLen = uint8(hdrLen)
	p.CmnHdr.TotalLen = uint16(hdrLen)
	p.CmnHdr.NextHdr = spkt.L4UDP
	p.CmnHdr.CurrInfoF = uint8(hdrLen)
	p.CmnHdr.CurrHopF = uint8(hdrLen)
	p.CmnHdr.Write(p.Raw)
	// Fill in address header and indexes
	p.idxs.srcIA = spkt.CmnHdrLen
	p.srcIA = conf.C.IA
	p.idxs.srcHost = p.idxs.srcIA + addr.IABytes
	p.srcHost = srcHost
	p.idxs.dstIA = p.idxs.srcHost + p.srcHost.Size()
	p.dstIA = dstIA
	p.idxs.dstHost = p.idxs.dstIA + addr.IABytes
	p.dstHost = dstHost
	p.idxs.path = hdrLen
	p.idxs.l4 = hdrLen
	// Write out address header
	p.srcIA.Write(p.Raw[p.idxs.srcIA:])
	copy(p.Raw[p.idxs.srcHost:], p.srcHost.Pack())
	p.dstIA.Write(p.Raw[p.idxs.dstIA:])
	copy(p.Raw[p.idxs.dstHost:], p.dstHost.Pack())
	return p, nil
}

func (p *Packet) AddL4UDP(srcPort, dstPort int) {
	p.L4Type = spkt.L4UDP
	udp := l4.UDP{SrcPort: uint16(srcPort), DstPort: uint16(dstPort)}
	p.l4 = L4Header(&udp)
	p.idxs.pld = p.idxs.l4 + l4.UDPLen
}

func (p *Packet) AddCtrlPld(msg *proto.SCION) *util.Error {
	p.pld = msg
	rawLen := len(p.Raw)
	p.Raw = append(p.Raw, make(util.RawBytes, p.idxs.pld-rawLen)...)
	p.Raw = p.Raw[:rawLen]
	return p.updateCtrlPld()
}
