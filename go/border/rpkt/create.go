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

package rpkt

import (
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

func CreateCtrlPacket(dirTo Dir, srcHost addr.HostAddr, dstIA *addr.ISD_AS,
	dstHost addr.HostAddr) (*RPkt, *util.Error) {
	addrLen := addr.IABytes*2 + srcHost.Size() + dstHost.Size()
	addrPad := util.CalcPadding(addrLen, common.LineLen)
	hdrLen := spkt.CmnHdrLen + addrLen + addrPad
	rp := &RPkt{}
	rp.Raw = make(util.RawBytes, hdrLen)
	rp.TimeIn = time.Now()
	rp.Logger = log.New("rpkt", logext.RandId(4))
	rp.DirFrom = DirSelf
	rp.DirTo = dirTo
	// Fill in common header and write it out
	rp.CmnHdr.SrcType = srcHost.Type()
	rp.CmnHdr.DstType = dstHost.Type()
	rp.CmnHdr.HdrLen = uint8(hdrLen)
	rp.CmnHdr.TotalLen = uint16(hdrLen)
	rp.CmnHdr.NextHdr = common.L4UDP
	rp.CmnHdr.CurrInfoF = uint8(hdrLen)
	rp.CmnHdr.CurrHopF = uint8(hdrLen)
	rp.CmnHdr.Write(rp.Raw)
	// Fill in address header and indexes
	rp.idxs.srcIA = spkt.CmnHdrLen
	rp.srcIA = conf.C.IA
	rp.idxs.srcHost = rp.idxs.srcIA + addr.IABytes
	rp.srcHost = srcHost
	rp.idxs.dstIA = rp.idxs.srcHost + rp.srcHost.Size()
	rp.dstIA = dstIA
	rp.idxs.dstHost = rp.idxs.dstIA + addr.IABytes
	rp.dstHost = dstHost
	rp.idxs.path = hdrLen
	rp.idxs.l4 = hdrLen
	// Write out address header
	rp.srcIA.Write(rp.Raw[rp.idxs.srcIA:])
	copy(rp.Raw[rp.idxs.srcHost:], rp.srcHost.Pack())
	rp.dstIA.Write(rp.Raw[rp.idxs.dstIA:])
	copy(rp.Raw[rp.idxs.dstHost:], rp.dstHost.Pack())
	return rp, nil
}

func (rp *RPkt) AddL4UDP(srcPort, dstPort int) {
	rp.L4Type = common.L4UDP
	udp := l4.UDP{SrcPort: uint16(srcPort), DstPort: uint16(dstPort)}
	rp.l4 = L4Header(&udp)
	rp.idxs.pld = rp.idxs.l4 + l4.UDPLen
}

func (rp *RPkt) AddCtrlPld(msg *proto.SCION) *util.Error {
	rp.pld = msg
	rawLen := len(rp.Raw)
	rp.Raw = append(rp.Raw, make(util.RawBytes, rp.idxs.pld-rawLen)...)
	rp.Raw = rp.Raw[:rawLen]
	return rp.updateCtrlPld()
}
