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
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/proto"
)

// FIXME(kormat): this should be reduced as soon as we respect the actual link MTU.
const pktBufSize = 1 << 16

var callbacks struct {
	locOutFs   map[int]OutputFunc
	intfOutFs  map[spath.IntfID]OutputFunc
	ifStateUpd func(proto.IFStateInfos)
	revTokenF  func(common.RawBytes)
}

func Init(locOut map[int]OutputFunc, intfOut map[spath.IntfID]OutputFunc,
	ifStateUpd func(proto.IFStateInfos), revTokenF func(common.RawBytes)) {
	callbacks.locOutFs = locOut
	callbacks.intfOutFs = intfOut
	callbacks.ifStateUpd = ifStateUpd
	callbacks.revTokenF = revTokenF
}

// Router representation of SCION packet, including metadata.
type RtrPkt struct {
	Id        string
	Raw       common.RawBytes
	TimeIn    time.Time
	DirFrom   Dir
	DirTo     Dir
	Ingress   AddrPair
	Egress    []EgressPair
	CmnHdr    spkt.CmnHdr
	idxs      packetIdxs
	srcIA     *addr.ISD_AS
	srcHost   addr.HostAddr
	dstIA     *addr.ISD_AS
	dstHost   addr.HostAddr
	infoF     *spath.InfoField
	hopF      *spath.HopField
	ifCurr    *spath.IntfID
	ifNext    *spath.IntfID
	upFlag    *bool
	HBHExt    []RExtension
	E2EExt    []RExtension
	L4Type    common.L4ProtocolType
	l4        l4.L4Header
	pld       common.Payload
	hooks     Hooks
	SCMPError bool
	log.Logger
}

func NewRtrPkt() *RtrPkt {
	r := &RtrPkt{}
	r.Raw = make(common.RawBytes, pktBufSize)
	return r
}

type Dir int

const (
	DirUnset Dir = iota
	DirSelf
	DirLocal
	DirExternal
)

func (d Dir) String() string {
	switch d {
	case DirUnset:
		return "Unset"
	case DirSelf:
		return "Self"
	case DirLocal:
		return "Local"
	case DirExternal:
		return "External"
	default:
		return "UNKNOWN"
	}
}

type AddrPair struct {
	Src *net.UDPAddr
	Dst *net.UDPAddr
}

type OutputFunc func(*RtrPkt)

type EgressPair struct {
	F   OutputFunc
	Dst *net.UDPAddr
}

type packetIdxs struct {
	srcIA      int
	srcHost    int
	dstIA      int
	dstHost    int
	path       int
	nextHdrIdx hdrIdx
	hbhExt     []extnIdx
	e2eExt     []extnIdx
	l4         int
	pld        int
}

type hdrIdx struct {
	Type  common.L4ProtocolType
	Index int
}

type extnIdx struct {
	Type  common.ExtnType
	Index int
}

func (rp *RtrPkt) Reset() {
	rp.Raw = rp.Raw[:cap(rp.Raw)-1]
	rp.DirFrom = DirUnset
	rp.DirTo = DirUnset
	rp.Ingress.Src = nil
	rp.Ingress.Dst = nil
	rp.Egress = rp.Egress[:0]
	rp.idxs = packetIdxs{}
	rp.srcIA = nil
	rp.srcHost = nil
	rp.dstIA = nil
	rp.dstHost = nil
	rp.infoF = nil
	rp.hopF = nil
	rp.ifCurr = nil
	rp.ifNext = nil
	rp.upFlag = nil
	rp.HBHExt = rp.HBHExt[:0]
	rp.E2EExt = rp.E2EExt[:0]
	rp.L4Type = common.L4None
	rp.l4 = nil
	rp.pld = nil
	rp.hooks = Hooks{}
	rp.SCMPError = false
	rp.Logger = nil
}

func (rp *RtrPkt) ToScnPkt(verify bool) (*spkt.ScnPkt, *common.Error) {
	var err *common.Error
	sp := &spkt.ScnPkt{}
	if sp.SrcIA, err = rp.SrcIA(); err != nil {
		return nil, err
	}
	if sp.SrcHost, err = rp.SrcHost(); err != nil {
		return nil, err
	}
	if sp.DstIA, err = rp.DstIA(); err != nil {
		return nil, err
	}
	if sp.DstHost, err = rp.DstHost(); err != nil {
		return nil, err
	}
	sp.Path = &spath.Path{
		Raw:    rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLen],
		InfOff: rp.CmnHdr.CurrInfoF - uint8(rp.idxs.path),
		HopOff: rp.CmnHdr.CurrHopF - uint8(rp.idxs.path),
	}
	for _, re := range rp.HBHExt {
		se, err := re.GetExtn()
		if err != nil {
			return nil, err
		}
		sp.HBHExt = append(sp.HBHExt, se)
	}
	for _, re := range rp.E2EExt {
		se, err := re.GetExtn()
		if err != nil {
			return nil, err
		}
		sp.E2EExt = append(sp.E2EExt, se)
	}
	if sp.L4, err = rp.L4Hdr(verify); err != nil {
		return nil, err
	}
	if sp.Pld, err = rp.Payload(verify); err != nil {
		return nil, err
	}
	return sp, nil
}

func (rp *RtrPkt) GetRaw(blk scmp.RawBlock) common.RawBytes {
	switch blk {
	case scmp.RawCmnHdr:
		return rp.Raw[:spkt.CmnHdrLen]
	case scmp.RawAddrHdr:
		return rp.Raw[rp.idxs.srcIA:rp.idxs.path]
	case scmp.RawPathHdr:
		return rp.Raw[rp.idxs.path:rp.CmnHdr.HdrLen]
	case scmp.RawExtHdrs:
		return rp.Raw[rp.CmnHdr.HdrLen:rp.idxs.l4]
	case scmp.RawL4Hdr:
		return rp.Raw[rp.idxs.l4:rp.idxs.pld]
	}
	rp.Crit("Invalid raw block requested", "blk", blk)
	return nil
}

func (rp *RtrPkt) String() string {
	// Pre-fetch required attributes
	rp.SrcIA()
	rp.SrcHost()
	rp.DstIA()
	rp.DstHost()
	rp.InfoF()
	rp.HopF()
	return fmt.Sprintf("Dir from/to: %v/%v Src: %v %v Dst: %v %v\n  InfoF: %v\n  HopF: %v",
		rp.DirFrom, rp.DirTo, rp.srcIA, rp.srcHost, rp.dstIA, rp.dstHost, rp.infoF, rp.hopF)
}

func (rp *RtrPkt) ErrStr(desc string) string {
	return fmt.Sprintf("Error: %v\n  RtrPkt: %v\n  Raw: %v", desc, rp, rp.Raw)
}
