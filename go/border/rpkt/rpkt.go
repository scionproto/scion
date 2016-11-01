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
	"encoding/binary"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

var callbacks struct {
	locOutFs   map[int]OutputFunc
	intfOutFs  map[spath.IntfID]OutputFunc
	ifStateUpd func(proto.IFStateInfos)
	revTokenF  func(util.RawBytes)
}

func Init(locOut map[int]OutputFunc, intfOut map[spath.IntfID]OutputFunc,
	ifStateUpd func(proto.IFStateInfos), revTokenF func(util.RawBytes)) {
	callbacks.locOutFs = locOut
	callbacks.intfOutFs = intfOut
	callbacks.ifStateUpd = ifStateUpd
	callbacks.revTokenF = revTokenF
}

// Router representation of SCION packet, including metadata.
type RPkt struct {
	Raw       util.RawBytes
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
	HBHExt    []Extension
	E2EExt    []Extension
	L4Type    common.L4ProtocolType
	l4        L4Header
	pld       interface{}
	hooks     Hooks
	SCMPError bool
	log.Logger
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

type OutputFunc func(*RPkt)

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

var order = binary.BigEndian

func (rp *RPkt) Reset() {
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
