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
	"encoding/binary"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/path"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/proto"
)

var callbacks struct {
	locOutFs   map[int]OutputFunc
	intfOutFs  map[path.IntfID]OutputFunc
	ifStateUpd func(proto.IFStateInfos)
}

func Init(locOut map[int]OutputFunc, intfOut map[path.IntfID]OutputFunc,
	ifStateUpd func(proto.IFStateInfos)) {
	callbacks.locOutFs = locOut
	callbacks.intfOutFs = intfOut
	callbacks.ifStateUpd = ifStateUpd
}

type Packet struct {
	Raw     util.RawBytes
	TimeIn  time.Time
	DirFrom Dir
	DirTo   Dir
	Ingress AddrPair
	Egress  []EgressPair
	CmnHdr  spkt.CmnHdr
	idxs    packetIdxs
	srcIA   *addr.ISD_AS
	srcHost addr.HostAddr
	dstIA   *addr.ISD_AS
	dstHost addr.HostAddr
	infoF   *path.InfoField
	hopF    *path.HopField
	ifCurr  *path.IntfID
	ifNext  *path.IntfID
	upFlag  *bool
	HBHExt  []Extension
	E2EExt  []Extension
	L4Type  spkt.L4ProtoType
	l4      L4Header
	pld     interface{}
	hooks   Hooks
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

type OutputFunc func(*Packet)

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
	Type  spkt.L4ProtoType
	Index int
}

type extnIdx struct {
	Type  spkt.ExtnType
	Index int
}

var order = binary.BigEndian

func (p *Packet) Reset() {
	p.Raw = p.Raw[:cap(p.Raw)-1]
	p.DirFrom = DirUnset
	p.DirTo = DirUnset
	p.Ingress.Src = nil
	p.Ingress.Dst = nil
	p.Egress = p.Egress[:0]
	p.idxs = packetIdxs{}
	p.srcIA = nil
	p.srcHost = nil
	p.dstIA = nil
	p.dstHost = nil
	p.infoF = nil
	p.hopF = nil
	p.ifCurr = nil
	p.ifNext = nil
	p.upFlag = nil
	p.HBHExt = p.HBHExt[:0]
	p.E2EExt = p.E2EExt[:0]
	p.L4Type = spkt.L4None
	p.l4 = nil
	p.pld = nil
	p.hooks = Hooks{}
	p.Logger = nil
}
