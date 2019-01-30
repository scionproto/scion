// Copyright 2018 ETH Zurich
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

package traceroute

import (
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/tools/scmp/cmn"
)

const pkts_per_hop uint = 3

var (
	id uint64
)

func Run() {
	var hopOff uint8
	var ext common.Extension
	var path *spath.Path
	var total uint = 1

	cmn.SetupSignals(nil)
	if cmn.PathEntry != nil {
		path = spath.New(cmn.PathEntry.Path.FwdPath)
		path.InitOffsets()
		total += uint(len(cmn.PathEntry.Path.Interfaces))
		hopOff = hopPktOff(path.HopOff)
		ext = &layers.ExtnSCMP{Error: false, HopByHop: true}
	}
	id = cmn.Rand()
	info := &scmp.InfoTraceRoute{Id: id, HopOff: hopOff}
	pkt := cmn.NewSCMPPkt(scmp.T_G_TraceRouteRequest, info, ext)
	total *= pkts_per_hop
	b := make(common.RawBytes, cmn.Mtu)
	nhAddr := cmn.NextHopAddr()
	for {
		var now time.Time
		var rtt time.Duration
		var pktRecv *spkt.ScnPkt
		var scmpHdr *scmp.Hdr
		var infoRecv *scmp.InfoTraceRoute

		ts := time.Now()
		cmn.UpdatePktTS(pkt, ts)
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(pkt, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
			break
		}
		// Send packet
		written, err := cmn.Conn.WriteTo(b[:pktLen], nhAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to write %v\n", err)
			break
		} else if written != pktLen {
			fmt.Fprintf(os.Stderr, "ERROR: Wrote incomplete message. written=%d, expected=%d\n",
				len(b), written)
			break
		}
		cmn.Stats.Sent += 1
		// Receive packet with timeout
		cmn.Conn.SetReadDeadline(ts.Add(cmn.Timeout))
		pktLen, err = cmn.Conn.Read(b)
		if err != nil {
			if common.IsTimeoutErr(err) {
				rtt = cmn.Timeout + 1
				goto next
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		now = time.Now()
		cmn.Stats.Recv += 1
		// Parse packet
		pktRecv = &spkt.ScnPkt{}
		err = hpkt.ParseScnPkt(pktRecv, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
			continue
		}
		// Validate packet
		scmpHdr, infoRecv, err = validate(pktRecv, cmn.PathEntry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation error: %v\n", err)
			continue
		}
		// Calculate return time
		rtt = now.Sub(scmpHdr.Time()).Round(time.Microsecond)
	next:
		prettyPrint(pktRecv, infoRecv, rtt)
		// More packets?
		if cmn.Stats.Sent == total {
			break
		}
		updateHopField(pkt, info, path, total)
	}
}

var hop_printed bool = false

func prettyPrint(pkt *spkt.ScnPkt, info *scmp.InfoTraceRoute, rtt time.Duration) {
	var str string
	if (cmn.Stats.Sent-1)%pkts_per_hop == 0 {
		fmt.Printf("%d ", cmn.Stats.Sent/pkts_per_hop)
	}
	if rtt > cmn.Timeout {
		fmt.Printf(" *")
	} else {
		if !hop_printed {
			hop_printed = true
			if info.HopOff == 0 {
				str = fmt.Sprintf("%s,[%s]  ", pkt.SrcIA, pkt.SrcHost)
			} else {
				str = fmt.Sprintf("%s,[%s] IfID=%d  ", pkt.SrcIA, pkt.SrcHost, info.IfID)
			}
		}
		fmt.Printf(" %s%s", str, rtt)
	}
	if cmn.Stats.Sent%pkts_per_hop == 0 {
		hop_printed = false
		fmt.Println()
	}
}

// hopPktOff returns HopF offset relative to the packet
func hopPktOff(offset int) uint8 {
	off := spkt.CmnHdrLen + spkt.AddrHdrLen(cmn.Local.Host.L3, cmn.Remote.Host.L3) + offset
	return uint8(off / common.LineLen)
}

func updateHopField(pkt *spkt.ScnPkt, info *scmp.InfoTraceRoute, path *spath.Path, total uint) {
	if cmn.Stats.Sent%pkts_per_hop != 0 {
		return
	}
	info.HopOff = 0
	if path != nil && cmn.Stats.Sent < total-pkts_per_hop {
		if !info.In { // Egress
			// Inc path
			path.IncOffsets()
		} else { //Ingress
			// Is Xover or nextHF is VerOnly
			hopF, _ := path.GetHopField(path.HopOff)
			if hopF.Xover {
				// The current HopOff Egress IfID is not used, increment path
				path.IncOffsets()
			}
		}
		info.In = !info.In
		info.HopOff = hopPktOff(path.HopOff)
	}
	pldBuf := pkt.Pld.(common.RawBytes)
	info.Write(pldBuf[scmp.MetaLen:])
}

func validate(pkt *spkt.ScnPkt, pathEntry *sciond.PathReplyEntry) (*scmp.Hdr,
	*scmp.InfoTraceRoute, error) {

	scmpHdr, scmpPld, err := cmn.Validate(pkt)
	if err != nil {
		return nil, nil, err
	}
	info, ok := scmpPld.Info.(*scmp.InfoTraceRoute)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an Info TraceRoute", nil, "type", common.TypeOf(scmpPld.Info))
	}
	if info.Id != id {
		return nil, nil,
			common.NewBasicError("Wrong SCMP ID", nil, "expected", id, "actual", info.Id)
	}
	if pathEntry == nil || info.HopOff == 0 {
		return scmpHdr, info, nil
	}
	interfaces := pathEntry.Path.Interfaces
	for _, e := range interfaces {
		if info.IA == e.RawIsdas.IA() && info.IfID == e.IfID {
			return scmpHdr, info, nil
		}
	}
	return nil, nil,
		common.NewBasicError("Invalid TraceRoute Reply", nil, "IA", info.IA, "IfID", info.IfID)
}
