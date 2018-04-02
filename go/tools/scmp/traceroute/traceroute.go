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
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"

	"github.com/scionproto/scion/go/tools/scmp/cmn"
)

func Run() {
	var hopOff uint8
	var ext *scmp.Extn
	var path *spath.Path
	var total uint = 1

	if cmn.PathEntry != nil {
		path = spath.New(cmn.PathEntry.Path.FwdPath)
		path.InitOffsets()
		total += uint(len(cmn.PathEntry.Path.Interfaces))
		hopOff = hopPktOff(path.HopOff)
		ext = &scmp.Extn{Error: false, HopByHop: true}
	}
	// Send packet
	info := &scmp.InfoTraceRoute{Id: cmn.Rand(), HopOff: hopOff}
	pkt := cmn.NewSCMPPkt(scmp.T_G_TraceRouteRequest, info, ext)

	b := make(common.RawBytes, cmn.Mtu)

	nhAddr := cmn.NextHopAddr()
	ts := time.Now()
	ticker := time.NewTicker(cmn.Interval)
	for ; true; ts = <-ticker.C {
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
			e, ok := err.(*net.OpError)
			if ok && e.Timeout() {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		cmn.Stats.Recv += 1
		now := time.Now()
		// Parse packet
		pktRecv := &spkt.ScnPkt{}
		err = hpkt.ParseScnPkt(pktRecv, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
			break
		}
		// Validate packet
		scmpHdr, infoRecv, err := validate(pktRecv, cmn.PathEntry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation error: %v\n", err)
			// We continue as one bad reply does not mean all replies would be bad ones
			continue
		}
		// Calculate return time
		rtt := now.Sub(scmpHdr.Time()).Round(time.Microsecond)
		prettyPrint(pktRecv, pktLen, infoRecv, rtt)
		// More packets?
		if cmn.Stats.Sent == total {
			break
		}
		// Update packet fields
		setNextHF(info, path, total)
		pldBuf := pkt.Pld.(common.RawBytes)
		info.Write(pldBuf[scmp.MetaLen:])
	}
}

func prettyPrint(pkt *spkt.ScnPkt, pktLen int, info *scmp.InfoTraceRoute, rtt time.Duration) {
	if info.HopOff == 0 {
		fmt.Printf("%d bytes from %s,[%s] time=%s\n",
			pktLen, pkt.SrcIA, pkt.SrcHost, rtt)
	} else {
		fmt.Printf("%d bytes from %s,[%s] IfID=%d time=%s\n",
			pktLen, pkt.SrcIA, pkt.SrcHost, info.IfID, rtt)
	}
}

// hopPktOff returns HopF offset relative to the packet
func hopPktOff(offset int) uint8 {
	off := spkt.CmnHdrLen + spkt.AddrHdrLen(cmn.Local.Host, cmn.Remote.Host) + offset
	return uint8(off / common.LineLen)
}

func setNextHF(info *scmp.InfoTraceRoute, path *spath.Path, total uint) {
	info.HopOff = 0
	if path != nil && cmn.Stats.Sent < total-1 {
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
}

func validate(pkt *spkt.ScnPkt, pathEntry *sciond.PathReplyEntry) (*scmp.Hdr,
	*scmp.InfoTraceRoute, error) {

	scmpHdr, ok := pkt.L4.(*scmp.Hdr)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an SCMP header", nil, "type", common.TypeOf(pkt.L4))
	}
	scmpPld, ok := pkt.Pld.(*scmp.Payload)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an SCMP payload", nil, "type", common.TypeOf(pkt.Pld))
	}
	info, ok := scmpPld.Info.(*scmp.InfoTraceRoute)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an Info TraceRoute", nil, "type", common.TypeOf(info))
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
