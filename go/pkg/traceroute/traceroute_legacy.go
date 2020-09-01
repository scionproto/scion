// Copyright 2020 Anapaya Systems
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

// Package traceroute implements tracerouting based on SCMP traceroute messages.
package traceroute

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

const pkts_per_hop uint = 3

// RunLegacy runs a traceroute based on the configuration. This blocks until
// the context is canceled.
func RunLegacy(ctx context.Context, cfg Config) (Stats, error) {
	go func() {
		defer log.HandlePanic()
		<-ctx.Done()
		os.Exit(0)
	}()

	ret := Stats{}

	hopPktOff := func(offset int) uint8 {
		off := spkt.CmnHdrLen + spkt.AddrHdrLen(addr.HostFromIP(cfg.Local.Host.IP),
			addr.HostFromIP(cfg.Remote.Host.IP)) + offset
		return uint8(off / common.LineLen)
	}

	updateHopField := func(pkt *spkt.ScnPkt, info *scmp.InfoTraceRoute,
		path *spath.Path, total uint) {
		if ret.Sent%pkts_per_hop != 0 {
			return
		}
		info.HopOff = 0
		if path != nil && ret.Sent < total-pkts_per_hop {
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

	newSCMPPkt := func(t scmp.Type, info scmp.Info, ext common.Extension) *spkt.ScnPkt {
		var exts []common.Extension
		scmpMeta := scmp.Meta{InfoLen: uint8(info.Len() / common.LineLen)}
		pld := make(common.RawBytes, scmp.MetaLen+uint(info.Len())+cfg.PayloadSize)
		scmpMeta.Write(pld)
		info.Write(pld[scmp.MetaLen:])
		scmpHdr := scmp.NewHdr(scmp.ClassType{Class: scmp.C_General, Type: t}, len(pld))
		if ext != nil {
			exts = []common.Extension{ext}
		}
		pkt := &spkt.ScnPkt{
			DstIA:   cfg.Remote.IA,
			SrcIA:   cfg.Local.IA,
			DstHost: addr.HostFromIP(cfg.Remote.Host.IP),
			SrcHost: addr.HostFromIP(cfg.Local.Host.IP),
			Path:    cfg.Remote.Path,
			HBHExt:  exts,
			L4:      scmpHdr,
			Pld:     pld,
		}
		return pkt
	}

	conn, _, err := cfg.Dispatcher.Register(ctx, cfg.Local.IA,
		cfg.Local.Host, addr.SvcNone)
	if err != nil {
		return Stats{}, err
	}
	defer conn.Close()

	var hopOff uint8
	var ext common.Extension
	var path *spath.Path
	var total uint = 1
	if cfg.PathEntry != nil {
		path = cfg.PathEntry.Path()
		total += uint(len(cfg.PathEntry.Interfaces()))
		if path != nil {
			hopOff = hopPktOff(path.HopOff)
		}
		ext = &layers.ExtnSCMP{Error: false, HopByHop: true}
	}
	id := rand.Uint64()
	info := &scmp.InfoTraceRoute{Id: id, HopOff: hopOff}
	pkt := newSCMPPkt(scmp.T_G_TraceRouteRequest, info, ext)
	total *= pkts_per_hop
	b := make(common.RawBytes, cfg.MTU)
	for {
		var now time.Time
		var rtt time.Duration
		var pktRecv *spkt.ScnPkt
		var scmpHdr *scmp.Hdr
		var infoRecv *scmp.InfoTraceRoute

		ts := time.Now()

		pkt.L4.(*scmp.Hdr).SetTime(ts)
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(pkt, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
			break
		}
		// Send packet
		written, err := conn.WriteTo(b[:pktLen], cfg.Remote.NextHop)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to write %v\n", err)
			break
		} else if written != pktLen {
			fmt.Fprintf(os.Stderr, "ERROR: Wrote incomplete message. written=%d, expected=%d\n",
				len(b), written)
			break
		}
		ret.Sent += 1
		// Receive packet with timeout
		conn.SetReadDeadline(ts.Add(cfg.Timeout))
		pktLen, _, err = conn.ReadFrom(b)
		if err != nil {
			if common.IsTimeoutErr(err) {
				rtt = cfg.Timeout + 1
				goto next
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		now = time.Now()
		ret.Recv += 1
		// Parse packet
		pktRecv = &spkt.ScnPkt{}
		err = hpkt.ParseScnPkt(pktRecv, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
			continue
		}
		// Validate packet
		scmpHdr, infoRecv, err = validate(pktRecv, cfg.PathEntry, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation error: %v\n", err)
			continue
		}
		// Calculate return time
		rtt = now.Sub(scmpHdr.Time()).Round(time.Microsecond)
	next:
		prettyPrint(pktRecv, infoRecv, rtt, cfg.Timeout, ret)
		// More packets?
		if ret.Sent == total {
			break
		}
		updateHopField(pkt, info, path, total)
	}

	return ret, nil
}

var hop_printed bool = false

func prettyPrint(pkt *spkt.ScnPkt, info *scmp.InfoTraceRoute,
	rtt, timeout time.Duration, cmnStats Stats) {
	var str string
	if (cmnStats.Sent-1)%pkts_per_hop == 0 {
		fmt.Printf("%d ", cmnStats.Sent/pkts_per_hop)
	}
	if rtt > timeout {
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
	if cmnStats.Sent%pkts_per_hop == 0 {
		hop_printed = false
		fmt.Println()
	}
}

func validate(pkt *spkt.ScnPkt, path snet.Path, id uint64) (*scmp.Hdr,
	*scmp.InfoTraceRoute, error) {

	scmpHdr, scmpPld, err := cmnValidate(pkt)
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
	if path == nil || info.HopOff == 0 {
		return scmpHdr, info, nil
	}
	for _, e := range path.Interfaces() {
		if info.IA == e.IA() && info.IfID == e.ID() {
			return scmpHdr, info, nil
		}
	}
	return nil, nil,
		common.NewBasicError("Invalid TraceRoute Reply", nil, "IA", info.IA, "IfID", info.IfID)
}

func cmnValidate(pkt *spkt.ScnPkt) (*scmp.Hdr, *scmp.Payload, error) {
	scmpHdr, ok := pkt.L4.(*scmp.Hdr)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an SCMP header", nil, "type", common.TypeOf(pkt.L4))
	}
	scmpPld, ok := pkt.Pld.(*scmp.Payload)
	if !ok {
		return scmpHdr, nil,
			common.NewBasicError("Not an SCMP payload", nil, "type", common.TypeOf(pkt.Pld))
	}
	if scmpHdr.Class != scmp.C_Path || scmpHdr.Type != scmp.T_P_RevokedIF {
		return scmpHdr, scmpPld, nil
	}
	// Handle revocation
	infoRev, ok := scmpPld.Info.(*scmp.InfoRevocation)
	if !ok {
		return scmpHdr, scmpPld,
			serrors.New("Failed to parse SCMP revocation Info")
	}
	signedRevInfo, err := path_mgmt.NewSignedRevInfoFromRaw(infoRev.RawSRev)
	if err != nil {
		return scmpHdr, scmpPld,
			serrors.New("Failed to decode SCMP signed revocation Info")
	}
	ri, err := signedRevInfo.RevInfo()
	if err != nil {
		return scmpHdr, scmpPld,
			serrors.New("Failed to decode SCMP revocation Info")
	}
	return scmpHdr, scmpPld, common.NewBasicError("", nil, "Revocation", ri)
}
