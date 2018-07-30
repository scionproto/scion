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

package recordpath

import (
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"

	"github.com/scionproto/scion/go/tools/scmp/cmn"
)

var (
	id uint64
)

func Run() {
	var n, pktLen int
	var ext common.Extension

	cmn.SetupSignals(nil)
	if cmn.PathEntry != nil {
		n = len(cmn.PathEntry.Path.Interfaces)
		ext = &scmp.Extn{Error: false, HopByHop: true}
	}
	entries := make([]*scmp.RecordPathEntry, 0, n)
	id = cmn.Rand()
	info := &scmp.InfoRecordPath{Id: id, Entries: entries}
	pkt := cmn.NewSCMPPkt(scmp.T_G_RecordPathRequest, info, ext)
	b := make(common.RawBytes, cmn.Mtu)
	nhAddr := cmn.NextHopAddr()
	ts := time.Now()
	cmn.UpdatePktTS(pkt, ts)
	// Serialize packet to internal buffer
	pktLen, err := hpkt.WriteScnPkt(pkt, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
		return
	}
	// Send packet
	written, err := cmn.Conn.WriteTo(b[:pktLen], nhAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to write %v\n", err)
		return
	} else if written != pktLen {
		fmt.Fprintf(os.Stderr, "ERROR: Wrote incomplete message. written=%d, expected=%d\n",
			len(b), written)
		return
	}
	cmn.Stats.Sent += 1
	// Receive packet with timeout
	cmn.Conn.SetReadDeadline(ts.Add(cmn.Timeout))
	pktLen, err = cmn.Conn.Read(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return
	}
	cmn.Stats.Recv += 1
	now := time.Now()
	// Parse packet
	pktRecv := &spkt.ScnPkt{}
	err = hpkt.ParseScnPkt(pktRecv, b[:pktLen])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
		return
	}
	// Validate packet
	var scmpHdr *scmp.Hdr
	scmpHdr, info, err = validate(pktRecv, cmn.PathEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return
	}
	// Calculate return time
	rtt := now.Sub(scmpHdr.Time()).Round(time.Microsecond)
	prettyPrint(pktRecv, pktLen, info, rtt)
}

func prettyPrint(pkt *spkt.ScnPkt, pktLen int, info *scmp.InfoRecordPath, rtt time.Duration) {
	fmt.Printf("%d bytes from %s,[%s] time=%s Hops=%d\n",
		pktLen, pkt.SrcIA, pkt.SrcHost, rtt, info.NumHops())
	for i, e := range info.Entries {
		fmt.Printf(" %2d. %s\n", i+1, e.String())
	}
}

func validate(pkt *spkt.ScnPkt, pathEntry *sciond.PathReplyEntry) (*scmp.Hdr,
	*scmp.InfoRecordPath, error) {

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
	info, ok := scmpPld.Info.(*scmp.InfoRecordPath)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an Info RecordPath", nil, "type", common.TypeOf(info))
	}
	if info.Id != id {
		return nil, nil,
			common.NewBasicError("Wrong SCMP ID", nil, "expected", id, "actual", info.Id)
	}
	if pathEntry == nil {
		return scmpHdr, info, nil
	}
	interfaces := pathEntry.Path.Interfaces
	if len(info.Entries) != len(interfaces) {
		return nil, nil,
			common.NewBasicError("Invalid number of entries", nil,
				"Expected", len(interfaces), "Actual", len(info.Entries))
	}
	for i, e := range info.Entries {
		ia := interfaces[i].RawIsdas.IA()
		if e.IA != ia {
			return nil, nil,
				common.NewBasicError("Invalid ISD-AS", nil, "entry", i,
					"Expected", ia, "Actual", e.IA)
		}
		ifid := common.IFIDType(interfaces[i].IfID)
		if e.IfID != ifid {
			return nil, nil,
				common.NewBasicError("Invalid IfID", nil, "entry", i,
					"Expected", ifid, "Actual", e.IfID)
		}
	}
	return scmpHdr, info, nil
}
