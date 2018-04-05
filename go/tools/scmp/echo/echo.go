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

package echo

import (
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"

	"github.com/scionproto/scion/go/tools/scmp/cmn"
)

var (
	ch chan time.Time
	id uint64
)

func Run() {
	ch = make(chan time.Time, 20)
	cmn.SetupSignals(summary)
	go sendPkts()
	recvPkts()
}

func sendPkts() {
	defer close(ch)

	id = cmn.Rand()
	info := &scmp.InfoEcho{Id: id, Seq: 0}
	pkt := cmn.NewSCMPPkt(scmp.T_G_EchoRequest, info, nil)
	b := make(common.RawBytes, cmn.Mtu)
	nhAddr := cmn.NextHopAddr()

	nextPktTS := time.Now()
	ticker := time.NewTicker(cmn.Interval)
	for ; true; nextPktTS = <-ticker.C {
		cmn.UpdatePktTS(pkt, nextPktTS)
		// Serialize packet to internal buffer
		pktLen, err := hpkt.WriteScnPkt(pkt, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to serialize SCION packet %v\n", err)
			break
		}
		written, err := cmn.Conn.WriteTo(b[:pktLen], nhAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to write %v\n", err)
			break
		} else if written != pktLen {
			fmt.Fprintf(os.Stderr, "ERROR: Wrote incomplete message. written=%d, expected=%d\n",
				len(b), written)
			break
		}
		// Notify the receiver
		ch <- nextPktTS
		cmn.Stats.Sent += 1
		// More packets?
		if cmn.Count != 0 && cmn.Stats.Sent == cmn.Count {
			break
		}
		// Update packet fields
		info.Seq += 1
		b := pkt.Pld.(common.RawBytes)
		info.Write(b[scmp.MetaLen:])
	}
}

func recvPkts() {
	pkt := &spkt.ScnPkt{}
	b := make(common.RawBytes, cmn.Mtu)

	nextTimeout := time.Now()
	for {
		nextPktTS, ok := <-ch
		if ok {
			nextTimeout = nextPktTS.Add(cmn.Timeout)
			cmn.Conn.SetReadDeadline(nextTimeout)
		} else if cmn.Stats.Recv == cmn.Stats.Sent || nextTimeout.Before(time.Now()) {
			break
		}
		pktLen, err := cmn.Conn.Read(b)
		if err != nil {
			if common.IsTimeoutErr(err) {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(pkt, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse error: %v\n", err)
			break
		}
		// Validate packet
		var scmpHdr *scmp.Hdr
		var info *scmp.InfoEcho
		scmpHdr, info, err = validate(pkt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation error: %v\n", err)
			break
		}
		cmn.Stats.Recv += 1
		// Calculate return time
		rtt := now.Sub(scmpHdr.Time()).Round(time.Microsecond)
		prettyPrint(pkt, pktLen, info, rtt, scmpHdr.Time(), nextPktTS)
	}
	summary()
}

func summary() {
	fmt.Printf("\n--- %s,[%s] statistics ---\n", cmn.Remote.IA, cmn.Remote.Host)
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
		cmn.Stats.Sent, cmn.Stats.Recv, 100-cmn.Stats.Recv*100/cmn.Stats.Sent,
		time.Since(cmn.Start).Round(time.Microsecond))
}

func validate(pkt *spkt.ScnPkt) (*scmp.Hdr, *scmp.InfoEcho, error) {
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
	info, ok := scmpPld.Info.(*scmp.InfoEcho)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an Info Echo", nil, "type", common.TypeOf(info))
	}
	if info.Id != id {
		return nil, nil,
			common.NewBasicError("Wrong SCMP ID", nil, "expected", id, "actual", info.Id)
	}
	return scmpHdr, info, nil
}

func prettyPrint(pkt *spkt.ScnPkt, pktLen int, info *scmp.InfoEcho, rtt time.Duration,
	pktTS, expectedTS time.Time) {

	var ooo string
	if rtt > cmn.Timeout {
		return
	}
	expectedTS = expectedTS.Truncate(time.Microsecond)
	if pktTS.Before(expectedTS) {
		ooo = "  Out of Order"
	}
	fmt.Printf("%d bytes from %s,[%s] scmp_seq=%d time=%s%s\n",
		pktLen, pkt.SrcIA, pkt.SrcHost, info.Seq, rtt, ooo)
}
