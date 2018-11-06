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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/tools/scmp/cmn"
)

var (
	id      uint64
	recvSeq uint16
	wg      sync.WaitGroup
)

func Run() {
	cmn.SetupSignals(summary)
	wg.Add(1)
	go sendPkts()
	recvPkts()
	wg.Wait()
	summary()
}

func sendPkts() {
	defer wg.Done()
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

func updateDeadline(t time.Time, seq uint16) {
	nextTimeout := t.Add(cmn.Interval * time.Duration(seq)).Add(cmn.Timeout)
	cmn.Conn.SetReadDeadline(nextTimeout)
}

func recvPkts() {
	var expectedSeq uint16

	pkt := &spkt.ScnPkt{}
	b := make(common.RawBytes, cmn.Mtu)

	start := time.Now()
	updateDeadline(start, 0)
	for cmn.Count == 0 || expectedSeq < uint16(cmn.Count) {
		pktLen, err := cmn.Conn.Read(b)
		if err != nil {
			if common.IsTimeoutErr(err) {
				if expectedSeq > recvSeq {
					expectedSeq += 1
				} else {
					expectedSeq = recvSeq + 1
				}
				updateDeadline(start, expectedSeq)
				continue
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: Unable to read: %v\n", err)
				break
			}
		}
		now := time.Now()
		err = hpkt.ParseScnPkt(pkt, b[:pktLen])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCION packet parse: %v\n", err)
			continue
		}
		// Validate packet
		var scmpHdr *scmp.Hdr
		var info *scmp.InfoEcho
		scmpHdr, info, err = validate(pkt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: SCMP validation: %v\n", err)
			continue
		}
		cmn.Stats.Recv += 1
		if info.Seq > recvSeq {
			recvSeq = info.Seq
		}
		// Update read deadline if the expected packet was received
		if info.Seq == expectedSeq {
			if expectedSeq > recvSeq {
				expectedSeq += 1
			} else {
				expectedSeq = recvSeq + 1
			}
			updateDeadline(start, expectedSeq)
		}
		// Calculate return time
		rtt := now.Sub(scmpHdr.Time()).Round(time.Microsecond)
		prettyPrint(pkt, pktLen, info, rtt)
	}
}

func summary() {
	pktLoss := uint(0)
	if cmn.Stats.Sent != 0 {
		pktLoss = 100 - cmn.Stats.Recv*100/cmn.Stats.Sent
	}
	fmt.Printf("\n--- %s,[%s] statistics ---\n", cmn.Remote.IA, cmn.Remote.Host)
	fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %v\n",
		cmn.Stats.Sent, cmn.Stats.Recv, pktLoss,
		time.Since(cmn.Start).Round(time.Microsecond))
}

func validate(pkt *spkt.ScnPkt) (*scmp.Hdr, *scmp.InfoEcho, error) {
	scmpHdr, scmpPld, err := cmn.Validate(pkt)
	if err != nil {
		if scmpPld != nil && len(scmpPld.L4Hdr) > 0 {
			// XXX Special case where the L4Hdr quote contains the Meta and Info fields
			info, e := scmp.InfoEchoFromRaw(scmpPld.L4Hdr[scmp.HdrLen+scmp.MetaLen:])
			if e == nil {
				return nil, nil, common.NewBasicError("", err, "scmp_seq", info.Seq)
			}
		}
		return nil, nil, err
	}
	info, ok := scmpPld.Info.(*scmp.InfoEcho)
	if !ok {
		return nil, nil,
			common.NewBasicError("Not an Info Echo", nil, "type", common.TypeOf(scmpPld.Info))
	}
	if info.Id != id {
		return nil, nil,
			common.NewBasicError("Wrong SCMP ID", nil, "expected", id, "actual", info.Id)
	}
	return scmpHdr, info, nil
}

func prettyPrint(pkt *spkt.ScnPkt, pktLen int, info *scmp.InfoEcho, rtt time.Duration) {
	var str string
	if rtt > cmn.Timeout {
		str = "  Packet too old"
	} else if info.Seq < recvSeq {
		str = "  Out of Order"
	}
	fmt.Printf("%d bytes from %s,[%s] scmp_seq=%d time=%s%s\n",
		pktLen, pkt.SrcIA, pkt.SrcHost, info.Seq, rtt, str)
}
