// Copyright 2017 Audrius Meskauskas with all possible permissions granted
// to ETH Zurich and Anapaya Systems
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
	"encoding/hex"

	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/border/conf"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
)

// The packet sample from node 1-14 to 1-17 as logged 20.11.2016
const sample = "0041003f03000011001000110010000e7f00001b7f00001ac350c35000270" +
	"a160000001b1008400211056a51080102ff100550010101021000070201330002"

// Prepare the packet from raw
func prepareRtrPacketSample() *RtrPkt {
	var err error
	packet, err := hex.DecodeString(sample)
	if err != nil {
		panic(err)
	}
	r := NewRtrPkt()
	r.Raw = packet
	// Set some other data that are required for the parsing to succeed:
	var config = &conf.Conf{
		IA: &addr.ISD_AS{I: 1, A: 2},
		Net: &netconf.NetConf{
			IFs: map[common.IFIDType]*netconf.Interface{777: nil},
		},
	}
	r.Ctx = rctx.New(config, 777)
	r.Ingress = addrIFPair{IfIDs: []common.IFIDType{1, 2}}
	return r
}

func TestParseBasic(t *testing.T) {
	Convey("Parse packet, basic", t, func() {
		r := prepareRtrPacketSample()

		r.parseBasic()
		srcIA, _ := r.SrcIA()
		dstIA, _ := r.DstIA()
		srcHost, _ := r.SrcHost()
		dstHost, _ := r.DstHost()

		SoMsg("Source IA", *srcIA, ShouldResemble, addr.ISD_AS{I: 1, A: 14})
		SoMsg("Destination IA", *dstIA, ShouldResemble, addr.ISD_AS{I: 1, A: 17})
		SoMsg("Source host IP", srcHost, ShouldResemble, addr.HostIPv4{127, 0, 0, 26})
		SoMsg("Destination host IP", dstHost, ShouldResemble, addr.HostIPv4{127, 0, 0, 27})
		SoMsg("CmnHdr", r.CmnHdr, ShouldResemble, spkt.CmnHdr{
			Ver:      0,
			DstType:  1,
			SrcType:  1,
			TotalLen: 63,
			HdrLen:   3,
			NextHdr:  17,
		})
	})
}

func TestParse(t *testing.T) {
	r := prepareRtrPacketSample()

	// Verify additional fields that appear after complete parse only
	Convey("Parse packet, complete", t, func() {
		r.Parse()
		l4hdr, _ := r.L4Hdr(false)
		SoMsg("L4Hdr must be expected UDP", l4hdr, ShouldResemble, &l4.UDP{
			SrcPort:  50000,
			DstPort:  50000,
			TotalLen: 39,
			Checksum: common.RawBytes{0x0a, 0x16},
		})
	})
}
