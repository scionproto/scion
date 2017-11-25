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
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/border/netconf"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

// The packet sample from node 1-14 to 1-17 as logged 20.11.2016
const sample = "0041003f03000011001000110010000e7f00001b7f00001ac350c35000270" +
	"a160000001b1008400211056a51080102ff100550010101021000070201330002"

// Prepare the packet from raw
func preparePacketSample() *RtrPkt {
	var err error
	packet, err := hex.DecodeString(sample)
	if err != nil {
		panic(err)
	}
	r := NewRtrPkt()

	// Set raw data:
	r.Raw = packet

	// Set some other data that are required for the parsing to succeed:
	var config = &conf.Conf{
		IA: &addr.ISD_AS{I: 1, A: 2},
		Net: &netconf.NetConf{IFs: map[common.IFIDType]*netconf.Interface{
			777: nil,
		}}}

	r.Ctx = rctx.New(config, 777)
	r.Ingress = addrIFPair{IfIDs: []common.IFIDType{1, 2}}

	return r
}

func Test_ParseBasic(t *testing.T) {
	r := preparePacketSample()

	Convey("Parse basic", t, func() {
		r.parseBasic()

		srcIA, _ := r.SrcIA()
		dstIA, _ := r.DstIA()

		srcHost, _ := r.SrcHost()
		dstHost, _ := r.DstHost()

		So(srcIA.String(), ShouldEqual, addr.ISD_AS{I: 1, A: 14}.String())
		So(dstIA.String(), ShouldEqual, addr.ISD_AS{I: 1, A: 17}.String())

		So(srcHost.String(), ShouldEqual,
			addr.HostFromIP(net.IPv4(127, 0, 0, 26)).String())
		So(dstHost.String(), ShouldEqual,
			addr.HostFromIP(net.IPv4(127, 0, 0, 27)).String())

		So(r.CmnHdr.Ver, ShouldEqual, 0)
		So(r.CmnHdr.DstType, ShouldEqual, 1)
		So(r.CmnHdr.SrcType, ShouldEqual, 1)
		So(r.CmnHdr.TotalLen, ShouldEqual, 63)
		So(r.CmnHdr.HdrLen, ShouldEqual, 3)
		So(r.CmnHdr.NextHdr, ShouldEqual, 17)
	})
}

func Test_Parse(t *testing.T) {
	r := preparePacketSample()

	Convey("Parse complete", t, func() {
		r.Parse()

		// Verify additional fields
		l4hdr, _ := r.L4Hdr(false)
		So(l4hdr.String(), ShouldEqual,
			"SPort=50000 DPort=50000 TotalLen=39 Checksum=0a16")
	})
}
