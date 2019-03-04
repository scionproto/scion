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
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/netconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
)

var rawUdpPkt = "testdata/udp-scion.bin"

func MustLoad(path string) common.RawBytes {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Unable to load file: %v", err))
	}
	return common.RawBytes(data)
}

// Prepare the packet from raw
func prepareRtrPacketSample() *RtrPkt {
	r := NewRtrPkt()
	r.Raw = MustLoad(rawUdpPkt)
	// Set some other data that are required for the parsing to succeed:
	var config = &brconf.Conf{
		IA: addr.IA{I: 1, A: 2},
		Net: &netconf.NetConf{
			IFs: map[common.IFIDType]*netconf.Interface{5: nil},
		},
	}
	r.Ctx = rctx.New(config)
	r.Ingress = addrIFPair{IfID: 5}
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

		SoMsg("Source IA", srcIA, ShouldResemble, addr.IA{I: 1, A: 10})
		SoMsg("Destination IA", dstIA, ShouldResemble, addr.IA{I: 2, A: 25})
		SoMsg("Source host IP", srcHost.IP().Equal(net.IPv4(127, 1, 1, 111)), ShouldBeTrue)
		SoMsg("Destination host IP", dstHost.IP().Equal(net.IPv4(127, 2, 2, 222)), ShouldBeTrue)
		SoMsg("CmnHdr", r.CmnHdr, ShouldResemble, spkt.CmnHdr{
			Ver:       0,
			DstType:   addr.HostTypeIPv4,
			SrcType:   addr.HostTypeIPv4,
			TotalLen:  1280,
			HdrLen:    17,
			CurrInfoF: 4 + 9, // 4 accounts for common header + address headers.
			CurrHopF:  4 + 12,
			NextHdr:   17,
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
			SrcPort:  44887,
			DstPort:  3000,
			TotalLen: 1144,
			Checksum: common.RawBytes{0x7c, 0x46},
		})
	})
}
