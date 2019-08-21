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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/border/rctx"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

var rawUdpPkt = "udp-scion.bin"

// Prepare the packet from raw
func prepareRtrPacketSample(t *testing.T) *RtrPkt {
	r := NewRtrPkt()
	r.Raw = xtest.MustReadFromFile(t, rawUdpPkt)
	// Set some other data that are required for the parsing to succeed:
	var config = &brconf.BRConf{
		IA: addr.IA{I: 1, A: 2},
		BR: &topology.BRInfo{
			IFs: map[common.IFIDType]*topology.IFInfo{5: nil},
		},
	}
	r.Ctx = rctx.New(config)
	r.Ingress = addrIFPair{IfID: 5}
	return r
}

func TestParseBasic(t *testing.T) {
	r := prepareRtrPacketSample(t)

	r.parseBasic()
	srcIA, _ := r.SrcIA()
	dstIA, _ := r.DstIA()
	srcHost, _ := r.SrcHost()
	dstHost, _ := r.DstHost()

	assert.Equal(t, addr.IA{I: 1, A: 10}, srcIA, "Source IA")
	assert.Equal(t, addr.IA{I: 2, A: 25}, dstIA, "Destination IA")
	assert.True(t, srcHost.IP().Equal(net.IPv4(127, 1, 1, 111)), "Source host IP")
	assert.True(t, dstHost.IP().Equal(net.IPv4(127, 2, 2, 222)), "Destination host IP")
	expectedHdr := spkt.CmnHdr{
		Ver:       0,
		DstType:   addr.HostTypeIPv4,
		SrcType:   addr.HostTypeIPv4,
		TotalLen:  1280,
		HdrLen:    17,
		CurrInfoF: 4 + 9, // 4 accounts for common header + address headers.
		CurrHopF:  4 + 12,
		NextHdr:   17,
	}
	assert.Equal(t, expectedHdr, r.CmnHdr)
}

func TestParse(t *testing.T) {
	r := prepareRtrPacketSample(t)

	// Verify additional fields that appear after complete parse only
	r.Parse()
	l4hdr, _ := r.L4Hdr(false)
	expected := &l4.UDP{
		SrcPort:  44887,
		DstPort:  3000,
		TotalLen: 1144,
		Checksum: common.RawBytes{0x7c, 0x46},
	}
	assert.Equal(t, expected, l4hdr, "L4Hdr must be expected UDP")
}
