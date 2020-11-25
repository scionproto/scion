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

package runner

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestComparePkt(t *testing.T) {
	testCases := map[string]struct {
		got, want gopacket.Packet
	}{
		"nils": {},
		"scion": {
			got:  prepareSCION(t, "172.168.1.1"),
			want: prepareSCION(t, "172.168.1.2"),
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := comparePkts(tc.got, tc.want, nil)
			assert.Error(t, err)
		})
	}
}

func prepareSCION(t *testing.T, diff string) gopacket.Packet {
	t.Helper()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	hash, err := scrypto.HFMacFactory([]byte("dummy"))
	assert.NoError(t, err)
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 1,
				SegLen: [3]uint8{3, 0, 0},
			},
			NumINF:  1,
			NumHops: 3,
		},
		InfoFields: []*path.InfoField{
			{
				SegID:     0x111,
				Timestamp: util.TimeToSecs(time.Now()),
			},
		},
		HopFields: []*path.HopField{
			{ConsIngress: 411, ConsEgress: 0},
			{ConsIngress: 131, ConsEgress: 141},
			{ConsIngress: 0, ConsEgress: 311},
		},
	}
	sp.HopFields[1].Mac = path.MAC(hash(), sp.InfoFields[0], sp.HopFields[1])
	sp.InfoFields[0].UpdateSegID(sp.HopFields[1].Mac)

	scionL := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4UDP,
		PathType:     scion.PathType,
		SrcIA:        xtest.MustParseIA("1-ff00:0:4"),
		DstIA:        xtest.MustParseIA("1-ff00:0:3"),
		Path:         sp,
	}
	if err := scionL.SetSrcAddr(&net.IPAddr{IP: net.ParseIP(diff)}); err != nil {
		assert.NoError(t, err)
	}
	if err := scionL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.3.1")}); err != nil {
		assert.NoError(t, err)
	}

	input := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(input, options, scionL); err != nil {
		assert.NoError(t, err)
	}
	packet := gopacket.NewPacket(input.Bytes(), slayers.LayerTypeSCION, gopacket.Default)
	return packet
}
