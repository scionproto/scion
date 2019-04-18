// Copyright 2019 Anapaya Systems
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

package beaconing

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestPropagatorRun(t *testing.T) {
	macProp, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	macSender, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)

	type test struct {
		name     string
		inactive map[common.IFIDType]bool
		expected int
	}

	nonCoreBeacons := [][]common.IFIDType{
		{graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
	}
	// All interfaces of the non-core AS
	nonCoreIntfs := map[common.IFIDType]common.IFIDType{
		graph.If_111_A_112_X: graph.If_112_X_111_A,
		graph.If_111_B_120_X: graph.If_120_X_111_B,
		graph.If_111_B_211_A: graph.If_211_A_111_B,
		graph.If_111_C_211_A: graph.If_211_A_111_C,
		graph.If_111_C_121_X: graph.If_121_X_111_C,
	}
	nonCore := []test{
		{
			name:     "All interfaces active",
			expected: 3,
		},
		{
			name:     "One peer inactive",
			inactive: map[common.IFIDType]bool{graph.If_111_C_121_X: true},
			expected: 3,
		},
		{
			name: "All peers inactive",
			inactive: map[common.IFIDType]bool{
				graph.If_111_C_121_X: true,
				graph.If_111_B_211_A: true,
				graph.If_111_C_211_A: true,
			},
			expected: 3,
		},
		{
			name:     "Child interface inactive",
			inactive: map[common.IFIDType]bool{graph.If_111_A_112_X: true},
			expected: 0,
		},
	}
	for _, test := range nonCore {
		Convey("Non-core: "+test.name, t, func() {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			setupItopo(t, topoNonCore)
			signer := testSigner(t, priv)
			// Activate all non-inactive interfaces.
			intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
			for ifid, remote := range nonCoreIntfs {
				if test.inactive[ifid] {
					continue
				}
				intfs.Get(ifid).Activate(remote)
			}

			g := graph.NewDefaultGraph(mctrl)
			provider := mock_beaconing.NewMockBeaconProvider(mctrl)
			conn := mock_snet.NewMockPacketConn(mctrl)

			p, err := NewPropagator(intfs, macProp, false, provider,
				Config{
					MTU:    uint16(itopo.Get().MTU),
					Signer: signer,
				},
				&onehop.Sender{
					IA:   itopo.Get().ISD_AS,
					Conn: conn,
					Addr: &addr.AppAddr{
						L3: addr.HostFromIPStr("127.0.0.1"),
						L4: addr.NewL4UDPInfo(4242),
					},
					MAC: macSender,
				},
			)
			SoMsg("err", err, ShouldBeNil)
			provider.EXPECT().BeaconsToPropagate(gomock.Any()).DoAndReturn(
				func(_ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, len(nonCoreBeacons))
					for _, desc := range nonCoreBeacons {
						res <- testBeaconOrErr(g, desc)
					}
					close(res)
					return res, nil
				},
			)
			type msg struct {
				pkt *snet.SCIONPacket
				ov  *overlay.OverlayAddr
			}
			msgsMtx := sync.Mutex{}
			var msgs []msg
			conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Times(test.expected).DoAndReturn(
				func(ipkt, iov interface{}) error {
					msgsMtx.Lock()
					defer msgsMtx.Unlock()
					msgs = append(msgs, msg{
						pkt: ipkt.(*snet.SCIONPacket),
						ov:  iov.(*overlay.OverlayAddr),
					})
					return nil
				},
			)
			p.Run(nil)
			for i, msg := range msgs {
				Convey(fmt.Sprintf("Packet %d is correct", i), func() {
					// Extract segment from the payload
					spld, err := ctrl.NewSignedPldFromRaw(msg.pkt.Payload.(common.RawBytes))
					SoMsg("SPldErr", err, ShouldBeNil)
					pld, err := spld.UnsafePld()
					SoMsg("PldErr", err, ShouldBeNil)
					err = pld.Beacon.Parse()
					SoMsg("ParseErr", err, ShouldBeNil)
					pseg := pld.Beacon.Segment
					Convey("Segment can be validated", func() {
						err = pseg.Validate(seg.ValidateBeacon)
						SoMsg("err", err, ShouldBeNil)
					})
					Convey("Segment can be verified", func() {
						err = pseg.VerifyASEntry(context.Background(),
							segVerifier(pub), pseg.MaxAEIdx())
						SoMsg("err", err, ShouldBeNil)
					})
					Convey("Beacon on correct interface", func() {
						hopF, err := msg.pkt.Path.GetHopField(msg.pkt.Path.HopOff)
						xtest.FailOnErr(t, err)
						bHopF, err := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField()
						xtest.FailOnErr(t, err)
						SoMsg("Egress", hopF.ConsEgress, ShouldEqual, bHopF.ConsEgress)
						brAddr := itopo.Get().IFInfoMap[hopF.ConsEgress].InternalAddrs
						SoMsg("ov", msg.ov, ShouldResemble, brAddr.PublicOverlay(brAddr.Overlay))
					})
				})
			}
		})
	}
}
