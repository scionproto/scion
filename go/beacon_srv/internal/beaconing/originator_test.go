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

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

const (
	topoCore    = "testdata/topology-core.json"
	topoNonCore = "testdata/topology.json"
)

func TestOriginatorRun(t *testing.T) {
	topoProvider := xtest.TopoProviderFromFile(t, topoCore)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap, ifstate.Config{})
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := testSigner(t, priv, topoProvider.Get().ISD_AS)
	Convey("Run originates ifid packets on all active core and child interfaces", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		conn := mock_snet.NewMockPacketConn(mctrl)
		o, err := OriginatorConf{
			Config: ExtenderConf{
				MTU:    uint16(topoProvider.Get().MTU),
				Signer: signer,
				Intfs:  intfs,
				Mac:    mac,
			},
			Sender: &onehop.Sender{
				IA:   xtest.MustParseIA("1-ff00:0:110"),
				Conn: conn,
				Addr: &addr.AppAddr{
					L3: addr.HostFromIPStr("127.0.0.1"),
					L4: addr.NewL4UDPInfo(4242),
				},
				MAC: mac,
			},
		}.New()
		xtest.FailOnErr(t, err)
		// Activate interfaces
		intfs.Get(42).Activate(84)
		intfs.Get(1129).Activate(82)

		msgsMtx := sync.Mutex{}
		var msgs []msg
		conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
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
		// Start beacon messages.
		o.Run(nil)
		for i, msg := range msgs {
			Convey(fmt.Sprintf("Packet %d is correct", i), func() {
				checkMsg(t, msg, pub, topoProvider.Get().IFInfoMap)
			})
		}
	})
}

type msg struct {
	pkt *snet.SCIONPacket
	ov  *overlay.OverlayAddr
}

func checkMsg(t *testing.T, msg msg, pub common.RawBytes, infos topology.IfInfoMap) {
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
		err = pseg.VerifyASEntry(context.Background(), segVerifier(pub), pseg.MaxAEIdx())
		SoMsg("err", err, ShouldBeNil)
	})
	Convey("Beacon on correct interface", func() {
		hopF, err := msg.pkt.Path.GetHopField(msg.pkt.Path.HopOff)
		xtest.FailOnErr(t, err)
		bHopF, err := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField()
		xtest.FailOnErr(t, err)
		SoMsg("Egress", hopF.ConsEgress, ShouldEqual, bHopF.ConsEgress)
		brAddr := infos[hopF.ConsEgress].InternalAddrs
		SoMsg("ov", msg.ov, ShouldResemble, brAddr.PublicOverlay(brAddr.Overlay))
	})
}

type segVerifier common.RawBytes

func (v segVerifier) Verify(_ context.Context, msg common.RawBytes, sign *proto.SignS) error {
	return scrypto.Verify(sign.SigInput(msg, false), sign.Signature,
		common.RawBytes(v), scrypto.Ed25519)
}
