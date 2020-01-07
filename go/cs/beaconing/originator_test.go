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
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
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
	topoProvider := itopotest.TopoProviderFromFile(t, topoCore)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := testSigner(t, priv, topoProvider.Get().IA())
	Convey("Run originates ifid packets on all active core and child interfaces", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		conn := mock_snet.NewMockPacketConn(mctrl)
		o, err := OriginatorConf{
			Config: ExtenderConf{
				MTU:           topoProvider.Get().MTU(),
				Signer:        signer,
				Intfs:         intfs,
				Mac:           mac,
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			},
			Period: time.Hour,
			BeaconSender: &onehop.BeaconSender{
				Sender: onehop.Sender{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Conn: conn,
					Addr: &net.UDPAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 4242,
					},
					MAC: mac,
				},
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
					ov:  iov.(*net.UDPAddr),
				})
				return nil
			},
		)
		// Start beacon messages.
		o.Run(nil)
		for i, msg := range msgs {
			Convey(fmt.Sprintf("Packet %d is correct", i), func() {
				checkMsg(t, msg, pub, topoProvider.Get().IFInfoMap())
			})
		}
		// The second run should not cause any beacons to originate.
		o.Run(nil)
	})
	Convey("Fast recovery", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		conn := mock_snet.NewMockPacketConn(mctrl)
		o, err := OriginatorConf{
			Config: ExtenderConf{
				MTU:           topoProvider.Get().MTU(),
				Signer:        signer,
				Intfs:         intfs,
				Mac:           mac,
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			},
			Period: 2 * time.Second,
			BeaconSender: &onehop.BeaconSender{
				Sender: onehop.Sender{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Conn: conn,
					Addr: &net.UDPAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 4242,
					},
					MAC: mac,
				},
			},
		}.New()
		xtest.FailOnErr(t, err)
		// Activate interfaces
		intfs.Get(42).Activate(84)
		intfs.Get(1129).Activate(82)

		// 1. Initial run where one beacon fails to send. -> 2 calls
		// 2. Second run where the beacon is delivered. -> 1 call
		// 3. Run where no beacon is sent. -> no call
		// 4. Run where beacons are sent on all interfaces. -> 2 calls
		first := conn.EXPECT().WriteTo(gomock.Any(), gomock.Any())
		first.Return(errors.New("fail"))
		conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).After(first).Times(4).Return(nil)
		// Initial run. Two writes expected, one write will fail.
		o.Run(nil)
		time.Sleep(1 * time.Second)
		// Second run. One write expected.
		o.Run(nil)
		// Third run. No write expected
		o.Run(nil)
		time.Sleep(1 * time.Second)
		// Fourth run. Since period has passed, two writes are expected.
		o.Run(nil)
	})
}

type msg struct {
	pkt *snet.SCIONPacket
	ov  *net.UDPAddr
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
		brAddr := infos[hopF.ConsEgress].InternalAddr
		SoMsg("ov", msg.ov, ShouldResemble, brAddr)
	})
}

type segVerifier []byte

func (v segVerifier) Verify(_ context.Context, msg []byte, sign *proto.SignS) error {
	return scrypto.Verify(sign.SigInput(msg, false), sign.Signature, []byte(v), scrypto.Ed25519)
}
