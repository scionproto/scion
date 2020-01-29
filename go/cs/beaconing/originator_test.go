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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)
	signer := testSigner(t, priv, topoProvider.Get().IA())
	t.Run("run originates ifid packets on all active interfaces", func(t *testing.T) {
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
		require.NoError(t, err)
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
					pkt: ipkt.(*snet.Packet),
					ov:  iov.(*net.UDPAddr),
				})
				return nil
			},
		)
		// Start beacon messages.
		o.Run(nil)
		for i, msg := range msgs {
			t.Run(fmt.Sprintf("Packet %d is correct", i), func(t *testing.T) {
				checkMsg(t, msg, pub, topoProvider.Get().IFInfoMap())
			})
		}
		// The second run should not cause any beacons to originate.
		o.Run(nil)
	})
	t.Run("Fast recovery", func(t *testing.T) {
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
		require.NoError(t, err)
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
	pkt *snet.Packet
	ov  *net.UDPAddr
}

func checkMsg(t *testing.T, msg msg, pub common.RawBytes, infos topology.IfInfoMap) {
	// Extract segment from the payload
	spld, err := ctrl.NewSignedPldFromRaw(msg.pkt.Payload.(common.RawBytes))
	require.NoError(t, err)
	pld, err := spld.UnsafePld()
	require.NoError(t, err)
	err = pld.Beacon.Parse()
	require.NoError(t, err)

	// Check the beacon is valid and verifiable.
	pseg := pld.Beacon.Segment
	assert.NoError(t, pseg.Validate(seg.ValidateBeacon))
	assert.NoError(t, pseg.VerifyASEntry(context.Background(), segVerifier(pub), pseg.MaxAEIdx()))

	// Extract the the first hop field from the constructed one hop path the
	// beacon is sent on. We want to make sure that the beacon is sent on the
	// correct egress interface.
	hopF, err := msg.pkt.Path.GetHopField(msg.pkt.Path.HopOff)
	require.NoError(t, err)
	// Extract the hop field from the current AS entry to compare.
	bHopF, err := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField()
	require.NoError(t, err)
	// Check the interface matches.
	assert.Equal(t, bHopF.ConsEgress, hopF.ConsEgress)
	// Check that the beacon is sent to the correct border router.
	assert.Equal(t, infos[hopF.ConsEgress].InternalAddr, msg.ov)
}

type segVerifier []byte

func (v segVerifier) Verify(_ context.Context, msg []byte, sign *proto.SignS) error {
	return scrypto.Verify(sign.SigInput(msg, false), sign.Signature, []byte(v), scrypto.Ed25519)
}
