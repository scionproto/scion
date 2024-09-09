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

package beaconing_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/beaconing/mock_beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

const (
	topoCore    = "testdata/topology-core.json"
	topoNonCore = "testdata/topology.json"
)

func TestOriginatorRun(t *testing.T) {
	topo, err := topology.FromJSONFile(topoCore)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
	signer := testSigner(t, priv, topo.IA())
	originationFilter := func(intf *ifstate.Interface) bool {
		topoInfo := intf.TopoInfo()
		if topoInfo.LinkType == topology.Core || topoInfo.LinkType == topology.Child {
			return true
		}
		return false
	}
	t.Run("run originates ifID packets on all active interfaces", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
		senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
		o := beaconing.Originator{
			Extender: &beaconing.DefaultExtender{
				IA:         topo.IA(),
				MTU:        topo.MTU(),
				SignerGen:  testSignerGen{Signers: []trust.Signer{signer}},
				Intfs:      intfs,
				MAC:        macFactory,
				MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
				StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
			},
			SenderFactory: senderFactory,
			IA:            topo.IA(),
			Signer:        signer,
			AllInterfaces: intfs,
			OriginationInterfaces: func() []*ifstate.Interface {
				return intfs.Filtered(originationFilter)
			},
			Tick: beaconing.NewTick(time.Hour),
		}

		require.NoError(t, err)

		senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Times(4).DoAndReturn(
			func(_ context.Context, dstIA addr.IA, egIfID uint16,
				nextHop *net.UDPAddr) (beaconing.Sender, error) {

				sender := mock_beaconing.NewMockSender(mctrl)
				sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
					func(_ context.Context, b *seg.PathSegment) error {
						// Check the beacon is valid and verifiable.
						assert.NoError(t, b.Validate(seg.ValidateBeacon))
						assert.NoError(t, b.VerifyASEntry(context.Background(),
							segVerifier{pubKey: pub}, b.MaxIdx()))
						// Extract the hop field from the current AS entry to compare.
						hopF := b.ASEntries[b.MaxIdx()].HopEntry.HopField
						// Check the interface matches.
						assert.Equal(t, hopF.ConsEgress, egIfID)
						// Check that the expected peering entry is there too.
						peering := b.ASEntries[b.MaxIdx()].PeerEntries[0]
						assert.Equal(t, peering.HopField.ConsIngress, uint16(4242))
						// Check that the beacon is sent to the correct border router.
						br := net.UDPAddrFromAddrPort(interfaceInfos(topo)[egIfID].InternalAddr)
						assert.Equal(t, br, nextHop)
						return nil
					},
				)
				sender.EXPECT().Close().Times(1)

				return sender, nil
			},
		)

		// Start beacon messages.
		o.Run(context.Background())
		// The second run should not cause any beacons to originate.
		o.Run(context.Background())
	})
	t.Run("Fast recovery", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
		senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
		sender := mock_beaconing.NewMockSender(mctrl)
		o := beaconing.Originator{
			Extender: &beaconing.DefaultExtender{
				IA:         topo.IA(),
				MTU:        topo.MTU(),
				SignerGen:  testSignerGen{Signers: []trust.Signer{signer}},
				Intfs:      intfs,
				MAC:        macFactory,
				MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
				StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
			},
			SenderFactory: senderFactory,
			IA:            topo.IA(),
			Signer:        signer,
			AllInterfaces: intfs,
			OriginationInterfaces: func() []*ifstate.Interface {
				return intfs.Filtered(originationFilter)
			},
			Tick: beaconing.NewTick(2 * time.Second),
		}

		senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Times(9).Return(sender, nil)

		// 1. Initial run where one beacon fails to send. -> 4 calls
		// 2. Second run where the beacon is delivered. -> 1 call
		// 3. Run where no beacon is sent. -> no call
		// 4. Run where beacons are sent on all interfaces. -> 4 calls

		sender.EXPECT().Send(
			gomock.Any(), gomock.Any(),
		).Return(serrors.New("fail"))
		sender.EXPECT().Send(
			gomock.Any(), gomock.Any(),
		).Times(8).Return(nil)
		sender.EXPECT().Close().Times(9)

		// Initial run. Two writes expected, one write will fail.
		o.Run(context.Background())
		time.Sleep(1 * time.Second)
		// Second run. One write expected.
		o.Run(context.Background())
		// Third run. No write expected
		o.Run(context.Background())
		time.Sleep(1 * time.Second)
		// Fourth run. Since period has passed, two writes are expected.
		o.Run(context.Background())
	})
}

type segVerifier struct {
	pubKey crypto.PublicKey
}

func (v segVerifier) Verify(_ context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	return signed.Verify(signedMsg, v.pubKey, associatedData...)
}
