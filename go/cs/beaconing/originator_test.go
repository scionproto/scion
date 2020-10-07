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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

const (
	topoCore    = "testdata/topology-core.json"
	topoNonCore = "testdata/topology.json"
)

func TestOriginatorRun(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, topoCore)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
	signer := testSigner(t, priv, topoProvider.Get().IA())
	t.Run("run originates ifid packets on all active interfaces", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		sender := mock_beaconing.NewMockBeaconSender(mctrl)
		o := Originator{
			Extender: &DefaultExtender{
				IA:         topoProvider.Get().IA(),
				MTU:        topoProvider.Get().MTU(),
				Signer:     signer,
				Intfs:      intfs,
				MAC:        func() hash.Hash { return mac },
				MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
				StaticInfo: func() *StaticInfoCfg { return nil },
			},
			BeaconSender: sender,
			IA:           topoProvider.Get().IA(),
			Signer:       signer,
			Intfs:        intfs,
			Tick:         NewTick(time.Hour),
		}

		require.NoError(t, err)

		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Times(4).DoAndReturn(

			func(_ context.Context, beacon *seg.PathSegment, dst addr.IA, egress common.IFIDType,
				nextHop *net.UDPAddr) error {

				// Check the beacon is valid and verifiable.
				assert.NoError(t, beacon.Validate(seg.ValidateBeacon))
				assert.NoError(t, beacon.VerifyASEntry(context.Background(),
					segVerifier{pubKey: pub}, beacon.MaxIdx()))

				// Extract the hop field from the current AS entry to compare.
				hopF := beacon.ASEntries[beacon.MaxIdx()].HopEntry.HopField
				// Check the interface matches.
				assert.Equal(t, hopF.ConsEgress, uint16(egress))
				// Check that the beacon is sent to the correct border router.
				br := topoProvider.Get().IFInfoMap()[egress].InternalAddr
				assert.Equal(t, br, nextHop)
				return nil
			},
		)

		// Start beacon messages.
		o.Run(nil)
		// The second run should not cause any beacons to originate.
		o.Run(nil)
	})
	t.Run("Fast recovery", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		sender := mock_beaconing.NewMockBeaconSender(mctrl)

		o := Originator{
			Extender: &DefaultExtender{
				IA:         topoProvider.Get().IA(),
				MTU:        topoProvider.Get().MTU(),
				Signer:     signer,
				Intfs:      intfs,
				MAC:        func() hash.Hash { return mac },
				MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
				StaticInfo: func() *StaticInfoCfg { return nil },
			},
			BeaconSender: sender,
			IA:           topoProvider.Get().IA(),
			Signer:       signer,
			Intfs:        intfs,
			Tick:         NewTick(2 * time.Second),
		}

		// 1. Initial run where one beacon fails to send. -> 4 calls
		// 2. Second run where the beacon is delivered. -> 1 call
		// 3. Run where no beacon is sent. -> no call
		// 4. Run where beacons are sent on all interfaces. -> 4 calls

		first := sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any())
		first.Return(serrors.New("fail"))

		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Times(8).Return(nil)
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

type segVerifier struct {
	pubKey crypto.PublicKey
}

func (v segVerifier) Verify(_ context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	return signed.Verify(signedMsg, v.pubKey, associatedData...)
}
