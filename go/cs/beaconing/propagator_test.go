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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestPropagatorRun(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	type test struct {
		name     string
		expected int
		core     bool
	}
	topoFile := map[bool]string{false: topoNonCore, true: topoCore}
	// The beacons to propagate for the non-core and core tests.
	beacons := map[bool][][]common.IFIDType{
		false: {
			{graph.If_120_X_111_B},
			{graph.If_130_B_120_A, graph.If_120_X_111_B},
			{graph.If_130_B_120_A, graph.If_120_X_111_B},
		},
		true: {
			{graph.If_120_A_110_X},
			{graph.If_130_B_120_A, graph.If_120_A_110_X},
		},
	}
	tests := []test{
		{
			name:     "Non-core",
			expected: 3,
		},
		{
			name:     "Core",
			expected: 3,
			core:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topoProvider := itopotest.TopoProviderFromFile(t, topoFile[test.core])
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
			provider := mock_beaconing.NewMockBeaconProvider(mctrl)
			sender := mock_beaconing.NewMockBeaconSender(mctrl)

			p := Propagator{
				Extender: &DefaultExtender{
					IA:         topoProvider.Get().IA(),
					MTU:        topoProvider.Get().MTU(),
					Signer:     testSigner(t, priv, topoProvider.Get().IA()),
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
					StaticInfo: func() *StaticInfoCfg { return nil },
				},
				BeaconSender: sender,
				IA:           topoProvider.Get().IA(),
				Signer:       testSigner(t, priv, topoProvider.Get().IA()),
				Intfs:        intfs,
				Tick:         NewTick(time.Hour),
				Core:         test.core,
				Provider:     provider,
			}
			g := graph.NewDefaultGraph(mctrl)
			provider.EXPECT().BeaconsToPropagate(gomock.Any()).MaxTimes(2).DoAndReturn(
				func(_ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, len(beacons[test.core]))
					for _, desc := range beacons[test.core] {
						res <- testBeaconOrErr(g, desc)
					}
					close(res)
					return res, nil
				},
			)

			sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any()).Times(test.expected).DoAndReturn(
				func(_ context.Context, beacon *seg.PathSegment, dst addr.IA,
					egress common.IFIDType, nextHop *net.UDPAddr) error {
					// Check the beacon is valid and verifiable.
					assert.NoError(t, beacon.Validate(seg.ValidateBeacon))
					assert.NoError(t, beacon.VerifyASEntry(context.Background(),
						segVerifier{pubKey: pub}, beacon.MaxIdx()))

					// Extract the hop field from the current AS entry to compare.
					hopF := beacon.ASEntries[beacon.MaxIdx()].HopEntry.HopField
					require.NoError(t, err)
					// Check the interface matches.
					assert.Equal(t, hopF.ConsEgress, uint16(egress))
					// Check that the beacon is sent to the correct router.
					br := topoProvider.Get().IFInfoMap()[egress].InternalAddr
					assert.Equal(t, br, nextHop)
					return nil
				},
			)
			p.Run(context.Background())
			// Check that no beacons are sent, since the period has not passed yet.
			p.Run(context.Background())
		})
	}
	t.Run("Fast recovery", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		topoProvider := itopotest.TopoProviderFromFile(t, topoCore)
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		provider := mock_beaconing.NewMockBeaconProvider(mctrl)
		sender := mock_beaconing.NewMockBeaconSender(mctrl)

		p := Propagator{
			Extender: &DefaultExtender{
				IA:         topoProvider.Get().IA(),
				MTU:        topoProvider.Get().MTU(),
				Signer:     testSigner(t, priv, topoProvider.Get().IA()),
				Intfs:      intfs,
				MAC:        macFactory,
				MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
				StaticInfo: func() *StaticInfoCfg { return nil },
			},
			BeaconSender: sender,
			IA:           topoProvider.Get().IA(),
			Signer:       testSigner(t, priv, topoProvider.Get().IA()),
			Intfs:        intfs,
			Tick:         NewTick(2 * time.Second),
			Core:         true,
			Provider:     provider,
		}

		g := graph.NewDefaultGraph(mctrl)
		// We call run 4 times in this test, since the interface to 1-ff00:0:120
		// will never be beaconed on, because the beacons are filtered for loops.
		provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(4).DoAndReturn(
			func(_ interface{}) (<-chan beacon.BeaconOrErr, error) {
				res := make(chan beacon.BeaconOrErr, 1)
				res <- testBeaconOrErr(g, beacons[true][0])
				close(res)
				return res, nil
			},
		)
		// 1. Initial run where one beacon fails to send. -> 2 calls
		// 2. Second run where the beacon is delivered. -> 1 call
		// 3. Run where no beacon is sent. -> no call
		// 4. Run where beacons are sent on all interfaces. -> 2 calls
		first := sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any())
		first.Return(serrors.New("fail"))

		sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Times(4).Return(nil)
		// Initial run. Two writes expected, one write will fail.
		p.Run(context.Background())
		time.Sleep(1 * time.Second)
		// Second run. One write expected.
		p.Run(context.Background())
		// Third run. No write expected
		p.Run(context.Background())
		time.Sleep(1 * time.Second)
		// Fourth run. Since period has passed, two writes are expected.
		p.Run(context.Background())
	})
}
