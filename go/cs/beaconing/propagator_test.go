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
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestPropagatorRun(t *testing.T) {
	macProp, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	macSender, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)

	type test struct {
		name     string
		inactive map[common.IFIDType]bool
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
	// The interfaces in the non-core and core topologies.
	allIntfs := map[bool]map[common.IFIDType]common.IFIDType{
		false: {
			graph.If_111_A_112_X: graph.If_112_X_111_A,
			graph.If_111_B_120_X: graph.If_120_X_111_B,
			graph.If_111_B_211_A: graph.If_211_A_111_B,
			graph.If_111_C_211_A: graph.If_211_A_111_C,
			graph.If_111_C_121_X: graph.If_121_X_111_C,
		},
		true: {
			graph.If_110_X_120_A: graph.If_120_A_110_X,
			graph.If_110_X_130_A: graph.If_130_A_110_X,
			graph.If_110_X_210_X: graph.If_210_X_110_X,
		},
	}
	tests := []test{
		{
			name:     "Non-core: All interfaces active",
			expected: 3,
		},
		{
			name:     "Non-core: One peer inactive",
			inactive: map[common.IFIDType]bool{graph.If_111_C_121_X: true},
			expected: 3,
		},
		{
			name: "Non-core: All peers inactive",
			inactive: map[common.IFIDType]bool{
				graph.If_111_C_121_X: true,
				graph.If_111_B_211_A: true,
				graph.If_111_C_211_A: true,
			},
			expected: 3,
		},
		{
			name:     "Non-core: Child interface inactive",
			inactive: map[common.IFIDType]bool{graph.If_111_A_112_X: true},
		},
		{
			name:     "Core: All interfaces active",
			expected: 3,
			core:     true,
		},
		{
			name:     "Core: 1-ff00:0:120 inactive",
			inactive: map[common.IFIDType]bool{graph.If_110_X_120_A: true},
			// Should not create beacon if ingress interface is down.
			expected: 0,
			core:     true,
		},
		{
			name:     "Core: 1-ff00:0:130 inactive",
			inactive: map[common.IFIDType]bool{graph.If_110_X_130_A: true},
			expected: 2,
			core:     true,
		},
		{
			name:     "Core: 2-ff00:0:210 inactive",
			inactive: map[common.IFIDType]bool{graph.If_110_X_210_X: true},
			expected: 1,
			core:     true,
		},
		{
			name: "Core: All inactive",
			inactive: map[common.IFIDType]bool{
				graph.If_110_X_120_A: true,
				graph.If_110_X_130_A: true,
				graph.If_110_X_210_X: true,
			},
			core: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topoProvider := itopotest.TopoProviderFromFile(t, topoFile[test.core])
			provider := mock_beaconing.NewMockBeaconProvider(mctrl)
			conn := mock_snet.NewMockPacketConn(mctrl)
			cfg := PropagatorConf{
				Config: ExtenderConf{
					Signer: testSigner(t, priv, topoProvider.Get().IA()),
					Mac:    macProp,
					Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
						ifstate.Config{}),
					MTU:           topoProvider.Get().MTU(),
					GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
				},
				Period:         time.Hour,
				BeaconProvider: provider,
				Core:           test.core,
				BeaconSender: &onehop.BeaconSender{
					Sender: onehop.Sender{
						IA:   topoProvider.Get().IA(),
						Conn: conn,
						Addr: &net.UDPAddr{
							IP:   net.ParseIP("127.0.0.1"),
							Port: 4242,
						},
						MAC: macSender,
					},
				},
			}
			p, err := cfg.New()
			require.NoError(t, err)
			for ifid, remote := range allIntfs[test.core] {
				if test.inactive[ifid] {
					continue
				}
				cfg.Config.Intfs.Get(ifid).Activate(remote)
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
			msgsMtx := sync.Mutex{}
			var msgs []msg
			conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Times(test.expected).DoAndReturn(
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
			p.Run(nil)
			for i, msg := range msgs {
				t.Run(fmt.Sprintf("Packet %d is correct", i), func(t *testing.T) {
					checkMsg(t, msg, pub, topoProvider.Get().IFInfoMap())
				})
			}
			// Check that no beacons are sent, since the period has not passed yet.
			p.Run(nil)
		})
	}
	t.Run("Fast recovery", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		topoProvider := itopotest.TopoProviderFromFile(t, topoCore)
		provider := mock_beaconing.NewMockBeaconProvider(mctrl)
		conn := mock_snet.NewMockPacketConn(mctrl)
		cfg := PropagatorConf{
			Config: ExtenderConf{
				Signer: testSigner(t, priv, topoProvider.Get().IA()),
				Mac:    macProp,
				Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
					ifstate.Config{}),
				MTU:           uint16(topoProvider.Get().MTU()),
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			},
			Period:         2 * time.Second,
			BeaconProvider: provider,
			Core:           true,
			BeaconSender: &onehop.BeaconSender{
				Sender: onehop.Sender{
					IA:   topoProvider.Get().IA(),
					Conn: conn,
					Addr: &net.UDPAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 4242,
					},
					MAC: macSender,
				},
			},
		}
		p, err := cfg.New()
		require.NoError(t, err)
		for ifid, remote := range allIntfs[true] {
			cfg.Config.Intfs.Get(ifid).Activate(remote)
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
		firstCall := conn.EXPECT().WriteTo(gomock.Any(), gomock.Any())
		firstCall.Return(errors.New("fail"))
		conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).After(firstCall).Times(4).Return(nil)
		// Initial run. Two writes expected, one write will fail.
		p.Run(nil)
		time.Sleep(1 * time.Second)
		// Second run. One write expected.
		p.Run(nil)
		// Third run. No write expected
		p.Run(nil)
		time.Sleep(1 * time.Second)
		// Fourth run. Since period has passed, two writes are expected.
		p.Run(nil)
	})
}
