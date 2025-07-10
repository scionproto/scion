// Copyright 2019 Anapaya Systems
// Copyright 2025 SCION Association
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
	"strings"
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
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/discovery"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

const (
	IA_1_ff00_0_110 = "testdata/big/ASff00_0_110.json"
	IA_1_ff00_0_120 = "testdata/big/ASff00_0_120.json"
	IA_1_ff00_0_121 = "testdata/big/ASff00_0_121.json"
	IA_3_ff00_0_310 = "testdata/big/ASff00_0_310.json"
)

func TestPropagatorRunNonCore(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	beacons := [][]uint16{
		{graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
	}

	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoNonCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(childLinkTypeFilter)
		},
		Tick:                beaconing.NewTick(time.Hour),
		Provider:            provider,
		AllowTransitTraffic: true,
	}
	g := graph.NewDefaultGraph(mctrl)
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(1).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)

	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Times(1).DoAndReturn(

		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(3).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)

			return sender, nil
		},
	)
	p.Run(context.Background())
	// Check that no beacons are sent, since the period has not passed yet.
	p.Run(context.Background())
}

func TestPropagatorRunCore(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	beacons := [][]uint16{
		{graph.If_120_A_110_X},
		{graph.If_130_B_120_A, graph.If_120_A_110_X},
	}

	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(coreLinkTypeFilter)
		},
		Tick:     beaconing.NewTick(time.Hour),
		Provider: provider,
	}
	g := graph.NewDefaultGraph(mctrl)
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(2).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)

	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), graph.If_110_X_210_X,
		gomock.Any()).DoAndReturn(
		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)
			return sender, nil
		},
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), graph.If_110_X_130_A,
		gomock.Any()).DoAndReturn(
		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)
			return sender, nil
		},
	)
	p.Run(context.Background())
	// Check that no beacons are sent, since the period has not passed yet.
	p.Run(context.Background())
}

func TestPropagatorFastRecovery(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	beacons := [][]uint16{
		{graph.If_120_A_110_X},
		{graph.If_130_B_120_A, graph.If_120_A_110_X},
	}
	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	sender := mock_beaconing.NewMockSender(mctrl)

	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(coreLinkTypeFilter)
		},
		Tick:                beaconing.NewTick(2 * time.Second),
		Provider:            provider,
		AllowTransitTraffic: true,
	}

	g := graph.NewDefaultGraph(mctrl)
	// We call run 4 times in this test, since the interface to 1-ff00:0:120
	// will never be beaconed on, because the beacons are filtered for loops.
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(4).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			return []beacon.Beacon{testBeacon(g, beacons[0])}, nil
		},
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Times(5).Return(sender, nil)

	// 1. Initial run where one beacon fails to send. -> 2 calls
	// 2. Second run where the beacon is delivered. -> 1 call
	// 3. Run where no beacon is sent. -> no call
	// 4. Run where beacons are sent on all interfaces. -> 2 calls
	first := sender.EXPECT().Send(gomock.Any(), gomock.Any())
	first.Return(serrors.New("fail"))

	sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(4).Return(nil)
	sender.EXPECT().Close().Times(5)

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
}

func TestPropagatorTransitTraffic(t *testing.T) {
	// The graph without peering links looks as follows:
	// 411 123
	// |   |
	// 410 121 122     111   211
	//   \    \ |      /     /
	//   310---120---110---210
	//   /      |
	// 311     510

	var tests = []struct {
		name                string
		topoFile            string
		filter              func(*ifstate.Interface) bool
		beacons             [][]uint16
		ifIDs               []uint16
		filteredIfIDs       []uint16
		allowTransitTraffic bool
	}{
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic allowed",
				"propagation expected from 1-ff00:0:110 to 2-ff00:0:210"}, ","),
			topoFile: IA_1_ff00_0_110,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_410_X_310_X, graph.If_310_X_120_X, graph.If_120_X_110_X},
				{graph.If_510_X_120_X, graph.If_120_X_110_X},
			},
			ifIDs:               []uint16{graph.If_110_X_210_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: true,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic allowed",
				"propagation expected from 1-ff00:0:120 to 3-ff00:0:310 and 5-ff00:0:510"}, ","),
			topoFile: IA_1_ff00_0_120,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_210_X_110_X, graph.If_110_X_120_X},
			},
			ifIDs:               []uint16{graph.If_120_X_310_X, graph.If_120_X_510_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: true,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic not allowed",
				"propagation not expected from 1-ff00:0:110"}, ","),
			topoFile: IA_1_ff00_0_110,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_410_X_310_X, graph.If_310_X_120_X, graph.If_120_X_110_X},
				{graph.If_510_X_120_X, graph.If_120_X_110_X},
			},
			ifIDs:               []uint16{},
			filteredIfIDs:       []uint16{graph.If_110_X_210_X},
			allowTransitTraffic: false,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic not allowed",
				"propagation not expected from 3-ff00:0:310"}, ","),
			topoFile: IA_3_ff00_0_310,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_410_X_310_X},
			},
			ifIDs:               []uint16{},
			filteredIfIDs:       []uint16{graph.If_310_X_120_X},
			allowTransitTraffic: false,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic not allowed",
				"propagation expected from 1-ff00:0:120 to 1-ff00:0:110",
				"propagation not expected from 1-ff00:0:120 to 5-ff00:0:510"}, ","),
			topoFile: IA_1_ff00_0_120,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_410_X_310_X, graph.If_310_X_120_X},
			},
			ifIDs:               []uint16{graph.If_120_X_110_X},
			filteredIfIDs:       []uint16{graph.If_120_X_510_X},
			allowTransitTraffic: false,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic not allowed",
				"propagation expected from 1-ff00:0:110 to 2-ff00:0:210"}, ","),
			topoFile: IA_1_ff00_0_110,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_120_X_110_X},
			},
			ifIDs:               []uint16{graph.If_110_X_210_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: false,
		},
		{
			name: strings.Join([]string{"Core beaconing",
				"transit traffic not allowed",
				"propagation expected from 1-ff00:0:120 to 3-ff00:0:310 and 5-ff00:0:510"}, ","),
			topoFile: IA_1_ff00_0_120,
			filter:   coreLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_110_X_120_X},
			},
			ifIDs:               []uint16{graph.If_120_X_310_X, graph.If_120_X_510_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: false,
		},
		{
			name: strings.Join([]string{"Intra-ISD beaconing",
				"transit traffic allowed",
				"propagation expected from 1-ff00:0:121 to 1-ff00:0:123"}, ","),
			topoFile: IA_1_ff00_0_121,
			filter:   childLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_120_X_121_X},
			},
			ifIDs:               []uint16{graph.If_121_X_123_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: true,
		},
		{
			name: strings.Join([]string{"Intra-ISD beaconing",
				"transit traffic not allowed",
				"propagation expected from 1-ff00:0:121 to 1-ff00:0:123"}, ","),
			topoFile: IA_1_ff00_0_121,
			filter:   childLinkTypeFilter,
			beacons: [][]uint16{
				{graph.If_120_X_121_X},
			},
			ifIDs:               []uint16{graph.If_121_X_123_X},
			filteredIfIDs:       []uint16{},
			allowTransitTraffic: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runTransitTrafficTest(t, test.topoFile, test.filter, test.beacons,
				test.ifIDs, test.filteredIfIDs, test.allowTransitTraffic)
		})
	}
}

func runTransitTrafficTest(t *testing.T, topoFile string, filter func(*ifstate.Interface) bool,
	beacons [][]uint16, ifIDs, filteredIfIDs []uint16, allowTransitTraffic bool) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoFile)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:         topo.IA(),
			MTU:        topo.MTU(),
			SignerGen:  testSignerGen{Signers: []trust.Signer{testSigner(t, priv, topo.IA())}},
			Intfs:      intfs,
			MAC:        macFactory,
			MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(filter)
		},
		Tick:                beaconing.NewTick(time.Hour),
		Provider:            provider,
		AllowTransitTraffic: allowTransitTraffic,
	}
	g := graph.NewFromDescription(mctrl, graph.BigGraphDescription)

	// Provider still provides all beacons as it doesn't know anything about their destination
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(1).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)

	if len(ifIDs) == 0 {
		senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any()).Times(0)
	} else {
		for _, ifID := range ifIDs {
			senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), ifID,
				gomock.Any()).Times(1).DoAndReturn(
				func(_ context.Context, _ addr.IA, egIfID uint16,
					nextHop *net.UDPAddr,
				) (beaconing.Sender, error) {
					sender := mock_beaconing.NewMockSender(mctrl)
					sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(len(beacons)).DoAndReturn(
						func(ctx context.Context, b *seg.PathSegment) error {
							validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
							return nil
						},
					)
					sender.EXPECT().Close().Times(1)
					return sender, nil
				},
			)
		}
		for _, filteredIfID := range filteredIfIDs {
			senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(),
				filteredIfID, gomock.Any()).Times(0)
		}
	}

	p.Run(context.Background())
}

func childLinkTypeFilter(intf *ifstate.Interface) bool {
	return intf.TopoInfo().LinkType == topology.Child
}

func coreLinkTypeFilter(intf *ifstate.Interface) bool {
	return intf.TopoInfo().LinkType == topology.Core
}

func validateSend(
	ctx context.Context,
	t *testing.T,
	b *seg.PathSegment,
	egIfID uint16,
	nextHop *net.UDPAddr,
	pub crypto.PublicKey,
	topo topology.Topology,
) {
	// Check the beacon is valid and verifiable.
	assert.NoError(t, b.Validate(seg.ValidateBeacon))
	assert.NoError(t, b.VerifyASEntry(ctx,
		segVerifier{pubKey: pub}, b.MaxIdx()))
	// Extract the hop field from the current AS entry to compare.
	hopF := b.ASEntries[b.MaxIdx()].HopEntry.HopField
	// Check the interface matches.
	assert.Equal(t, hopF.ConsEgress, egIfID)
	// Check that the beacon is sent to the correct border router.
	br := net.UDPAddrFromAddrPort(interfaceInfos(topo)[egIfID].InternalAddr)
	assert.Equal(t, br, nextHop)
}
