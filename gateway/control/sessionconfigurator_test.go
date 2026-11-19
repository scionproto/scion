// Copyright 2020 Anapaya Systems
// Copyright 2026 SCION Association
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

package control_test

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/pathpol"
)

func TestSessionConfigurator(t *testing.T) {
	t.Run("calling run twice", func(t *testing.T) {
		sc := control.SessionConfigurator{
			SessionPolicies:       make(chan control.SessionPolicies),
			RoutingUpdates:        make(chan control.RemoteGateways),
			SessionConfigurations: make(chan []*control.SessionConfig),
		}
		go func() {
			assert.NoError(t, sc.Run(context.Background()))
		}()
		time.Sleep(50 * time.Millisecond)
		assert.Error(t, sc.Run(context.Background()))
	})
	t.Run("calling run after close", func(t *testing.T) {
		sc := control.SessionConfigurator{
			SessionPolicies:       make(chan control.SessionPolicies),
			RoutingUpdates:        make(chan control.RemoteGateways),
			SessionConfigurations: make(chan []*control.SessionConfig),
		}
		assert.NoError(t, sc.Close(context.Background()))
		assert.NoError(t, sc.Run(context.Background()))
	})
	t.Run("validation fails if no static updates channel", func(t *testing.T) {
		sc := control.SessionConfigurator{
			RoutingUpdates:        make(chan control.RemoteGateways),
			SessionConfigurations: make(chan []*control.SessionConfig),
		}
		assert.Error(t, sc.Run(context.Background()))
	})
	t.Run("validation fails if no routing updates channel", func(t *testing.T) {
		sc := control.SessionConfigurator{
			SessionPolicies:       make(chan control.SessionPolicies),
			SessionConfigurations: make(chan []*control.SessionConfig),
		}
		assert.Error(t, sc.Run(context.Background()))
	})
	t.Run("validation fails if no session config channel", func(t *testing.T) {
		sc := control.SessionConfigurator{
			SessionPolicies: make(chan control.SessionPolicies),
			RoutingUpdates:  make(chan control.RemoteGateways),
		}
		assert.Error(t, sc.Run(context.Background()))
	})
	t.Run("test Run", func(t *testing.T) {
		tpChan := make(chan control.SessionPolicies)
		ruChan := make(chan control.RemoteGateways)
		cfgChan := make(chan []*control.SessionConfig)
		sc := control.SessionConfigurator{
			SessionPolicies:       tpChan,
			RoutingUpdates:        ruChan,
			SessionConfigurations: cfgChan,
		}
		go func() {
			assert.NoError(t, sc.Run(context.Background()))
		}()

		routingUpdate := control.RemoteGateways{
			Gateways: map[addr.IA][]control.RemoteGateway{
				addr.MustParseIA("1-ff00:0:110"): {
					{
						Gateway: control.Gateway{
							Probe: mustParseUDPAddr(t, "10.0.1.1:25"),
						},
						Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
					},
					{
						Gateway: control.Gateway{
							Probe: mustParseUDPAddr(t, "10.0.1.2:25"),
						},
						Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
					},
				},
			},
		}
		sessionPolicies := control.SessionPolicies{
			{
				IA:             addr.MustParseIA("1-ff00:0:110"),
				ID:             42,
				TrafficMatcher: pktcls.CondTrue,
				PerfPolicy:     dummyPerfPolicy{},
				PathPolicy:     control.DefaultPathPolicy,
				PathCount:      control.DefaultPathCount,
				Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/24"),
			},
		}
		expectedConfig := []*control.SessionConfig{
			{
				ID:             0,
				PolicyID:       42,
				IA:             addr.MustParseIA("1-ff00:0:110"),
				TrafficMatcher: pktcls.CondTrue,
				PerfPolicy:     dummyPerfPolicy{},
				PathPolicy:     control.DefaultPathPolicy,
				PathCount:      control.DefaultPathCount,
				Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
				Gateway: control.Gateway{
					Probe: mustParseUDPAddr(t, "10.0.1.1:25"),
				},
			},
			{
				ID:             1,
				PolicyID:       42,
				IA:             addr.MustParseIA("1-ff00:0:110"),
				TrafficMatcher: pktcls.CondTrue,
				PerfPolicy:     dummyPerfPolicy{},
				PathPolicy:     control.DefaultPathPolicy,
				PathCount:      control.DefaultPathCount,
				Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
				Gateway: control.Gateway{
					Probe: mustParseUDPAddr(t, "10.0.1.2:25"),
				},
			},
		}

		select {
		case ruChan <- routingUpdate:
		case <-time.After(time.Second):
			t.Fatalf("write timed out")
		}
		select {
		case cfg := <-cfgChan:
			assert.Empty(t, cfg)
		case <-time.After(time.Second):
			t.Fatalf("config update not received")
		}

		select {
		case tpChan <- sessionPolicies:
		case <-time.After(time.Second):
			t.Fatalf("write timed out")
		}

		select {
		case cfg := <-cfgChan:
			assert.Equal(t, expectedConfig, cfg)
		case <-time.After(time.Second):
			t.Fatalf("config updated not received")
		}

		// check that sending same configuration again doesn't trigger a
		// reconfiguration.
		select {
		case ruChan <- routingUpdate:
		case <-time.After(time.Second):
			t.Fatalf("write timed out")
		}
		select {
		case tpChan <- sessionPolicies:
		case <-time.After(time.Second):
			t.Fatalf("write timed out")
		}
		assert.Empty(t, cfgChan)

		assert.NoError(t, sc.Close(context.Background()))
	})
}

func TestBuildSessionConfigs(t *testing.T) {
	gatewayPolicy := func(ia addr.IA, intfs []uint64) policies.PathPolicy {
		pol := control.NewPathPolForEnteringAS(ia, intfs)
		return pol
	}
	testCases := map[string]struct {
		SessionPolicies control.SessionPolicies
		RoutingUpdate   control.RemoteGateways
		Expected        []*control.SessionConfig
	}{
		"empty static": {
			SessionPolicies: nil,
			RoutingUpdate: control.RemoteGateways{
				Gateways: map[addr.IA][]control.RemoteGateway{
					addr.MustParseIA("1-ff00:0:110"): {
						{
							Gateway: control.Gateway{
								Probe: mustParseUDPAddr(t, "10.0.1.1:25"),
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
						},
						{
							Gateway: control.Gateway{
								Probe: mustParseUDPAddr(t, "10.0.1.2:25"),
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
						},
					},
				},
			},
			Expected: nil,
		},
		"empty dynamic": {
			SessionPolicies: control.SessionPolicies{
				{
					IA:             addr.MustParseIA("1-ff00:0:110"),
					ID:             42,
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      1,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.1.0.0/24")},
				},
			},
			Expected: nil,
		},
		"simple": {
			SessionPolicies: control.SessionPolicies{
				{
					IA:             addr.MustParseIA("1-ff00:0:110"),
					ID:             42,
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      1,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.1.0.0/24")},
				},
			},
			RoutingUpdate: control.RemoteGateways{
				Gateways: map[addr.IA][]control.RemoteGateway{
					addr.MustParseIA("1-ff00:0:110"): {
						{
							Gateway: control.Gateway{
								Probe: mustParseUDPAddr(t, "10.0.1.1:25"),
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
						},
						{
							Gateway: control.Gateway{
								Probe: mustParseUDPAddr(t, "10.0.1.2:25"),
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
						},
					},
				},
			},
			Expected: []*control.SessionConfig{
				{
					ID:             0,
					PolicyID:       42,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      control.DefaultPathCount,
					Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
					Gateway: control.Gateway{
						Probe: mustParseUDPAddr(t, "10.0.1.1:25"),
					},
				},
				{
					ID:             1,
					PolicyID:       42,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      control.DefaultPathCount,
					Prefixes:       xtest.MustParseCIDRs(t, "10.1.0.0/24", "10.2.0.0/24"),
					Gateway: control.Gateway{
						Probe: mustParseUDPAddr(t, "10.0.1.2:25"),
					},
				},
			},
		},
		"complex": {
			SessionPolicies: control.SessionPolicies{
				{
					IA:             addr.MustParseIA("1-ff00:0:110"),
					ID:             1,
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      control.DefaultPathCount,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.1.0.0/24")},
				},
				{
					IA:             addr.MustParseIA("1-ff00:0:110"),
					ID:             2,
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     &pathpol.Policy{Name: "pol2"},
					PathCount:      control.DefaultPathCount,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.1.0.0/24")},
				},
				{
					IA:             addr.MustParseIA("1-ff00:0:110"),
					ID:             3,
					TrafficMatcher: pktcls.CondFalse,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     &pathpol.Policy{Name: "pol2"},
					PathCount:      control.DefaultPathCount,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.1.0.0/24")},
				},
				{
					IA:             addr.MustParseIA("1-ff00:0:111"),
					ID:             1,
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     control.DefaultPathPolicy,
					PathCount:      control.DefaultPathCount,
					Prefixes:       []*net.IPNet{xtest.MustParseCIDR(t, "10.25.0.0/24")},
				},
			},
			RoutingUpdate: control.RemoteGateways{
				Gateways: map[addr.IA][]control.RemoteGateway{
					addr.MustParseIA("1-ff00:0:110"): {
						{
							Gateway: control.Gateway{
								Probe:      mustParseUDPAddr(t, "10.0.1.1:25"),
								Interfaces: []uint64{40, 4},
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.40.0.0/24", "10.4.0.0/24"),
						},
						{
							Gateway: control.Gateway{
								Probe:      mustParseUDPAddr(t, "10.0.1.2:25"),
								Interfaces: []uint64{13, 37},
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.13.0.0/24", "10.37.0.0/24"),
						},
					},
					addr.MustParseIA("1-ff00:0:111"): {
						{
							Gateway: control.Gateway{
								Probe:      mustParseUDPAddr(t, "10.6.20.1:404"),
								Interfaces: []uint64{1},
							},
							Prefixes: xtest.MustParseCIDRs(t, "10.21.0.0/24"),
						},
					},
				},
			},
			Expected: []*control.SessionConfig{
				{
					ID:             0,
					PolicyID:       1,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"),
						[]uint64{40, 4}),
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.40.0.0/24", "10.4.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.1:25"),
						Interfaces: []uint64{40, 4},
					},
				},
				{
					ID:             1,
					PolicyID:       1,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"),
						[]uint64{13, 37}),
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.13.0.0/24", "10.37.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.2:25"),
						Interfaces: []uint64{13, 37},
					},
				},
				{
					ID:             2,
					PolicyID:       2,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: control.ConjunctionPathPol{
						Pol1: &pathpol.Policy{Name: "pol2"},
						Pol2: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"),
							[]uint64{40, 4}),
					},
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.40.0.0/24", "10.4.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.1:25"),
						Interfaces: []uint64{40, 4},
					},
				},
				{
					ID:             3,
					PolicyID:       2,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: control.ConjunctionPathPol{
						Pol1: &pathpol.Policy{Name: "pol2"},
						Pol2: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"), []uint64{13, 37}),
					},
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.13.0.0/24", "10.37.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.2:25"),
						Interfaces: []uint64{13, 37},
					},
				},
				{
					ID:             4,
					PolicyID:       3,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondFalse,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: control.ConjunctionPathPol{
						Pol1: &pathpol.Policy{Name: "pol2"},
						Pol2: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"), []uint64{40, 4}),
					},
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.40.0.0/24", "10.4.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.1:25"),
						Interfaces: []uint64{40, 4},
					},
				},
				{
					ID:             5,
					PolicyID:       3,
					IA:             addr.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondFalse,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy: control.ConjunctionPathPol{
						Pol1: &pathpol.Policy{Name: "pol2"},
						Pol2: gatewayPolicy(addr.MustParseIA("1-ff00:0:110"), []uint64{13, 37}),
					},
					PathCount: control.DefaultPathCount,
					Prefixes: xtest.MustParseCIDRs(t,
						"10.1.0.0/24", "10.13.0.0/24", "10.37.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.0.1.2:25"),
						Interfaces: []uint64{13, 37},
					},
				},
				{
					ID:             6,
					PolicyID:       1,
					IA:             addr.MustParseIA("1-ff00:0:111"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     dummyPerfPolicy{},
					PathPolicy:     gatewayPolicy(addr.MustParseIA("1-ff00:0:111"), []uint64{1}),
					PathCount:      control.DefaultPathCount,
					Prefixes:       xtest.MustParseCIDRs(t, "10.25.0.0/24", "10.21.0.0/24"),
					Gateway: control.Gateway{
						Probe:      mustParseUDPAddr(t, "10.6.20.1:404"),
						Interfaces: []uint64{1},
					},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfgs, err := control.BuildSessionConfigs(tc.SessionPolicies, tc.RoutingUpdate)
			assert.Equal(t, tc.Expected, cfgs)
			assert.NoError(t, err)
		})
	}
}

func TestConjuctionPolicy(t *testing.T) {
	mustSeqPol := func(seq string) policies.PathPolicy {
		s, err := pathpol.NewSequence(seq)
		require.NoError(t, err)
		return &pathpol.Policy{Sequence: s}
	}
	testCases := map[string]struct {
		Pol1, Pol2    policies.PathPolicy
		InputPaths    []snet.Path
		AcceptedPaths []snet.Path
		RejectedPaths []snet.Path
	}{
		"reject all Pol1": {
			Pol1: control.DefaultPathPolicy,
			Pol2: denyAllPathPolicy{},
			InputPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			AcceptedPaths: nil,
			RejectedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
		},
		"reject all Pol2": {
			Pol1: control.DefaultPathPolicy,
			Pol2: denyAllPathPolicy{},
			InputPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			AcceptedPaths: nil,
			RejectedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
		},
		"accept all": {
			Pol1: control.DefaultPathPolicy,
			Pol2: control.DefaultPathPolicy,
			InputPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			AcceptedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			RejectedPaths: nil,
		},
		"allow subset": {
			Pol1: mustSeqPol("0* 2-ff00:0:210 0*"),
			Pol2: mustSeqPol("0* 1-ff00:0:110#1"),
			InputPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("2-ff00:0:210"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("2-ff00:0:210"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 2},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("3-ff00:0:310"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			AcceptedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("2-ff00:0:210"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			RejectedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("2-ff00:0:210"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 2},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("3-ff00:0:310"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			pol := control.ConjunctionPathPol{Pol1: tc.Pol1, Pol2: tc.Pol2}
			acceptedPaths := pol.Filter(tc.InputPaths)
			rejectedPaths := make([]snet.Path, 0, len(tc.InputPaths)-len(acceptedPaths))
			for _, p := range tc.InputPaths {
				accepted := false
				for _, op := range acceptedPaths {
					accepted = accepted || p.Metadata().Fingerprint() == op.Metadata().Fingerprint()
				}
				if !accepted {
					rejectedPaths = append(rejectedPaths, p)
				}
			}
			assert.ElementsMatch(t, tc.AcceptedPaths, acceptedPaths)
			assert.ElementsMatch(t, tc.RejectedPaths, rejectedPaths)
		})
	}
}

func TestNewPathPolForEnteringAS(t *testing.T) {
	testCases := map[string]struct {
		Interfaces    []uint64
		IA            addr.IA
		AcceptedPaths []snet.Path
		RejectedPaths []snet.Path
	}{
		"empty interfaces": {
			Interfaces: []uint64{},
			IA:         addr.MustParseIA("1-ff00:0:110"),
			AcceptedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
		},
		"single interface": {
			Interfaces: []uint64{1},
			IA:         addr.MustParseIA("1-ff00:0:110"),
			AcceptedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
			},
			RejectedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:111"), ID: 25},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 2},
						},
					},
				},
			},
		},
		"multi interface": {
			Interfaces: []uint64{1, 2, 3, 4},
			IA:         addr.MustParseIA("1-ff00:0:110"),
			AcceptedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 2},
						},
					},
				},
			},
			RejectedPaths: []snet.Path{
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
						},
					},
				},
				path.Path{
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{
							{IA: addr.MustParseIA("1-ff00:0:111"), ID: 25},
							{IA: addr.MustParseIA("1-ff00:0:110"), ID: 1},
							{IA: addr.MustParseIA("1-ff00:0:112"), ID: 2},
						},
					},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pol := control.NewPathPolForEnteringAS(tc.IA, tc.Interfaces)
			assert.ElementsMatch(t, tc.AcceptedPaths, pol.Filter(tc.AcceptedPaths))
			assert.Empty(t, pol.Filter(tc.RejectedPaths))
		})
	}
}

func mustParseUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()

	h, rp, err := net.SplitHostPort(s)
	require.NoError(t, err)
	ip := net.ParseIP(h)
	if ip == nil {
		t.Fatalf("empty IP specified")
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	p, err := strconv.Atoi(rp)
	require.NoError(t, err)
	return &net.UDPAddr{IP: ip, Port: p}
}

type denyAllPathPolicy struct{}

func (denyAllPathPolicy) Filter(s []snet.Path) []snet.Path { return nil }

type dummyPerfPolicy struct{}

func (dummyPerfPolicy) Better(_, _ *policies.Stats) bool {
	return false
}

func voicePolicy(ia addr.IA) control.SessionPolicy {
	return control.SessionPolicy{
		IA:             ia,
		ID:             1,
		Name:           "voice",
		TrafficMatcher: pktcls.CondTrue,
		PerfPolicy:     dummyPerfPolicy{},
		PathPolicy:     control.DefaultPathPolicy,
		PathCount:      1,
	}
}

func testGateways(t *testing.T, n int) []control.RemoteGateway {
	t.Helper()
	result := make([]control.RemoteGateway, 0, n)
	for i := range n {
		result = append(result, control.RemoteGateway{Gateway: control.Gateway{
			Control: mustParseUDPAddr(t, fmt.Sprintf("10.0.%d.%d:30256", i/256, i%256)),
		}})
	}
	return result
}

func buildConfigs(policy control.SessionPolicy,
	gateways []control.RemoteGateway) ([]*control.SessionConfig, error) {

	return control.BuildSessionConfigs(control.SessionPolicies{policy},
		remoteGateways(policy.IA, gateways))
}

func TestBuildSessionConfigsStableIDs(t *testing.T) {
	policy := voicePolicy(addr.MustParseIA("1-ff00:0:110"))

	t.Run("gateway order does not change the IDs", func(t *testing.T) {
		forward := testGateways(t, 3)
		reverse := slices.Clone(forward)
		slices.Reverse(reverse)
		reverseCopy := slices.Clone(reverse)

		a, err := buildConfigs(policy, forward)
		require.NoError(t, err)
		b, err := buildConfigs(policy, reverse)
		require.NoError(t, err)
		require.Len(t, a, 3)
		assert.Equal(t, a, b)
		for i, cfg := range a {
			assert.Equal(t, uint8(i), cfg.ID)
		}
		assert.Equal(t, "voice", a[0].PolicyName)
		assert.Equal(t, reverseCopy, reverse)
	})

	t.Run("256 sessions", func(t *testing.T) {
		cfgs, err := buildConfigs(policy, testGateways(t, 256))
		require.NoError(t, err)
		require.Len(t, cfgs, 256)
		assert.Equal(t, uint8(255), cfgs[255].ID)
	})

	t.Run("257 sessions", func(t *testing.T) {
		cfgs, err := buildConfigs(policy, testGateways(t, 257))
		assert.ErrorContains(t, err, "too many sessions")
		assert.ErrorContains(t, err, "sessions=257")
		assert.ErrorContains(t, err, "isd_as=1-ff00:0:110")
		assert.ErrorContains(t, err, "session_policy_id=1")
		assert.Nil(t, cfgs)
	})

	second := policy
	second.ID = 2
	other := addr.MustParseIA("1-ff00:0:111")
	twoPolicies := control.SessionPolicies{policy, second}

	t.Run("two session policies give 256 sessions", func(t *testing.T) {
		cfgs, err := control.BuildSessionConfigs(twoPolicies, control.RemoteGateways{
			Gateways: map[addr.IA][]control.RemoteGateway{
				policy.IA: testGateways(t, 128),
				other:     testGateways(t, 300),
			},
		})
		require.NoError(t, err)
		require.Len(t, cfgs, 256)
		assert.Equal(t, 1, cfgs[127].PolicyID)
		assert.Equal(t, 2, cfgs[128].PolicyID)
		assert.Equal(t, uint8(255), cfgs[255].ID)
	})

	t.Run("two session policies give 258 sessions", func(t *testing.T) {
		cfgs, err := control.BuildSessionConfigs(twoPolicies,
			remoteGateways(policy.IA, testGateways(t, 129)))
		assert.ErrorContains(t, err, "sessions=258")
		assert.ErrorContains(t, err, "session_policy_id=2")
		assert.Nil(t, cfgs)
	})

	t.Run("the error names the first session policy above the limit", func(t *testing.T) {
		third := policy
		third.IA = other
		third.ID = 3
		cfgs, err := control.BuildSessionConfigs(
			control.SessionPolicies{policy, second, third},
			control.RemoteGateways{Gateways: map[addr.IA][]control.RemoteGateway{
				policy.IA: testGateways(t, 200),
				other:     testGateways(t, 100),
			}})
		assert.ErrorContains(t, err, "sessions=500")
		assert.ErrorContains(t, err, "isd_as=1-ff00:0:110")
		assert.ErrorContains(t, err, "session_policy_id=2")
		assert.Nil(t, cfgs)
	})

	ctrl := mustParseUDPAddr(t, "10.0.0.1:30256")
	probe1 := mustParseUDPAddr(t, "10.0.1.1:25")
	probe2 := mustParseUDPAddr(t, "10.0.1.2:25")
	data1 := mustParseUDPAddr(t, "10.0.2.1:30056")
	data2 := mustParseUDPAddr(t, "10.0.2.2:30056")
	orderCases := map[string][2]control.Gateway{
		"same control address, the probe address decides": {
			{Control: ctrl, Probe: probe1},
			{Control: ctrl, Probe: probe2},
		},
		"nil control address, the probe address decides": {
			{Probe: probe1},
			{Probe: probe2},
		},
		"same control and probe address, the data address decides": {
			{Control: ctrl, Probe: probe1, Data: data1},
			{Control: ctrl, Probe: probe1, Data: data2},
		},
	}
	for name, gws := range orderCases {
		t.Run(name, func(t *testing.T) { assertGatewayOrder(t, policy, gws[0], gws[1]) })
	}

	t.Run("same addresses, the sorted interfaces decide", func(t *testing.T) {
		first := control.Gateway{Control: ctrl, Probe: probe1, Data: data1,
			Interfaces: []uint64{5, 1}}
		second := control.Gateway{Control: ctrl, Probe: probe1, Data: data1,
			Interfaces: []uint64{3, 2}}
		assertGatewayOrder(t, policy, first, second)
		assert.Equal(t, []uint64{5, 1}, first.Interfaces)
		assert.Equal(t, []uint64{3, 2}, second.Interfaces)
	})
}

func assertGatewayOrder(t *testing.T, policy control.SessionPolicy,
	first, second control.Gateway) {

	t.Helper()
	a := control.RemoteGateway{Gateway: first}
	b := control.RemoteGateway{Gateway: second}
	for _, in := range [][]control.RemoteGateway{{a, b}, {b, a}} {
		cfgs, err := buildConfigs(policy, in)
		require.NoError(t, err)
		require.Len(t, cfgs, 2)
		assert.Equal(t, first, cfgs[0].Gateway)
		assert.Equal(t, second, cfgs[1].Gateway)
	}
}

func TestDiffSessionPoliciesOrder(t *testing.T) {
	ia := addr.MustParseIA("1-ff00:0:110")
	voice := control.SessionPolicy{
		IA:             ia,
		ID:             1,
		TrafficMatcher: mustCond(t, "dscp=0x2e"),
		PerfPolicy:     control.DefaultPerfPolicy,
		PathPolicy:     control.DefaultPathPolicy,
		PathCount:      1,
	}
	rest := voice
	rest.ID = 2
	rest.TrafficMatcher = pktcls.CondTrue

	a := control.SessionPolicies{voice, rest}
	assert.True(t, control.DiffSessionPolicies(a, control.SessionPolicies{rest, voice}))
	assert.False(t, control.DiffSessionPolicies(a, control.SessionPolicies{voice, rest}))

	renamed := voice
	renamed.Name = "voip"
	assert.True(t, control.DiffSessionPolicies(a, control.SessionPolicies{renamed, rest}))

	moved := voice
	moved.IA = addr.MustParseIA("1-ff00:0:111")
	assert.True(t, control.DiffSessionPolicies(control.SessionPolicies{voice},
		control.SessionPolicies{moved}))

	assert.True(t, control.DiffSessionPolicies(control.SessionPolicies{voice}, a))
	assert.True(t, control.DiffSessionPolicies(a, control.SessionPolicies{voice}))
}

func remoteGateways(ia addr.IA, gateways []control.RemoteGateway) control.RemoteGateways {
	return control.RemoteGateways{Gateways: map[addr.IA][]control.RemoteGateway{ia: gateways}}
}
