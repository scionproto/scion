// Copyright 2020 Anapaya Systems
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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestEngineControllerRun(t *testing.T) {
	t.Run("double run", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		configurationUpdates := make(chan []*control.SessionConfig)
		routingTableSwapper := mock_control.NewMockRoutingTableSwapper(ctrl)
		routingTableFactory := mock_control.NewMockRoutingTableFactory(ctrl)
		engineFactory := mock_control.NewMockEngineFactory(ctrl)

		engineController := &control.EngineController{
			ConfigurationUpdates: configurationUpdates,
			RoutingTableSwapper:  routingTableSwapper,
			RoutingTableFactory:  routingTableFactory,
			EngineFactory:        engineFactory,
		}

		var bg errgroup.Group
		bg.Go(func() error {
			return engineController.Run(context.Background())
		})
		time.Sleep(50 * time.Millisecond)
		err := engineController.Run(context.Background())
		assert.Error(t, err)
		close(configurationUpdates)
		assert.NoError(t, bg.Wait())
	})

	t.Run("nil configuration updates", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		routingTableSwapper := mock_control.NewMockRoutingTableSwapper(ctrl)
		routingTableFactory := mock_control.NewMockRoutingTableFactory(ctrl)
		engineFactory := mock_control.NewMockEngineFactory(ctrl)

		engineController := &control.EngineController{
			RoutingTableSwapper: routingTableSwapper,
			RoutingTableFactory: routingTableFactory,
			EngineFactory:       engineFactory,
		}

		err := engineController.Run(context.Background())
		assert.Error(t, err)
	})

	t.Run("nil routing table swapper", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		configurationUpdates := make(chan []*control.SessionConfig)
		routingTableFactory := mock_control.NewMockRoutingTableFactory(ctrl)
		engineFactory := mock_control.NewMockEngineFactory(ctrl)

		engineController := &control.EngineController{
			ConfigurationUpdates: configurationUpdates,
			RoutingTableFactory:  routingTableFactory,
			EngineFactory:        engineFactory,
		}

		err := engineController.Run(context.Background())
		assert.Error(t, err)
	})

	t.Run("nil routing table factory", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		configurationUpdates := make(chan []*control.SessionConfig)
		routingTableSwapper := mock_control.NewMockRoutingTableSwapper(ctrl)
		engineFactory := mock_control.NewMockEngineFactory(ctrl)

		engineController := &control.EngineController{
			ConfigurationUpdates: configurationUpdates,
			RoutingTableSwapper:  routingTableSwapper,
			EngineFactory:        engineFactory,
		}

		err := engineController.Run(context.Background())
		assert.Error(t, err)
	})

	t.Run("nil engine factory", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		configurationUpdates := make(chan []*control.SessionConfig)
		routingTableSwapper := mock_control.NewMockRoutingTableSwapper(ctrl)
		routingTableFactory := mock_control.NewMockRoutingTableFactory(ctrl)

		engineController := &control.EngineController{
			ConfigurationUpdates: configurationUpdates,
			RoutingTableSwapper:  routingTableSwapper,
			RoutingTableFactory:  routingTableFactory,
		}

		err := engineController.Run(context.Background())
		assert.Error(t, err)
	})
}

func TestBuildRoutingChains(t *testing.T) {
	testCases := map[string]struct {
		Input          []*control.SessionConfig
		Chains         []*control.RoutingChain
		SessionMapping map[int][]uint8
	}{
		"nil": {
			Input:          nil,
			Chains:         nil,
			SessionMapping: nil,
		},
		"empty": {
			Input:          []*control.SessionConfig{},
			Chains:         nil,
			SessionMapping: nil,
		},
		"single": {
			Input: []*control.SessionConfig{
				{
					ID:             23,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.1.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.99.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:110"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {23},
			},
		},
		"single multi prefix": {
			Input: []*control.SessionConfig{
				{
					ID:             23,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.1.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:110"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {23},
			},
		},
		"single multi prefix multi traffic classes": {
			Input: []*control.SessionConfig{
				{
					ID:             21,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 42}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.1.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
				},
				{
					ID:             23,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.1.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      1,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 42}},
						},
						{ID: 2, Matcher: pktcls.CondTrue},
					},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {21},
				2: {23},
			},
		},
		"security with prefix pinning": {
			Input: []*control.SessionConfig{
				{
					ID:             100,
					PolicyID:       1,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1 and R1
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.1.0.0/16"),
				},
				{
					ID:             101,
					PolicyID:       1,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1 and R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.2:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.2.0.0/16"),
				},
				{
					ID:             102,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via (R1 or R2) and R1
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.1.0.0/16"),
				},
				{
					ID:             103,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via (R1 or R2) and R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.2:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.2.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      1,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
						{ID: 4, Matcher: pktcls.CondTrue},
					},
				},
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      2,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
						{ID: 5, Matcher: pktcls.CondTrue},
					},
				},
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.2.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      3,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
						{ID: 6, Matcher: pktcls.CondTrue},
					},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {100, 101},
				2: {100},
				3: {101},
				4: {102, 103},
				5: {102},
				6: {103},
			},
		},
		"traffic policy with prefix pinning": {
			Input: []*control.SessionConfig{
				{
					ID:             100,
					PolicyID:       1,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1 and R1
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.1.0.0/16"),
				},
				{
					ID:             101,
					PolicyID:       1,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1 and R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.2:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.2.0.0/16"),
				},
				{
					ID:             102,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via Any and R1
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.1.0.0/16"),
				},
				{
					ID:             103,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via Any and R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.2:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t,
						"10.98.0.0/16", "10.99.0.0/16", "10.2.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      1,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
					},
				},
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      2,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
					},
				},
				{
					RemoteIA: xtest.MustParseIA("1-ff00:0:110"),
					Prefixes: xtest.MustParseCIDRs(t, "10.2.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{
						{
							ID:      3,
							Matcher: &pktcls.CondIPv4{Predicate: &pktcls.IPv4MatchDSCP{DSCP: 1}},
						},
					},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {100, 101, 102, 103},
				2: {100, 102},
				3: {101, 103},
			},
		},
		"mixed prefixes": {
			Input: []*control.SessionConfig{
				{
					ID:             100,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1 and R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/16", "10.2.0.0/16"),
				},
				{
					ID:             101,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R1
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.2:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.1.0.0/16"),
				},
				{
					ID:             102,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy, // via R2
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.45.0.3:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.2.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:110"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.1.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
				},
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:110"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.2.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 2, Matcher: pktcls.CondTrue}},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {100, 101},
				2: {100, 102},
			},
		},
		"multi IA": {
			Input: []*control.SessionConfig{
				{
					ID:             23,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:110"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.1.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
				},
				{
					ID:             42,
					PolicyID:       0,
					IA:             xtest.MustParseIA("1-ff00:0:111"),
					TrafficMatcher: pktcls.CondTrue,
					PerfPolicy:     control.DefaultPerfPolicy,
					PathPolicy:     control.DefaultPathPolicy,
					Gateway: control.Gateway{
						Control: xtest.MustParseUDPAddr(t, "10.42.0.1:30256"),
					},
					Prefixes: xtest.MustParseCIDRs(t, "10.13.0.0/16", "10.14.0.0/16"),
				},
			},
			Chains: []*control.RoutingChain{
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:110"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.98.0.0/16", "10.99.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 1, Matcher: pktcls.CondTrue}},
				},
				{
					RemoteIA:        xtest.MustParseIA("1-ff00:0:111"),
					Prefixes:        xtest.MustParseCIDRs(t, "10.13.0.0/16", "10.14.0.0/16"),
					TrafficMatchers: []control.TrafficMatcher{{ID: 2, Matcher: pktcls.CondTrue}},
				},
			},
			SessionMapping: map[int][]uint8{
				1: {23},
				2: {42},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			chains, sm := control.BuildRoutingChains(tc.Input)
			assert.Equal(t, tc.Chains, chains)
			assert.Equal(t, tc.SessionMapping, sm)
		})
	}
}

type testPktWriter struct {
	ID uint8
}

func (_ testPktWriter) Write(gopacket.Packet) {}
