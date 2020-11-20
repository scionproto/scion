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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/mock_control"
)

func TestGatewayWatcherRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fetcherCounts := metrics.NewTestCounter()
	discoveryCounts := metrics.NewTestCounter()

	gateway1 := control.Gateway{Control: udp(t, "127.0.0.1:30256")}
	gateway2 := control.Gateway{Control: udp(t, "127.0.0.2:30256")}
	fetcher := mock_control.NewMockPrefixFetcher(ctrl)
	discoverer := mock_control.NewMockDiscoverer(ctrl)

	discoverer.EXPECT().Gateways(gomock.Any()).DoAndReturn(
		func(interface{}) ([]control.Gateway, error) {
			discoveryCounts.Add(1)
			return []control.Gateway{gateway1, gateway2}, nil
		},
	)

	fetcher.EXPECT().Prefixes(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ interface{}, g *net.UDPAddr) ([]*net.IPNet, error) {
			fetcherCounts.With("gateway", g.String()).Add(1)
			return nil, serrors.New("error")
		},
	)

	discoverer.EXPECT().Gateways(gomock.Any()).AnyTimes().DoAndReturn(
		func(interface{}) ([]control.Gateway, error) {
			discoveryCounts.Add(1)
			return []control.Gateway{gateway1}, nil
		},
	)

	w := control.GatewayWatcher{
		Discoverer:       discoverer,
		DiscoverInterval: 10 * time.Millisecond,
		Template: control.PrefixWatcherConfig{
			Consumer:     mock_control.NewMockPrefixConsumer(ctrl),
			Fetcher:      fetcher,
			PollInterval: 1 * time.Millisecond,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go w.Run(ctx)
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)

	g1 := fetcherCounts.With("gateway", gateway1.Control.String())
	g2 := fetcherCounts.With("gateway", gateway2.Control.String())

	// Use loose lower and upper bounds to avoid flakiness. The exact values is
	// not important. Important is, that gateway 1 still fetches prefixes after
	// the discoverer has dropped gateway 2. On the other hand, gateway 2 must
	// not fetch prefixes after the second discovery.
	assert.Greater(t, metrics.CounterValue(g1), 25.)
	assert.Less(t, metrics.CounterValue(g2), 15.)
	assert.GreaterOrEqual(t, metrics.CounterValue(g2), 5.)
	assert.Greater(t, metrics.CounterValue(discoveryCounts), 2.)
}

func TestPrefixWatcherRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fetcherCounts := metrics.NewTestCounter()
	consumerCounts := metrics.NewTestCounter()

	gateway := control.Gateway{Control: udp(t, "127.0.0.1:30256")}
	fetcher := mock_control.NewMockPrefixFetcher(ctrl)
	consumer := mock_control.NewMockPrefixConsumer(ctrl)

	// Initial error to check consumer is not called on error.
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).Return(nil, serrors.New("internal"))

	// First successful result has one more subnet, to check that consumer is
	// called with the up to date list.
	first := []*net.IPNet{cidr(t, "127.0.0.0/24"), cidr(t, "127.0.1.0/24"), cidr(t, "::/64")}
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).DoAndReturn(
		func(_, _ interface{}) ([]*net.IPNet, error) {
			fetcherCounts.Add(1)
			return first, nil
		},
	)
	consumer.EXPECT().Prefixes(gomock.Any(), gateway, first).Do(func(_, _, _ interface{}) {
		consumerCounts.Add(1)
	})

	afterwards := []*net.IPNet{cidr(t, "127.0.0.0/24"), cidr(t, "::/64")}
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).AnyTimes().DoAndReturn(
		func(_, _ interface{}) ([]*net.IPNet, error) {
			fetcherCounts.Add(1)
			return afterwards, nil
		},
	)
	consumer.EXPECT().Prefixes(gomock.Any(), gateway, afterwards).AnyTimes().Do(
		func(_, _, _ interface{}) {
			consumerCounts.Add(1)
		},
	)

	cfg := control.PrefixWatcherConfig{
		Consumer:     consumer,
		Fetcher:      fetcher,
		PollInterval: 1 * time.Millisecond,
	}
	w := control.NewPrefixWatcher(gateway, addr.IA{}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go w.Run(ctx)
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)

	// Use loose lower bounds to avoid flakiness. The exact values is not
	// important. Important is that multiple calls were made, and that the
	// consumer was notified for every fetch.
	assert.GreaterOrEqual(t, metrics.CounterValue(fetcherCounts), 5.)
	assert.GreaterOrEqual(t, metrics.CounterValue(consumerCounts), 5.)
	assert.Equal(t, metrics.CounterValue(fetcherCounts), metrics.CounterValue(consumerCounts))
}

func TestComputeDiff(t *testing.T) {
	testCases := map[string]struct {
		Previous []control.Gateway
		Next     []control.Gateway
		Expected control.Diff
	}{
		"all new": {
			Next: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
				{Control: udp(t, "127.0.0.2:30256"), Data: udp(t, "127.0.0.2:30056")},
			},
			Expected: control.Diff{
				Add: []control.Gateway{
					{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
					{Control: udp(t, "127.0.0.2:30256"), Data: udp(t, "127.0.0.2:30056")},
				},
			},
		},
		"one removed, one kept": {
			Previous: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
				{Control: udp(t, "127.0.0.2:30256"), Data: udp(t, "127.0.0.2:30056")},
			},
			Next: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
			},
			Expected: control.Diff{
				Remove: []control.Gateway{
					{Control: udp(t, "127.0.0.2:30256"), Data: udp(t, "127.0.0.2:30056")},
				},
			},
		},
		"change ctrl port": {
			Previous: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
			},
			Next: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30257"), Data: udp(t, "127.0.0.1:30056")},
			},
			Expected: control.Diff{
				Add: []control.Gateway{
					{Control: udp(t, "127.0.0.1:30257"), Data: udp(t, "127.0.0.1:30056")},
				},
				Remove: []control.Gateway{
					{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
				},
			},
		},
		"change data port": {
			Previous: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
			},
			Next: []control.Gateway{
				{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30057")},
			},
			Expected: control.Diff{
				Add: []control.Gateway{
					{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30057")},
				},
				Remove: []control.Gateway{
					{Control: udp(t, "127.0.0.1:30256"), Data: udp(t, "127.0.0.1:30056")},
				},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			diff := control.ComputeDiff(tc.Previous, tc.Next)
			assert.ElementsMatch(t, tc.Expected.Add, diff.Add)
			assert.ElementsMatch(t, tc.Expected.Remove, diff.Remove)
		})
	}
}

func udp(t *testing.T, addr string) *net.UDPAddr {
	u, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)
	return u

}

func cidr(t *testing.T, network string) *net.IPNet {
	_, n, err := net.ParseCIDR(network)
	require.NoError(t, err)
	return n
}
