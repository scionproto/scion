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
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
)

func TestGatewayWatcherRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fetcherCounts := metrics.NewTestCounter()
	discoveryCounts := metrics.NewTestCounter()
	remotes := metrics.NewTestGauge()

	gateway1 := control.Gateway{Control: udp(t, "127.0.0.1:30256")}
	gateway2 := control.Gateway{Control: udp(t, "127.0.0.2:30256")}
	fetcher := mock_control.NewMockPrefixFetcher(ctrl)
	fetcherFactory := mock_control.NewMockPrefixFetcherFactory(ctrl)
	discoverer := mock_control.NewMockDiscoverer(ctrl)

	fetcherFactory.EXPECT().NewPrefixFetcher(gomock.Any(), gomock.Any()).AnyTimes().Return(fetcher)
	fetcher.EXPECT().Close().AnyTimes().Return(nil)

	discoverer.EXPECT().Gateways(gomock.Any()).DoAndReturn(
		func(any) ([]control.Gateway, error) {
			discoveryCounts.Add(1)
			return []control.Gateway{gateway1, gateway2}, nil
		},
	)

	fetcher.EXPECT().Prefixes(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ any, g *net.UDPAddr) ([]*net.IPNet, error) {
			fetcherCounts.With("gateway", g.String()).Add(1)
			return nil, serrors.New("error")
		},
	)

	// we use super high values for the interval so that we can be certain that
	// periodicity never kicks in and only we are controlling when things run.
	w := control.GatewayWatcher{
		Discoverer:       discoverer,
		DiscoverInterval: 10 * time.Hour,
		Template: control.PrefixWatcherConfig{
			Consumer:       mock_control.NewMockPrefixConsumer(ctrl),
			FetcherFactory: fetcherFactory,
			PollInterval:   10 * time.Hour,
		},
		Metrics: control.GatewayWatcherMetrics{
			Remotes: remotes,
		},
	}

	// run initially
	remotes.Set(0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	var bg errgroup.Group
	bg.Go(func() error {
		return w.Run(ctx)
	})
	t.Cleanup(func() {
		assert.NoError(t, bg.Wait())
	})

	for {
		if metrics.GaugeValue(remotes) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	g1 := fetcherCounts.With("gateway", gateway1.Control.String())
	g2 := fetcherCounts.With("gateway", gateway2.Control.String())

	// fetching should have happened exactly once.
	assert.Equal(t, 1, int(metrics.CounterValue(g1)))
	assert.Equal(t, 1, int(metrics.CounterValue(g2)))
	assert.Equal(t, 1, int(metrics.CounterValue(discoveryCounts)))

	// now let's reset and remove one gateway, this time we only return gateway1
	discoverer.EXPECT().Gateways(gomock.Any()).DoAndReturn(
		func(any) ([]control.Gateway, error) {
			discoveryCounts.Add(1)
			return []control.Gateway{gateway1}, nil
		},
	)
	w.RunOnce(context.Background())
	ctx, cancel = context.WithCancel(context.Background())
	// nothing really checks the context except the run loop, so we can
	// immediately cancel and then it will run only once.
	cancel()
	assert.NoError(t, w.RunAllPrefixWatchersOnceForTest(ctx))

	assert.Equal(t, 2, int(metrics.CounterValue(g1)))
	assert.Equal(t, 1, int(metrics.CounterValue(g2)))
	assert.Equal(t, 2, int(metrics.CounterValue(discoveryCounts)))
}

func TestPrefixWatcherRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fetcherCounts := metrics.NewTestCounter()
	consumerCounts := metrics.NewTestCounter()

	gateway := control.Gateway{Control: udp(t, "127.0.0.1:30256")}
	fetcher := mock_control.NewMockPrefixFetcher(ctrl)
	fetcherFactory := mock_control.NewMockPrefixFetcherFactory(ctrl)
	consumer := mock_control.NewMockPrefixConsumer(ctrl)

	fetcherFactory.EXPECT().NewPrefixFetcher(gomock.Any(), gomock.Any()).AnyTimes().Return(fetcher)
	fetcher.EXPECT().Close().AnyTimes().Return(nil)

	// Initial error to check consumer is not called on error.
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).Return(nil, serrors.New("internal"))

	// First successful result has one more subnet, to check that consumer is
	// called with the up to date list.
	first := []*net.IPNet{cidr(t, "127.0.0.0/24"), cidr(t, "127.0.1.0/24"), cidr(t, "::/64")}
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).DoAndReturn(
		func(_, _ any) ([]*net.IPNet, error) {
			fetcherCounts.Add(1)
			return first, nil
		},
	)
	consumer.EXPECT().Prefixes(gomock.Any(), gateway, first).Do(
		func(_, _, _ any) {
			consumerCounts.Add(1)
		},
	)

	afterwards := []*net.IPNet{cidr(t, "127.0.0.0/24"), cidr(t, "::/64")}
	fetcher.EXPECT().Prefixes(gomock.Any(), gateway.Control).AnyTimes().DoAndReturn(
		func(_, _ any) ([]*net.IPNet, error) {
			fetcherCounts.Add(1)
			return afterwards, nil
		},
	)
	consumer.EXPECT().Prefixes(gomock.Any(), gateway, afterwards).AnyTimes().Do(
		func(_, _, _ any) {
			consumerCounts.Add(1)
		},
	)

	cfg := control.PrefixWatcherConfig{
		Consumer:       consumer,
		FetcherFactory: fetcherFactory,
		PollInterval:   1 * time.Millisecond,
	}
	w := control.NewPrefixWatcher(context.Background(), gateway, 0, cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var bg errgroup.Group
	bg.Go(func() error {
		return w.Run(ctx)
	})
	t.Cleanup(func() {
		assert.NoError(t, bg.Wait())
	})
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
