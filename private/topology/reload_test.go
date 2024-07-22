// Copyright 2021 Anapaya Systems
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

package topology_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/mock_metrics"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/topology"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/private/topology/mock_topology"
)

func TestLoader(t *testing.T) {
	testBasicTopo := func(t *testing.T, l *topology.Loader) {
		t.Helper()

		assert.Equal(t, addr.MustParseIA("1-ff00:0:311"), l.IA())
		assert.Equal(t, uint16(1472), l.MTU())
		assert.Equal(t, false, l.Core())
		assert.ElementsMatch(t, []uint16{1, 3, 8, 11}, l.IfIDs())
		assert.ElementsMatch(t,
			xtest.MustParseUDPAddrs(t,
				"127.0.0.67:30073",
				"[2001:db8:f00:b43::1]:23421",
				"[2001:db8:f00:b43::1%some-zone]:23425",
			),
			l.ControlServiceAddresses(),
		)
		assert.Equal(t, xtest.MustParseUDPAddr(t, "10.1.0.1:0"), l.UnderlayNextHop(3))
	}
	modifiedTopo := func(t *testing.T, mod func(*jsontopo.Topology)) string {
		t.Helper()

		topo, err := jsontopo.LoadFromFile("testdata/basic.json")
		require.NoError(t, err)
		mod(topo)
		raw, err := json.MarshalIndent(topo, "", "  ")
		require.NoError(t, err)
		f, err := xtest.TempFileName("", "topologyloader")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(f, append(raw, byte('\n')), 0644))
		return f
	}
	t.Run("constructor fails on invalid topo", func(t *testing.T) {
		l, err := topology.NewLoader(topology.LoaderCfg{
			File: "non-existing",
		})
		assert.Nil(t, l)
		assert.Error(t, err)
	})
	t.Run("run exits once context is cancelled", func(t *testing.T) {
		l, err := topology.NewLoader(topology.LoaderCfg{
			File: "testdata/basic.json",
		})
		assert.NoError(t, err)
		ctx, cancelF := context.WithCancel(context.Background())
		g, errCtx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return l.Run(errCtx)
		})
		cancelF()
		assert.NoError(t, g.Wait())
	})
	t.Run("topology data is valid on load", func(t *testing.T) {
		l, err := topology.NewLoader(topology.LoaderCfg{
			File: "testdata/basic.json",
		})
		assert.NoError(t, err)
		testBasicTopo(t, l)
	})
	t.Run("unreadable reload is ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCtr := mock_metrics.NewMockCounter(ctrl)
		reloadCh := make(chan struct{})
		l, err := topology.NewLoader(topology.LoaderCfg{
			File:   "testdata/basic.json",
			Reload: reloadCh,
			Metrics: topology.LoaderMetrics{
				ReadErrors: mockCtr,
			},
		})
		assert.NoError(t, err)
		ctx, cancelF := context.WithCancel(context.Background())
		t.Cleanup(cancelF)
		g, errCtx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return l.Run(errCtx)
		})
		readErrCh := make(chan struct{})
		mockCtr.EXPECT().Add(float64(1)).Do(func(float64) {
			close(readErrCh)
		})
		topology.SetFile(l, "non-existing")
		reloadCh <- struct{}{}
		xtest.AssertReadReturnsBefore(t, readErrCh, time.Second)
		testBasicTopo(t, l)
	})
	t.Run("invalid reload is ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCtr := mock_metrics.NewMockCounter(ctrl)
		mockValidator := mock_topology.NewMockValidator(ctrl)
		// initial load is ignored
		mockValidator.EXPECT().Validate(gomock.Any(), nil)
		// second load is triggered and fails validation.
		mockValidator.EXPECT().Validate(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_, _ *topology.RWTopology) error {
				return errors.New("validation error")
			},
		)
		reloadCh := make(chan struct{})
		l, err := topology.NewLoader(topology.LoaderCfg{
			File:      "testdata/basic.json",
			Reload:    reloadCh,
			Validator: mockValidator,
			Metrics: topology.LoaderMetrics{
				ValidationErrors: mockCtr,
			},
		})
		assert.NoError(t, err)
		ctx, cancelF := context.WithCancel(context.Background())
		t.Cleanup(cancelF)
		g, errCtx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return l.Run(errCtx)
		})
		validationErrCh := make(chan struct{})
		mockCtr.EXPECT().Add(float64(1)).Do(func(float64) {
			close(validationErrCh)
		})
		reloadCh <- struct{}{}
		xtest.AssertReadReturnsBefore(t, validationErrCh, time.Second)
		testBasicTopo(t, l)
	})
	t.Run("valid reload is executed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockCtr := mock_metrics.NewMockCounter(ctrl)
		mockCtr.EXPECT().Add(float64(1))
		reloadCh := make(chan struct{})
		l, err := topology.NewLoader(topology.LoaderCfg{
			File:   "testdata/basic.json",
			Reload: reloadCh,
			Metrics: topology.LoaderMetrics{
				Updates: mockCtr,
			},
		})
		assert.NoError(t, err)
		ctx, cancelF := context.WithCancel(context.Background())
		t.Cleanup(cancelF)
		g, errCtx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return l.Run(errCtx)
		})
		// check before reload
		testBasicTopo(t, l)
		assert.Equal(t,
			xtest.MustParseUDPAddr(t, "[2001:db8:a0b:12f0::1%some-internal-zone]:0"),
			l.UnderlayNextHop(11),
		)

		// reload
		reloadMetricCh := make(chan struct{})
		mockCtr.EXPECT().Add(float64(1)).Do(func(float64) {
			close(reloadMetricCh)
		})
		file := modifiedTopo(t, func(topo *jsontopo.Topology) {
			topo.BorderRouters["br1-ff00:0:311-2"].InternalAddr = "10.0.0.1:42"
		})
		topology.SetFile(l, file)
		reloadCh <- struct{}{}
		xtest.AssertReadReturnsBefore(t, reloadMetricCh, time.Second)

		// check after reload
		testBasicTopo(t, l)
		assert.Equal(t, xtest.MustParseUDPAddr(t, "10.0.0.1:42"), l.UnderlayNextHop(11))
	})
	t.Run("test subscription", func(t *testing.T) {
		reloadCh := make(chan struct{})
		l, err := topology.NewLoader(topology.LoaderCfg{
			File:   "testdata/basic.json",
			Reload: reloadCh,
		})
		assert.NoError(t, err)
		ctx, cancelF := context.WithCancel(context.Background())
		t.Cleanup(cancelF)
		g, errCtx := errgroup.WithContext(ctx)
		g.Go(func() error {
			return l.Run(errCtx)
		})
		sub1 := l.Subscribe()
		sub2 := l.Subscribe()
		timeout := time.After(time.Second)
		reloadCh <- struct{}{}
		// the updates channel can be filled in anyorder so below code has to be
		// oder independent.
		for i := 0; i < 2; i++ {
			select {
			case <-sub1.Updates:
				t.Log("sub1 update received")
			case <-sub2.Updates:
				t.Log("sub2 update received")
			case <-timeout:
				t.Fatal("updates not received in time")
			}
		}
		sub1.Close()
		reloadCh <- struct{}{}
		xtest.AssertReadReturnsBefore(t, sub2.Updates, time.Second)
	})
}
