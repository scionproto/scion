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

package gateway

import (
	"context"
	"fmt"
	"sync"

	"github.com/scionproto/scion/gateway/control"
	controlgrpc "github.com/scionproto/scion/gateway/control/grpc"
	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type fetcherFactory struct {
	remote addr.IA
	wf     *WatcherFactory
}

func (f fetcherFactory) NewPrefixFetcher(ctx context.Context,
	gateway control.Gateway) control.PrefixFetcher {

	return &prefixFetcher{
		PrefixFetcher: &controlgrpc.PrefixFetcher{
			Remote: f.remote,
			Dialer: f.wf.Dialer,
			Pather: f.wf.PathMonitor.Register(
				ctx,
				f.remote,
				&policies.Policies{
					PathPolicy: control.PathPolicyWithAllowedInterfaces(
						f.wf.Policies.PathPolicy,
						f.remote,
						gateway.Interfaces,
					),
					PerfPolicy: f.wf.Policies.PerfPolicy,
					PathCount:  f.wf.Policies.PathCount,
				},
				// XXX(roosd): This potentially can lead to label value
				// explosion. However, the gateway IPs are rather stable in
				// practice. Conceptually, this is similar to using the remote
				// ISD-AS as a label value, which we do as well.
				fmt.Sprintf("prefix-watcher-%s", gateway.Control.IP),
			),
		},
	}
}

type prefixFetcher struct {
	*controlgrpc.PrefixFetcher

	closedMtx sync.RWMutex
	closed    bool
}

func (f *prefixFetcher) Close() error {
	f.closedMtx.Lock()
	defer f.closedMtx.Unlock()
	if f.closed {
		return serrors.New("already closed")
	}
	f.closed = true
	f.Pather.Close()
	return nil
}

type WatcherFactory struct {
	Dialer      libgrpc.Dialer
	PathMonitor control.PathMonitor
	Aggregator  control.PrefixConsumer
	Policies    *policies.Policies
}

func (wf *WatcherFactory) New(
	ctx context.Context,
	remote addr.IA,
	metrics control.GatewayWatcherMetrics,
) control.Runner {

	pather := wf.PathMonitor.Register(ctx, remote, wf.Policies, "gateway-watcher")
	return &watcherWrapper{
		GatewayWatcher: control.GatewayWatcher{
			Remote: remote,
			Discoverer: controlgrpc.Discoverer{
				Remote: remote,
				Dialer: wf.Dialer,
				Paths:  pather,
			},
			Template: control.PrefixWatcherConfig{
				Consumer: wf.Aggregator,
				FetcherFactory: fetcherFactory{
					remote: remote,
					wf:     wf,
				},
			},
			Metrics: metrics,
		},
		pather: pather,
	}
}

type watcherWrapper struct {
	control.GatewayWatcher
	pather control.PathMonitorRegistration
}

func (w *watcherWrapper) Run(ctx context.Context) error {
	err := w.GatewayWatcher.Run(ctx)
	w.pather.Close()
	return err
}
