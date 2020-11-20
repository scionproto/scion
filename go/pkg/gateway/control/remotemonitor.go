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

package control

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/worker"
)

// Runner represents a runnable task.
type Runner interface {
	// Run is blocking  and can be concelled via the context.
	Run(context.Context) error
}

type GatewayWatcherFactory interface {
	New(addr.IA, GatewayWatcherMetrics) Runner
}

// RemoteMinitor watches for currently monitored remote ASes and creates
// GatewayWatchers accordingly. For all new IAs that weren't seen
// before new GatewayWatcher is created. For all IAs that were seen before
// but are not present in an update the corresponding GatewayWatcher is stopped.
type RemoteMonitor struct {
	// GatewayWatcherFactory is used to create remote gateway watchers.
	GatewayWatcherFactory GatewayWatcherFactory
	// IAs is a channel that is notified with the full set of IAs to watch.
	IAs <-chan []addr.IA
	// Logger is the logger to use. If set to nil, no logging will be done.
	Logger log.Logger
	// RemotesMonitored is the number of remote gateways discovered. If nil, no metric is reported.
	RemotesMonitored metrics.Gauge

	// context is the parent context for all watcher contexts.
	context context.Context
	// cancel is a function that cancels context.
	cancel context.CancelFunc
	// currentWatchers is a map of all currently active watchers.
	currentWatchers map[addr.IA]watcherEntry

	workerBase worker.Base
}

type watcherEntry struct {
	runner Runner
	cancel context.CancelFunc
}

func (rm *RemoteMonitor) Run() error {
	return rm.workerBase.RunWrapper(rm.setup, rm.run)
}

func (rm *RemoteMonitor) Close() error {
	return rm.workerBase.CloseWrapper(nil)
}

func (rm *RemoteMonitor) setup() error {
	if rm.GatewayWatcherFactory == nil {
		return serrors.New("whatcher factory not specified")
	}
	if rm.IAs == nil {
		return serrors.New("IAs channel not specified")
	}
	rm.context, rm.cancel = context.WithCancel(context.Background())
	rm.currentWatchers = make(map[addr.IA]watcherEntry)
	return nil
}

func (rm *RemoteMonitor) run() error {
	for {
		select {
		case ias := <-rm.IAs:
			rm.process(ias)
		case <-rm.workerBase.GetDoneChan():
			rm.cancel()
			return nil
		}
	}
}

func (rm *RemoteMonitor) process(ias []addr.IA) {
	newWatchers := make(map[addr.IA]watcherEntry)
	for _, ia := range ias {
		we, ok := rm.currentWatchers[ia]
		if ok {
			// Watcher for the remote IA exists. Move it to the new map of
			// watchers.
			newWatchers[ia] = we
			delete(rm.currentWatchers, ia)
		} else {
			// Watcher for the remote IA does not exist. Create it.
			ctx, cancel := context.WithCancel(rm.context)
			we = watcherEntry{
				runner: rm.GatewayWatcherFactory.New(ia, GatewayWatcherMetrics{
					Remotes: metrics.GaugeWith(rm.RemotesMonitored, "remote_isd_as", ia.String()),
				}),
				cancel: cancel,
			}
			go func() {
				defer log.HandlePanic()
				if err := we.runner.Run(ctx); err != nil {
					if rm.Logger != nil {
						rm.Logger.Error("Cannot start GatewayWatcher", "ia", ia, "err", err)
					}
				}
			}()
			newWatchers[ia] = we
		}
	}
	// Cancel all the watchers that are not needed anymore.
	for _, we := range rm.currentWatchers {
		we.cancel()
	}
	// Replace old watchers with the new watchers.
	rm.currentWatchers = newWatchers
}
