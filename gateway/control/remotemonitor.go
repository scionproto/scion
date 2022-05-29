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
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/worker"
)

// Runner represents a runnable task.
type Runner interface {
	// Run is blocking  and can be concelled via the context.
	Run(context.Context) error
}

type GatewayWatcherFactory interface {
	New(context.Context, addr.IA, GatewayWatcherMetrics) Runner
}

// RemoteMonitor watches for currently monitored remote ASes and creates
// GatewayWatchers accordingly. For all new IAs that weren't seen
// before new GatewayWatcher is created. For all IAs that were seen before
// but are not present in an update the corresponding GatewayWatcher is stopped.
type RemoteMonitor struct {
	// GatewayWatcherFactory is used to create remote gateway watchers.
	GatewayWatcherFactory GatewayWatcherFactory
	// IAs is a channel that is notified with the full set of IAs to watch.
	IAs <-chan []addr.IA
	// RemotesMonitored is the number of remote gateways discovered, per ISD-AS.
	// If nil, no metric is reported.
	RemotesMonitored func(addr.IA) metrics.Gauge
	// RemotesChanges is the changes to the number of remote gateways
	// discovered, per ISD-AS. If nil, no metric is reported.
	RemotesChanges func(addr.IA) metrics.Counter
	// RemoteDiscoveryErrors is the number of remote gateway discovery errors,
	// per remote ISD-AS. If nil, no metric is reported.
	RemoteDiscoveryErrors func(addr.IA) metrics.Counter
	// PrefixFetchErrors is the number of prefix fetch errors, per remote
	// ISD-AS. If nil, no metric is reported.
	PrefixFetchErrors func(addr.IA) metrics.Counter

	// stateMtx protects the state below from concurrent access.
	stateMtx sync.RWMutex
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

// remoteDiagnostics represents the gathered diagnostics from the gateways.
type remoteDiagnostics struct {
	Gateways map[string]gatewayDiagnostics `json:"gateways"`
}

func (rm *RemoteMonitor) Run(ctx context.Context) error {
	return rm.workerBase.RunWrapper(ctx, rm.setup, rm.run)
}

func (rm *RemoteMonitor) Close(ctx context.Context) error {
	return rm.workerBase.CloseWrapper(ctx, nil)
}

func (rm *RemoteMonitor) setup(ctx context.Context) error {
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

func (rm *RemoteMonitor) run(ctx context.Context) error {
	for {
		select {
		case ias := <-rm.IAs:
			rm.process(ctx, ias)
		case <-rm.workerBase.GetDoneChan():
			rm.cancel()
			return nil
		}
	}
}

func (rm *RemoteMonitor) process(ctx context.Context, ias []addr.IA) {
	rm.stateMtx.Lock()
	defer rm.stateMtx.Unlock()
	logger := log.FromCtx(ctx)
	newWatchers := make(map[addr.IA]watcherEntry)
	for _, ia := range ias {
		ia := ia
		we, ok := rm.currentWatchers[ia]
		if ok {
			// Watcher for the remote IA exists. Move it to the new map of
			// watchers.
			newWatchers[ia] = we
			delete(rm.currentWatchers, ia)
		} else {
			// Watcher for the remote IA does not exist. Create it.
			ctx, cancel := context.WithCancel(rm.context)
			var remotesMonitored metrics.Gauge
			var remotesChanges metrics.Counter
			var discoveryErrors metrics.Counter
			var prefixFetchErrors metrics.Counter
			if rm.RemotesMonitored != nil {
				remotesMonitored = rm.RemotesMonitored(ia)
			}
			if rm.RemotesChanges != nil {
				remotesChanges = rm.RemotesChanges(ia)
			}
			if rm.RemoteDiscoveryErrors != nil {
				discoveryErrors = rm.RemoteDiscoveryErrors(ia)
			}
			if rm.PrefixFetchErrors != nil {
				prefixFetchErrors = rm.PrefixFetchErrors(ia)
			}
			we = watcherEntry{
				runner: rm.GatewayWatcherFactory.New(ctx, ia, GatewayWatcherMetrics{
					Remotes:           remotesMonitored,
					RemotesChanges:    remotesChanges,
					DiscoveryErrors:   discoveryErrors,
					PrefixFetchErrors: prefixFetchErrors,
				}),
				cancel: cancel,
			}
			go func() {
				defer log.HandlePanic()
				if err := we.runner.Run(ctx); err != nil {
					logger.Error("Cannot start GatewayWatcher", "ia", ia, "err", err)
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

// DiagnosticsWrite writes diagnostics to the writer.
func (rm *RemoteMonitor) DiagnosticsWrite(w io.Writer) {
	rm.stateMtx.RLock()
	defer rm.stateMtx.RUnlock()

	// assemble the diagnostics json output
	diagnostics := struct {
		Remotes map[addr.IA]remoteDiagnostics `json:"remotes"`
	}{
		Remotes: make(map[addr.IA]remoteDiagnostics),
	}

	for ia, watcher := range rm.currentWatchers {
		gatewaywatcher, ok := watcher.runner.(interface {
			diagnostics() (remoteDiagnostics, error)
		})
		if !ok {
			continue
		}
		var err error
		diagnostics.Remotes[ia], err = gatewaywatcher.diagnostics()
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Error collecting  diagnostics from gateways %v", err)))
			return
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(diagnostics); err != nil {
		w.Write([]byte(fmt.Sprintf("Error collecting Remotes diagnostics %v", err)))
		return
	}
}
