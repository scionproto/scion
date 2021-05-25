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
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// defaultGatewayDiscoveryInterval is the default interval for discovering
	// remote gateways.
	defaultGatewayDiscoveryInterval = 5 * time.Second
	// defaultGatewayDiscoveryTimeout is the default timeout for discovering
	// remote gateways.
	defaultGatewayDiscoveryTimeout = 5 * time.Second
	// defaultGatewayPollInterval is the default interval for polling the remote
	// gateway for prefixes.
	defaultGatewayPollInterval = 5 * time.Second
	// defaultGatewayPollTimeout is the default timeout for polling the remote
	// gateway for prefixes.
	defaultGatewayPollTimeout = 5 * time.Second
)

var (
	// ErrAlreadyRunning is the error returned when attempting to run a task twice.
	ErrAlreadyRunning = serrors.New("is running")
)

// Gateway represents a remote gateway instance.
type Gateway struct {
	// Control contains the control-plane address of the remote gateway.
	Control *net.UDPAddr
	// Probe contains the probing address of the remote gateway.
	Probe *net.UDPAddr
	// Data contains the data-plane address of the remote gateway.
	Data *net.UDPAddr
	// Interfaces are the last-hop SCION interfaces that should be preferred.
	Interfaces []uint64
}

func (g Gateway) Equal(other Gateway) bool {
	return g.Control.String() == other.Control.String() &&
		g.Probe.String() == other.Probe.String() &&
		g.Data.String() == other.Data.String() &&
		interfacesKey(g.Interfaces) == interfacesKey(other.Interfaces)
}

func interfacesKey(interfaces []uint64) string {
	keyParts := make([]string, 0, len(interfaces))
	for _, i := range interfaces {
		keyParts = append(keyParts, strconv.FormatUint(i, 10))
	}
	sort.Strings(keyParts)
	return strings.Join(keyParts, "-")
}

// Discoverer discovers gateway instances. It must be scoped to the intended
// remote for the GatewayWatcher.
type Discoverer interface {
	Gateways(ctx context.Context) ([]Gateway, error)
}

// GatewayWatcherMetrics contains the metrics the GatewayWatcher reports.
type GatewayWatcherMetrics struct {
	// Remotes is the number of remote gateways discovered in the remote AS.
	Remotes metrics.Gauge
}

// GatewayWatcher watches gateways in a specific remote AS.
//
// Per discovered gateway, the watcher starts a PrefixWatcher that periodically
// polls the IP prefixes served by that gateway. The PrefixWatcher tasks are
// dynamically added and removed depending on the gateway discovery responses.
// The delta in the list of gateways is assumed to be empty, if a discovery
// attempt fails.
//
// When the GatewayWatcher is stopped, all spawaned PrefixWatcher tasks are
// stopped as well.
type GatewayWatcher struct {
	// Remote is the remote AS to watch.
	Remote addr.IA
	// Discoverer is used for remote gateway discovery. It must not be nil.
	Discoverer Discoverer
	// DiscoverInterval is the time between consecutive gateway discovery
	// attempts. If zero, this defaults to 5 seconds.
	DiscoverInterval time.Duration
	// DiscoverTimeout is the timout for an individual gateway discovery
	// attempts. If zero, this defaults to 5 seconds.
	DiscoverTimeout time.Duration
	// Template serves as the template for the PrefixWatcher tasks that are
	// spawned. For each discovered gateway, a PrefixWatcher task is started
	// based on this template.
	Template PrefixWatcherConfig
	// Metrics can be used to report information about discovered remote gateways. If not
	// initialized, no metrics will be reported.
	Metrics GatewayWatcherMetrics

	// stateMtx protects the state below from concurrent access.
	stateMtx sync.RWMutex
	gateways []Gateway
	// currentWatchers is a map of all currently active prefix watchers.
	currentWatchers map[string]watcherItem
	runMarkerLock   sync.Mutex
	// runMarker is set to true the first time a Session runs. Subsequent calls use this value to
	// return an error.
	runMarker bool
}

type watcherItem struct {
	*prefixWatcher
	cancel func()
}

// gatewayDiagnostics represents the gathered diagnostics from the prefixes.
type gatewayDiagnostics struct {
	DataAddr   string    `json:"data_address"`
	ProbeAddr  string    `json:"probe_address"`
	Interfaces []uint64  `json:"interfaces"`
	Prefixes   []string  `json:"prefixes"`
	Timestamp  time.Time `json:"timestamp"`
}

// Run watches the remote for gateways. This method blocks until the context
// expires, or an irrecoverable error is encountered.
func (w *GatewayWatcher) Run(ctx context.Context) error {
	if err := w.runOnceCheck(); err != nil {
		return err
	}
	if err := w.validateParameters(); err != nil {
		return err
	}
	logger := log.FromCtx(ctx).New("debug_id", log.NewDebugID(), "remote", w.Remote)
	ctx = log.CtxWith(ctx, logger)
	logger.Info("Starting periodic gateway discovery")
	defer logger.Info("Stopped periodic gateway discovery")

	ticker := time.NewTicker(w.DiscoverInterval)
	defer ticker.Stop()
	w.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.run(ctx)
		}
	}
}

func (w *GatewayWatcher) run(runCtx context.Context) {
	ctx, cancel := context.WithTimeout(runCtx, w.DiscoverTimeout)
	defer cancel()
	logger := log.FromCtx(ctx)
	logger.Debug("Discovering remote gateways")
	discovered, err := w.Discoverer.Gateways(ctx)
	if err != nil {
		logger.Info("Failed to discover remote gateways", "err", err)
		return
	}
	w.stateMtx.Lock()
	defer w.stateMtx.Unlock()
	diff := computeDiff(w.gateways, discovered)
	for _, gateway := range diff.Add {
		w.currentWatchers[fmt.Sprint(gateway)] = w.watchPrefixes(runCtx, gateway)
	}
	for _, gateway := range diff.Remove {
		key := fmt.Sprint(gateway)
		if prefixWatcher, ok := w.currentWatchers[key]; ok {
			prefixWatcher.cancel()
			delete(w.currentWatchers, key)
		}
	}
	if len(diff.Add) != 0 {
		logger.Info("Start prefix discovery", "gateways", diff.Add)
	}
	if len(diff.Remove) != 0 {
		logger.Info("Stop prefix discovery", "gateways", diff.Remove)
	}
	w.gateways = discovered
	metrics.GaugeSet(w.Metrics.Remotes, float64(len(discovered)))
}

func (w *GatewayWatcher) watchPrefixes(ctx context.Context, gateway Gateway) watcherItem {
	ctx, cancel := context.WithCancel(ctx)
	watcher := newPrefixWatcher(gateway, w.Remote, w.Template)
	go func(ctx context.Context, watcher *prefixWatcher) {
		defer log.HandlePanic()
		if err := watcher.Run(ctx); err != nil {
			addr := snet.UDPAddr{
				IA:   watcher.remote,
				Host: watcher.gateway.Control,
			}
			log.FromCtx(ctx).Info("PrefixWatcher stopped with error", "remote", addr, "err", err)
		}
	}(ctx, watcher)
	return watcherItem{
		prefixWatcher: watcher,
		cancel:        cancel,
	}
}

func (w *GatewayWatcher) runOnceCheck() error {
	w.runMarkerLock.Lock()
	defer w.runMarkerLock.Unlock()
	if w.runMarker {
		return ErrAlreadyRunning
	}
	w.runMarker = true
	w.currentWatchers = map[string]watcherItem{}
	return nil
}

// Diagnostics gives back a RemoteDiagnostics map
func (w *GatewayWatcher) diagnostics() (remoteDiagnostics, error) {
	w.stateMtx.RLock()
	defer w.stateMtx.RUnlock()

	// assemble the diagnostics json output
	diagnostics := struct {
		Gateways map[string]gatewayDiagnostics `json:"gateways"`
	}{
		Gateways: make(map[string]gatewayDiagnostics),
	}
	for _, watcher := range w.currentWatchers {
		watcher.stateMtx.RLock()
		defer watcher.stateMtx.RUnlock()
		interfaces := watcher.gateway.Interfaces
		if watcher.gateway.Interfaces == nil {
			interfaces = []uint64{}
		}
		diagnostics.Gateways[watcher.gateway.Control.String()] = gatewayDiagnostics{
			DataAddr:   watcher.gateway.Data.String(),
			ProbeAddr:  watcher.gateway.Probe.String(),
			Interfaces: interfaces,
			Prefixes:   watcher.prefixes,
			Timestamp:  watcher.timestamp,
		}
	}
	return diagnostics, nil
}

func (w *GatewayWatcher) validateParameters() error {
	if w.Discoverer == nil {
		return serrors.New("discoverer must not be nil")
	}
	if w.DiscoverInterval == 0 {
		w.DiscoverInterval = defaultGatewayDiscoveryInterval
	}
	if w.DiscoverTimeout == 0 {
		w.DiscoverTimeout = defaultGatewayDiscoveryTimeout
	}
	if err := w.Template.validateParameters(); err != nil {
		return serrors.WrapStr("validating PrefixWatcher template", err)
	}
	return nil
}

// PrefixConsumer consumes the prefixes fetched by the PrefixWatcher.
type PrefixConsumer interface {
	Prefixes(remote addr.IA, gateway Gateway, prefixes []*net.IPNet)
}

// PrefixFetcher fetches the IP prefixes from a remote gateway.
type PrefixFetcher interface {
	Prefixes(ctx context.Context, gateway *net.UDPAddr) ([]*net.IPNet, error)
}

// PrefixWatcherConfig configures a prefix watcher that watches IP prefixes
// advertised by a remote gateway. The discovered IP prefixes are advertised to
// the prefix consumer. The watcher is stateless and does not keep track of
// previously discovered IP prefixes.
type PrefixWatcherConfig struct {
	// Consumer consume the fetched prefixes. Its methods are called
	// synchroniously and should return swiftly.
	Consumer PrefixConsumer
	// PrefixFetcher is used to fetch IP prefixes from the remote gateway.
	Fetcher PrefixFetcher
	// PollInterval is the time between consecutive poll attempts. If zero, this
	// defaults to 5 seconds.
	PollInterval time.Duration
	// PollTimeout is the timout for an individual poll attempts. If zero, this
	// defaults to 5 seconds.
	PollTimeout time.Duration
}

func (c *PrefixWatcherConfig) validateParameters() error {
	if c.Consumer == nil {
		return serrors.New("consumer must not be nil")
	}
	if c.Fetcher == nil {
		return serrors.New("fetcher must not be nil")
	}
	if c.PollInterval == 0 {
		c.PollInterval = defaultGatewayPollInterval
	}
	if c.PollTimeout == 0 {
		c.PollTimeout = defaultGatewayPollTimeout
	}
	return nil
}

// prefixWatcher watches IP prefixes advertised by a remote gateway. The
// discovered IP prefixes are advertised to the prefix consumer. The watcher is
// stateless and does not keep track of previously discovered IP prefixes.
type prefixWatcher struct {
	PrefixWatcherConfig

	gateway       Gateway
	remote        addr.IA
	runMarkerLock sync.Mutex
	// runMarker is set to true the first time a Session runs. Subsequent calls use this value to
	// return an error.
	runMarker bool
	// stateMtx protects the state below from concurrent access.
	stateMtx sync.RWMutex
	// state of last fetched prefixes
	prefixes []string
	// timestamp of last fetched prefixes
	timestamp time.Time
}

func newPrefixWatcher(gateway Gateway, remote addr.IA, cfg PrefixWatcherConfig) *prefixWatcher {
	return &prefixWatcher{
		PrefixWatcherConfig: cfg,
		gateway:             gateway,
		remote:              remote,
	}
}

// Run periodically fetches the prefixes advertised by the remote gateway. This
// method blocks until the context is closed or an irrecoverable error is
// encountered.
func (w *prefixWatcher) Run(ctx context.Context) error {
	if err := w.runOnceCheck(); err != nil {
		return err
	}
	if err := w.validateParameters(); err != nil {
		return err
	}

	logger := log.FromCtx(ctx).New("ctrl_addr", w.gateway.Control)
	ctx = log.CtxWith(ctx, logger)
	logger.Debug("Starting periodic IP prefix discovery")
	defer logger.Debug("Stopped periodic IP prefix discovery")

	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()
	w.run(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.run(ctx)
		}
	}
}

func (w *prefixWatcher) run(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, w.PollTimeout)
	defer cancel()

	logger := log.FromCtx(ctx)
	logger.Debug("Fetching IP prefixes from remote gateway")
	prefixes, err := w.Fetcher.Prefixes(ctx, w.gateway.Control)
	if err != nil {
		logger.Debug("Failed to fetch IP prefixes from remote gateway", "err", err)
		return
	}
	logger.Debug("Fetched prefixes successfully", "prefixes", fmtPrefixes(prefixes))

	snapshot := fmtPrefixes(prefixes)
	w.Consumer.Prefixes(w.remote, w.gateway, prefixes)

	w.stateMtx.Lock()
	defer w.stateMtx.Unlock()
	w.prefixes = snapshot
	w.timestamp = time.Now()
}

func fmtPrefixes(prefixes []*net.IPNet) []string {
	ret := []string{}
	for _, p := range prefixes {
		ret = append(ret, p.String())
	}
	return ret
}

func (w *prefixWatcher) runOnceCheck() error {
	w.runMarkerLock.Lock()
	defer w.runMarkerLock.Unlock()
	if w.runMarker {
		return ErrAlreadyRunning
	}
	w.runMarker = true
	return nil
}

type diff struct {
	Add    []Gateway
	Remove []Gateway
}

func computeDiff(prev, next []Gateway) diff {
	return diff{
		Add:    subtract(next, prev),
		Remove: subtract(prev, next),
	}
}

// subtract subtracts all the gateways in b from the ones in a.
func subtract(a, b []Gateway) []Gateway {
	set := map[string]Gateway{}
	for _, gateway := range a {
		set[fmt.Sprint(gateway)] = gateway
	}
	for _, gateway := range b {
		delete(set, fmt.Sprint(gateway))
	}
	result := make([]Gateway, 0, len(set))
	for _, gateway := range set {
		result = append(result, gateway)
	}
	return result
}
