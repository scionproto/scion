// Copyright 2019 Anapaya Systems
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

// Package idiscovery fetches the topology from the discovery service.
//
// Client packages can start a periodic.Runner with StartRunners that
// periodically fetches the static and dynamic topology from the discovery
// service. The received topology is set in itopo.
//
// Initially, the runners try to fetch the topology every second for the
// configured InitialPeriod until a fetch succeeded. If no fetch is successful
// after the InitialPeriod, the FailAction is taken. 'Fatal' causes the process
// to exit. 'Continue' logs a warning, the process continues its execution.
//
// By default changes to the semi-mutable section of static topologies is
// not allowed. It can be enabled by providing a custom topo handler.
//
// The periodic.Runner for the static topology can be instructed to
// write updated versions to the file system. To enable this, set
// the filename in StaticConfig.
//
// A periodic.Task with a customized TopoHandler can be created with
// NewFetcher, when the client package requires more control.
package idiscovery

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/topofetcher"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

// TopoHandler handles a topology fetched from the discovery service, and
// returns whether the provided topology is an update.
type TopoHandler func(topo *topology.Topo) (bool, error)

func staticSetter(topo *topology.Topo) (bool, error) {
	_, updated, err := itopo.SetStatic(topo, false)
	return updated, err
}

// dynamicSetter sets the dynamic topology in itopo with the provided topology.
func dynamicSetter(topo *topology.Topo) (bool, error) {
	_, updated, err := itopo.SetDynamic(topo)
	return updated, err
}

// TopoHandlers contains custom topology handlers.
type TopoHandlers struct {
	// Static handles the static topology.
	Static TopoHandler
	// Dynamic handles the dynamic topology.
	Dynamic TopoHandler
}

func (t *TopoHandlers) static() TopoHandler {
	if t.Static != nil {
		return t.Static
	}
	return staticSetter
}

func (t *TopoHandlers) dynamic() TopoHandler {
	if t.Dynamic != nil {
		return t.Dynamic
	}
	return dynamicSetter
}

type Runners struct {
	// Static periodically fetches the static topology and sets it in itopo.
	Static *Runner
	// Dynamic periodically fetches the dynamic topology and sets it in itopo.
	Dynamic *Runner
	// Cleaner periodically cleans the expired dynamic topology in itopo.
	Cleaner *periodic.Runner
}

// StartRunners starts the runners for the specified configuration. In case the topo handler
// function is not set, StartRunners defaults to setting the topology in itopo.
func StartRunners(cfg Config, file discovery.File, handlers TopoHandlers,
	client *http.Client) (Runners, error) {

	cfg.InitDefaults()
	var err error
	r := Runners{}
	if cfg.Static.Enable {
		r.Static, err = startPeriodicFetcher(
			cfg.Static.FetchConfig,
			handlers.static(),
			discovery.FetchParams{
				Mode:  discovery.Static,
				Https: cfg.Static.Https,
				File:  file,
			},
			cfg.Static.Filename,
			client,
		)
		if err != nil {
			return Runners{}, err
		}
	}
	if cfg.Dynamic.Enable {
		r.Dynamic, err = startPeriodicFetcher(
			cfg.Dynamic,
			handlers.dynamic(),
			discovery.FetchParams{
				Mode:  discovery.Dynamic,
				Https: cfg.Dynamic.Https,
				File:  file,
			},
			"",
			client,
		)
		if err != nil {
			r.Kill()
			return Runners{}, err
		}
		r.Cleaner = itopo.StartCleaner(1*time.Second, 1*time.Second)
		log.Info("[idiscovery] Started dynamic topology fetcher")
	}
	return r, nil
}

// Stop stops all runners.
func (r *Runners) Stop() {
	if r.Static != nil {
		r.Static.Stop()
	}
	if r.Dynamic != nil {
		r.Dynamic.Stop()
	}
	if r.Cleaner != nil {
		r.Cleaner.Stop()
	}
}

// Kill kills all runners.
func (r *Runners) Kill() {
	if r.Static != nil {
		r.Static.Kill()
	}
	if r.Dynamic != nil {
		r.Dynamic.Kill()
	}
	if r.Cleaner != nil {
		r.Cleaner.Kill()
	}
}

// Runner periodically fetches the topology from the discovery service. On start up,
// every second a request is sent, until the configured initial period has passed,
// or a topology has been fetched successfully.
type Runner struct {
	fetcherMtx sync.Mutex
	// fetcher periodically fetches the topology.
	fetcher *periodic.Runner
	// rawHandler is the handler provided by the caller.
	rawHandler TopoHandler
	// stop is a channel to signal the initial period go routine to stop.
	stop chan struct{}
	// stopping indicates that the stopping process has started.
	stopping bool
	// fetched is used to communicate a successfully fetched topology.
	fetched flag
}

// Stop stops the periodic execution of the Runner. If the task is currently running
// this method will block until it is done.
func (r *Runner) Stop() {
	r.fetcherMtx.Lock()
	defer r.fetcherMtx.Unlock()
	r.stopping = true
	close(r.stop)
	if r.fetcher != nil {
		r.fetcher.Stop()
	}
}

// Kill is like stop but it also cancels the context of the current running method.
func (r *Runner) Kill() {
	r.fetcherMtx.Lock()
	defer r.fetcherMtx.Unlock()
	r.stopping = true
	close(r.stop)
	if r.fetcher != nil {
		r.fetcher.Stop()
	}
}

// startPeriodicFetcher starts a runner that periodically fetches the topology.
// If during the InitialPeriod no topology is successfully fetched, the process takes
// the configured FailAction.
func startPeriodicFetcher(cfg FetchConfig, handler TopoHandler, params discovery.FetchParams,
	filename string, client *http.Client) (*Runner, error) {

	fatal.Check()
	r := &Runner{
		rawHandler: handler,
		stop:       make(chan struct{}),
		fetched: flag{
			c: make(chan struct{}),
		},
	}
	fetcher, err := NewFetcher(r.handler, params, filename, client)
	if err != nil {
		return nil, err
	}
	r.startInitialPeriod(fetcher, cfg)
	return r, nil
}

// startInitialPeriod fetches the topology every second for the initial period,
// or until the a topology has been fetched successfully.
func (r *Runner) startInitialPeriod(fetcher *task, cfg FetchConfig) {
	go func() {
		defer log.LogPanicAndExit()
		ticker := time.NewTicker(time.Second)
		initialPeriod := time.NewTimer(cfg.Connect.InitialPeriod.Duration)
		defer ticker.Stop()
		defer initialPeriod.Stop()
		r.startFetch(fetcher, cfg.Timeout.Duration)
		for {
			select {
			case <-r.stop:
				return
			case <-initialPeriod.C:
				r.execFailAction(fetcher, cfg)
				return
			case <-r.fetched.c:
				r.startRegularFetcher(fetcher, cfg)
				return
			case <-ticker.C:
				r.startFetch(fetcher, cfg.Timeout.Duration)
			}
		}
	}()
}

// execFailAction executes the FailAction.
func (r *Runner) execFailAction(fetcher *task, cfg FetchConfig) {
	switch cfg.Connect.FailAction {
	case FailActionContinue:
		log.Warn("[discovery] Unable to get a valid initial topology, ignoring")
		r.startRegularFetcher(fetcher, cfg)
	default:
		fatal.Fatal(common.NewBasicError("Unable to get a valid initial topology", nil))
	}
}

// startRegularFetcher starts a periodic fetcher with the configured interval and timeout.
// If the runner is in the process of stopping, no fetcher is started.
func (r *Runner) startRegularFetcher(fetcher *task, cfg FetchConfig) {
	r.fetcherMtx.Lock()
	defer r.fetcherMtx.Unlock()
	if r.stopping {
		return
	}
	r.fetcher = periodic.StartPeriodicTask(fetcher, periodic.NewTicker(cfg.Interval.Duration),
		cfg.Timeout.Duration)
}

// startFetch starts a go routine that executes the fetch task.
func (r *Runner) startFetch(fetcher *task, timeout time.Duration) {
	go func() {
		defer log.LogPanicAndExit()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		fetcher.Run(ctx)
	}()
}

// handler wraps the handler provided by the caller and sets the set flag if a topology
// is handled successfully without error.
func (r *Runner) handler(topo *topology.Topo) (bool, error) {
	updated, err := r.rawHandler(topo)
	if err != nil {
		return updated, err
	}
	r.fetched.Set()
	return updated, err
}

// task is a periodic.Task that fetches the topology from the discovery service.
type task struct {
	log.Logger
	handler  TopoHandler
	fetcher  *topofetcher.Fetcher
	filename string
}

// NewFetcher creates a periodic.Task that fetches the topology from the discovery
// service and calls the provided handler on the received topology. If the handler
// indicates an update, and filename is set, the topology is written.
func NewFetcher(handler TopoHandler, params discovery.FetchParams,
	filename string, client *http.Client) (*task, error) {

	if handler == nil {
		return nil, common.NewBasicError("handler must not be nil", nil)
	}
	t := &task{
		Logger:   log.New("Module", "Discovery", "Mode", params.Mode),
		handler:  handler,
		filename: filename,
	}
	var err error
	t.fetcher, err = topofetcher.New(
		itopo.Get().DS,
		params,
		topofetcher.Callbacks{
			Error: t.handleErr,
			Raw:   t.handleRaw,
		},
		client,
	)
	if err != nil {
		return nil, common.NewBasicError("Unable to initialize fetcher", err)
	}
	return t, nil
}

func (t *task) Run(ctx context.Context) {
	if err := t.fetcher.UpdateInstances(itopo.Get().DS); err != nil {
		log.Error("[discovery] Unable to update instances", "err", err)
		return
	}
	t.fetcher.Run(ctx)
}

func (t *task) handleErr(err error) {
	t.Error("[discovery] Unable to fetch topology", "err", err)
}

func (t *task) handleRaw(raw common.RawBytes, topo *topology.Topo) {
	updated, err := t.callHandler(topo)
	if err != nil || t.filename == "" || !updated {
		return
	}
	if err := util.WriteFile(t.filename, raw, 0644); err != nil {
		t.Error("[discovery] Unable to write new topology to filesystem", "err", err)
		return
	}
	t.Trace("[discovery] Topology written to filesystem",
		"file", t.filename, "params", t.fetcher.Params)
}

func (t *task) callHandler(topo *topology.Topo) (bool, error) {
	updated, err := t.handler(topo)
	if err != nil {
		t.Error("[discovery] Unable to handle topology", "err", err)
	} else if updated {
		t.Trace("[discovery] Set topology", "params", t.fetcher.Params)
	}
	return updated, err
}

type flag struct {
	sync.Mutex
	set bool
	c   chan struct{}
}

func (f *flag) Set() {
	f.Lock()
	defer f.Unlock()
	if !f.set {
		close(f.c)
	}
	f.set = true
}
