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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/topofetcher"
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
	Static *periodic.Runner
	// Dynamic periodically fetches the dynamic topology and sets it in itopo.
	Dynamic *periodic.Runner
	// Cleaner periodically cleans the expired dynamic topology in itopo.
	Cleaner *periodic.Runner
}

// StartRunners starts the runners for the specified configuration. In case the topo handler
// function is not set, StartRunners defaults to setting the topology in itopo.
func StartRunners(cfg Config, file discovery.File, handlers TopoHandlers,
	client *http.Client) (Runners, error) {

	var err error
	r := Runners{}
	if cfg.Static.Enable {
		r.Static, err = startPeriodicStaticFetcher(
			cfg.Static,
			handlers.static(),
			discovery.FetchParams{
				Mode:  discovery.Static,
				Https: cfg.Static.Https,
				File:  file,
			},
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

// startPeriodicFetcherWriter starts a runner that periodically fetches the topology.
// If a filename is specified, the topology is written to disk.
func startPeriodicStaticFetcher(cfg StaticConfig, handler TopoHandler,
	params discovery.FetchParams, client *http.Client) (*periodic.Runner, error) {

	if cfg.Filename == "" {
		return startPeriodicFetcher(cfg.FetchConfig, handler, params, client)
	}
	fetcher, err := NewWriteFetcher(handler, params, cfg.Filename, client)
	if err != nil {
		return nil, err
	}
	return startPeriodic(fetcher, cfg.FetchConfig), nil
}

// startPeriodicFetcher starts a runner that periodically fetches the topology.
func startPeriodicFetcher(cfg FetchConfig, handler TopoHandler,
	params discovery.FetchParams, client *http.Client) (*periodic.Runner, error) {

	fetcher, err := NewFetcher(handler, params, client)
	if err != nil {
		return nil, err
	}
	return startPeriodic(fetcher, cfg), nil
}

func startPeriodic(fetcher *task, cfg FetchConfig) *periodic.Runner {
	return periodic.StartPeriodicTask(fetcher, periodic.NewTicker(cfg.Interval.Duration),
		cfg.Timeout.Duration)
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

// task is a periodic.Task that fetches the topology from the discovery service.
type task struct {
	log.Logger
	handler  TopoHandler
	fetcher  *topofetcher.Fetcher
	filename string
}

// NewFetcher creates a periodic.Task that fetches the topology from the discovery
// service and calls the provided handler on the received topology.
func NewFetcher(handler TopoHandler, params discovery.FetchParams,
	client *http.Client) (*task, error) {

	if handler == nil {
		return nil, common.NewBasicError("handler must not be nil", nil)
	}
	t := &task{
		Logger:  log.New("Module", "Discovery", "Mode", params.Mode),
		handler: handler,
	}
	var err error
	t.fetcher, err = topofetcher.New(
		itopo.Get().DS,
		params,
		topofetcher.Callbacks{
			Error:  t.handleErr,
			Update: t.handleTopo,
		},
		client,
	)
	if err != nil {
		return nil, common.NewBasicError("Unable to initialize fetcher", err)
	}
	return t, nil
}

// NewWriteFetcher creates a periodic.Task that fetches the topology from the discovery
// service and calls the provided handler on the received topology. If the handler indiacates
// an update, the topology is written to filename.
func NewWriteFetcher(handler TopoHandler, params discovery.FetchParams, filename string,
	client *http.Client) (*task, error) {

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
	if err != nil || !updated {
		return
	}
	if err := util.WriteFile(t.filename, raw, 0644); err != nil {
		t.Error("[discovery] Unable to write new topology to filesystem", "err", err)
		return
	}
	t.Trace("[discovery] Topology written to filesystem",
		"file", t.filename, "params", t.fetcher.Params)
}

func (t *task) handleTopo(topo *topology.Topo) {
	t.callHandler(topo)
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
