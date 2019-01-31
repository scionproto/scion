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
// periodically fetches the dynamic topology from the discovery service.
// The received topology is set in itopo.
//
// A periodic.Taks with a customized TopoHandler can be created with
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
)

// TopoHandler handles a topology fetched from the discovery service, and
// returns whether the provided topology is an update.
type TopoHandler func(topo *topology.Topo) (bool, error)

// dynamicSetter sets the dynamic topology in itopo with the provided topology.
func dynamicSetter(topo *topology.Topo) (bool, error) {
	_, updated, err := itopo.SetDynamic(topo)
	return updated, err
}

type Runners struct {
	// Dynamic periodically fetches the dynamic topology and sets it in itopo.
	Dynamic *periodic.Runner
	// Cleaner periodically cleans the expired dynamic topology in itopo.
	Cleaner *periodic.Runner
}

// StartRunners starts the runners for the specified configuration.
func StartRunners(cfg Config, file discovery.File, client *http.Client) (Runners, error) {
	r := Runners{}
	if cfg.Dynamic.Enable {
		var err error
		r.Dynamic, err = startPeriodic(
			cfg.Dynamic,
			dynamicSetter,
			discovery.FetchParams{
				Mode:  discovery.Dynamic,
				Https: cfg.Dynamic.Https,
				File:  file,
			},
			client,
		)
		if err != nil {
			return Runners{}, err
		}
		r.Cleaner = itopo.StartCleaner(1*time.Second, 1*time.Second)
		log.Info("[idiscovery] Started dynamic topology fetcher")
	}
	return r, nil
}

// Stop stops all runners.
func (r *Runners) Stop() {
	if r.Dynamic != nil {
		r.Dynamic.Stop()
	}
	if r.Cleaner != nil {
		r.Cleaner.Stop()
	}
}

// Kill kills all runners.
func (r *Runners) Kill() {
	if r.Dynamic != nil {
		r.Dynamic.Kill()
	}
	if r.Cleaner != nil {
		r.Cleaner.Kill()
	}
}

// startPeriodic starts a runner that periodically fetches the topology.
func startPeriodic(cfg FetchConfig, handler TopoHandler,
	params discovery.FetchParams, client *http.Client) (*periodic.Runner, error) {

	fetcher, err := NewFetcher(handler, params, client)
	if err != nil {
		return nil, err
	}
	runner := periodic.StartPeriodicTask(fetcher, periodic.NewTicker(cfg.Interval.Duration),
		cfg.Timeout.Duration)
	return runner, nil
}

// task is a periodic.Task that fetches the topology from the discovery service.
type task struct {
	log.Logger
	handler TopoHandler
	fetcher *topofetcher.Fetcher
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

func (t *task) handleTopo(topo *topology.Topo) {
	updated, err := t.handler(topo)
	if err != nil {
		t.Error("[discovery] Unable to handle topology", "err", err)
	} else if updated {
		t.Trace("[discovery] Set topology", "params", t.fetcher.Params)
	}
}
