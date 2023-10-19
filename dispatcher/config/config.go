// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

// Package config contains the configuration of the SCION dispatcher.
package config

import (
	"context"
	"fmt"
	"io"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/topology"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Features   env.Features `toml:"features,omitempty"`
	Logging    log.Config   `toml:"log,omitempty"`
	Metrics    env.Metrics  `toml:"metrics,omitempty"`
	API        api.Config   `toml:"api,omitempty"`
	Dispatcher Dispatcher   `toml:"dispatcher,omitempty"`
}

// Dispatcher contains the dispatcher specific config.
type Dispatcher struct {
	config.NoDefaulter
	// ID is the SCION element ID. This is used to choose the relevant
	// portion of the topology file for some services.
	ID string `toml:"id,omitempty"`
	// Topologies contain a list of topology files to be loaded.
	//
	// When supporting regular endhost, this value can be omitted.
	// When supporting infrastructure nodes, the list must contain the
	// topologies for their respective ASes. Normally, in a developer/testing
	// environment this list may contain multiple ASes.
	Topologies []string `toml:"topologies,omitempty"`
	// UnderlayPort is the native port opened by the dispatcher (default 30041)
	UnderlayPort int `toml:"underlay_port,omitempty"`
}

func (cfg *Dispatcher) Validate() error {
	if cfg.UnderlayPort == 0 {
		cfg.UnderlayPort = topology.EndhostPort
	}
	if cfg.ID == "" {
		return serrors.New("id must be set")
	}
	return nil
}

func (cfg *Dispatcher) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(dispSample, idSample))
}

func (cfg *Dispatcher) ConfigName() string {
	return "dispatcher"
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Dispatcher,
	)
}

func (cfg *Config) ConfigName() string {
	return "dispatcher_config"
}

func (cfg *Config) Topologies(ctx context.Context) (map[addr.AS]*topology.Loader, error) {
	topologies := make(map[addr.AS]*topology.Loader)
	for _, path := range cfg.Dispatcher.Topologies {
		topo, err := topology.NewLoader(topology.LoaderCfg{
			File:   path,
			Reload: app.SIGHUPChannel(ctx),
		})
		if err != nil {
			log.Error("loading topologies", "err", err)
			continue
		}
		topologies[topo.IA().AS()] = topo
	}
	return topologies, nil
}
