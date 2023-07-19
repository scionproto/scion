// Copyright 2016 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// Package config defines the router's configuration file.
package config

import (
	"io"
	"runtime"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
)

const idSample = "router-1"

type Config struct {
	General  env.General  `toml:"general,omitempty"`
	Features env.Features `toml:"features,omitempty"`
	Logging  log.Config   `toml:"log,omitempty"`
	Metrics  env.Metrics  `toml:"metrics,omitempty"`
	API      api.Config   `toml:"api,omitempty"`
	Router   RouterConfig `toml:"router,omitempty"`
}

type RouterConfig struct {
	ReceiveBufferSize int       `toml:"receive_buffer_size,omitempty"`
	SendBufferSize    int       `toml:"send_buffer_size,omitempty"`
	RunConfig         RunConfig `toml:"run_config,omitempty"`
}

func (cfg *RouterConfig) ConfigName() string {
	return "router"
}

func (cfg *RouterConfig) Validate() error {
	ok := cfg.RunConfig.Validate()
	if cfg.ReceiveBufferSize < 0 {
		ok = false
	}
	if cfg.SendBufferSize < 0 {
		ok = false
	}
	if !ok {
		cfg.InitDefaults()
		log.Error("Provided router config is invalid. Use default settings.")
	}

	return nil
}

func (cfg *RouterConfig) InitDefaults() {
	cfg.ReceiveBufferSize = 1 << 20
	cfg.SendBufferSize = 0 // use system default
}

func (cfg *RouterConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, routerConfigSample)
}

type RunConfig struct {
	NumProcessors         int `toml:"num_processors,omitempty"`
	NumSlowPathProcessors int `toml:"num_slow_processors,omitempty"`
	BatchSize             int `toml:"batch_size,omitempty"`
}

func (cfg *RunConfig) Validate() bool {
	ok := true
	if cfg.BatchSize <= 0 {
		ok = false
	}
	if cfg.NumProcessors == 0 {
		cfg.NumProcessors = runtime.GOMAXPROCS(0)
	}
	if cfg.NumProcessors < 0 {
		ok = false
	}
	if cfg.NumSlowPathProcessors <= 0 {
		ok = false
	}
	if !ok {
		cfg.InitDefaults()
	}
	return ok
}
func (cfg *RunConfig) InitDefaults() {
	cfg.NumProcessors = runtime.GOMAXPROCS(0)
	cfg.NumSlowPathProcessors = 1
	cfg.BatchSize = 256
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Router,
	)
}
