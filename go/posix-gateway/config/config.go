// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	gatewayconfig "github.com/scionproto/scion/go/pkg/gateway/config"
)

type Config struct {
	Features env.Features          `toml:"features,omitempty"`
	Logging  log.Config            `toml:"log,omitempty"`
	Metrics  env.Metrics           `toml:"metrics,omitempty"`
	Daemon   env.SCIONDClient      `toml:"sciond_connection,omitempty"`
	Gateway  gatewayconfig.Gateway `toml:"gateway,omitempty"`
	Tunnel   gatewayconfig.Tunnel  `toml:"tunnel,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: "gateway"},
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Daemon,
		&cfg.Gateway,
		&cfg.Tunnel,
	)
}
