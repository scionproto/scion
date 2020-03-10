// Copyright 2018 Anapaya Systems
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

// Package config contains the configuration of sciond.
package config

import (
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

var _ config.Config = (*Config)(nil)

type Config struct {
	General  env.General              `toml:"general,omitempty"`
	Features env.Features             `toml:"features,omitempty"`
	Logging  log.Config               `toml:"log,omitempty"`
	Metrics  env.Metrics              `toml:"metrics,omitempty"`
	Tracing  env.Tracing              `toml:"tracing,omitempty"`
	TrustDB  truststorage.TrustDBConf `toml:"trust_db,omitempty"`
	// PathDB contains the configuration for the PathDB connection.
	PathDB pathstorage.PathDBConf `toml:"path_db,omitempty"`
	SD     SDConfig               `toml:"sd,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.TrustDB,
		&cfg.PathDB,
		&cfg.SD,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.PathDB,
		&cfg.SD,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.TrustDB,
		&cfg.PathDB,
		&cfg.SD,
	)
}

func (cfg *Config) ConfigName() string {
	return "sd_config"
}

var _ config.Config = (*SDConfig)(nil)

type SDConfig struct {
	// Address is the local address to listen on for SCION messages, and to send out messages to
	// other nodes.
	Address string `toml:"address,omitempty"`
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap `toml:"query_interval,omitempty"`
}

func (cfg *SDConfig) InitDefaults() {
	if cfg.Address == "" {
		cfg.Address = sciond.DefaultSCIONDAddress
	}
	if cfg.QueryInterval.Duration == 0 {
		cfg.QueryInterval.Duration = DefaultQueryInterval
	}
}

func (cfg *SDConfig) Validate() error {
	if cfg.QueryInterval.Duration == 0 {
		return serrors.New("QueryInterval must not be zero")
	}
	return nil
}

func (cfg *SDConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, sdSample)
}

func (cfg *SDConfig) ConfigName() string {
	return "sd"
}
