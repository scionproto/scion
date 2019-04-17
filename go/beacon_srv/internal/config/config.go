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

// Package config describes the configuration of the beacon server.
package config

import (
	"io"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/truststorage"
)

var _ config.Config = (*Config)(nil)

// Config is the beacon server configuration.
type Config struct {
	General        env.General
	Logging        env.Logging
	Metrics        env.Metrics
	TrustDB        truststorage.TrustDBConf
	Discovery      idiscovery.Config
	BS             BSConfig
	EnableQUICTest bool
}

// InitDefaults initializes the default values for all parts of the config.
func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// Validate validates all parts of the config.
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// Sample generates a sample config file for the beacon server.
func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// ConfigName is the toml key.
func (cfg *Config) ConfigName() string {
	return "bs_config"
}

var _ config.Config = (*BSConfig)(nil)

// BSConfig holds the configuration specific to the beacon server.
type BSConfig struct {
	config.NoDefaulter
	config.NoValidator
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *BSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, bsconfigSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *BSConfig) ConfigName() string {
	return "bs"
}
