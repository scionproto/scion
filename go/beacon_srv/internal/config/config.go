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
	"time"

	"github.com/scionproto/scion/go/cs/beaconstorage"
	controlconfig "github.com/scionproto/scion/go/cs/config"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/truststorage"
)

const (
	idSample = "bs-1"
)

const (
	// DefaultKeepaliveInterval is the default interval between sending
	// interface keepalives.
	DefaultKeepaliveInterval = time.Second
	// DefaultKeepaliveTimeout is the timeout indicating how long an interface
	// can receive no keepalive default until it is considered expired.
	DefaultKeepaliveTimeout = 3 * time.Second
	// DefaultOriginationInterval is the default interval between originating
	// beacons in a core BS.
	DefaultOriginationInterval = 5 * time.Second
	// DefaultPropagationInterval is the default interval between propagating beacons.
	DefaultPropagationInterval = 5 * time.Second
	// DefaultRegistrationInterval is the default interval between registering segments.
	DefaultRegistrationInterval = 5 * time.Second
	// DefaultExpiredCheckInterval is the default interval between checking for
	// expired interfaces.
	DefaultExpiredCheckInterval = 200 * time.Millisecond
	// DefaultRevTTL is the default revocation TTL.
	DefaultRevTTL = path_mgmt.MinRevTTL
	// DefaultRevOverlap specifies the default for how long before the expiry of an existing
	// revocation the revoker can reissue a new revocation.
	DefaultRevOverlap = DefaultRevTTL / 2
)

var _ config.Config = (*Config)(nil)

// Config is the beacon server configuration.
type Config struct {
	General        env.General
	Features       env.Features
	Logging        env.Logging
	Metrics        env.Metrics
	Tracing        env.Tracing
	QUIC           env.QUIC `toml:"quic"`
	TrustDB        truststorage.TrustDBConf
	BeaconDB       beaconstorage.BeaconDBConf
	Discovery      idiscovery.Config
	BS             controlconfig.BSConfig
	EnableQUICTest bool
}

// InitDefaults initializes the default values for all parts of the config.
func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// Validate validates all parts of the config.
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// Sample generates a sample config file for the beacon server.
func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.QUIC,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.Discovery,
		&cfg.BS,
	)
}

// ConfigName is the toml key.
func (cfg *Config) ConfigName() string {
	return "bs_config"
}
