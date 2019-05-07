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

	"github.com/scionproto/scion/go/beacon_srv/internal/beaconstorage"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
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
)

var _ config.Config = (*Config)(nil)

// Config is the beacon server configuration.
type Config struct {
	General        env.General
	Logging        env.Logging
	Metrics        env.Metrics
	TrustDB        truststorage.TrustDBConf
	BeaconDB       beaconstorage.BeaconDBConf
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
		&cfg.BeaconDB,
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
		&cfg.BeaconDB,
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
		&cfg.BeaconDB,
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
	// KeepaliveInterval is the interval between sending interface keepalives.
	KeepaliveInterval util.DurWrap
	// KeepaliveTimeout is the timeout indicating how long an interface can
	// receive no keepalive until it is considered expired.
	KeepaliveTimeout util.DurWrap
	// OriginationInterval is the interval between originating beacons in a core BS.
	OriginationInterval util.DurWrap
	// PropagationInterval is the interval between propagating beacons.
	PropagationInterval util.DurWrap
	// RegistrationInterval is the interval between registering segments.
	RegistrationInterval util.DurWrap
}

// InitDefaults the default values for the durations that are equal to zero.
func (cfg *BSConfig) InitDefaults() {
	initDurWrap(&cfg.KeepaliveInterval, DefaultKeepaliveInterval)
	initDurWrap(&cfg.KeepaliveTimeout, DefaultKeepaliveTimeout)
	initDurWrap(&cfg.OriginationInterval, DefaultOriginationInterval)
	initDurWrap(&cfg.PropagationInterval, DefaultPropagationInterval)
	initDurWrap(&cfg.RegistrationInterval, DefaultRegistrationInterval)
}

// Validate validates that all durations are set.
func (cfg *BSConfig) Validate() error {
	if cfg.KeepaliveInterval.Duration == 0 {
		return common.NewBasicError("KeepaliveInterval not set", nil)
	}
	if cfg.KeepaliveTimeout.Duration == 0 {
		return common.NewBasicError("KeepaliveTimeout not set", nil)
	}
	if cfg.OriginationInterval.Duration == 0 {
		return common.NewBasicError("OriginationInterval not set", nil)
	}
	if cfg.PropagationInterval.Duration == 0 {
		return common.NewBasicError("PropagationInterval not set", nil)
	}
	if cfg.RegistrationInterval.Duration == 0 {
		return common.NewBasicError("RegistrationInterval not set", nil)
	}
	return nil
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *BSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, bsconfigSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *BSConfig) ConfigName() string {
	return "bs"
}

func initDurWrap(w *util.DurWrap, def time.Duration) {
	if w.Duration == 0 {
		w.Duration = def
	}
}
