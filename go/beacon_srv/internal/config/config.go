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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
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
	// ExpiredCheckInterval is the interval between checking whether interfaces
	// have expired and should be revoked.
	ExpiredCheckInterval util.DurWrap
	// RevTTL is the revocation TTL. (default 10s)
	RevTTL util.DurWrap
	// RevOverlap specifies for how long before the expiry of an existing revocation the revoker
	// can reissue a new revocation. (default 5s)
	RevOverlap util.DurWrap
	// Policies contains the policy files.
	Policies Policies
}

// InitDefaults the default values for the durations that are equal to zero.
func (cfg *BSConfig) InitDefaults() {
	initDurWrap(&cfg.KeepaliveInterval, DefaultKeepaliveInterval)
	initDurWrap(&cfg.KeepaliveTimeout, DefaultKeepaliveTimeout)
	initDurWrap(&cfg.OriginationInterval, DefaultOriginationInterval)
	initDurWrap(&cfg.PropagationInterval, DefaultPropagationInterval)
	initDurWrap(&cfg.RegistrationInterval, DefaultRegistrationInterval)
	initDurWrap(&cfg.ExpiredCheckInterval, DefaultExpiredCheckInterval)
	initDurWrap(&cfg.RevTTL, DefaultRevTTL)
	initDurWrap(&cfg.RevOverlap, DefaultRevOverlap)
}

// Validate validates that all durations are set.
func (cfg *BSConfig) Validate() error {
	if cfg.KeepaliveInterval.Duration == 0 {
		return serrors.New("KeepaliveInterval not set")
	}
	if cfg.KeepaliveTimeout.Duration == 0 {
		return serrors.New("KeepaliveTimeout not set")
	}
	if cfg.OriginationInterval.Duration == 0 {
		return serrors.New("OriginationInterval not set")
	}
	if cfg.PropagationInterval.Duration == 0 {
		return serrors.New("PropagationInterval not set")
	}
	if cfg.RegistrationInterval.Duration == 0 {
		return serrors.New("RegistrationInterval not set")
	}
	if cfg.ExpiredCheckInterval.Duration == 0 {
		return serrors.New("ExpiredCheckInterval not set")
	}
	if cfg.RevTTL.Duration == 0 {
		return serrors.New("RevTTL is not set")
	}
	if cfg.RevTTL.Duration < path_mgmt.MinRevTTL {
		return common.NewBasicError("RevTTL must be equal or greater than MinRevTTL", nil,
			"MinRevTTL", path_mgmt.MinRevTTL)
	}
	if cfg.RevOverlap.Duration == 0 {
		return serrors.New("RevOverlap not set")
	}
	if cfg.RevOverlap.Duration > cfg.RevTTL.Duration {
		return serrors.New("RevOverlap cannot be greater than RevTTL")
	}
	return nil
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *BSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, controlconfig.BSSample)
	config.WriteSample(dst, path, ctx, &cfg.Policies)
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

var _ config.Config = (*Policies)(nil)

// Policies contains the file paths of the policies.
type Policies struct {
	config.NoDefaulter
	config.NoValidator
	// Propagation contains the file path for the propagation policy. If this
	// is the empty string, the default policy is used.
	Propagation string
	// CoreRegistration contains the file path for the core registration
	// policy. If this is the empty string, the default policy is used. In a
	// non-core beacon server, this field is ignored.
	CoreRegistration string
	// UpRegistration contains the file path for the up registration policy. If
	// this is the empty string, the default policy is used. In a core beacon
	// server, this field is ignored.
	UpRegistration string
	// DownRegistration contains the file path for the down registration policy.
	// If this is the empty string, the default policy is used. In a core beacon
	// server, this field is ignored.
	DownRegistration string
	// HiddenPathRegistration contains the file path for the hidden path registration policy
	// and the corresponding hidden path groups.
	// If this is the empty string, no hidden path functionality is used.
	HiddenPathRegistration string
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *Policies) Sample(dst io.Writer, _ config.Path, _ config.CtxMap) {
	config.WriteString(dst, controlconfig.PoliciesSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *Policies) ConfigName() string {
	return "policies"
}
