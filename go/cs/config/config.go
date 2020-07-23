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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/storage"
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
	// DefaultQueryInterval is the default interval after which the segment
	// cache expires.
	DefaultQueryInterval = 5 * time.Minute
	// DefaultMaxASValidity is the default validity period for renewed AS certificates.
	DefaultMaxASValidity = 3 * 24 * time.Hour
)

// Error values
const (
	ErrKeyConf   common.ErrMsg = "Unable to load KeyConf"
	ErrCustomers common.ErrMsg = "Unable to load Customers"
)

var _ config.Config = (*Config)(nil)

// Config is the control server configuration.
type Config struct {
	General   env.General      `toml:"general,omitempty"`
	Features  env.Features     `toml:"features,omitempty"`
	Logging   log.Config       `toml:"log,omitempty"`
	Metrics   env.Metrics      `toml:"metrics,omitempty"`
	Tracing   env.Tracing      `toml:"tracing,omitempty"`
	QUIC      env.QUIC         `toml:"quic,omitempty"`
	BeaconDB  storage.DBConfig `toml:"beacon_db,omitempty"`
	TrustDB   storage.DBConfig `toml:"trust_db,omitempty"`
	RenewalDB storage.DBConfig `toml:"renewal_db,omitempty"`
	PathDB    storage.DBConfig `toml:"path_db,omitempty"`
	BS        BSConfig         `toml:"beaconing,omitempty"`
	PS        PSConfig         `toml:"path,omitempty"`
	CA        CA               `toml:"ca,omitempty"`
}

// InitDefaults initializes the default values for all parts of the config.
func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.BeaconDB,
		&cfg.TrustDB,
		&cfg.RenewalDB,
		&cfg.PathDB,
		&cfg.BS,
		&cfg.PS,
		&cfg.CA,
	)
}

// Validate validates all parts of the config.
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.BeaconDB,
		&cfg.TrustDB,
		&cfg.RenewalDB,
		&cfg.PathDB,
		&cfg.BS,
		&cfg.PS,
		&cfg.CA,
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
		config.OverrideName(
			config.FormatData(
				&cfg.BeaconDB,
				storage.SetID(storage.SampleBeaconDB, idSample).Connection,
			),
			"beacon_db",
		),
		config.OverrideName(
			config.FormatData(
				&cfg.TrustDB,
				storage.SetID(storage.SampleTrustDB, idSample).Connection,
			),
			"trust_db",
		),
		config.OverrideName(
			config.FormatData(
				&cfg.RenewalDB,
				storage.SetID(storage.SampleRenewalDB, idSample).Connection,
			),
			"renewal_db",
		),
		config.OverrideName(
			config.FormatData(
				&cfg.PathDB,
				storage.SetID(storage.SamplePathDB, idSample).Connection,
			),
			"path_db",
		),
		&cfg.BS,
		&cfg.PS,
		&cfg.CA,
	)
}

var _ config.Config = (*BSConfig)(nil)

// BSConfig holds the configuration specific to the beacon server.
type BSConfig struct {
	// KeepaliveInterval is the interval between sending interface keepalives.
	KeepaliveInterval util.DurWrap `toml:"keepalive_interval,omitempty"`
	// KeepaliveTimeout is the timeout indicating how long an interface can
	// receive no keepalive until it is considered expired.
	KeepaliveTimeout util.DurWrap `toml:"keepalive_timeout,omitempty"`
	// OriginationInterval is the interval between originating beacons in a core BS.
	OriginationInterval util.DurWrap `toml:"origination_interval,omitempty"`
	// PropagationInterval is the interval between propagating beacons.
	PropagationInterval util.DurWrap `toml:"propagation_interval,omitempty"`
	// RegistrationInterval is the interval between registering segments.
	RegistrationInterval util.DurWrap `toml:"registration_interval,omitempty"`
	// ExpiredCheckInterval is the interval between checking whether interfaces
	// have expired and should be revoked.
	ExpiredCheckInterval util.DurWrap `toml:"expired_check_interval,omitempty"`
	// RevTTL is the revocation TTL. (default 10s)
	RevTTL util.DurWrap `toml:"rev_ttl,omitempty"`
	// RevOverlap specifies for how long before the expiry of an existing revocation the revoker
	// can reissue a new revocation. (default 5s)
	RevOverlap util.DurWrap `toml:"rev_overlap,omitempty"`
	// Policies contains the policy files.
	Policies Policies `toml:"policies,omitempty"`
}

// InitDefaults the default values for the durations that are equal to zero.
func (cfg *BSConfig) InitDefaults() {
}

// Validate validates that all durations are set.
func (cfg *BSConfig) Validate() error {
	if cfg.KeepaliveInterval.Duration == 0 {
		initDurWrap(&cfg.KeepaliveInterval, DefaultKeepaliveInterval)
	}
	if cfg.KeepaliveTimeout.Duration == 0 {
		initDurWrap(&cfg.KeepaliveTimeout, DefaultKeepaliveTimeout)
	}
	if cfg.OriginationInterval.Duration == 0 {
		initDurWrap(&cfg.OriginationInterval, DefaultOriginationInterval)
	}
	if cfg.PropagationInterval.Duration == 0 {
		initDurWrap(&cfg.PropagationInterval, DefaultPropagationInterval)
	}
	if cfg.RegistrationInterval.Duration == 0 {
		initDurWrap(&cfg.RegistrationInterval, DefaultRegistrationInterval)
	}
	if cfg.ExpiredCheckInterval.Duration == 0 {
		initDurWrap(&cfg.ExpiredCheckInterval, DefaultExpiredCheckInterval)
	}
	if cfg.RevTTL.Duration == 0 {
		initDurWrap(&cfg.RevTTL, DefaultRevTTL)
	}
	if cfg.RevTTL.Duration < path_mgmt.MinRevTTL {
		return common.NewBasicError("rev_ttl must be equal or greater than MinRevTTL", nil,
			"MinRevTTL", path_mgmt.MinRevTTL)
	}
	if cfg.RevOverlap.Duration == 0 {
		initDurWrap(&cfg.RevOverlap, DefaultRevOverlap)
	}
	if cfg.RevOverlap.Duration > cfg.RevTTL.Duration {
		return serrors.New("rev_overlap cannot be greater than rev_ttl")
	}
	return nil
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *BSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, bsSample)
	config.WriteSample(dst, path, ctx, &cfg.Policies)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *BSConfig) ConfigName() string {
	return "beaconing"
}

func initDurWrap(w *util.DurWrap, def time.Duration) {
	if w.Duration == 0 {
		w.Duration = def
	}
}

var _ config.Config = (*PSConfig)(nil)

type PSConfig struct {
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap `toml:"query_interval,omitempty"`
}

func (cfg *PSConfig) InitDefaults() {
	if cfg.QueryInterval.Duration == 0 {
		cfg.QueryInterval.Duration = DefaultQueryInterval
	}
}

func (cfg *PSConfig) Validate() error {
	if cfg.QueryInterval.Duration == 0 {
		return serrors.New("query_interval must not be zero")
	}
	return nil
}

func (cfg *PSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, psSample)
}

func (cfg *PSConfig) ConfigName() string {
	return "path"
}

var _ config.Config = (*Policies)(nil)

// Policies contains the file paths of the policies.
type Policies struct {
	config.NoDefaulter
	config.NoValidator
	// Propagation contains the file path for the propagation policy. If this
	// is the empty string, the default policy is used.
	Propagation string `toml:"propagation,omitempty"`
	// CoreRegistration contains the file path for the core registration
	// policy. If this is the empty string, the default policy is used. In a
	// non-core beacon server, this field is ignored.
	CoreRegistration string `toml:"core_registration,omitempty"`
	// UpRegistration contains the file path for the up registration policy. If
	// this is the empty string, the default policy is used. In a core beacon
	// server, this field is ignored.
	UpRegistration string `toml:"up_registration,omitempty"`
	// DownRegistration contains the file path for the down registration policy.
	// If this is the empty string, the default policy is used. In a core beacon
	// server, this field is ignored.
	DownRegistration string `toml:"down_registration,omitempty"`
	// HiddenPathRegistration contains the file path for the hidden path registration policy
	// and the corresponding hidden path groups.
	// If this is the empty string, no hidden path functionality is used.
	HiddenPathRegistration string `toml:"hidden_path_registration,omitempty"`
}

// Sample generates a sample for the beacon server specific configuration.
func (cfg *Policies) Sample(dst io.Writer, _ config.Path, _ config.CtxMap) {
	config.WriteString(dst, policiesSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *Policies) ConfigName() string {
	return "policies"
}

// CA is the CA configuration.
type CA struct {
	config.NoDefaulter
	// MaxASValidity is the maximum AS certificate lifetime.
	MaxASValidity util.DurWrap `toml:"max_as_validity,omitempty"`
}

func (cfg *CA) Validate() error {
	if cfg.MaxASValidity.Duration == 0 {
		cfg.MaxASValidity.Duration = DefaultMaxASValidity
	}
	return nil
}

func (cfg *CA) Sample(dst io.Writer, _ config.Path, _ config.CtxMap) {
	config.WriteString(dst, caSample)
}

func (cfg *CA) ConfigName() string {
	return "ca"
}
