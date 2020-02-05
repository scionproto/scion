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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/serrors"
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
	// DefaultExpiredCheckInterval is the default interval between checking for
	// expired interfaces.
	DefaultExpiredCheckInterval = 200 * time.Millisecond
	// DefaultRevTTL is the default revocation TTL.
	DefaultRevTTL = path_mgmt.MinRevTTL
	// DefaultRevOverlap specifies the default for how long before the expiry of an existing
	// revocation the revoker can reissue a new revocation.
	DefaultRevOverlap = DefaultRevTTL / 2

	// LeafReissTime is the default value for CSConf.LeafReissTime. It is set to
	// the default path segment TTL to provide optimal coverage.
	LeafReissTime = 6 * time.Hour
	// IssuerReissTime is the default value for CSConf.IssuerReissTime. It is larger
	// than the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = (3*24 + 1) * time.Hour
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second
	// ReissueReqTimeout is the default timeout of a reissue request.
	ReissueReqTimeout = 5 * time.Second
)

var (
	DefaultQueryInterval      = 5 * time.Minute
	DefaultCryptoSyncInterval = 30 * time.Second
)

// Error values
const (
	ErrKeyConf   common.ErrMsg = "Unable to load KeyConf"
	ErrCustomers common.ErrMsg = "Unable to load Customers"
)

var _ config.Config = (*Config)(nil)

// Config is the beacon server configuration.
type Config struct {
	General        env.General
	Features       env.Features
	Logging        env.Logging
	Metrics        env.Metrics
	Tracing        env.Tracing
	QUIC           env.QUIC         `toml:"quic"`
	SCIOND         env.SCIONDClient `toml:"sd_client"`
	TrustDB        truststorage.TrustDBConf
	BeaconDB       beaconstorage.BeaconDBConf
	BS             BSConfig
	CS             CSConfig
	PS             PSConfig
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
		&cfg.SCIOND,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.BS,
		&cfg.CS,
		&cfg.PS,
	)
}

// Validate validates all parts of the config.
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.SCIOND,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.BS,
		&cfg.CS,
		&cfg.PS,
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
		&cfg.SCIOND,
		&cfg.TrustDB,
		&cfg.BeaconDB,
		&cfg.BS,
		&cfg.CS,
		&cfg.PS,
	)
}

// ConfigName is the toml key.
func (cfg *Config) ConfigName() string {
	return "cs_config"
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
	config.WriteString(dst, BSSample)
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

var _ config.Config = (*CSConfig)(nil)

type CSConfig struct {
	// LeafReissueLeadTime indicates how long in advance of leaf cert expiration
	// the reissuance process starts.
	LeafReissueLeadTime util.DurWrap
	// IssuerReissueLeadTime indicates how long in advance core cert expiration
	// the self reissuance process starts.
	IssuerReissueLeadTime util.DurWrap
	// ReissueRate is the interval between two consecutive reissue requests.
	ReissueRate util.DurWrap
	// ReissueTimeout is the timeout for resissue request.
	ReissueTimeout util.DurWrap
	// AutomaticRenewal whether automatic reissuing is enabled.
	AutomaticRenewal bool
	// DisableCorePush disables the core pusher task.
	DisableCorePush bool
}

func (cfg *CSConfig) InitDefaults() {
	if cfg.LeafReissueLeadTime.Duration == 0 {
		cfg.LeafReissueLeadTime.Duration = LeafReissTime
	}
	if cfg.IssuerReissueLeadTime.Duration == 0 {
		cfg.IssuerReissueLeadTime.Duration = IssuerReissTime
	}
	if cfg.ReissueRate.Duration == 0 {
		cfg.ReissueRate.Duration = ReissReqRate
	}
	if cfg.ReissueTimeout.Duration == 0 {
		cfg.ReissueTimeout.Duration = ReissueReqTimeout
	}
}

func (cfg *CSConfig) Validate() error {
	if cfg.LeafReissueLeadTime.Duration == 0 {
		return serrors.New("LeafReissueLeadTime must not be zero")
	}
	if cfg.IssuerReissueLeadTime.Duration == 0 {
		return serrors.New("IssuerReissueLeadTime must not be zero")
	}
	if cfg.ReissueRate.Duration == 0 {
		return serrors.New("ReissueRate must not be zero")
	}
	if cfg.ReissueTimeout.Duration == 0 {
		return serrors.New("ReissueTimeout must not be zero")
	}
	return nil
}

func (cfg *CSConfig) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, CSSample)
}

func (cfg *CSConfig) ConfigName() string {
	return "cs"
}

var _ config.Config = (*PSConfig)(nil)

type PSConfig struct {
	// SegSync enables the "old" replication of down segments between cores,
	// using SegSync messages.
	SegSync  bool
	PathDB   pathstorage.PathDBConf
	RevCache pathstorage.RevCacheConf
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap
	// CryptoSyncInterval specifies the interval of crypto pushes towards
	// the local CS.
	CryptoSyncInterval util.DurWrap
}

func (cfg *PSConfig) InitDefaults() {
	if cfg.QueryInterval.Duration == 0 {
		cfg.QueryInterval.Duration = DefaultQueryInterval
	}
	if cfg.CryptoSyncInterval.Duration == 0 {
		cfg.CryptoSyncInterval.Duration = DefaultCryptoSyncInterval
	}
	config.InitAll(&cfg.PathDB, &cfg.RevCache)
}

func (cfg *PSConfig) Validate() error {
	if cfg.QueryInterval.Duration == 0 {
		return serrors.New("QueryInterval must not be zero")
	}
	return config.ValidateAll(&cfg.PathDB, &cfg.RevCache)
}

func (cfg *PSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, PSSample)
	config.WriteSample(dst, path, ctx, &cfg.PathDB, &cfg.RevCache)
}

func (cfg *PSConfig) ConfigName() string {
	return "ps"
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
	config.WriteString(dst, PoliciesSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *Policies) ConfigName() string {
	return "policies"
}
