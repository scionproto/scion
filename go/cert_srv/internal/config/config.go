// Copyright 2018 ETH Zurich, Anapaya Systems
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

package config

import (
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// LeafReissTime is the default value for CSConf.LeafReissTime. It is set to
	// the default path segment TTL to provide optimal coverage.
	LeafReissTime = 6 * time.Hour
	// IssuerReissTime is the default value for CSConf.IssuerReissTime. It is larger
	// than the leaf certificate validity period in order to provide optimal coverage.
	IssuerReissTime = 1*time.Hour + cert.DefaultLeafCertValidity*time.Second
	// ReissReqRate is the default interval between two consecutive reissue requests.
	ReissReqRate = 10 * time.Second
	// ReissueReqTimeout is the default timeout of a reissue request.
	ReissueReqTimeout = 5 * time.Second

	ErrorKeyConf   = "Unable to load KeyConf"
	ErrorCustomers = "Unable to load Customers"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	General   env.General
	Logging   env.Logging
	Metrics   env.Metrics
	Tracing   env.Tracing
	QUIC      env.QUIC         `toml:"quic"`
	Sciond    env.SciondClient `toml:"sd_client"`
	TrustDB   truststorage.TrustDBConf
	Discovery idiscovery.Config
	CS        CSConfig
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.Sciond,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.CS,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.CS,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Sciond,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Tracing,
		&cfg.QUIC,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.CS,
	)
}

func (cfg *Config) ConfigName() string {
	return "cs_config"
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
		return common.NewBasicError("LeafReissueLeadTime must not be zero", nil)
	}
	if cfg.IssuerReissueLeadTime.Duration == 0 {
		return common.NewBasicError("IssuerReissueLeadTime must not be zero", nil)
	}
	if cfg.ReissueRate.Duration == 0 {
		return common.NewBasicError("ReissueRate must not be zero", nil)
	}
	if cfg.ReissueTimeout.Duration == 0 {
		return common.NewBasicError("ReissueTimeout must not be zero", nil)
	}
	return nil
}

func (cfg *CSConfig) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, csconfigSample)
}

func (cfg *CSConfig) ConfigName() string {
	return "cs"
}
