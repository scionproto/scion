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

// Package config contains the configuration of the path server.
package config

import (
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval      = 5 * time.Minute
	DefaultCryptoSyncInterval = 30 * time.Second
)

var _ config.Config = (*Config)(nil)

type Config struct {
	General   env.General
	Logging   env.Logging
	Metrics   env.Metrics
	Client    env.Client
	Server    env.Server
	TrustDB   truststorage.TrustDBConf
	Discovery idiscovery.Config
	PS        PSConfig
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.PS,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.PS,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.TrustDB,
		&cfg.Discovery,
		&cfg.PS,
	)
}

func (cfg *Config) ConfigName() string {
	return "ps_config"
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
		return common.NewBasicError("QueryInterval must not be zero", nil)
	}
	return config.ValidateAll(&cfg.PathDB, &cfg.RevCache)
}

func (cfg *PSConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, psSample)
	config.WriteSample(dst, path, ctx, &cfg.PathDB, &cfg.RevCache)
}

func (cfg *PSConfig) ConfigName() string {
	return "ps"
}
