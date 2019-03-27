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

package idiscovery

import (
	"io"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	// DefaultDynamicFetchInterval is the default time between two dynamic topology queries.
	DefaultDynamicFetchInterval = 5 * time.Second
	// DefaultStaticFetchInterval is the default time between two static topology queries.
	DefaultStaticFetchInterval = 5 * time.Minute
	// DefaultFetchTimeout is the default timeout for a query.
	DefaultFetchTimeout = 1 * time.Second
	// DefaultInitialConnectPeriod is the default total amount of time spent attempting
	// to connect to the discovery service on start.
	DefaultInitialConnectPeriod = 20 * time.Second
)

var _ config.Config = (*Config)(nil)

type Config struct {
	// Static contains the parameters for fetching the static
	// topology from the discovery service.
	Static StaticConfig
	// Dynamic contains the parameters for fetching the dynamic
	// topology from the discovery service.
	Dynamic FetchConfig
}

func (cfg *Config) InitDefaults() {
	config.InitAll(&cfg.Static, &cfg.Dynamic)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(&cfg.Static, &cfg.Dynamic)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, ctx, &cfg.Static, &cfg.Dynamic)
}

func (cfg *Config) ConfigName() string {
	return "discovery"
}

var _ config.Config = (*StaticConfig)(nil)

type StaticConfig struct {
	FetchConfig
	// Filename indicates the file that the static topology is written to on updates.
	// The empty string indicates that the static topology is not written.
	Filename string
}

func (cfg *StaticConfig) InitDefaults() {
	cfg.Connect.InitDefaults()
	if cfg.Interval.Duration == 0 {
		cfg.Interval.Duration = DefaultStaticFetchInterval
	}
	if cfg.Timeout.Duration == 0 {
		cfg.Timeout.Duration = DefaultFetchTimeout
	}
}

func (cfg *StaticConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, staticSample)
	config.WriteSample(dst, path, ctx, &cfg.Connect)
}

func (cfg *StaticConfig) ConfigName() string {
	return "static"
}

var _ config.Config = (*FetchConfig)(nil)

type FetchConfig struct {
	// Enable indicates whether the discovery service is queried
	// for updated topologies.
	Enable bool
	// Interval specifies the time between two queries.
	Interval util.DurWrap
	// Timeout specifies the timeout for a single query.
	Timeout util.DurWrap
	// Https indicates whether https must be used to fetch the topology.
	Https bool
	// Connect contains the parameters for the initial connection
	// check to the discovery service.
	Connect ConnectParams
}

func (cfg *FetchConfig) InitDefaults() {
	cfg.Connect.InitDefaults()
	if cfg.Interval.Duration == 0 {
		cfg.Interval.Duration = DefaultDynamicFetchInterval
	}
	if cfg.Timeout.Duration == 0 {
		cfg.Timeout.Duration = DefaultFetchTimeout
	}
}

func (cfg *FetchConfig) Validate() error {
	if cfg.Interval.Duration == 0 {
		return common.NewBasicError("Interval must not be zero", nil)
	}
	if cfg.Timeout.Duration == 0 {
		return common.NewBasicError("Timeout must not be zero", nil)
	}
	return cfg.Connect.Validate()
}

func (cfg *FetchConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, dynamicSample)
	config.WriteSample(dst, path, ctx, &cfg.Connect)
}

func (cfg *FetchConfig) ConfigName() string {
	return "dynamic"
}

var _ config.Config = (*ConnectParams)(nil)

type ConnectParams struct {
	// InitialPeriod indicates for how long the process tries to get a valid
	// response from the discovery service until FailAction is executed.
	InitialPeriod util.DurWrap
	// FailAction indicates the action that should be taken if no topology can
	// be fetched from the discovery service within the InitialPeriod.
	FailAction FailAction
}

func (cfg *ConnectParams) InitDefaults() {
	if cfg.InitialPeriod.Duration == 0 {
		cfg.InitialPeriod.Duration = DefaultInitialConnectPeriod
	}
	if cfg.FailAction != FailActionFatal {
		cfg.FailAction = FailActionContinue
	}
}

func (cfg *ConnectParams) Validate() error {
	if cfg.InitialPeriod.Duration == 0 {
		return common.NewBasicError("InitialPeriod must not be zero", nil)
	}
	return cfg.FailAction.Validate()
}

func (cfg *ConnectParams) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, connectSample)
}

func (cfg *ConnectParams) ConfigName() string {
	return "connect"
}

type FailAction string

const (
	// FailActionFatal indicates that the process exits on error.
	FailActionFatal FailAction = "Fatal"
	// FailActionContinue indicates that the process continues on error.
	FailActionContinue FailAction = "Continue"
)

func (f *FailAction) Validate() error {
	switch *f {
	case FailActionContinue, FailActionFatal:
		return nil
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", string(*f))
	}
}

func (f *FailAction) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case strings.ToLower(string(FailActionFatal)):
		*f = FailActionFatal
	case strings.ToLower(string(FailActionContinue)):
		*f = FailActionContinue
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", string(text))
	}
	return nil
}
