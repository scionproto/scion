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
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/common"
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

type Config struct {
	// Static contains the parameters for fetching the static
	// topology from the discovery service.
	Static StaticConfig
	// Dynamic contains the parameters for fetching the dynamic
	// topology from the discovery service.
	Dynamic FetchConfig
}

func (c *Config) InitDefaults() {
	c.Static.InitDefaults()
	c.Dynamic.InitDefaults()
}

type StaticConfig struct {
	FetchConfig
	// Filename indicates the file that the static topology is written to on updates.
	// The empty string indicates that the static topology is not written.
	Filename string
}

func (s *StaticConfig) InitDefaults() {
	s.Connect.InitDefaults()
	if s.Interval.Duration == 0 {
		s.Interval.Duration = DefaultStaticFetchInterval
	}
	if s.Timeout.Duration == 0 {
		s.Timeout.Duration = DefaultFetchTimeout
	}
}

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

func (f *FetchConfig) InitDefaults() {
	f.Connect.InitDefaults()
	if f.Interval.Duration == 0 {
		f.Interval.Duration = DefaultDynamicFetchInterval
	}
	if f.Timeout.Duration == 0 {
		f.Timeout.Duration = DefaultFetchTimeout
	}
}

type ConnectParams struct {
	// InitialPeriod indicates for how long the process tries to get a valid
	// response from the discovery service until FailAction is executed.
	InitialPeriod util.DurWrap
	// FailAction indicates the action that should be taken if no topology can
	// be fetched from the discovery service within the InitialPeriod.
	FailAction FailAction
}

func (c *ConnectParams) InitDefaults() {
	if c.InitialPeriod.Duration == 0 {
		c.InitialPeriod.Duration = DefaultInitialConnectPeriod
	}
	if c.FailAction != FailActionFatal {
		c.FailAction = FailActionContinue
	}
}

type FailAction string

const (
	// FailActionFatal indicates that the process exits on error.
	FailActionFatal FailAction = "Fatal"
	// FailActionContinue indicates that the process continues on error.
	FailActionContinue FailAction = "Continue"
)

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
