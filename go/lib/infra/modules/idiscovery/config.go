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
	"time"

	"github.com/scionproto/scion/go/lib/util"
)

var (
	// DefaultDynamicFetchInterval is the default time between two dynamic topology queries.
	DefaultDynamicFetchInterval = 5 * time.Second
	// DefaultStaticFetchInterval is the default time between two static topology queries.
	DefaultStaticFetchInterval = 5 * time.Minute
	// DefaultFetchTimeout is the default timeout for a query.
	DefaultFetchTimeout = 1 * time.Second
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
}

func (s *StaticConfig) InitDefaults() {
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
	// Timeout specifies the timout for a single query.
	Timeout util.DurWrap
	// Https indicates whether https must be used to fetch the topology.
	Https bool
}

func (f *FetchConfig) InitDefaults() {
	if f.Interval.Duration == 0 {
		f.Interval.Duration = DefaultDynamicFetchInterval
	}
	if f.Timeout.Duration == 0 {
		f.Timeout.Duration = DefaultFetchTimeout
	}
}
