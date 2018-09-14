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

// Package psconfig contains the configuration of the path server.
package psconfig

import (
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

type Config struct {
	// SegSync enables the "old" replication of down segments between cores,
	// using SegSync messages.
	SegSync bool
	PathDB  string
	// queryInterval specifies after how much time segments
	// for a destination should be refetched.
	queryInterval duration `toml:"QueryInterval"`
}

func (c *Config) InitDefaults() {
	if c.queryInterval.Duration == 0 {
		c.queryInterval.Duration = DefaultQueryInterval
	}
}

func (c *Config) QueryInterval() time.Duration {
	return c.queryInterval.Duration
}

var _ (toml.TextUnmarshaler) = (*duration)(nil)

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = util.ParseDuration(string(text))
	return err
}
