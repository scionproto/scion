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

// Package sdconfig contains the configuration of sciond.
package sdconfig

import (
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

type Config struct {
	// Address to listen on via the reliable socket protocol. If empty,
	// a reliable socket server on the default socket is started.
	Reliable string
	// Address to listen on for normal unixgram messages. If empty, a
	// unixgram server on the default socket is started.
	Unix string
	// If set to True, the socket is removed before being created
	DeleteSocket bool
	// Public is the local address to listen on for SCION messages (if Bind is
	// not set), and to send out messages to other nodes.
	Public *snet.Addr
	// If set, Bind is the preferred local address to listen on for SCION
	// messages.
	Bind *snet.Addr
	// PathDB contains the file location  of the path segment database.
	PathDB string
	// queryInterval specifies after how much time segments
	// for a destination should be refetched.
	queryInterval duration `toml:"QueryInterval"`
}

func (c *Config) InitDefaults() {
	if c.Reliable == "" {
		c.Reliable = sciond.DefaultSCIONDPath
	}
	if c.Unix == "" {
		c.Unix = "/run/shm/sciond/default-unix.sock"
	}
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
