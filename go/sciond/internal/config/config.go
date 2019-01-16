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

// Package config contains the configuration of sciond.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/pathstorage"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

type Config struct {
	General env.General
	Logging env.Logging
	Metrics env.Metrics
	TrustDB truststorage.TrustDBConf
	SD      SDConfig
}

func (c *Config) InitDefaults() {
	c.SD.initDefaults()
}

type SDConfig struct {
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
	// PathDB contains the configuration for the PathDB connection.
	PathDB pathstorage.PathDBConf
	// RevCache contains the configuration for the RevCache connection.
	RevCache pathstorage.RevCacheConf
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap
}

func (c *SDConfig) initDefaults() {
	if c.Reliable == "" {
		c.Reliable = sciond.DefaultSCIONDPath
	}
	if c.Unix == "" {
		c.Unix = "/run/shm/sciond/default-unix.sock"
	}
	if c.QueryInterval.Duration == 0 {
		c.QueryInterval.Duration = DefaultQueryInterval
	}
	c.PathDB.InitDefaults()
	c.RevCache.InitDefaults()
}

func (c *SDConfig) CreateSocketDirs() error {
	reliableDir := filepath.Dir(c.Reliable)
	if _, err := os.Stat(reliableDir); os.IsNotExist(err) {
		if err = os.MkdirAll(reliableDir, 0755); err != nil {
			return common.NewBasicError("Cannot create reliable socket dir", err, "dir",
				reliableDir)
		}
	}
	unixDir := filepath.Dir(c.Unix)
	if _, err := os.Stat(unixDir); os.IsNotExist(err) {
		if err = os.MkdirAll(unixDir, 0755); err != nil {
			return common.NewBasicError("Cannot create unix socket dir", err, "dir", unixDir)
		}
	}
	return nil
}
