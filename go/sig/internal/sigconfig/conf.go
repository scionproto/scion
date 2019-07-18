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

package sigconfig

import (
	"fmt"
	"io"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
)

const (
	DefaultCtrlPort    = 30256
	DefaultEncapPort   = 30056
	DefaultTunName     = "sig"
	DefaultTunRTableId = 11
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Logging env.Logging
	Metrics env.Metrics
	Sciond  env.SciondClient `toml:"sd_client"`
	Sig     SigConf
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.Sciond,
		&cfg.Sig,
	)
}

func (cfg *Config) ConfigName() string {
	return "sig_config"
}

var _ config.Config = (*SigConf)(nil)

// SigConf contains the configuration specific to the SIG.
type SigConf struct {
	// ID of the SIG (required)
	ID string
	// The SIG config json file. (required)
	SIGConfig string
	// IA the local IA (required)
	IA addr.IA
	// IP the bind IP address (required)
	IP net.IP
	// Control data port, e.g. keepalives. (default DefaultCtrlPort)
	CtrlPort uint16
	// Encapsulation data port. (default DefaultEncapPort)
	EncapPort uint16
	// SCION dispatcher path. (default "")
	Dispatcher string
	// Name of TUN device to create. (default DefaultTunName)
	Tun string
	// TunRTableId the id of the routing table used in the SIG. (default DefaultTunRTableId)
	TunRTableId int
	// IPv4 source address hint to put into routing table.
	SrcIP4 net.IP
	// IPv6 source address hint to put into routing table.
	SrcIP6 net.IP
}

// InitDefaults sets the default values to unset values.
func (cfg *SigConf) InitDefaults() {
	if cfg.CtrlPort == 0 {
		cfg.CtrlPort = DefaultCtrlPort
	}
	if cfg.EncapPort == 0 {
		cfg.EncapPort = DefaultEncapPort
	}
	if cfg.Tun == "" {
		cfg.Tun = DefaultTunName
	}
	if cfg.TunRTableId == 0 {
		cfg.TunRTableId = DefaultTunRTableId
	}
}

// Validate validate the config and returns an error if a value is not valid.
func (cfg *SigConf) Validate() error {
	if cfg.ID == "" {
		return common.NewBasicError("ID must be set!", nil)
	}
	if cfg.SIGConfig == "" {
		return common.NewBasicError("Config must be set!", nil)
	}
	if cfg.IA.IsZero() {
		return common.NewBasicError("IA must be set", nil)
	}
	if cfg.IA.IsWildcard() {
		return common.NewBasicError("Wildcard IA not allowed", nil)
	}
	if cfg.IP.IsUnspecified() {
		return common.NewBasicError("IP must be set", nil)
	}
	return nil
}

func (cfg *SigConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(sigSample, ctx[config.ID]))
}

func (cfg *SigConf) ConfigName() string {
	return "sig"
}
