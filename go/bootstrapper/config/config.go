// Copyright 2020 Anapaya Systems
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

// Package config contains the configuration of bootstrapper.
package config

import (
	"io"

	"github.com/scionproto/scion/go/bootstrapper/hinting"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/log"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	InterfaceName   string
	SciondConfigDir string                        `toml:"sciond_config_dir"`
	MOCK            hinting.MOCKHintGeneratorConf `toml:"mock"`
	DHCP            hinting.DHCPHintGeneratorConf `toml:"dhcp"`
	DNSSD           hinting.DNSHintGeneratorConf  `toml:"dnssd"`
	MDNS            hinting.MDNSHintGeneratorConf `toml:"mdns"`
	Logging         log.Config                    `toml:"log,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Logging,
	)
	if cfg.SciondConfigDir == "" {
		cfg.SciondConfigDir = "."
	}
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.Logging,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, bootstrapperSample)
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Logging,
	)
}

func (cfg *Config) ConfigName() string {
	return "bootstrapper_config"
}
