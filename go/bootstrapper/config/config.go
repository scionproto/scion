// Package config contains the configuration of bootstrapper.
package config

import (
	"github.com/scionproto/scion/go/bootstrapper/hinting"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/log"
	"io"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Interface   string                        `toml:"interface"`
	SCIONFolder string                        `toml:"scion_folder"`
	SDConf      string                        `toml:"sd_conf"`
	MOCK        hinting.MOCKHintGeneratorConf `toml:"mock"`
	DHCP        hinting.DHCPHintGeneratorConf `toml:"dhcp"`
	DNSSD       hinting.DNSHintGeneratorConf  `toml:"dnssd"`
	MDNS        hinting.MDNSHintGeneratorConf `toml:"mdns"`
	Logging     log.Config                    `toml:"log"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Logging,
	)

	if cfg.SCIONFolder == "" {
		cfg.SCIONFolder = "."
	}
}

func (cfg *Config) Validate() error {
	if cfg.Interface == "" {
		return common.NewBasicError("Interface must be set", nil)
	}

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
