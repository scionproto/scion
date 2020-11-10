// Package config contains the configuration of bootstrapper.
package config

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"io"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Interface string

	SciondDirectory string

	Mechanisms struct {
		DHCP bool

		MDNS bool

		DNSSD bool

		DNSNAPTR bool
	}

	Logging env.Logging
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Logging,
	)

	if cfg.SciondDirectory == "" {
		cfg.SciondDirectory = "."
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
