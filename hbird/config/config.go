// Copyright 2026 ETH Zurich
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

// Package config describes the configuration of the hummingbird service.
package config

import (
	"github.com/scionproto/scion/pkg/private/util"
	"io"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
)

const (
	// DefaultReservationDuration is the default duration of a hummingbird reservation.
	DefaultReservationDuration = 5 * time.Second
)

var _ config.Config = (*Config)(nil)

// Config is the hummingbird service configuration.
type Config struct {
	General  env.General  `toml:"general,omitempty"`
	Features env.Features `toml:"features,omitempty"`
	Logging  log.Config   `toml:"log,omitempty"`
	Metrics  env.Metrics  `toml:"metrics,omitempty"`
	HB       HBConfig     `toml:"hummingbird,omitempty"`
}

// InitDefaults initializes the default values for all parts of the config.
func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
	)
}

// Validate validates all parts of the config.
func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.HB,
	)
}

// Sample generates a sample config file for the hummingbird service.
func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.HB,
	)
}

var _ config.Config = (*HBConfig)(nil)

// HBConfig holds the configuration specific to the hummingbird service.
type HBConfig struct {
	// DefaultReservationDuration is the duration of a hummingbird reservation.
	ReservationDuration util.DurWrap `toml:"reservation_duration,omitempty"`
	// TrustDBPath is the path to the trust sqlite DB used by the service.
	TrustDBPath string `toml:"trust_db_path,omitempty"`
	MinBandwidth        int          `toml:"min_bandwidth,omitempty"`
	MaxBandwidth        int          `toml:"max_bandwidth,omitempty"`
	MinCost             int          `toml:"min_cost,omitempty"`
}

// InitDefaults the default values for the durations that are equal to zero.
func (cfg *HBConfig) InitDefaults() {
}

// Validate validates that all durations are set.
func (cfg *HBConfig) Validate() error {
	if cfg.ReservationDuration.Duration == 0 {
		initDurWrap(&cfg.ReservationDuration, DefaultReservationDuration)
	}
	return nil
}

// Sample generates a sample for the hummingbird service specific configuration.
func (cfg *HBConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, hbSample)
}

// ConfigName is the toml key for the beacon server specific configuration.
func (cfg *HBConfig) ConfigName() string {
	return "hummingbird"
}

func initDurWrap(w *util.DurWrap, def time.Duration) {
	if w.Duration == 0 {
		w.Duration = def
	}
}
