// Copyright 2018 ETH Zurich
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

// Package config contains the configuration of the SCION dispatcher.
package config

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var _ config.Config = (*Config)(nil)

type Config struct {
	Logging    env.Logging
	Metrics    env.Metrics
	Dispatcher struct {
		// ID of the Dispatcher (required)
		ID string
		// ApplicationSocket is the local API socket (default /run/shm/dispatcher/default.sock)
		ApplicationSocket string
		// OverlayPort is the native port opened by the dispatcher (default 30041)
		OverlayPort int
		// PerfData starts the pprof HTTP server on the specified address. If not set,
		// the server is not started.
		PerfData string
		// DeleteSocket specifies whether the dispatcher should delete the
		// socket file prior to attempting to create a new one.
		DeleteSocket bool
	}
}

func (cfg *Config) InitDefaults() {
	if cfg.Dispatcher.ApplicationSocket == "" {
		cfg.Dispatcher.ApplicationSocket = reliable.DefaultDispPath
	}
	if cfg.Dispatcher.OverlayPort == 0 {
		cfg.Dispatcher.OverlayPort = overlay.EndhostPort
	}
}

func (cfg *Config) Validate() error {
	if cfg.Dispatcher.ApplicationSocket == "" {
		return common.NewBasicError("ApplicationSocket must be set", nil)
	}
	if cfg.Dispatcher.OverlayPort == 0 {
		return common.NewBasicError("OverlayPort must be set", nil)
	}
	if cfg.Dispatcher.ID == "" {
		return common.NewBasicError("ID must be set", nil)
	}
	return config.ValidateAll(&cfg.Logging, &cfg.Metrics)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	dispSampler := config.StringSampler{
		Text: fmt.Sprintf(dispSample, idSample),
		Name: "dispatcher",
	}
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.Logging,
		&cfg.Metrics,
		dispSampler,
	)
}

func (cfg *Config) ConfigName() string {
	return "godispatcher_config"
}
