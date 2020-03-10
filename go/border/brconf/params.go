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

package brconf

import (
	"io"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
)

var _ config.Config = (*Config)(nil)

// Config is the border router configuration that is loaded from file.
type Config struct {
	General  env.General  `toml:"general,omitempty"`
	Features env.Features `toml:"features,omitempty"`
	Logging  log.Config   `toml:"log,omitempty"`
	Metrics  env.Metrics  `toml:"metrics,omitempty"`
	BR       BR           `toml:"br,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.BR,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.BR,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.BR,
	)
}

func (cfg *Config) ConfigName() string {
	return "br_config"
}

var _ config.Config = (*BR)(nil)

// BR contains the border router specific parts of the configuration.
type BR struct {
	// RollbackFailAction indicates the action that should be taken
	// if the rollback fails.
	RollbackFailAction FailAction `toml:"rollback_fail_action,omitempty"`
}

func (cfg *BR) InitDefaults() {
	if cfg.RollbackFailAction != FailActionContinue {
		cfg.RollbackFailAction = FailActionFatal
	}
}

func (cfg *BR) Validate() error {
	return cfg.RollbackFailAction.Validate()
}

func (cfg *BR) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, brSample)
}

func (cfg *BR) ConfigName() string {
	return "br"
}

type FailAction string

const (
	// FailActionFatal indicates that the process exits on error.
	FailActionFatal FailAction = "fatal"
	// FailActionContinue indicates that the process continues on error.
	FailActionContinue FailAction = "continue"
)

func (f *FailAction) Validate() error {
	switch *f {
	case FailActionFatal, FailActionContinue:
		return nil
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", *f)
	}
}

func (f *FailAction) UnmarshalText(text []byte) error {
	switch FailAction(strings.ToLower(string(text))) {
	case FailActionFatal:
		*f = FailActionFatal
	case FailActionContinue:
		*f = FailActionContinue
	default:
		return common.NewBasicError("Unknown FailAction", nil, "input", string(text))
	}
	return nil
}
