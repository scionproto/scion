// Copyright 2019 Anapaya Systems
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

package propagation

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
)

const (
	// DefaultIfidSize is the default bit-size for ifids in the hop-fields.
	DefaultIfidSize = 12
)

type Config struct {
	// Signer is used to sign path segments.
	Signer infra.Signer
	// IfidSize is the bit-size of the ifid in the hop-fields.
	IfidSize uint8
	// MTU is the MTU value set in the AS entries.
	MTU uint16
}

// InitDefaults initializes the default values, if not set.
func (cfg *Config) InitDefaults() {
	if cfg.IfidSize == 0 {
		cfg.IfidSize = DefaultIfidSize
	}
}

// Validate checks that the config contains a signer.
func (cfg *Config) Validate() error {
	if cfg.Signer == nil {
		return common.NewBasicError("Signer must be set", nil)
	}
	if cfg.IfidSize == 0 {
		return common.NewBasicError("IfidSize must be set", nil)
	}
	if cfg.MTU == 0 {
		return common.NewBasicError("MTU must be set", nil)
	}
	return nil
}
