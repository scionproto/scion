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

package beaconing

import (
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"hash"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

const (
	// DefaultIfidSize is the default bit-size for ifids in the hop-fields.
	DefaultIfidSize = 12
)

// ExtenderConf is the configuration used when extending beacons.
type ExtenderConf struct {
	// Signer is used to sign path segments.
	Signer infra.Signer
	// Mac is used to calculate the hop field MAC.
	Mac hash.Hash
	// Intfs holds all interfaces in the AS.
	Intfs *ifstate.Interfaces
	// MTU is the MTU value set in the AS entries.
	MTU uint16
	// IfidSize is the bit-size of the ifid in the hop-fields.
	IfidSize uint8
	// GetMaxExpTime returns the maximum relative expiration time.
	GetMaxExpTime func() spath.ExpTimeType
	// task contains an identifier specific to the task that uses the extender.
	task string
	// StaticInfoCfg contains the Configdata used for the StaticInfo Extension.
	StaticInfoCfg seg.Configdata
}

// InitDefaults initializes the default values, if not set.
func (cfg *ExtenderConf) InitDefaults() {
	if cfg.IfidSize == 0 {
		cfg.IfidSize = DefaultIfidSize
	}
}

// Validate checks that the config contains a signer.
func (cfg *ExtenderConf) Validate() error {
	if cfg.Signer == nil {
		return serrors.New("Signer must be set")
	}
	if cfg.IfidSize == 0 {
		return serrors.New("IfidSize must be set")
	}
	if cfg.MTU == 0 {
		return serrors.New("MTU must be set")
	}
	return nil
}
