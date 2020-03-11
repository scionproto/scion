// Copyright 2019 ETH Zurich, Anapaya Systems
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

package env

import (
	"io"

	"github.com/scionproto/scion/go/lib/config"
)

var _ config.Config = (*Features)(nil)

// Features contains all feautre flags. Add feature flags to this structure as
// needed. Feature flags are always boolean. Don't use any other types here!
type Features struct {
	AllowRunAsRoot bool `toml:"allow_run_as_root,omitempty"`
	UseSIGEgress2  bool `toml:"sig_egress_v2,omitempty"`
}

func (cfg *Features) InitDefaults() {
	// All feature flags are intialized to false.
}

func (cfg *Features) Validate() error {
	return nil
}

func (cfg *Features) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, featuresSample)
}

func (cfg *Features) ConfigName() string {
	return "features"
}
