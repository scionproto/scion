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

package ifstate

import (
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/topology"
)

func (intf *Interface) SetLastActivate(t time.Time) {
	intf.lastActivate = t
}

func (intf *Interface) SetRev(rev *path_mgmt.SignedRevInfo) {
	intf.revocation = rev
}

func (intf *Interface) Cfg() *Config {
	return &intf.cfg
}

func (intf *Interface) LastActivate() time.Time {
	return intf.lastActivate
}

func (intf *Interface) TopoInfoRef() *topology.IFInfo {
	return &intf.topoInfo
}
