// Copyright 2021 Anapaya Systems
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
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/private/topology"
)

func (cfg StaticInfoCfg) TestGenerate(ifType map[common.IfIdType]topology.LinkType,
	ingress, egress common.IfIdType) *staticinfo.Extension {
	return cfg.generate(ifType, ingress, egress)
}
