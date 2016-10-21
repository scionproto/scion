// Copyright 2016 ETH Zurich
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

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/scmp"
	"github.com/netsec-ethz/scion/go/lib/util"
)

func (p *RPkt) parseSCMPPayload() (HookResult, interface{}, *util.Error) {
	pld, err := scmp.PldFromRaw(p.Raw[p.idxs.pld:], p.l4.(*scmp.Hdr))
	if err != nil {
		return HookError, nil, err
	}
	return HookFinish, pld, nil
}
