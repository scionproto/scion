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

// This file handles SCMP payload retrieval.

package rpkt

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/scmp"
)

type RawSRevCallbackArgs struct {
	SignedRevInfo *path_mgmt.SignedRevInfo
	Addrs         []addr.HostSVC
}

// parseSCMPPayload is a hook that can be used for hookPayload, to retrieve the
// SCMP payload.
func (rp *RtrPkt) parseSCMPPayload() (HookResult, common.Payload, error) {
	hdr := rp.l4.(*scmp.Hdr)
	pld, err := scmp.PldFromRaw(rp.Raw[rp.idxs.pld:],
		scmp.ClassType{Class: hdr.Class, Type: hdr.Type})
	if err != nil {
		return HookError, nil, err
	}
	return HookFinish, pld, nil
}
