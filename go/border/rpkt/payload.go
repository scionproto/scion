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

// This file handles generic payload retrieval.

package rpkt

import (
	"github.com/netsec-ethz/scion/go/lib/common"
)

// Payload retrieves the packet's payload if not already known. It ensures that
// the layer 4 header has been parsed first, and then uses registered hooks to
// retrieve the payload. Note there is no generic fallback; if no hooks are
// registered, then no work is done.
func (rp *RtrPkt) Payload(verify bool) (common.Payload, error) {
	if rp.pld == nil && len(rp.hooks.Payload) > 0 {
		_, err := rp.L4Hdr(verify)
		if err != nil {
			return nil, err
		}
		for _, f := range rp.hooks.Payload {
			ret, pld, err := f()
			switch {
			case err != nil:
				return nil, err
			case ret == HookContinue:
				continue
			case ret == HookFinish:
				rp.pld = pld
				return rp.pld, nil
			}
		}
	}
	return rp.pld, nil
}
