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

// This file handles SCION control message payloads (i.e. messages sent between
// instances of the SCION infrastructure).

package rpkt

import (
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
)

func (rp *RtrPkt) parseCtrlPayload() (HookResult, common.Payload, error) {
	if rp.L4Type != common.L4UDP {
		return HookContinue, nil, nil
	}
	cpld, err := ctrl.NewPldFromRaw(rp.Raw[rp.idxs.pld:])
	if err != nil {
		return HookError, nil, err
	}
	return HookFinish, cpld, nil
}

// updateCtrlPld writes a new payload instance to the underlying buffer, and
// updates the layer 4 and common headers accordingly.
func (rp *RtrPkt) updateCtrlPld() error {
	// Reset buffer to full size
	rp.Raw = rp.Raw[:cap(rp.Raw)]
	// Write payload to buffer
	plen, err := rp.pld.WritePld(rp.Raw[rp.idxs.pld:])
	if err != nil {
		return err
	}
	// Trim buffer to the end of the payload.
	rp.Raw = rp.Raw[:rp.idxs.pld+plen]
	// Now start updating headers
	if err := rp.updateL4(); err != nil {
		return err
	}
	rp.CmnHdr.TotalLen = uint16(len(rp.Raw))
	rp.CmnHdr.Write(rp.Raw)
	return nil
}
