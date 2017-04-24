// Copyright 2017 ETH Zurich
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

// Router's implementation of the OPT hop-by-hop extension

package rpkt

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/opt"
	"fmt"
)

// satisfies the interface rExtension in extns.go
var _ rExtension = (*rOPTExt)(nil)

// rOPTExt is the router's representation of the OPT extension.
type rOPTExt struct {
	*opt.Extn
	rp  *RtrPkt
	raw common.RawBytes
	log.Logger
}

func rOPTExtFromRaw(rp *RtrPkt, start, end int) (*rOPTExt, *common.Error) {
	var err *common.Error
	o := &rOPTExt{rp: rp, raw: rp.Raw[start:end]}
	o.Extn, err = opt.ExtnFromRaw(o.raw)
	if err != nil {
		return nil, err
	}
	o.Logger = rp.Logger.New("ext", "opt")
	return o, nil
}

func (o *rOPTExt) RegisterHooks(h *hooks) *common.Error {
	// process field and update pvf
	h.Process = append(h.Process, o.rp.processOPT)
	return nil
}

func (o *rOPTExt) GetExtn() (common.Extension, *common.Error) {
	return o.Extn, nil
}

// processOPTis a processing hook used to handle OPT payloads.
func (rp *RtrPkt) processOPT() (HookResult, *common.Error) {
	exts := rp.HBHExt
	for _, ext := range exts {
		if ext.Type() == 4 {
			fmt.Sprintf("%T", ext)
			repr, err := rp.extnParseHBH(common.ExtnOPType, 0, ext.Len(), 4)
			// process OPT field here, update pvf
			if err != nil {
				return err
			} else {
				repr.Extn.UpdatePVF()
			}
			break
		}
	}
	return HookFinish, nil
}
