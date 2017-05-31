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
	//"crypto/cipher"
	//"github.com/netsec-ethz/scion/go/lib/util"
	//"github.com/netsec-ethz/scion/go/border/conf"
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

// processOPT is a processing hook used to handle OPT payloads.
func (o *RtrPkt) processOPT() (HookResult, *common.Error) {
	exts := o.HBHExt
	for _, ext := range exts {
		if ext.Type().Type == 4 {
			fmt.Sprintf("%T", ext)
			repr, err := o.extnParseHBH(common.ExtnOPTType, 0, ext.Len(), 4)
			// process OPT field here, update pvf
			if err != nil {
				return HookError, err
			} else {
				fmt.Sprintf("%T", repr)
				//rOPTExt(repr).UpdatePVF()
			}
			break
		}
	}
	return HookFinish, nil
}

// calcDRKey calculates the DRKey for this packet.
func (o *RtrPkt) CalcDRKey() (common.RawBytes, *common.Error) {
	// stuff in with src ISD|src AS, compute CBCMac over it with key DRKeyAESBlock: K_x = cbcmac(DRKeyAESBlock, in)
	in := make(common.RawBytes, 16)
	common.Order.PutUint32(in, uint32(o.srcIA.I))
	common.Order.PutUint32(in[4:], uint32(o.srcIA.A))
	// blockFstOrder is K_{SV_{AS_i}}
	// Missing DRKey block
	blockFstOrder, e := make(common.RawBytes, 16), common.NewError("") // o.getDRKeyBlock(util.CBCMac(conf.C.DRKeyAESBlock, in))
	fmt.Sprintf("%T", blockFstOrder)
	if e != nil {
		return nil, e
	}

	// stuff in with OPT|src host addr|dst host addr, compute CBCMac over it with key K_x = cbcmac(K_x, in)
	in = make(common.RawBytes, 48)
	copy(in[0:3], []byte("OPT"))
	copy(in[16:32], o.srcHost.Pack())
	copy(in[32:48], o.dstHost.Pack())
	// keyOpt is K^OPT_{AS_i -> S:H_S, D:H_D}
	// Missing Mac from block
	keyOPT, e := make(common.RawBytes, 16), common.NewError("")  // util.CBCMac(blockFstOrder, in)
	return keyOPT, e
}