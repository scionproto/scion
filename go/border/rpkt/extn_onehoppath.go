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

// This file implements the router's handling of the One Hop Path hop-by-hop
// extension.

package rpkt

import (
	"hash"

	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

var _ rExtension = (*rOneHopPath)(nil)

// rOneHopPath is the router's representation of the One Hop Path extension.
type rOneHopPath struct {
	log.Logger
	rp *RtrPkt
	spkt.OneHopPath
}

func rOneHopPathFromRaw(rp *RtrPkt) (*rOneHopPath, error) {
	o := &rOneHopPath{rp: rp}
	o.Logger = rp.Logger.New("ext", "OneHopPath")
	o.rp = rp
	return o, nil
}

func (o *rOneHopPath) RegisterHooks(h *hooks) error {
	// Override Hop Field parsing.
	h.HopF = append(h.HopF, o.HopF)
	return nil
}

// HopF generates and returns a new hop field on ingress to an AS.
func (o *rOneHopPath) HopF() (HookResult, *spath.HopField, error) {
	if o.rp.DirFrom == rcmn.DirLocal {
		// The existing HopF is still in use, so use HookContinue to read that
		// instead.
		return HookContinue, nil, nil
	}
	hOff := o.rp.CmnHdr.HopFOffBytes()
	currHopF, err := spath.HopFFromRaw(o.rp.Raw[hOff:])
	if err != nil {
		return HookError, nil, err
	}
	if currHopF.ConsIngress != 0 || currHopF.ConsEgress != 0 {
		// The current hop field has already been generated.
		return HookContinue, nil, nil
	}
	infoF, err := o.rp.InfoF()
	if err != nil {
		return HookError, nil, err
	}
	// Retrieve the previous HopF, create a new HopF for this AS, and write it into the path header.
	prevIdx := hOff - spath.HopFieldLength
	prevHof := o.rp.Raw[prevIdx+1 : hOff]
	inIFid := o.rp.Ingress.IfIDs[0]
	hopF := spath.NewHopField(o.rp.Raw[hOff:], inIFid, 0)
	hfmac := o.rp.Ctx.Conf.HFMacPool.Get().(hash.Hash)
	mac, err := hopF.CalcMac(hfmac, infoF.TsInt, prevHof)
	o.rp.Ctx.Conf.HFMacPool.Put(hfmac)
	if err != nil {
		return HookError, nil, err
	}
	hopF.Mac = mac
	hopF.Write()
	// Return HookContinue so that the default HopF parsing will read the newly
	// created HopF out of the raw buffer.
	return HookContinue, nil, nil
}

func (o *rOneHopPath) Type() common.ExtnType {
	return common.ExtnOneHopPathType
}

func (o *rOneHopPath) Len() int {
	return common.ExtnFirstLineLen
}

func (o *rOneHopPath) String() string {
	return "OneHopPath"
}

func (o *rOneHopPath) GetExtn() (common.Extension, error) {
	return &o.OneHopPath, nil
}
