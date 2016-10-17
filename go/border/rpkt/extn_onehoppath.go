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
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
)

var _ RExtension = (*ROneHopPath)(nil)

type ROneHopPath struct {
	log.Logger
	rp *RtrPkt
	spkt.OneHopPath
}

func ROneHopPathFromRaw(rp *RtrPkt) (*ROneHopPath, *common.Error) {
	o := &ROneHopPath{rp: rp}
	o.Logger = rp.Logger.New("ext", "OneHopPath")
	o.rp = rp
	return o, nil
}

func (o *ROneHopPath) RegisterHooks(hooks *Hooks) *common.Error {
	hooks.HopF = append(hooks.HopF, o.HopF)
	return nil
}

func (o *ROneHopPath) HopF() (HookResult, *spath.HopField, *common.Error) {
	if o.rp.DirFrom == DirLocal {
		return HookContinue, nil, nil
	}
	infoF, err := o.rp.InfoF()
	if err != nil {
		return HookError, nil, err
	}
	prevIdx := o.rp.CmnHdr.CurrHopF - spath.HopFieldLength
	prevHof := o.rp.Raw[prevIdx+1 : o.rp.CmnHdr.CurrHopF]
	inIF := conf.C.Net.IFAddrMap[o.rp.Ingress.Dst.String()]
	hopF := spath.NewHopField(o.rp.Raw[o.rp.CmnHdr.CurrHopF:], inIF, 0)
	mac, err := hopF.CalcMac(conf.C.HFGenBlock, infoF.TsInt, prevHof)
	if err != nil {
		return HookError, nil, err
	}
	hopF.Mac = mac
	hopF.Write()
	return HookContinue, nil, nil
}

func (o *ROneHopPath) Type() common.ExtnType {
	return common.ExtnOneHopPathType
}

func (o *ROneHopPath) Len() int {
	return common.LineLen
}

func (o *ROneHopPath) String() string {
	return "OneHopPath"
}

func (o *ROneHopPath) GetExtn() (common.Extension, *common.Error) {
	return &o.OneHopPath, nil
}
