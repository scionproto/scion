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
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type OneHopPath struct {
	log.Logger
	rp *RPkt
}

func OneHopPathFromRaw(rp *RPkt) (*OneHopPath, *util.Error) {
	o := &OneHopPath{rp: rp}
	o.Logger = rp.Logger.New("ext", "OneHopPath")
	o.rp = rp
	return o, nil
}

func (o *OneHopPath) RegisterHooks(hooks *Hooks) *util.Error {
	hooks.HopF = append(hooks.HopF, o.HopF)
	return nil
}

func (o *OneHopPath) HopF() (HookResult, *spath.HopField, *util.Error) {
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

func (o *OneHopPath) String() string {
	return "OneHopPath"
}
