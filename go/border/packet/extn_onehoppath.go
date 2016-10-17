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

package packet

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/conf"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type OneHopPath struct {
	log.Logger
	p *Packet
}

func OneHopPathFromRaw(p *Packet) (*OneHopPath, *util.Error) {
	o := &OneHopPath{p: p}
	o.Logger = p.Logger.New("ext", "OneHopPath")
	o.p = p
	return o, nil
}

func (o *OneHopPath) RegisterHooks(hooks *Hooks) *util.Error {
	hooks.HopF = append(hooks.HopF, o.HopF)
	return nil
}

func (o *OneHopPath) HopF() (HookResult, *spath.HopField, *util.Error) {
	if o.p.DirFrom == DirLocal {
		return HookContinue, nil, nil
	}
	infoF, err := o.p.InfoF()
	if err != nil {
		return HookError, nil, err
	}
	prevIdx := o.p.CmnHdr.CurrHopF - spath.HopFieldLength
	prevHof := o.p.Raw[prevIdx+1 : o.p.CmnHdr.CurrHopF]
	inIF := conf.C.Net.IFAddrMap[o.p.Ingress.Dst.String()]
	hopF := spath.NewHopField(o.p.Raw[o.p.CmnHdr.CurrHopF:], inIF, 0)
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
