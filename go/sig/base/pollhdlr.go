// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package base

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/disp"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/sigcmn"
)

func PollReqHdlr() {
	log.Info("PollReqHdlr: starting")
	for rpld := range disp.Dispatcher.PollReqC {
		req, ok := rpld.P.(*mgmt.PollReq)
		if !ok {
			log.Error("PollReqHdlr: non-SIGPollReq payload received",
				"src", rpld.Addr, "type", common.TypeOf(rpld.P), "Id", rpld.Id, "pld", rpld.P)
			continue
		}
		//log.Debug("PollReqHdlr: got PollReq", "src", rpld.Addr, "pld", req,
		//	"replyAddr", sigcmn.MgmtAddr, "replySession", req.Session)
		spld, err := mgmt.NewPld(rpld.Id, mgmt.NewPollRep(sigcmn.MgmtAddr, req.Session))
		if err != nil {
			log.Error("PollReqHdlr: Error creating SIGCtrl payload", "err", err)
			break
		}
		cpld, err := ctrl.NewPld(spld, nil)
		if err != nil {
			log.Error("PollReqHdlr: Error creating Ctrl payload", "err", err)
			break
		}
		scpld, err := cpld.SignedPld(infra.NullSigner)
		if err != nil {
			log.Error("PollReqHdlr: Error creating signed Ctrl payload", "err", err)
			break
		}
		raw, err := scpld.PackPld()
		if err != nil {
			log.Error("PollReqHdlr: Error packing signed Ctrl payload", "err", err)
			break
		}
		l4 := addr.NewL4UDPInfo(req.Addr.Ctrl.Port)
		sigCtrlAddr := &snet.Addr{
			IA:      rpld.Addr.IA,
			Host:    &addr.AppAddr{L3: req.Addr.Ctrl.Host(), L4: l4},
			Path:    rpld.Addr.Path,
			NextHop: rpld.Addr.NextHop.Copy(),
		}
		_, err = sigcmn.CtrlConn.WriteToSCION(raw, sigCtrlAddr)
		if err != nil {
			log.Error("PollReqHdlr: Error sending Ctrl payload", "dest", rpld.Addr, "err", err)
		}
	}
	log.Info("PollReqHdlr: stopped")
}
