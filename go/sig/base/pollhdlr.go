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

package base

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/disp"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

func PollReqHdlr() {
	defer liblog.LogPanicAndExit()
	log.Info("PollReqHdlr: starting")
	for rpld := range disp.Dispatcher.PollReqC {
		req, ok := rpld.P.(*mgmt.PollReq)
		if !ok {
			log.Error("PollReqHdlr: non-SIGPollReq payload received",
				"src", rpld.Addr, "type", common.TypeOf(rpld.P), "Id", rpld.Id, "pld", rpld.P)
			continue
		}
		//log.Debug("PollReqHdlr: got PollReq", "src", rpld.Addr, "pld", req)
		spld, err := mgmt.NewPld(rpld.Id, mgmt.NewPollRep(req.Session))
		if err != nil {
			log.Error("PollReqHdlr: Error creating SIGCtrl payload", "err", err)
			break
		}
		scpld, err := ctrl.NewSignedPldFromUnion(spld)
		if err != nil {
			log.Error("PollReqHdlr: Error creating Ctrl payload", "err", err)
			break
		}
		raw, err := scpld.PackPld()
		if err != nil {
			log.Error("PollReqHdlr: Error packing Ctrl payload", "err", err)
			break
		}
		sigCtrlAddr := &snet.Addr{
			IA: rpld.Addr.IA, Host: req.Addr.Ctrl.Host(), L4Port: req.Addr.Ctrl.Port,
			Path: rpld.Addr.Path, NextHopHost: rpld.Addr.NextHopHost,
			NextHopPort: rpld.Addr.NextHopPort,
		}
		_, err = sigcmn.CtrlConn.WriteToSCION(raw, sigCtrlAddr)
		if err != nil {
			log.Error("PollReqHdlr: Error sending Ctrl payload", "err", err, "desc", rpld.Addr)
		}
	}
	log.Info("PollReqHdlr: stopped")
}
