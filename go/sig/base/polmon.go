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
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/disp"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

type policyMonitor struct {
	log.Logger
	pp     *PathPolicy
	getSig func() *SIGEntry
}

func newPolicyMonitor(pp *PathPolicy, getSig func() *SIGEntry) *policyMonitor {
	return &policyMonitor{pp: pp, getSig: getSig,
		Logger: log.New("ia", pp.IA, "policy", pp.Name, "sessId", pp.Session)}
}

func (pm *policyMonitor) run() {
	defer liblog.LogPanicAndExit()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer close(pm.pp.polMonStopped)
	defer ticker.Stop()
	// Initialise currSig.
	pm.pp.setSig(pm.getSig())
	pm.Info("PolicyMonitor: starting")
	regc := make(disp.RegPldChan, 1)
	disp.Dispatcher.Register(disp.RegPollRep, disp.MkRegPollKey(pm.pp.IA, pm.pp.Session), regc)
Top:
	for {
		select {
		case <-pm.pp.polMonStop:
			pm.Info("PolicyMonitor: graceful shutdown")
			break Top
		case <-ticker.C:
			pm.sendReq()
		case rpld := <-regc:
			pm.handleRep(rpld)
		}
	}
	pm.Info("PolicyMonitor: stopped")
}

func (pm *policyMonitor) sendReq() {
	info := pm.pp.Info()
	sig := info.Sig
	if sig == nil {
		sig = pm.getSig()
	}
	if sig == nil {
		pm.Error("PolicyMonitor: No remote sigs found")
		return
	}
	spld, err := mgmt.NewPld(mgmt.NewPollReq(pm.pp.Session))
	if err != nil {
		pm.Error("PolicyMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld)
	if err != nil {
		pm.Error("PolicyMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	raw, err := cpld.PackPld()
	if err != nil {
		pm.Error("PolicyMonitor: Error packing Ctrl payload", "err", err)
		return
	}
	_, err = pm.pp.conn.WriteToSCION(raw, sig.CtrlSnetAddr())
	if err != nil {
		pm.Error("PolicyMonitor: Error sending Ctrl payload", "err", err)
	}
}

func (pm *policyMonitor) handleRep(rpld *disp.RegPld) {
	_, ok := rpld.P.(*mgmt.PollRep)
	if !ok {
		log.Error("PolicyMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !pm.pp.IA.Eq(rpld.Addr.IA) {
		log.Error("PolicyMonitor: SIGPollRep from wrong IA",
			"expected", pm.pp.IA, "actual", rpld.Addr.IA)
		return
	}
	pm.Info("Got SIGPollRep!", "src", rpld.Addr, "pld", rpld)
}

func PollReqHdlr() {
	defer liblog.LogPanicAndExit()
	log.Info("PollReqHdlr: starting")
	for rpld := range disp.PollReqC {
		// FIXME(kormat): poll replies _should_ go back over the path the requests arrived on,
		// but snet doesn't support this yet. https://github.com/netsec-ethz/scion/issues/1277
		req, ok := rpld.P.(*mgmt.PollReq)
		if !ok {
			log.Error("PollReqHdlr: non-SIGPollReq payload received",
				"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
			continue
		}
		log.Debug("PollReqHdlr: got PollReq", "src", rpld.Addr, "pld", req)
		spld, err := mgmt.NewPld(mgmt.NewPollRep(req.Session))
		if err != nil {
			log.Error("PollReqHdlr: Error creating SIGCtrl payload", "err", err)
			break
		}
		cpld, err := ctrl.NewPld(spld)
		if err != nil {
			log.Error("PollReqHdlr: Error creating Ctrl payload", "err", err)
			break
		}
		raw, err := cpld.PackPld()
		if err != nil {
			log.Error("PollReqHdlr: Error packing Ctrl payload", "err", err)
			break
		}
		sigCtrlAddr := &snet.Addr{IA: rpld.Addr.IA, Host: req.Addr.Ctrl.Host(),
			L4Port: req.Addr.Ctrl.Port}
		_, err = sigcmn.CtrlConn.WriteToSCION(raw, sigCtrlAddr)
		if err != nil {
			log.Error("PollReqHdlr: Error sending Ctrl payload", "err", err, "desc", sigCtrlAddr)
		}
	}
	log.Info("PollReqHdlr: stopped")
}
