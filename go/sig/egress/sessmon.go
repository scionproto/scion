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

package egress

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/sig/disp"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/siginfo"
)

type sessMonitor struct {
	log.Logger
	pp     *Session
	getSig func() *siginfo.Sig
}

func newSessMonitor(pp *Session, getSig func() *siginfo.Sig) *sessMonitor {
	return &sessMonitor{pp: pp, getSig: getSig,
		Logger: log.New("ia", pp.IA, "sessId", pp.SessId, "policy", pp.PolName)}
}

func (pm *sessMonitor) run() {
	defer liblog.LogPanicAndExit()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer close(pm.pp.polMonStopped)
	defer ticker.Stop()
	// Initialise currSig.
	pm.pp.setSig(pm.getSig())
	pm.Info("sessMonitor: starting")
	regc := make(disp.RegPldChan, 1)
	disp.Dispatcher.Register(disp.RegPollRep, disp.MkRegPollKey(pm.pp.IA, pm.pp.SessId), regc)
Top:
	for {
		select {
		case <-pm.pp.polMonStop:
			pm.Info("sessMonitor: graceful shutdown")
			break Top
		case <-ticker.C:
			pm.sendReq()
		case rpld := <-regc:
			pm.handleRep(rpld)
		}
	}
	pm.Info("sessMonitor: stopped")
}

func (pm *sessMonitor) sendReq() {
	info := pm.pp.Info()
	sig := info.Sig
	if sig == nil {
		sig = pm.getSig()
	}
	if sig == nil {
		pm.Error("sessMonitor: No remote sigs found")
		return
	}
	spld, err := mgmt.NewPld(mgmt.NewPollReq(pm.pp.SessId))
	if err != nil {
		pm.Error("sessMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld)
	if err != nil {
		pm.Error("sessMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	raw, err := cpld.PackPld()
	if err != nil {
		pm.Error("sessMonitor: Error packing Ctrl payload", "err", err)
		return
	}
	_, err = pm.pp.conn.WriteToSCION(raw, sig.CtrlSnetAddr())
	if err != nil {
		pm.Error("sessMonitor: Error sending Ctrl payload", "err", err)
	}
}

func (pm *sessMonitor) handleRep(rpld *disp.RegPld) {
	_, ok := rpld.P.(*mgmt.PollRep)
	if !ok {
		log.Error("sessMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !pm.pp.IA.Eq(rpld.Addr.IA) {
		log.Error("sessMonitor: SIGPollRep from wrong IA",
			"expected", pm.pp.IA, "actual", rpld.Addr.IA)
		return
	}
	pm.Info("Got SIGPollRep!", "src", rpld.Addr, "pld", rpld)
}
