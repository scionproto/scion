// Copyright 2020 Anapaya Systems
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

package control

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/border/rctrl/grpc"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/router/control/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

// revTimer is used to keep revocation timers per IFID.
// A sync.Map is used so that the timer goroutine can clean up the entry once fineshed.
type revTimer sync.Map

func (t *revTimer) Delete(key common.IFIDType) {
	(*sync.Map)(t).Delete(key)
}

func (t *revTimer) Load(key common.IFIDType) (*time.Timer, bool) {
	val, loaded := (*sync.Map)(t).Load(key)
	if val == nil {
		return nil, loaded
	}
	return val.(*time.Timer), loaded

}

func (t *revTimer) Store(key common.IFIDType, timer *time.Timer) {
	(*sync.Map)(t).Store(key, timer)
}

func (t *revTimer) StopAll() {
	(*sync.Map)(t).Range(func(k, v interface{}) bool {
		timer := v.(*time.Timer)
		timer.Stop()
		return true
	})
}

type StateHandler struct {
	c *IACtx
}

// UpdateState processes Interface State updates from the beacon service.
// The controller is responsible for setting/deleting interface revocation, thus it keeps track of
// existing revocation per interface and when it should remove them.
// The current behavior ignores revocations that are not active, it sets/re-sets active revocations
// and remove revocations if the Interface State update did not have a revocation attached.
// In this model, from the data plane point of view, a revocation is simply a data blob
// to return if set on an interface, regardless of its validaity.
func (h StateHandler) UpdateState(ifStates []grpc.InterfaceState) {
	var err error
	cl := metrics.ControlLabels{Result: metrics.Success}
	merr := common.MultiError{}
	for _, info := range ifStates {
		ifid := common.IFIDType(info.ID)
		intf, ok := h.c.BRConf.Topo.IFInfoMap()[ifid]
		if !ok {
			log.Info("Interface ID does not exist", "ifid", ifid)
			continue
		}

		label := metrics.IntfLabels{
			Intf:    metrics.IntfToLabel(ifid),
			NeighIA: intf.IA.String(),
		}
		var rawSRev common.RawBytes
		if info.Revocation != nil {
			rawSRev, err = proto.PackRoot(info.Revocation)
			if err != nil {
				cl.Result = metrics.ErrProcess
				metrics.Control.ReceivedIFStateInfo(cl).Inc()
				merr = append(merr, serrors.WrapStr("packing SRevInfo", err,
					"revinfo", info))
				continue
			}
			revinfo, err := info.Revocation.RevInfo()
			if err != nil {
				merr = append(merr, serrors.WrapStr("parsing RevInfo", err,
					"revinfo", info))
				continue
			}
			if ifid != revinfo.IfID {
				log.Info("IFStateInfo/RevInfo interface ID mismatch!",
					"ifstateinfo_ifid", ifid, "revinfo_ifid", revinfo.IfID)
			}
			if err := revinfo.Active(); err != nil {
				merr = append(merr, serrors.WrapStr("revocation ignored! (not active)", err,
					"revinfo", info))
				continue
			}
			// Active revocation.
			t, ok := h.c.timers.Load(ifid)
			if ok {
				// There is a revocation timer for this ifid, so cancel it.
				// It doesn't matter if the revocation was removed or not, as we are
				// setting a new one now
				t.Stop()
				h.c.timers.Delete(ifid)
				log.Debug("Revocation deletion stopped ", "timer", t, "ifid", ifid)
			}
			// Set the new revocation.
			err = h.c.DP.SetRevocation(h.c.BRConf.IA, ifid, rawSRev)
			if err != nil {
				merr = append(merr, common.NewBasicError("set revocation", err,
					"revinfo", info))
				continue
			}
			// Schedule revocation removal
			h.c.timers.Store(ifid, time.AfterFunc(revinfo.Expiration().Sub(time.Now()), func() {
				h.c.timers.Delete(ifid)
				err = h.c.DP.DelRevocation(h.c.BRConf.IA, ifid)
				if err != nil {
					log.Error("Delete expired revocation failed", "err", err, "ifid", ifid)
					return
				}
				log.Info("Interface activated", "ifid", ifid)
				metrics.Control.IFState(label).Set(1)
			}))
			log.Debug("Delete revocation schedule", "expire", revinfo.Expiration(),
				"revinfo", revinfo)
			if !ok {
				log.Info("Interface deactivated", "ifid", ifid)
			}
			metrics.Control.IFState(label).Set(0)
		} else {
			t, ok := h.c.timers.Load(ifid)
			if ok {
				// There is a revocation in place, so remove it and set interface active.
				// If the timer stop fails, it means the delRevocation function is running or
				// already run, so do nothing else.
				if t.Stop() {
					// Timer stopped successfully, hence delRevocation did not run yet.
					err = h.c.DP.DelRevocation(h.c.BRConf.IA, ifid)
					if err != nil {

						merr = append(merr, common.NewBasicError("delete revocation", err,
							"ifid", ifid))
					}
				}
				h.c.timers.Delete(ifid)
				log.Info("Interface activated", "ifid", ifid)
			}
			metrics.Control.IFState(label).Set(1)
		}
	}
	metrics.Control.ReceivedIFStateInfo(cl).Inc()
	log.Debug("StateHandler processed message", "err", merr.ToError())
}
