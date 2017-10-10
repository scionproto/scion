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
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/sig/disp"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/siginfo"
)

const (
	tickLen = 500 * time.Millisecond
	tout    = 1 * time.Second
)

type sessMonitor struct {
	log.Logger
	sess     *Session
	sigMap   siginfo.SigMap
	pool     *pathmgr.SyncPaths
	sessPool sessPathPool
	// Used for sending polls
	smRemote    *RemoteInfo
	needUpdate  bool
	updateMsgId mgmt.MsgIdType
	lastReply   time.Time
}

func newSessMonitor(sess *Session) *sessMonitor {
	return &sessMonitor{
		Logger: sess.Logger, sess: sess, pool: sess.pool, sessPool: make(sessPathPool),
	}
}

func (sm *sessMonitor) run() {
	defer liblog.LogPanicAndExit()
	defer close(sm.sess.sessMonStopped)
	// Setup timers
	reqTick := time.NewTicker(tickLen)
	defer reqTick.Stop()
	// Register with SIG ctrl dispatcher
	regc := make(disp.RegPldChan, 1)
	disp.Dispatcher.Register(disp.RegPollRep, disp.MkRegPollKey(sm.sess.IA, sm.sess.SessId), regc)
	sm.lastReply = time.Now()
	sm.Info("sessMonitor: starting")
Top:
	for {
		select {
		case <-sm.sess.sessMonStop:
			sm.Info("sessMonitor: stopping")
			break Top
		case <-reqTick.C:
			// Update paths and sigs
			sm.sessPool.update(sm.pool.Load())
			sm.sigMap = sm.sess.sigMapF()
			sm.checkRemote()
			sm.sendReq()
		case rpld := <-regc:
			sm.handleRep(rpld)
		}
	}
	sm.Info("sessMonitor: stopped")
}

func (sm *sessMonitor) checkRemote() {
	now := time.Now()
	remote := sm.sess.Remote()
	if remote == nil {
		sm.Debug("No remote info")
		remote = &RemoteInfo{}
		sm.needUpdate = true
	}
	since := now.Sub(sm.lastReply)
	if since > tout {
		sm.Debug("Timeout", "remote", remote, "duration", since)
		remote.Sig = sm.updateSig(remote.Sig)
		remote.sessPath = sm.updatePath(remote.sessPath)
		sm.needUpdate = true
	} else {
		if remote.Sig == nil {
			// No remote SIG
			sm.Debug("No remote SIG", "remote", remote)
			remote.Sig = sm.updateSig(nil)
			sm.needUpdate = true
		} else if _, ok := sm.sigMap[remote.Sig.Id]; !ok {
			// Current SIG is no longer listed, need to switch to a new one.
			sm.Debug("Current SIG invalid", "remote", remote)
			remote.Sig = sm.updateSig(nil)
			sm.needUpdate = true
		}
		poolPaths := sm.pool.Load()
		if remote.sessPath == nil {
			sm.needUpdate = true
			sm.Debug("No path", "remote", remote)
			remote.sessPath = sm.updatePath(nil)
			sm.needUpdate = true
		} else if _, ok := poolPaths[remote.sessPath.key]; !ok {
			// Current path is no longer in pool, need to switch to a new one.
			sm.needUpdate = true
			sm.Debug("Current path invalid", "remote", remote)
			remote.sessPath = sm.updatePath(nil)
			sm.needUpdate = true
		}
	}
	sm.smRemote = remote
}

func (sm *sessMonitor) updateSig(old *siginfo.Sig) *siginfo.Sig {
	if old != nil {
		// Try to get a different SIG, if possible.
		if sig := sm.sigMap.GetSig(old.Id); sig != nil {
			return sig
		}
	}
	// Get SIG with lowest failure count.
	return sm.sigMap.GetSig("")
}

func (sm *sessMonitor) updatePath(old *sessPath) *sessPath {
	if old != nil {
		// Try to get a different path, if possible.
		if sp := sm.sessPool.get(old.key); sp != nil {
			return sp
		}
	}
	// Get path with lowest failure count
	return sm.sessPool.get("")
}

func (sm *sessMonitor) sendReq() {
	if sm.smRemote == nil || sm.smRemote.Sig == nil || sm.smRemote.sessPath == nil {
		return
	}
	msgId := mgmt.MsgIdType(time.Now().UnixNano())
	if sm.needUpdate {
		sm.updateMsgId = msgId
		sm.Debug("sessMonitor: trying new remote", "remote", sm.smRemote)
	}
	spld, err := mgmt.NewPld(msgId, mgmt.NewPollReq(sm.sess.SessId))
	if err != nil {
		sm.Error("sessMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld)
	if err != nil {
		sm.Error("sessMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	raw, err := cpld.PackPld()
	if err != nil {
		sm.Error("sessMonitor: Error packing Ctrl payload", "err", err)
		return
	}
	_, err = sm.sess.conn.WriteToSCION(raw, sm.smRemote.Sig.CtrlSnetAddr())
	if err != nil {
		sm.Error("sessMonitor: Error sending Ctrl payload", "err", err)
	}
}

func (sm *sessMonitor) handleRep(rpld *disp.RegPld) {
	_, ok := rpld.P.(*mgmt.PollRep)
	if !ok {
		log.Error("sessMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !sm.sess.IA.Eq(rpld.Addr.IA) {
		log.Error("sessMonitor: SIGPollRep from wrong IA",
			"expected", sm.sess.IA, "actual", rpld.Addr.IA)
		return
	}
	sm.lastReply = time.Now()
	if sm.needUpdate && sm.updateMsgId == rpld.Id {
		// Only update the session's RemoteInfo if we get a response matching
		// the last poll we sent.
		sm.Info("sessMonitor: updating remote Info", "pld", rpld)
		sm.sess.currRemote.Store(sm.smRemote)
		sm.needUpdate = false
	}
}
