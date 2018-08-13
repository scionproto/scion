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

package session

import (
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/sig/disp"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/siginfo"
)

const (
	tickLen   = 500 * time.Millisecond
	tout      = 1 * time.Second
	writeTout = 100 * time.Millisecond
)

// sessMonitor is responsible for monitoring a session, polling remote SIGs, and switching
// remote SIGs and paths as needed.
type sessMonitor struct {
	log.Logger
	// the Session this instance is monitoring.
	sess *Session
	// the (filtered) pool of paths to the remote AS, maintained by pathmgr.
	pool egress.PathPool
	// the pool of paths this session is currently using, frequently refreshed from pool.
	sessPathPool egress.SessPathPool
	// the remote Info (remote SIG, and path) used for sending polls. This
	// differs from the parent session's remote info when the session monitor
	// is polling a new SIG or over a new path, and is waiting for a response.
	smRemote *egress.RemoteInfo
	// this flag is set whenever sessMonitor is trying to switch SIGs/paths.
	// When a successful response is received, this flag will cause the
	// sessions remoteInfo to be updated from smRemote.
	needUpdate bool
	// when sessMonitor is trying to switch SIGs/paths, this is the id of the
	// last PollReq sent, so that sessMonitor can correlate replies to the
	// remoteInfo used for the request.
	updateMsgId mgmt.MsgIdType
	// the last time a PollRep was received.
	lastReply time.Time
}

func newSessMonitor(sess *Session) *sessMonitor {
	return &sessMonitor{
		Logger: sess.Logger, sess: sess, pool: sess.pool, sessPathPool: make(egress.SessPathPool),
	}
}

func (sm *sessMonitor) run() {
	defer log.LogPanicAndExit()
	defer close(sm.sess.sessMonStopped)
	// Setup timers
	reqTick := time.NewTicker(tickLen)
	defer reqTick.Stop()
	// Register with SIG ctrl dispatcher
	regc := make(disp.RegPldChan, 1)
	disp.Dispatcher.Register(disp.RegPollRep, disp.MkRegPollKey(sm.sess.IA(), sm.sess.SessId), regc)
	sm.lastReply = time.Now()
	sm.Info("sessMonitor: starting")
Top:
	for {
		select {
		case <-sm.sess.sessMonStop:
			break Top
		case <-reqTick.C:
			// Update paths and sigs
			sm.sessPathPool.Update(sm.pool.Paths())
			sm.updateRemote()
			sm.sendReq()
		case rpld := <-regc:
			sm.handleRep(rpld)
		}
	}
	err := disp.Dispatcher.Unregister(disp.RegPollRep, disp.MkRegPollKey(sm.sess.IA(),
		sm.sess.SessId))
	if err != nil {
		log.Error("sessMonitor: unable to unregister from ctrl dispatcher", "err", err)
	}
	sm.Info("sessMonitor: stopped")
}

func (sm *sessMonitor) updateRemote() {
	currRemote := sm.smRemote
	var currSig *siginfo.Sig
	var currSessPath *egress.SessPath
	if currRemote == nil {
		sm.needUpdate = true
	} else {
		currSig = currRemote.Sig
		currSessPath = currRemote.SessPath
	}
	since := time.Since(sm.lastReply)
	if since > tout {
		if currSig != nil {
			currSig.Fail()
		}
		if currSessPath != nil {
			// FIXME(kormat): these debug statements should be converted to prom metrics.
			sm.Debug("Timeout", "remote", currRemote, "duration", since)
			currSessPath.Fail()
		}
		currSig = sm.getNewSig(currSig)
		currSessPath = sm.getNewPath(currSessPath)
		sm.needUpdate = true
	} else {
		if currSig == nil {
			// No remote SIG
			sm.Debug("No remote SIG", "remote", currRemote)
			currSig = sm.getNewSig(nil)
			sm.needUpdate = true
		} else if _, ok := sm.sess.sigMap.Load(currSig.Id); !ok {
			// Current SIG is no longer listed, need to switch to a new one.
			sm.Debug("Current SIG invalid", "remote", currRemote)
			currSig = sm.getNewSig(nil)
			sm.needUpdate = true
		}
		if currSessPath == nil {
			sm.Debug("No path", "remote", currRemote)
			currSessPath = sm.getNewPath(nil)
			sm.needUpdate = true
		} else if _, ok := sm.sessPathPool[currSessPath.Key()]; !ok {
			// Current path is no longer in pool, need to switch to a new one.
			sm.Debug("Current path invalid", "remote", currRemote)
			currSessPath = sm.getNewPath(nil)
			sm.needUpdate = true
		}
	}
	sm.sess.healthy.Store(!sm.needUpdate)
	sm.smRemote = &egress.RemoteInfo{Sig: currSig, SessPath: currSessPath}
}

func (sm *sessMonitor) getNewSig(old *siginfo.Sig) *siginfo.Sig {
	if old != nil {
		// Try to get a different SIG, if possible.
		if sig := sm.sess.sigMap.GetSig(old.Id); sig != nil {
			return sig
		}
	}
	// Get SIG with lowest failure count.
	return sm.sess.sigMap.GetSig("")
}

func (sm *sessMonitor) getNewPath(old *egress.SessPath) *egress.SessPath {
	if old != nil {
		// Try to get a different path, if possible.
		if sp := sm.sessPathPool.Get(old.Key()); sp != nil {
			return sp
		}
	}
	// Get path with lowest failure count
	return sm.sessPathPool.Get("")
}

func (sm *sessMonitor) sendReq() {
	if sm.smRemote == nil || sm.smRemote.Sig == nil || sm.smRemote.SessPath == nil {
		return
	}
	now := time.Now()
	msgId := mgmt.MsgIdType(now.UnixNano())
	if sm.needUpdate {
		sm.updateMsgId = msgId
		sm.Debug("sessMonitor: trying new remote", "msgId", msgId, "remote", sm.smRemote)
	}
	spld, err := mgmt.NewPld(msgId, mgmt.NewPollReq(sigcmn.MgmtAddr, sm.sess.SessId))
	if err != nil {
		sm.Error("sessMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld, nil)
	if err != nil {
		sm.Error("sessMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(ctrl.NullSigner)
	if err != nil {
		sm.Error("sessMonitor: Error creating signed Ctrl payload", "err", err)
		return
	}
	raw, err := scpld.PackPld()
	if err != nil {
		sm.Error("sessMonitor: Error packing signed Ctrl payload", "err", err)
		return
	}
	raddr := sm.smRemote.Sig.CtrlSnetAddr()
	raddr.Path = spath.New(sm.smRemote.SessPath.PathEntry().Path.FwdPath)
	if err := raddr.Path.InitOffsets(); err != nil {
		sm.Error("sessMonitor: Error initializing path offsets", "err", err)
	}
	nh, err := sm.smRemote.SessPath.PathEntry().HostInfo.Overlay()
	if err != nil {
		sm.Error("sessMonitor: Unsupported NextHop", "err", err)
	}
	raddr.NextHop = nh
	// XXX(kormat): if this blocks, both the sessMon and egress worker
	// goroutines will block. Can't just use SetWriteDeadline, as both
	// goroutines write to it.
	_, err = sm.sess.conn.WriteToSCION(raw, raddr)
	if err != nil {
		sm.Error("sessMonitor: Error sending signed Ctrl payload", "err", err)
	}
}

func (sm *sessMonitor) handleRep(rpld *disp.RegPld) {
	_, ok := rpld.P.(*mgmt.PollRep)
	if !ok {
		sm.Error("sessMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !sm.sess.IA().Eq(rpld.Addr.IA) {
		sm.Error("sessMonitor: SIGPollRep from wrong IA",
			"expected", sm.sess.IA(), "actual", rpld.Addr.IA)
		return
	}
	sm.lastReply = time.Now()
	if sm.needUpdate && sm.updateMsgId == rpld.Id {
		// Only update the session's RemoteInfo if we get a response matching
		// the last poll we sent.
		sm.Info("sessMonitor: updating remote Info", "msgId", rpld.Id, "remote", sm.smRemote)
		sm.sess.currRemote.Store(sm.smRemote)
		sm.needUpdate = false
		sm.sess.healthy.Store(true)
	}
}
