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

package session

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/sig/disp"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/siginfo"
)

const (
	// How long before path TTL expires we should already try to switch to a different path.
	tickLen       = 500 * time.Millisecond
	tout          = 1 * time.Second
	writeTout     = 100 * time.Millisecond
	pathExpiryLen = 10 * time.Second
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
	sessPathPool *egress.SessPathPool
	// the remote Info (remote SIG, and path) used for sending polls. This
	// differs from the parent session's remote info when the session monitor
	// is polling a new SIG or over a new path, and is waiting for a response.
	smRemote *egress.RemoteInfo
	// when sessMonitor is trying to switch SIGs/paths, this is the id of the
	// last PollReq sent, so that sessMonitor can correlate replies to the
	// remoteInfo used for the request.
	updateMsgId mgmt.MsgIdType
	// the last time a PollRep was received.
	lastReply time.Time
}

func newSessMonitor(sess *Session) *sessMonitor {
	return &sessMonitor{
		Logger: sess.Logger,
		sess:   sess, pool: sess.pool,
		sessPathPool: egress.NewSessPathPool(),
	}
}

func (sm *sessMonitor) run() {
	defer close(sm.sess.sessMonStopped)
	// Setup timers
	reqTick := time.NewTicker(tickLen)
	defer reqTick.Stop()
	pathExpiryTick := time.NewTicker(pathExpiryLen)
	defer pathExpiryTick.Stop()
	// Register with SIG ctrl dispatcher
	regc := make(disp.RegPldChan, 1)
	disp.Dispatcher.Register(disp.RegPollRep, disp.MkRegPollKey(sm.sess.IA(), sm.sess.SessId), regc)
	sm.lastReply = time.Now()
	// Start by querying for the remote SIG instance.
	sm.smRemote = &egress.RemoteInfo{
		Sig: &siginfo.Sig{
			IA:   sm.sess.IA(),
			Host: addr.SvcSIG,
		},
		SessPath: sm.sessPathPool.Get(""),
	}
Top:
	for {
		select {
		case <-sm.sess.sessMonStop:
			break Top
		case <-reqTick.C:
			sm.updatePaths()
			sm.updateRemote()
			sm.sendReq()
		case rpld := <-regc:
			sm.handleRep(rpld)
		case <-pathExpiryTick.C:
			sm.sessPathPool.ExpireFails()
		}
	}
	err := disp.Dispatcher.Unregister(disp.RegPollRep, disp.MkRegPollKey(sm.sess.IA(),
		sm.sess.SessId))
	if err != nil {
		log.Error("sessMonitor: unable to unregister from ctrl dispatcher", "err", err)
	}
	sm.Info("sessMonitor: stopped")
}

func (sm *sessMonitor) updatePaths() {
	if sm.smRemote == nil || sm.smRemote.SessPath == nil {
		sm.sessPathPool.Update(sm.pool.Paths())
		return
	}
	currPath := sm.smRemote.SessPath
	expTime := currPath.PathEntry().Path.ExpTime
	mtu := currPath.PathEntry().Path.Mtu
	sm.sessPathPool.Update(sm.pool.Paths())
	// Expiration or MTU of the current path may have changed during the update.
	// In such a case we want to push the updated path to the Session.
	if currPath.PathEntry().Path.ExpTime != expTime || currPath.PathEntry().Path.Mtu != mtu {
		sm.Trace("sessMonitor: Path metadata changed",
			"oldExpiration", expTime,
			"newExpiration", currPath.PathEntry().Path.ExpTime,
			"oldMTU", mtu,
			"newMTU", currPath.PathEntry().Path.Mtu)
		sm.updateSessSnap()
	}
}

func (sm *sessMonitor) updateRemote() {
	// There were no replies from the remote SIG for some time. We don't know whether
	// the failure was caused by bad path or bad SIG. Therefore, we choose a different
	// path but also ask for a new SIG address via anycast SvcSIG request.
	since := time.Since(sm.lastReply)
	if since > tout {
		sm.Info("sessMonitor: Remote SIG timeout", "remote", sm.smRemote, "duration", since)
		metrics.SessionTimedOut.WithLabelValues(
			sm.sess.IA().String(),
			sm.sess.SessId.String()).Inc()
		sm.sess.healthy.Store(false)
		if sm.smRemote.SessPath != nil {
			// Update path statistics. This is a bit of a stretch. The path
			// may be OK, but the remote SIG may be down. However, we accept
			// the inaccuracy so that we don't have to do separate health
			// checking for the path.
			sm.sessPathPool.Timeout(sm.smRemote.SessPath, sm.updateMsgId.Time())
		}
		// Start monitoring new path and discover a new SIG.
		sm.smRemote.Sig.Host = addr.SvcSIG
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath)
		// XXX(roosd): The session's remote SIG will remain the same until the
		// monitor discovers a remote SIG.
		sm.updateSessSnap()
		sm.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// There's no path selected yet. This happens at the beginning of the session,
	// but also when the pool is empty. Try to get a new path.
	if sm.smRemote.SessPath == nil {
		sm.Info("sessMonitor: Path not available", "remote", sm.smRemote)
		sm.sess.healthy.Store(false)
		// Start monitoring the new path.
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath)
		sm.updateSessSnap()
		sm.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// The current path was retired from the path pool. Traffic must no longer be sent on
	// the old path. This implies that the encap traffic is sent on a path that has not been
	// tested by the session monitor yet. If the new path is unhealthy, it is changed quickly
	// by the session monitor through the regular timeout mechanism above.
	updatedPath := sm.sessPathPool.GetByKey(sm.smRemote.SessPath.Key())
	if updatedPath == nil {
		sm.Info("sessMonitor: Current path was invalidated", "remote", sm.smRemote)
		// Start monitoring the new path.
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath)
		// Make session use the new path immediately even though we haven't yet checked
		// whether it works.
		sm.updateSessSnap()
		sm.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// If the current path is about to expire, make session use the updated version of the path.
	// If the updated version is about to expire as well, let's switch to a different path.
	if sm.smRemote.SessPath.IsCloseToExpiry() {
		sm.Info("sessMonitor: Current path is about to expire", "remote", sm.smRemote)
		sm.smRemote.SessPath = updatedPath
		if sm.smRemote.SessPath.IsCloseToExpiry() {
			sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath)
		}
		sm.updateSessSnap()
		sm.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}
}

// updateSessSnap updates the remote snapshot in the session. If the new remote
// SIG host is an SVC address, the previous host of the session is kept.
func (sm *sessMonitor) updateSessSnap() {
	// Copy the remote to avoid capturing the object in the session.
	remote := sm.smRemote.Copy()
	// XXX(roosd): Data traffic should never be sent to a SVC address if avoidable.
	if remote.Sig.Host.Equal(addr.SvcSIG) {
		old := sm.sess.Remote()
		// If the previous remote is not set, do not set the snapshot.
		if old == nil {
			return
		}
		remote.Sig = old.Sig
	}
	sm.sess.currRemote.Store(remote)
}

func (sm *sessMonitor) getNewPath(old *egress.SessPath) *egress.SessPath {
	var res *egress.SessPath
	if old == nil {
		res = sm.sessPathPool.Get("")
	} else {
		res = sm.sessPathPool.Get(old.Key())
	}
	// If the path has changed, report it to Prometheus.
	var report bool
	if old == nil || res == nil {
		report = old != res
	} else {
		report = old.Key() != res.Key()
	}
	if report {
		metrics.SessionPathSwitched.WithLabelValues(
			sm.sess.IA().String(),
			sm.sess.SessId.String()).Inc()
	}
	return res
}

func (sm *sessMonitor) sendReq() {
	if sm.smRemote == nil || sm.smRemote.SessPath == nil {
		return
	}
	sm.updateMsgId = mgmt.MsgIdType(time.Now().UnixNano())
	spld, err := mgmt.NewPld(sm.updateMsgId, mgmt.NewPollReq(sigcmn.MgmtAddr, sm.sess.SessId))
	if err != nil {
		sm.Error("sessMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld, nil)
	if err != nil {
		sm.Error("sessMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(infra.NullSigner)
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
	pollRep, ok := rpld.P.(*mgmt.PollRep)
	if !ok {
		sm.Error("sessMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !sm.sess.IA().Equal(rpld.Addr.IA) {
		sm.Error("sessMonitor: SIGPollRep from wrong IA",
			"expected", sm.sess.IA(), "actual", rpld.Addr.IA)
		return
	}

	// Inform SessPathPool that a reply has arrived.
	if sm.smRemote.SessPath != nil {
		sm.sessPathPool.Reply(sm.smRemote.SessPath, rpld.Id.Time())
	}

	// Only update the session's RemoteInfo if we get a response matching
	// the last poll we sent.
	if sm.updateMsgId == rpld.Id {
		sm.lastReply = time.Now()
		// Update sessmon's remote.
		sm.smRemote.Sig = &siginfo.Sig{
			IA:          sm.smRemote.Sig.IA,
			Host:        pollRep.Addr.Ctrl.Host(),
			CtrlL4Port:  int(pollRep.Addr.Ctrl.Port),
			EncapL4Port: int(pollRep.Addr.EncapPort),
		}
		// Update session's remote, if needed.
		sessRemote := sm.sess.Remote()
		if sessRemote == nil || !sm.smRemote.Sig.Equal(sessRemote.Sig) {
			sm.updateSessSnap()
			sm.Info("sessMonitor: updating remote Info", "msgId", rpld.Id, "remote", sm.smRemote)
		}
		sm.sess.healthy.Store(true)
	} else {
		// This is going to happen if latency of the path is greater than the poll ticker period.
		sm.Info("Reply to an old request received", "request", sm.updateMsgId, "reply", rpld.Id)
		metrics.SessionOldPollReplies.WithLabelValues(
			sm.sess.IA().String(),
			sm.sess.SessId.String()).Inc()
	}
}
