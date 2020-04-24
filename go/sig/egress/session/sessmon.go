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
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sigdisp"
	"github.com/scionproto/scion/go/sig/egress/iface"
	"github.com/scionproto/scion/go/sig/egress/siginfo"
	"github.com/scionproto/scion/go/sig/internal/metrics"
	"github.com/scionproto/scion/go/sig/internal/sigcmn"
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
	logger log.Logger
	// the Session this instance is monitoring.
	sess *Session
	// the (filtered) pool of paths to the remote AS, maintained by pathmgr.
	pool iface.PathPool
	// the pool of paths this session is currently using, frequently refreshed from pool.
	sessPathPool *iface.SessPathPool
	// the remote Info (remote SIG, and path) used for sending polls. This
	// differs from the parent session's remote info when the session monitor
	// is polling a new SIG or over a new path, and is waiting for a response.
	smRemote *iface.RemoteInfo
	// when sessMonitor is trying to switch SIGs/paths, this is the id of the
	// last PollReq sent, so that sessMonitor can correlate replies to the
	// remoteInfo used for the request.
	updateMsgId sig_mgmt.MsgIdType
	// the last time a PollRep was received.
	lastReply time.Time
}

func newSessMonitor(sess *Session) *sessMonitor {
	// Session starts as unhealthy.
	metrics.SessionHealth.WithLabelValues(sess.IA().String(),
		sess.SessId.String()).Set(0.0)
	return &sessMonitor{
		logger:       sess.logger,
		sess:         sess,
		pool:         sess.pool,
		sessPathPool: iface.NewSessPathPool(),
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
	regc := make(sigdisp.RegPldChan, 1)
	sigdisp.Dispatcher.Register(sigdisp.RegPollRep,
		sigdisp.MkRegPollKey(sm.sess.IA(), sm.sess.SessId, 0), regc)
	sm.lastReply = time.Now()
	// Start by querying for the remote SIG instance.
	sm.smRemote = &iface.RemoteInfo{
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
	err := sigdisp.Dispatcher.Unregister(sigdisp.RegPollRep, sigdisp.MkRegPollKey(sm.sess.IA(),
		sm.sess.SessId, 0))
	if err != nil {
		log.Error("sessMonitor: unable to unregister from ctrl dispatcher", "err", err)
	}
	sm.logger.Info("sessMonitor: stopped")
}

func (sm *sessMonitor) updatePaths() {
	if sm.smRemote == nil || sm.smRemote.SessPath == nil {
		sm.sessPathPool.Update(sm.pool.Paths())
		return
	}
	currPath := sm.smRemote.SessPath
	expTime := currPath.Path().Expiry()
	mtu := currPath.Path().MTU()
	sm.sessPathPool.Update(sm.pool.Paths())
	metrics.SessionPaths.WithLabelValues(sm.sess.IA().String(),
		sm.sess.SessId.String()).Set(float64(sm.sessPathPool.PathCount()))
	// Expiration or MTU of the current path may have changed during the update.
	// In such a case we want to push the updated path to the Session.
	if currPath.Path().Expiry() != expTime || currPath.Path().MTU() != mtu {
		sm.logger.Trace("sessMonitor: Path metadata changed",
			"oldExpiration", expTime,
			"newExpiration", currPath.Path().Expiry(),
			"oldMTU", mtu,
			"newMTU", currPath.Path().MTU)
		sm.updateSessSnap()
	}
}

func (sm *sessMonitor) updateRemote() {
	// There were no replies from the remote SIG for some time. We don't know whether
	// the failure was caused by bad path or bad SIG. Therefore, we choose a different
	// path but also ask for a new SIG address via anycast SvcSIG request.
	since := time.Since(sm.lastReply)
	if since > tout {
		sm.logger.Info("sessMonitor: Remote SIG timeout", "remote", sm.smRemote, "duration", since)
		metrics.SessionTimedOut.WithLabelValues(
			sm.sess.IA().String(),
			sm.sess.SessId.String()).Inc()
		sm.setHealth(false)
		if sm.smRemote.SessPath != nil {
			// Update path statistics. This is a bit of a stretch. The path
			// may be OK, but the remote SIG may be down. However, we accept
			// the inaccuracy so that we don't have to do separate health
			// checking for the path.
			sm.sessPathPool.Timeout(sm.smRemote.SessPath, sm.updateMsgId.Time())
		}
		// Start monitoring new path and discover a new SIG.
		sm.smRemote.Sig.Host = addr.SvcSIG
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath, "timeout")
		// XXX(roosd): The session's remote SIG will remain the same until the
		// monitor discovers a remote SIG.
		sm.updateSessSnap()
		sm.logger.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// There's no path selected yet. This happens at the beginning of the session,
	// but also when the pool is empty. Try to get a new path.
	if sm.smRemote.SessPath == nil {
		sm.logger.Info("sessMonitor: Path not available", "remote", sm.smRemote)
		sm.setHealth(false)
		// Start monitoring the new path.
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath, "no_path")
		sm.updateSessSnap()
		sm.logger.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// The current path was retired from the path pool. Traffic must no longer be sent on
	// the old path. This implies that the encap traffic is sent on a path that has not been
	// tested by the session monitor yet. If the new path is unhealthy, it is changed quickly
	// by the session monitor through the regular timeout mechanism above.
	updatedPath := sm.sessPathPool.GetByKey(sm.smRemote.SessPath.Key())
	if updatedPath == nil {
		sm.logger.Info("sessMonitor: Current path was invalidated", "remote", sm.smRemote)
		// Start monitoring the new path.
		sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath, "retired")
		// Make session use the new path immediately even though we haven't yet checked
		// whether it works.
		sm.updateSessSnap()
		sm.logger.Info("sessMonitor: New remote", "remote", sm.smRemote)
		return
	}

	// If the current path is about to expire, make session use the updated version of the path.
	// If the updated version is about to expire as well, let's switch to a different path.
	if sm.smRemote.SessPath.IsCloseToExpiry() {
		sm.logger.Info("sessMonitor: Current path is about to expire", "remote", sm.smRemote)
		sm.smRemote.SessPath = updatedPath
		if sm.smRemote.SessPath.IsCloseToExpiry() {
			sm.smRemote.SessPath = sm.getNewPath(sm.smRemote.SessPath, "expired")
		}
		sm.updateSessSnap()
		sm.logger.Info("sessMonitor: New remote", "remote", sm.smRemote)
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
	if remote.SessPath != nil {
		mtu := remote.SessPath.Path().MTU()
		metrics.SessionMTU.WithLabelValues(sm.sess.IA().String(),
			sm.sess.SessId.String()).Set(float64(mtu))
	}
}

func (sm *sessMonitor) getNewPath(old *iface.SessPath, reason string) *iface.SessPath {
	var res *iface.SessPath
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
		metrics.SessionPathSwitched.WithLabelValues(sm.sess.IA().String(),
			sm.sess.SessId.String(), reason).Inc()
	}
	return res
}

func (sm *sessMonitor) sendReq() {
	if sm.smRemote == nil || sm.smRemote.SessPath == nil {
		return
	}
	sm.updateMsgId = sig_mgmt.MsgIdType(time.Now().UnixNano())
	mgmtAddr := sigcmn.GetMgmtAddr()
	spld, err := sig_mgmt.NewPld(sm.updateMsgId, sig_mgmt.NewPollReq(&mgmtAddr,
		sm.sess.SessId))
	if err != nil {
		sm.logger.Error("sessMonitor: Error creating SIGCtrl payload", "err", err)
		return
	}
	cpld, err := ctrl.NewPld(spld, nil)
	if err != nil {
		sm.logger.Error("sessMonitor: Error creating Ctrl payload", "err", err)
		return
	}
	scpld, err := cpld.SignedPld(infra.NullSigner)
	if err != nil {
		sm.logger.Error("sessMonitor: Error creating signed Ctrl payload", "err", err)
		return
	}
	raw, err := scpld.PackPld()
	if err != nil {
		sm.logger.Error("sessMonitor: Error packing signed Ctrl payload", "err", err)
		return
	}
	raddr := sm.smRemote.Sig.CtrlSnetAddr(
		sm.smRemote.SessPath.Path().Path(),
		sm.smRemote.SessPath.Path().UnderlayNextHop(),
	)
	// XXX(kormat): if this blocks, both the sessMon and egress worker
	// goroutines will block. Can't just use SetWriteDeadline, as both
	// goroutines write to it.
	_, err = sm.sess.conn.WriteTo(raw, raddr)
	if err != nil {
		sm.logger.Error("sessMonitor: Error sending signed Ctrl payload", "err", err)
	}
	metrics.SessionProbes.WithLabelValues(sm.sess.IA().String(), sm.sess.SessId.String()).Inc()
}

func (sm *sessMonitor) handleRep(rpld *sigdisp.RegPld) {
	pollRep, ok := rpld.P.(*sig_mgmt.PollRep)
	if !ok {
		sm.logger.Error("sessMonitor: non-SIGPollRep payload received",
			"src", rpld.Addr, "type", common.TypeOf(rpld.P), "pld", rpld.P)
		return
	}
	if !sm.sess.IA().Equal(rpld.Addr.IA) {
		sm.logger.Error("sessMonitor: SIGPollRep from wrong IA",
			"expected", sm.sess.IA(), "actual", rpld.Addr.IA)
		return
	}
	metrics.SessionProbeReplies.WithLabelValues(sm.sess.IA().String(),
		sm.sess.SessId.String()).Inc()

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
			EncapL4Port: int(pollRep.Addr.Data.Port),
		}
		// Update session's remote, if needed.
		sessRemote := sm.sess.Remote()
		if sessRemote == nil || !sm.smRemote.Sig.Equal(sessRemote.Sig) {
			sm.updateSessSnap()
			sm.logger.Info("sessMonitor: updating remote Info",
				"msgId", rpld.Id, "remote", sm.smRemote)
			metrics.SessionRemoteSwitched.WithLabelValues(sm.sess.IA().String(),
				sm.sess.SessId.String()).Inc()
		}
		sm.setHealth(true)

		latency := time.Now().Sub(rpld.Id.Time())
		metrics.SessionProbeRTT.WithLabelValues(sm.sess.IA().String(),
			sm.sess.SessId.String()).Observe(latency.Seconds())
	} else {
		// This is going to happen if latency of the path is greater than the poll ticker period.
		sm.logger.Info("Reply to an old request received",
			"request", sm.updateMsgId, "reply", rpld.Id)
		metrics.SessionOldPollReplies.WithLabelValues(
			sm.sess.IA().String(),
			sm.sess.SessId.String()).Inc()
	}
}

func (sm *sessMonitor) setHealth(healthy bool) {
	sm.sess.healthy.Store(healthy)
	var healthVal float64
	if healthy {
		healthVal = 1
	}
	metrics.SessionHealth.WithLabelValues(sm.sess.IA().String(),
		sm.sess.SessId.String()).Set(healthVal)
}
