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

// Package session monitors session health and maintains a concurrency-safe
// remote SIG address (that includes a working path) for each session.
package session

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/pktdisp"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/siginfo"
)

var _ egress.Session = (*Session)(nil)

// Session contains a pool of paths to the remote AS, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type Session struct {
	log.Logger
	ia     addr.IA
	SessId mgmt.SessionType

	// pool of paths, managed by pathmgr
	pool egress.PathPool
	// remote SIGs
	sigMap *siginfo.SigMap
	// *egress.RemoteInfo
	currRemote atomic.Value
	// bool
	healthy        atomic.Value
	ring           *ringbuf.Ring
	conn           snet.Conn
	sessMonStop    chan struct{}
	sessMonStopped chan struct{}
	workerStopped  chan struct{}
	factory        egress.WorkerFactory
}

func NewSession(dstIA addr.IA, sessId mgmt.SessionType, sigMap *siginfo.SigMap, logger log.Logger,
	pool egress.PathPool, factory egress.WorkerFactory) (*Session, error) {

	var err error
	s := &Session{
		Logger:  logger.New("sessId", sessId),
		ia:      dstIA,
		SessId:  sessId,
		sigMap:  sigMap,
		pool:    pool,
		factory: factory,
	}
	s.currRemote.Store((*egress.RemoteInfo)(nil))
	s.healthy.Store(false)
	s.ring = ringbuf.New(64, nil, "egress",
		prometheus.Labels{"ringId": dstIA.String(), "sessId": sessId.String()})
	// Not using a fixed local port, as this is for outgoing data only.
	s.conn, err = snet.ListenSCION("udp4",
		&snet.Addr{IA: sigcmn.IA, Host: &addr.AppAddr{L3: sigcmn.Host}})
	// spawn a PktDispatcher to log any unexpected messages received on a write-only connection.
	go pktdisp.PktDispatcher(s.conn, pktdisp.DispLogger)
	s.sessMonStop = make(chan struct{})
	s.sessMonStopped = make(chan struct{})
	s.workerStopped = make(chan struct{})
	return s, err
}

func (s *Session) Start() {
	go newSessMonitor(s).run()
	go s.factory(s, s.Logger).Run()
}

func (s *Session) Cleanup() error {
	s.ring.Close()
	close(s.sessMonStop)
	s.Debug("egress.Session Cleanup: wait for worker")
	<-s.workerStopped
	s.Debug("egress.Session Cleanup: wait for session monitor")
	<-s.sessMonStopped
	s.Debug("egress.Session Cleanup: closing conn")
	if err := s.conn.Close(); err != nil {
		return common.NewBasicError("Unable to close conn", err)
	}
	if err := s.pool.Destroy(); err != nil {
		return common.NewBasicError("Error destroying path pool", err)
	}
	return nil
}

func (s *Session) Remote() *egress.RemoteInfo {
	return s.currRemote.Load().(*egress.RemoteInfo)
}

func (s *Session) Ring() *ringbuf.Ring {
	return s.ring
}

func (s *Session) Conn() snet.Conn {
	return s.conn
}

func (s *Session) IA() addr.IA {
	return s.ia
}

func (s *Session) ID() mgmt.SessionType {
	return s.SessId
}

func (s *Session) Healthy() bool {
	// FIxME(kormat): export as metric.
	return s.healthy.Load().(bool)
}

func (s *Session) PathPool() egress.PathPool {
	return s.pool
}

func (s *Session) AnnounceWorkerStopped() {
	close(s.workerStopped)
}

type PathPool struct {
	ia   addr.IA
	pool *pathmgr.SyncPaths
}

var _ egress.PathPool = (*PathPool)(nil)

func NewPathPool(dst addr.IA) (*PathPool, error) {
	pool, err := sigcmn.PathMgr.Watch(sigcmn.IA, dst)
	if err != nil {
		return nil, common.NewBasicError("Unable to register watch", err)
	}
	return &PathPool{
		ia:   dst,
		pool: pool,
	}, nil
}

func (pp *PathPool) Destroy() error {
	return sigcmn.PathMgr.Unwatch(sigcmn.IA, pp.ia)
}

func (pp *PathPool) Paths() spathmeta.AppPathSet {
	return pp.pool.Load().APS
}
