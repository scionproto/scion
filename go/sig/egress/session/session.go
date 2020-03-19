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

// Package session monitors session health and maintains a concurrency-safe
// remote SIG address (that includes a working path) for each session.
package session

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/pktdisp"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sig/egress/iface"
	"github.com/scionproto/scion/go/sig/egress/worker"
	"github.com/scionproto/scion/go/sig/internal/sigcmn"
)

var _ iface.Session = (*Session)(nil)

// Session contains a pool of paths to the remote AS, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type Session struct {
	logger log.Logger
	ia     addr.IA
	SessId sig_mgmt.SessionType

	// pool contains paths managed by pathmgr.
	pool iface.PathPool
	// FIXME: Use AtomicRemoteInfo instead
	currRemote atomic.Value
	// FIXME: Use AtomicBool instead.
	healthy        atomic.Value
	ring           *ringbuf.Ring
	conn           *snet.Conn
	sessMonStop    chan struct{}
	sessMonStopped chan struct{}
	pktDispStop    chan struct{}
	pktDispStopped chan struct{}
	workerStopped  chan struct{}
}

func NewSession(dstIA addr.IA, sessId sig_mgmt.SessionType, logger log.Logger,
	pool iface.PathPool) (*Session, error) {

	var err error
	s := &Session{
		logger: logger.New("sessId", sessId),
		ia:     dstIA,
		SessId: sessId,
		pool:   pool,
	}
	s.currRemote.Store((*iface.RemoteInfo)(nil))
	s.healthy.Store(false)
	s.ring = ringbuf.New(64, nil, fmt.Sprintf("egress_%s_%s", dstIA, sessId))
	// Not using a fixed local port, as this is for outgoing data only.
	s.conn, err = sigcmn.Network.Listen(context.Background(), "udp",
		&net.UDPAddr{IP: sigcmn.DataAddr}, addr.SvcNone)
	s.sessMonStop = make(chan struct{})
	s.sessMonStopped = make(chan struct{})
	s.pktDispStop = make(chan struct{})
	s.pktDispStopped = make(chan struct{})
	s.workerStopped = make(chan struct{})
	// spawn a PktDispatcher to log any unexpected messages received on a write-only connection.
	go func() {
		defer log.HandlePanic()
		defer close(s.pktDispStopped)
		pktdisp.PktDispatcher(s.conn, pktdisp.DispLogger, s.pktDispStop)
	}()
	return s, err
}

func (s *Session) Logger() log.Logger {
	return s.logger
}

func (s *Session) Start() {
	go func() {
		defer log.HandlePanic()
		newSessMonitor(s).run()
	}()
	go func() {
		defer log.HandlePanic()
		worker.NewWorker(s, s.conn, false, s.logger).Run()
	}()
}

func (s *Session) Cleanup() error {
	s.ring.Close()
	close(s.sessMonStop)
	s.logger.Debug("iface.Session Cleanup: wait for worker")
	<-s.workerStopped
	s.logger.Debug("iface.Session Cleanup: wait for session monitor")
	<-s.sessMonStopped
	close(s.pktDispStop)
	s.logger.Debug("iface.Session Cleanup: wait for pktDisp")
	s.conn.SetReadDeadline(time.Now())
	<-s.pktDispStopped
	s.logger.Debug("iface.Session Cleanup: closing conn")
	if err := s.conn.Close(); err != nil {
		return common.NewBasicError("Unable to close conn", err)
	}
	if err := s.pool.Destroy(); err != nil {
		return common.NewBasicError("Error destroying path pool", err)
	}
	return nil
}

func (s *Session) Remote() *iface.RemoteInfo {
	return s.currRemote.Load().(*iface.RemoteInfo)
}

func (s *Session) Ring() *ringbuf.Ring {
	return s.ring
}

func (s *Session) Conn() *snet.Conn {
	return s.conn
}

func (s *Session) IA() addr.IA {
	return s.ia
}

func (s *Session) ID() sig_mgmt.SessionType {
	return s.SessId
}

func (s *Session) Healthy() bool {
	// FIxME(kormat): export as metric.
	return s.healthy.Load().(bool)
}

func (s *Session) PathPool() iface.PathPool {
	return s.pool
}

func (s *Session) AnnounceWorkerStopped() {
	close(s.workerStopped)
}

type PathPool struct {
	ia   addr.IA
	pool *pathmgr.SyncPaths
}

var _ iface.PathPool = (*PathPool)(nil)

func NewPathPool(dst addr.IA) (*PathPool, error) {
	pool, err := sigcmn.PathMgr.Watch(context.TODO(), sigcmn.IA, dst)
	if err != nil {
		return nil, common.NewBasicError("Unable to register watch", err)
	}
	return &PathPool{
		ia:   dst,
		pool: pool,
	}, nil
}

func (pp *PathPool) Destroy() error {
	pp.pool.Destroy()
	return nil
}

func (pp *PathPool) Paths() spathmeta.AppPathSet {
	return pp.pool.Load().APS
}
