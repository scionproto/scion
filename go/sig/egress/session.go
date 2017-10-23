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
	"fmt"
	"sync/atomic"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
	"github.com/netsec-ethz/scion/go/sig/siginfo"
)

// Session contains a pool of paths to the remote AS, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type Session struct {
	log.Logger
	IA     *addr.ISD_AS
	SessId sigcmn.SessionType
	// pool of paths, managed by pathmgr
	pool *pathmgr.SyncPaths
	// function pointer to return SigMap from parent ASEntry.
	sigMapF func() siginfo.SigMap
	// *RemoteInfo
	currRemote atomic.Value
	// bool
	healthy        atomic.Value
	ring           *ringbuf.Ring
	conn           *snet.Conn
	sessMonStop    chan struct{}
	sessMonStopped chan struct{}
	workerStopped  chan struct{}
}

func NewSession(dstIA *addr.ISD_AS, sessId sigcmn.SessionType,
	sigMapF func() siginfo.SigMap, logger log.Logger) (*Session, error) {
	var err error
	s := &Session{
		Logger:  logger.New("sessId", sessId),
		IA:      dstIA,
		SessId:  sessId,
		sigMapF: sigMapF,
	}
	if s.pool, err = sigcmn.PathMgr.Register(sigcmn.IA, s.IA); err != nil {
		return nil, err
	}
	s.currRemote.Store((*RemoteInfo)(nil))
	s.healthy.Store(false)
	s.ring = ringbuf.New(64, nil, "egress",
		prometheus.Labels{"ringId": dstIA.String(), "sessId": sessId.String()})
	// Not using a fixed local port, as this is for outgoing data only.
	s.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	// spawn a PktDispatcher to log any unexpected messages received on a write-only connection.
	go snet.PktDispatcher(s.conn, snet.DispLogger)
	s.sessMonStop = make(chan struct{})
	s.sessMonStopped = make(chan struct{})
	s.workerStopped = make(chan struct{})
	return s, err
}

func (s *Session) Start() {
	go newSessMonitor(s).run()
	go NewWorker(s, s.Logger).Run()
}

func (s *Session) Cleanup() error {
	s.ring.Close()
	close(s.sessMonStop)
	s.Debug("egress.Session Cleanup: wait for worker")
	<-s.workerStopped
	s.Debug("egress.Session Cleanup: wait for session monitor")
	<-s.sessMonStopped
	s.Debug("egress.Session Cleanup: closing conn")
	return s.conn.Close()
}

func (s *Session) Remote() *RemoteInfo {
	return s.currRemote.Load().(*RemoteInfo)
}

func (s *Session) Healthy() bool {
	// FIxME(kormat): export as metric.
	return s.healthy.Load().(bool)
}

type RemoteInfo struct {
	Sig      *siginfo.Sig
	sessPath *sessPath
}

func (r *RemoteInfo) String() string {
	return fmt.Sprintf("Sig: %s Path: %s", r.Sig, r.sessPath)
}
