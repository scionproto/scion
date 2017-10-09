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
	"sync/atomic"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
	"github.com/netsec-ethz/scion/go/sig/siginfo"
)

type SyncSession struct {
	atomic.Value
}

func NewSyncSession() *SyncSession {
	ss := &SyncSession{}
	ss.Store(([]*Session)(nil))
	return ss
}

func (ss *SyncSession) Load() []*Session {
	return ss.Value.Load().([]*Session)
}

// FIXME(kormat): update
// Session contains the path policy for a given remote AS. This means having
// a pool of paths that match the specified policy, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type Session struct {
	IA      *addr.ISD_AS
	SessId  sigcmn.SessionType
	PolName string
	// FIXME(kormat): not implemented yet :P contstrains what interfaces to route through.
	policy interface{}
	// pool of paths that meet the policy requirement, managed by pathmgr
	pool *pathmgr.SyncPaths
	// sessionInfo
	sessInfo atomic.Value
	// Metrics per set of path hops, entries added/removed whenever pool changes.
	PathsMetrics  map[pathmgr.PathKey]PathMetrics
	ring          *ringbuf.Ring
	conn          *snet.Conn
	polMonStop    chan struct{}
	polMonStopped chan struct{}
	workerStopped chan struct{}
}

func NewSession(dstIA *addr.ISD_AS, sessId sigcmn.SessionType, polName string,
	policy interface{}) (*Session, error) {
	var err error
	s := &Session{IA: dstIA, SessId: sessId, PolName: polName, policy: policy}
	// FIXME(kormat): change to `RegisterFilter once pathmgr supports policies.
	s.pool, err = sigcmn.PathMgr.Register(sigcmn.IA, dstIA)
	if err != nil {
		return nil, err
	}
	// Initalize session info
	var pathEntry *sciond.PathReplyEntry
	aps := s.pool.Load()
	if aps != nil {
		ap := aps.GetAppPath()
		if ap != nil {
			pathEntry = ap.Entry
		}
	}
	s.sessInfo.Store(SessionInfo{Path: pathEntry})
	s.ring = ringbuf.New(64, nil, "egress",
		prometheus.Labels{"ringId": dstIA.String(), "sessId": sessId.String()})
	// Not using a fixed local port, as this is for outgoing data only.
	s.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	s.polMonStop = make(chan struct{})
	s.polMonStopped = make(chan struct{})
	s.workerStopped = make(chan struct{})
	return s, err
}

func (s *Session) Start(getSig func() *siginfo.Sig) {
	go newSessMonitor(s, getSig).run()
	go NewEgressWorker(s).Run()
}

func (s *Session) Info() SessionInfo {
	return s.sessInfo.Load().(SessionInfo)
}

func (s *Session) CurrPath() *sciond.PathReplyEntry {
	info := s.Info()
	return info.Path
}

func (s *Session) setPath(path *sciond.PathReplyEntry) {
	info := s.Info()
	info.Path = path
	s.sessInfo.Store(info)
}

func (s *Session) setSig(se *siginfo.Sig) {
	info := s.Info()
	info.Sig = se
	s.sessInfo.Store(info)
}

func (s *Session) Cleanup() error {
	s.ring.Close()
	close(s.polMonStop)
	log.Debug("egress.Session Cleanup: wait for worker")
	<-s.workerStopped
	log.Debug("egress.Session Cleanup: wait for poller")
	<-s.polMonStopped
	log.Debug("egress.Session Cleanup: closing conn")
	return s.conn.Close()
}

type SessionInfo struct {
	Sig  *siginfo.Sig
	Path *sciond.PathReplyEntry
}

type PathMetrics struct {
	// Some statistics about latency and loss
}
