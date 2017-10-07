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
	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
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
	log.Logger
	IA      *addr.ISD_AS
	SessId  sigcmn.SessionType
	PolName string
	// FIXME(kormat): not implemented yet :P contstrains what interfaces to route through.
	policy interface{}
	// pool of paths that meet the policy requirement, managed by pathmgr
	pool *pathmgr.SyncPaths
	// function pointer to return SigMap from parent ASEntry.
	sigMapF func() siginfo.SigMap
	// *RemoteInfo
	currRemote     atomic.Value
	ring           *ringbuf.Ring
	conn           *snet.Conn
	sessMonStop    chan struct{}
	sessMonStopped chan struct{}
	workerStopped  chan struct{}
}

func NewSession(dstIA *addr.ISD_AS, sessId sigcmn.SessionType, polName string,
	policy interface{}, sigMapF func() siginfo.SigMap) (*Session, error) {
	var err error
	s := &Session{
		IA: dstIA, SessId: sessId, PolName: polName, policy: policy, sigMapF: sigMapF,
	}
	s.Logger = log.New("ia", s.IA, "sessId", s.SessId, "policy", s.PolName)
	// FIXME(kormat): change to `RegisterFilter once pathmgr supports policies.
	s.pool, err = sigcmn.PathMgr.Register(sigcmn.IA, dstIA)
	if err != nil {
		return nil, err
	}
	s.currRemote.Store((*RemoteInfo)(nil))
	s.ring = ringbuf.New(64, nil, "egress",
		prometheus.Labels{"ringId": dstIA.String(), "sessId": sessId.String()})
	// Not using a fixed local port, as this is for outgoing data only.
	s.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	go snet.PktDispatcher(s.conn, snet.DispLogger)
	s.sessMonStop = make(chan struct{})
	s.sessMonStopped = make(chan struct{})
	s.workerStopped = make(chan struct{})
	return s, err
}

func (s *Session) Start() {
	go newSessMonitor(s).run()
	go NewWorker(s).Run()
	go connReader(s.conn, "session")
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

type RemoteInfo struct {
	Sig      *siginfo.Sig
	sessPath *sessPath
}

func (r *RemoteInfo) String() string {
	return fmt.Sprintf("Sig: %s Path: %s", r.Sig, r.sessPath)
}

// connReader logs everything read from conn. This is used to make sure the
// dispatcher doesn't block if it tries to deliver unexpected messages to a
// write-only connection.
func connReader(conn *snet.Conn, name string) {
	defer liblog.LogPanicAndExit()
	buf := make(common.RawBytes, common.MaxMTU)
	for {
		l, src, err := conn.ReadFromSCION(buf)
		if err != nil {
			log.Error("connReader error", "name", name, "err", err)
			continue
		}
		log.Debug("connReader", "name", name, "src", src, "raw", buf[:l])
	}
}
