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

package base

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
)

type SyncPathPolicies struct {
	atomic.Value
}

func NewSyncPathPolicies() *SyncPathPolicies {
	spp := &SyncPathPolicies{}
	spp.Store(([]*PathPolicy)(nil))
	return spp
}

func (spp *SyncPathPolicies) Load() []*PathPolicy {
	return spp.Value.Load().([]*PathPolicy)
}

// PathPolicy contains the path policy for a given remote AS. This means having
// a pool of paths that match the specified policy, metrics about those paths,
// as well as maintaining the currently favoured path and remote SIG to use.
type PathPolicy struct {
	IA      *addr.ISD_AS
	Name    string
	Session sigcmn.SessionType
	// FIXME(kormat): not implemented yet :P contstrains what interfaces to route through.
	policy interface{}
	// pool of paths that meet the policy requirement, managed by pathmgr
	pool *pathmgr.SyncPaths
	info atomic.Value // PathPolicyInfo
	// Metrics per set of path hops, entries added/removed whenever pool changes.
	PathsMetrics  map[pathmgr.PathKey]PathMetrics
	ring          *ringbuf.Ring
	conn          *snet.Conn
	polMonStop    chan struct{}
	polMonStopped chan struct{}
	workerStopped chan struct{}
}

func NewPathPolicy(dstIA *addr.ISD_AS, name string,
	sess sigcmn.SessionType, policy interface{}) (*PathPolicy, error) {
	var err error
	// FIXME(kormat): change to `RegisterFilter once pathmgr supports policies.
	pp := &PathPolicy{IA: dstIA, Name: name, Session: sess, policy: policy}
	pp.pool, err = sigcmn.PathMgr.Register(sigcmn.IA, dstIA)
	if err != nil {
		return nil, err
	}
	// Initialize currPath
	var pathEntry *sciond.PathReplyEntry
	aps := pp.pool.Load()
	if aps != nil {
		ap := aps.GetAppPath()
		if ap != nil {
			pathEntry = ap.Entry
		}
	}
	pp.info.Store(PathPolicyInfo{Path: pathEntry})
	pp.ring = ringbuf.New(64, nil, "egress", prometheus.Labels{"ringId": dstIA.String()})
	// Not using a fixed local port, as this is for outgoing data only.
	pp.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	pp.polMonStop = make(chan struct{})
	pp.polMonStopped = make(chan struct{})
	pp.workerStopped = make(chan struct{})
	return pp, err
}

func (pp *PathPolicy) Start(getSig func() *SIGEntry) {
	go newPolicyMonitor(pp, getSig).run()
	go NewEgressWorker(pp).Run()
}

func (pp *PathPolicy) Info() PathPolicyInfo {
	return pp.info.Load().(PathPolicyInfo)
}

func (pp *PathPolicy) CurrPath() *sciond.PathReplyEntry {
	info := pp.Info()
	return info.Path
}

func (pp *PathPolicy) setPath(path *sciond.PathReplyEntry) {
	info := pp.Info()
	info.Path = path
	pp.info.Store(info)
}

func (pp *PathPolicy) setSig(se *SIGEntry) {
	info := pp.Info()
	info.Sig = se
	pp.info.Store(info)
}

func (pp *PathPolicy) Cleanup() error {
	pp.ring.Close()
	close(pp.polMonStop)
	log.Debug("PathPolicy Cleanup: wait for worker")
	<-pp.workerStopped
	log.Debug("PathPolicy Cleanup: wait for poller")
	<-pp.polMonStopped
	log.Debug("PathPolicy Cleanup: closing conn")
	return pp.conn.Close()
}

type PathPolicyInfo struct {
	Sig  *SIGEntry
	Path *sciond.PathReplyEntry
}

type PathMetrics struct {
	// Some statistics about latency and loss
}
