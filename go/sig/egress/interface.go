// Copyright 2018 ETH Zurich
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
	"math"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/siginfo"
)

func Init() {
	EgressFreePkts = ringbuf.New(EgressFreePktsCap, func() interface{} {
		return make(common.RawBytes, common.MaxMTU)
	}, "egress", prometheus.Labels{"ringId": "freePkts", "sessId": ""})
}

const (
	// FIXME(kormat): these relative sizes will fail if there are lots of egress dispatchers.
	EgressFreePktsCap = 1024
	EgressBufPkts     = 32
)

var EgressFreePkts *ringbuf.Ring

type Session interface {
	log.Logger
	IA() addr.IA
	ID() mgmt.SessionType
	Conn() *snet.Conn
	Ring() *ringbuf.Ring
	Remote() *RemoteInfo
	Cleanup() error
	Healthy() bool
	PathPool() PathPool
	AnnounceWorkerStopped()
}

type Worker interface {
	Run()
}

type WorkerFactory func(Session, log.Logger) Worker

type Reader interface {
	Run()
}

type Dispatcher interface {
	Run()
}

type RemoteInfo struct {
	Sig      *siginfo.Sig
	SessPath *SessPath
}

func (r *RemoteInfo) String() string {
	return fmt.Sprintf("Sig: %s Path: %s", r.Sig, r.SessPath)
}

type PathPool interface {
	Paths() spathmeta.AppPathSet
	Destroy() error
}

type SessionSet map[mgmt.SessionType]Session

const pathFailExpiration = 5 * time.Minute

type SessPathPool map[spathmeta.PathKey]*SessPath

// Return the path with the fewest failures, excluding the current path (if specified).
func (spp SessPathPool) Get(currKey spathmeta.PathKey) *SessPath {
	var sp *SessPath
	var minFail uint16 = math.MaxUint16
	for k, v := range spp {
		if k == currKey {
			// Exclude the current path, if specified.
			continue
		}
		if v.failCount < minFail {
			sp = v
			minFail = v.failCount
		}
	}
	return sp
}

func (spp SessPathPool) Update(aps spathmeta.AppPathSet) {
	// Remove any old entries that aren't present in the update.
	for key := range spp {
		if _, ok := aps[key]; !ok {
			delete(spp, key)
		}
	}
	for key, ap := range aps {
		e, ok := spp[key]
		if !ok {
			// This is a new path, add an entry.
			spp[key] = NewSessPath(key, ap.Entry)
		} else {
			// This path already exists, update it.
			e.pathEntry = ap.Entry
		}
	}
}

type SessPath struct {
	key       spathmeta.PathKey
	pathEntry *sciond.PathReplyEntry
	lastFail  time.Time
	failCount uint16
}

func NewSessPath(key spathmeta.PathKey, pathEntry *sciond.PathReplyEntry) *SessPath {
	return &SessPath{key: key, pathEntry: pathEntry, lastFail: time.Now()}
}

func (sp *SessPath) Key() spathmeta.PathKey {
	return sp.key
}

func (sp *SessPath) PathEntry() *sciond.PathReplyEntry {
	return sp.pathEntry
}

func (sp *SessPath) Fail() {
	sp.lastFail = time.Now()
	if sp.failCount < math.MaxInt16 {
		sp.failCount += 1
	}
}

func (sp *SessPath) ExpireFails() {
	if time.Since(sp.lastFail) > pathFailExpiration {
		sp.failCount /= 2
	}
}

func (sp *SessPath) String() string {
	return fmt.Sprintf("Key: %s %s lastFail: %s failCount: %d", sp.key,
		sp.pathEntry.Path, sp.lastFail, sp.failCount)
}

type SessionSelector interface {
	ChooseSess(b common.RawBytes) Session
}
