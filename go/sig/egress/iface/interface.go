// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// iface contains interfaces that different components within egress use to communicate.
package iface

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/sig/egress/siginfo"
)

func Init() {
	EgressFreePkts = ringbuf.New(EgressFreePktsCap, func() interface{} {
		return make(common.RawBytes, common.MaxMTU)
	}, "egress_free")
}

const (
	// FIXME(kormat): these relative sizes will fail if there are lots of egress dispatchers.
	EgressFreePktsCap = 2048
	EgressRemotePkts  = 512
	EgressBufPkts     = 32
	SafetyInterval    = 60 * time.Second
)

var EgressFreePkts *ringbuf.Ring

// Session defines a stateful context for sending traffic to a remote AS.
type Session interface {
	// Logger returns the logger associated with this session.
	Logger() log.Logger
	// IA returns the session's remote IA
	IA() addr.IA
	// ID returns the session's ID.
	ID() sig_mgmt.SessionType
	// Conn returns the session's outbound *snet.Conn.
	// The returned value must be the same for the entire lifetime of the object.
	Conn() *snet.Conn
	// Ring returns the session's ring buffer.
	Ring() *ringbuf.Ring
	// Remote returns the session's currently chosen SIG and path.
	Remote() *RemoteInfo
	// Cleanup shuts down the session and cleans resources.
	Cleanup() error
	// Healthy returns true if the session has a remote SIG and is receiving
	// keepalive responses from it.
	Healthy() bool
	// PathPool returns the session's available pool of paths.
	PathPool() PathPool
	// AnnounceWorkerStopped is used to inform the session that its worker needed to shut down.
	AnnounceWorkerStopped()
}

type RemoteInfo struct {
	Sig      *siginfo.Sig
	SessPath *SessPath
}

// Copy created a deep copy of the object.
func (r *RemoteInfo) Copy() *RemoteInfo {
	if r == nil {
		return nil
	}
	return &RemoteInfo{
		Sig:      r.Sig.Copy(),
		SessPath: r.SessPath.Copy(),
	}
}

func (r *RemoteInfo) String() string {
	return fmt.Sprintf("Sig: %s Path: %s", r.Sig, r.SessPath)
}

// PathPool is implemented by objects that maintain sets of paths. PathPools
// must be safe for concurrent use by multiple goroutines.
type PathPool interface {
	// Paths returns the paths contained in the pool.
	Paths() spathmeta.AppPathSet
	// Destroy cleans up any resources associated with the PathPool.
	Destroy() error
}

type SessionSelector interface {
	ChooseSess(b common.RawBytes) Session
}
