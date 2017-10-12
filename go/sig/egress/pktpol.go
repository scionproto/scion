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

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pktcls"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

type SyncPktPols struct {
	atomic.Value
}

func NewSyncPktPols() *SyncPktPols {
	spp := &SyncPktPols{}
	spp.Store(([]*PktPolicy)(nil))
	return spp
}

func (spp *SyncPktPols) Load() []*PktPolicy {
	return spp.Value.Load().([]*PktPolicy)
}

type PktPolicy struct {
	ClassName string
	Class     *pktcls.Class
	Sessions  []*Session
}

func NewPktPolicy(name string, cls *pktcls.Class, sessIds []sigcmn.SessionType,
	currSessions []*Session) (*PktPolicy, error) {
	ppol := &PktPolicy{ClassName: name, Class: cls, Sessions: make([]*Session, len(sessIds))}
Top:
	for i, sessId := range sessIds {
		for _, sess := range currSessions {
			if sessId == sess.SessId {
				ppol.Sessions[i] = sess
				continue Top
			}
		}
		return nil, common.NewCError("newPktPolicy: unknown session id",
			"name", name, "sessId", sessId)
	}
	return ppol, nil
}
