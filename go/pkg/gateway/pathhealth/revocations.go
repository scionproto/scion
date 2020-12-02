// Copyright 2020 Anapaya Systems
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

package pathhealth

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

// MemoryRevocationStore holds a list of current revocations. It can be used to
// determine whether a path goes through interfaces which are revoked.
type MemoryRevocationStore struct {
	Logger log.Logger

	mu   sync.RWMutex
	revs map[snet.PathInterface]*path_mgmt.RevInfo
}

// AddRevocation adds the revocation to the list of currently active
// revocations.
func (s *MemoryRevocationStore) AddRevocation(rev *path_mgmt.RevInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rev == nil {
		return
	}
	iface := snet.PathInterface{IA: rev.RawIsdas.IA(), ID: rev.IfID}
	if _, ok := s.revs[iface]; !ok {
		log.SafeDebug(s.Logger, "Revocation added", "isd_as", iface.IA, "intf", iface.ID)
	}
	if s.revs == nil {
		s.revs = make(map[snet.PathInterface]*path_mgmt.RevInfo)
	}
	s.revs[iface] = rev
}

// Cleanup removes all expired revocations.
func (s *MemoryRevocationStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, rev := range s.revs {
		if rev.Expiration().Before(now) {
			log.SafeDebug(s.Logger, "Revocation expired", "isd_as", rev.RawIsdas, "intf", rev.IfID)
			delete(s.revs, k)
		}
	}
}

// IsRevoked returns true if there is at least one revoked interface on the path.
func (s *MemoryRevocationStore) IsRevoked(path snet.Path) bool {
	var ifaces []snet.PathInterface
	if meta := path.Metadata(); meta != nil {
		ifaces = meta.Interfaces
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, iface := range ifaces {
		key := snet.PathInterface{ID: iface.ID, IA: iface.IA}
		if rev := s.revs[key]; rev != nil && rev.Expiration().After(now) {
			return true
		}
	}
	return false
}
