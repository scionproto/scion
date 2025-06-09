// Copyright 2025 SCION Association
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

package afpacketudpip

import (
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/log"
)

const (
	neighborTick = 1 * time.Second // Cache clock period.
	neighborTTL  = 10              // Time until resolved entry is stale.
	neighborTTR  = 3               // Time until giving up on unresolved entry.
)

type neighbor struct {
	mac *[6]byte
	// timer keeps track of the time that the entry has been resolved or pending:
	timer int
}

// Not re-entrant: you must bring your own Mutex. The reason is that we have two different usage
// patterns; one of which needs to manipulate another object in the same critical section.
type neighborCache map[netip.Addr]neighbor

// Lookup returns the mac address associated with the given IP, or nil if not known, and whether an
// entry already existed. A new (pending) entry is created if none existed. A resolution should be
// triggered if the entry did not exist. This is optional, but the pending entry will exist for as
// long as specified by the TTR.
func (cache neighborCache) get(ip netip.Addr) (*[6]byte, bool) {
	entry := cache[ip]
	if entry.timer > 0 {
		// Valid.
		return entry.mac, true
	}
	if entry.timer < 0 {
		// Already pending
		return nil, true
	}
	// Unknown. Must trigger a resolution.
	cache[ip] = neighbor{nil, -neighborTTR}
	return nil, false
}

func (cache neighborCache) check(ip netip.Addr) bool {
	return cache[ip].timer != 0
}

// Associates the given IP address to the given MAC address, unless an identical association
// already exists. Returns a pointer to the retained value. This cannonicalization reduces GC
// pressure by not forcing a copy of the given address to escape to the heap unnecessarily.
func (cache neighborCache) put(ip netip.Addr, mac [6]byte) *[6]byte {
	oldEntry := cache[ip]
	if oldEntry.mac == nil || *oldEntry.mac != mac {
		newMAC := &mac
		cache[ip] = neighbor{newMAC, neighborTTL}
		log.Debug("Neighbor cache updated ptp", "IP", ip, "isat", mac)
		return newMAC
	}
	return oldEntry.mac
}

// tick updates the timer of each entry.
func (cache neighborCache) tick() {
	for k, n := range cache {
		if n.timer == 0 {
			// Stale. Throw away.
			delete(cache, k)
			continue
		}
		if n.timer > 0 {
			n.timer--
		} else {
			n.timer++
		}
		cache[k] = n
	}
}
