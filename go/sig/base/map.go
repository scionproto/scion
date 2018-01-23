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

// Package base contains the tables for remote SIGs, ASes and their prefixes
package base

import (
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

var Map = newASMap()

// ASMap is a RWMutex-protected map of ASEntries.
type ASMap struct {
	// FIXME(kormat): when we switch to go 1.9, consider replacing this with sync.Map.
	sync.RWMutex
	t map[addr.IAInt]*ASEntry
}

func newASMap() *ASMap {
	return &ASMap{t: make(map[addr.IAInt]*ASEntry)}
}

// AddIA idempotently adds an entry for a remote IA.
func (am *ASMap) AddIA(ia *addr.ISD_AS) (*ASEntry, error) {
	if ia.I == 0 || ia.A == 0 {
		// A 0 for either ISD or AS indicates a wildcard, and not a specific ISD-AS.
		return nil, common.NewCError("AddIA: ISD and AS must not be 0", "ia", ia)
	}
	am.Lock()
	defer am.Unlock()
	key := ia.IAInt()
	ae, ok := am.t[key]
	if ok {
		return ae, nil
	}
	ae, err := newASEntry(ia)
	if err != nil {
		return nil, err
	}
	am.t[key] = ae
	log.Info("Added IA", "ia", ia)
	return ae, nil
}

// DelIA removes an entry for a remote IA.
func (am *ASMap) DelIA(ia *addr.ISD_AS) error {
	am.Lock()
	key := ia.IAInt()
	ae, ok := am.t[key]
	if !ok {
		am.Unlock()
		return common.NewCError("DelIA: No entry found", "ia", ia)
	}
	delete(am.t, key)
	am.Unlock() // Do cleanup outside the lock.
	log.Info("Removed IA", "ia", ia)
	return ae.Cleanup()
}

// ASEntry returns the entry for the specified remote IA, or nil if not present.
func (am *ASMap) ASEntry(ia *addr.ISD_AS) *ASEntry {
	am.RLock()
	defer am.RUnlock()
	return am.t[ia.IAInt()]
}
