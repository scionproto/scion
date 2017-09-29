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
)

var Table = newASTable()

type ASTable struct {
	// FIXME(kormat): when we switch to go 1.9, consider replacing this with sync.Map.
	sync.RWMutex
	t map[addr.IAInt]*ASEntry
}

func newASTable() *ASTable {
	return &ASTable{t: make(map[addr.IAInt]*ASEntry)}
}

// Add IA entry, true if added
func (at *ASTable) AddIA(ia *addr.ISD_AS) (bool, error) {
	at.Lock()
	defer at.Unlock()
	key := ia.IAInt()
	_, ok := at.t[key]
	if ok {
		return false, nil
	}
	at.t[key] = newASEntry(ia)
	log.Debug("Added IA", "ia", ia)
	return true, nil
}

// Remove IA entry, true if removed
func (at *ASTable) DelIA(ia *addr.ISD_AS) (bool, error) {
	at.Lock()
	key := ia.IAInt()
	entry, ok := at.t[key]
	if !ok {
		at.Unlock()
		return false, nil
	}
	delete(at.t, key)
	// Unlock before cleanup to reduce time spent holding this mutex.
	at.Unlock()
	log.Debug("Removed IA", "ia", ia)
	return true, entry.Cleanup()
}

func (at *ASTable) ASEntry(ia *addr.ISD_AS) *ASEntry {
	at.RLock()
	defer at.RUnlock()
	return at.t[ia.IAInt()]
}
