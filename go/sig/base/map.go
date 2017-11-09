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
	"github.com/netsec-ethz/scion/go/sig/config"
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

func (am *ASMap) ReloadConfig(cfg *config.Cfg) bool {
	// Run this as a single transaction under lock to prevent races while
	// iterating over the map of ASes during deletion
	am.Lock()
	defer am.Unlock()
	success := true
	if !am.addNewIAs(cfg) {
		success = false
	}
	if !am.delOldIAs(cfg) {
		success = false
	}
	return success
}

func (am *ASMap) addNewIAs(cfg *config.Cfg) bool {
	success := true
	for iaVal, cfgEntry := range cfg.ASes {
		ia := &iaVal
		log.Info("ReloadConfig: Adding AS...", "ia", ia)
		ae, err := am.addIA(ia)
		if err != nil {
			cerr := err.(*common.CError)
			log.Error(cerr.Desc, cerr.Ctx...)
			success = false
			continue
		}
		ae.ReloadConfig(cfgEntry)
		log.Info("ReloadConfig: Added AS", "ia", ia)
	}
	return success
}

func (am *ASMap) delOldIAs(cfg *config.Cfg) bool {
	success := true
	for iaVal := range am.t {
		ia := iaVal.IA()
		if _, ok := cfg.ASes[*ia]; !ok {
			log.Info("ReloadConfig: Deleting AS...", "ia", ia)
			// Deletion also handles session/tun device cleanup
			err := am.delIA(ia)
			if err != nil {
				cerr := err.(*common.CError)
				log.Error(cerr.Desc, cerr.Ctx...)
				success = false
				continue
			}
			log.Info("ReloadConfig: Deleted AS", "ia", ia)
		}
	}
	return success
}

func (am *ASMap) AddIA(ia *addr.ISD_AS) (*ASEntry, error) {
	am.Lock()
	defer am.Unlock()
	return am.addIA(ia)
}

// AddIA idempotently adds an entry for a remote IA.
func (am *ASMap) addIA(ia *addr.ISD_AS) (*ASEntry, error) {
	if ia.I == 0 || ia.A == 0 {
		// A 0 for either ISD or AS indicates a wildcard, and not a specific ISD-AS.
		return nil, common.NewCError("AddIA: ISD and AS must not be 0", "ia", ia)
	}
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
	return ae, nil
}

func (am *ASMap) DelIA(ia *addr.ISD_AS) error {
	am.Lock()
	defer am.Unlock()
	return am.delIA(ia)
}

// DelIA removes an entry for a remote IA.
func (am *ASMap) delIA(ia *addr.ISD_AS) error {
	key := ia.IAInt()
	ae, ok := am.t[key]
	if !ok {
		return common.NewCError("DelIA: No entry found", "ia", ia)
	}
	delete(am.t, key)
	return ae.Cleanup()
}

// ASEntry returns the entry for the specified remote IA, or nil if not present.
func (am *ASMap) ASEntry(ia *addr.ISD_AS) *ASEntry {
	am.RLock()
	defer am.RUnlock()
	return am.t[ia.IAInt()]
}
