// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package core contains the tables for remote SIGs, ASes and their prefixes
package core

import (
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/sig/config"
)

var Map = &ASMap{}

// ASMap is not concurrency safe against multiple writers.
type ASMap sync.Map

func (am *ASMap) Delete(key addr.IAInt) {
	(*sync.Map)(am).Delete(key)
}

func (am *ASMap) Load(key addr.IAInt) (*ASEntry, bool) {
	value, ok := (*sync.Map)(am).Load(key)
	if value == nil {
		return nil, ok
	}
	return value.(*ASEntry), ok
}

func (am *ASMap) LoadOrStore(key addr.IAInt, value *ASEntry) (*ASEntry, bool) {
	actual, ok := (*sync.Map)(am).LoadOrStore(key, value)
	if actual == nil {
		return nil, ok
	}
	return actual.(*ASEntry), ok
}

func (am *ASMap) Store(key addr.IAInt, value *ASEntry) {
	(*sync.Map)(am).Store(key, value)
}

func (am *ASMap) Range(f func(key addr.IAInt, value *ASEntry) bool) {
	(*sync.Map)(am).Range(func(key, value interface{}) bool {
		return f(key.(addr.IAInt), value.(*ASEntry))
	})
}

func (am *ASMap) ReloadConfig(cfg *config.Cfg) bool {
	// Method calls first to prevent skips due to logical short-circuit
	s := am.addNewIAs(cfg)
	return am.delOldIAs(cfg) && s
}

// addNewIAs adds the ASes in cfg that are not currently configured.
func (am *ASMap) addNewIAs(cfg *config.Cfg) bool {
	s := true
	for ia, cfgEntry := range cfg.ASes {
		log.Info("ReloadConfig: Adding AS...", "ia", ia)
		ae, err := am.AddIA(ia)
		if err != nil {
			log.Error("ReloadConfig: Adding AS failed", "err", err)
			s = false
			continue
		}
		s = ae.ReloadConfig(cfgEntry) && s
		log.Info("ReloadConfig: Added AS", "ia", ia)
	}
	return s
}

func (am *ASMap) delOldIAs(cfg *config.Cfg) bool {
	s := true
	// Delete all ASes that currently exist but are not in cfg
	am.Range(func(iaInt addr.IAInt, as *ASEntry) bool {
		ia := iaInt.IA()
		if _, ok := cfg.ASes[ia]; !ok {
			log.Info("ReloadConfig: Deleting AS...", "ia", ia)
			// Deletion also handles session/tun device cleanup
			err := am.DelIA(ia)
			if err != nil {
				log.Error("ReloadConfig: Deleting AS failed", "err", err)
				s = false
				return true
			}
			log.Info("ReloadConfig: Deleted AS", "ia", ia)
		}
		return true
	})
	return s
}

// AddIA idempotently adds an entry for a remote IA.
func (am *ASMap) AddIA(ia addr.IA) (*ASEntry, error) {
	if ia.IsWildcard() {
		return nil, common.NewBasicError("AddIA: Wildcard IA not allowed", nil, "ia", ia)
	}
	key := ia.IAInt()
	ae, ok := am.Load(key)
	if ok {
		return ae, nil
	}
	ae, err := newASEntry(ia)
	if err != nil {
		return nil, err
	}
	am.Store(key, ae)
	return ae, nil
}

// DelIA removes an entry for a remote IA.
func (am *ASMap) DelIA(ia addr.IA) error {
	key := ia.IAInt()
	ae, ok := am.Load(key)
	if !ok {
		return common.NewBasicError("DelIA: No entry found", nil, "ia", ia)
	}
	am.Delete(key)
	return ae.Cleanup()
}

// ASEntry returns the entry for the specified remote IA, or nil if not present.
func (am *ASMap) ASEntry(ia addr.IA) *ASEntry {
	if as, ok := am.Load(ia.IAInt()); ok {
		return as
	}
	return nil
}
