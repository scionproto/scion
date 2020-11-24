// Copyright 2019 Anapaya Systems
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

package ifstate

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// DefaultKeepaliveInterval is the default time between sending IFID
	// keepalive packets to the neighbor.
	DefaultKeepaliveInterval = time.Second
	// DefaultKeepaliveTimeout specifies the default for how long an interface
	// can receive no IFID keepalive packets until it is considered expired.
	DefaultKeepaliveTimeout = 3 * DefaultKeepaliveInterval
)

// Config enables configuration of the interfaces.
type Config struct {
	// KeepaliveTimeout specifies for how long an interface can receive no
	// IFID keepalive packets until it is considered expired.
	KeepaliveTimeout time.Duration
}

// InitDefaults initializes the config fields that are not set to the
// default values.
func (c *Config) InitDefaults() {
	if c.KeepaliveTimeout == 0 {
		c.KeepaliveTimeout = DefaultKeepaliveTimeout
	}
}

// Interfaces keeps track of all interfaces of the AS.
type Interfaces struct {
	mu    sync.RWMutex
	intfs map[common.IFIDType]*Interface
	cfg   Config
}

// NewInterfaces initializes the the interfaces with the provided interface info map.
func NewInterfaces(ifInfomap topology.IfInfoMap, cfg Config) *Interfaces {
	intfs := &Interfaces{
		cfg: cfg,
	}
	intfs.cfg.InitDefaults()
	intfs.Update(ifInfomap)
	return intfs
}

// Update updates the interface mapping. Interfaces no longer present in
// the topology are removed. The state of existing interfaces is preserved.
// New interfaces are added as inactive.
func (intfs *Interfaces) Update(ifInfomap topology.IfInfoMap) {
	intfs.mu.Lock()
	defer intfs.mu.Unlock()
	m := make(map[common.IFIDType]*Interface, len(intfs.intfs))
	for ifid, info := range ifInfomap {
		if intf, ok := intfs.intfs[ifid]; ok {
			intf.updateTopoInfo(info)
			m[ifid] = intf
		} else {
			m[ifid] = &Interface{
				topoInfo: info,
				cfg:      intfs.cfg,
			}
		}
	}
	intfs.intfs = m
}

// Reset resets all interface states to inactive. This should be called
// by the beacon server if it is elected leader.
func (intfs *Interfaces) Reset() {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	for _, intf := range intfs.intfs {
		intf.reset()
	}
}

// All returns a copy of the map from interface id to interface.
func (intfs *Interfaces) All() map[common.IFIDType]*Interface {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	res := make(map[common.IFIDType]*Interface, len(intfs.intfs))
	for ifid, intf := range intfs.intfs {
		res[ifid] = intf
	}
	return res
}

// Get returns the interface for the specified id, or nil if not present.
func (intfs *Interfaces) Get(ifid common.IFIDType) *Interface {
	intfs.mu.RLock()
	defer intfs.mu.RUnlock()
	return intfs.intfs[ifid]
}

// Interface keeps track of the interface state.
type Interface struct {
	mu            sync.RWMutex
	topoInfo      topology.IFInfo
	lastOriginate time.Time
	lastPropagate time.Time
	cfg           Config
}

// Activate sets the remote interface ID.
//
// Deprecated: Please do not use this anymore. It's only kept for testing
// purposes.
func (intf *Interface) Activate(remote common.IFIDType) {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	intf.topoInfo.RemoteIFID = remote
}

// TopoInfo returns the topology information.
func (intf *Interface) TopoInfo() topology.IFInfo {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.topoInfo
}

// Originate sets the time this interface has been originated on last.
func (intf *Interface) Originate(now time.Time) {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	intf.lastOriginate = now
}

// LastOriginate indicates the last time this interface has been originated on.
func (intf *Interface) LastOriginate() time.Time {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.lastOriginate
}

// Propagate sets the time this interface has been propagated on last.
func (intf *Interface) Propagate(now time.Time) {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	intf.lastPropagate = now
}

// LastPropagate indicates the last time this interface has been propagated on.
func (intf *Interface) LastPropagate() time.Time {
	intf.mu.RLock()
	defer intf.mu.RUnlock()
	return intf.lastPropagate
}

func (intf *Interface) reset() {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	intf.lastOriginate = time.Time{}
	intf.lastPropagate = time.Time{}
}

func (intf *Interface) updateTopoInfo(topoInfo topology.IFInfo) {
	intf.mu.Lock()
	defer intf.mu.Unlock()
	// Keep remote topo info.
	topoInfo.RemoteIFID = intf.topoInfo.RemoteIFID
	intf.topoInfo = topoInfo
}
