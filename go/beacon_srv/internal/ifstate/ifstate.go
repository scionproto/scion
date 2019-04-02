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
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
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

const (
	// Inactive indicates that the interface has not been activated or
	// expired yet.
	Inactive State = "Inactive"
	// Active indicates that the interface is active.
	Active State = "Active"
	// Expired indicates that the interface is expired.
	Expired State = "Expired"
	// Revoked indicates that the interface is revoked.
	Revoked State = "Revoked"
)

// State is the state of an interface.
type State string

// Config enables configuration of the interface infos.
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

// Infos keeps track of all interfaces infos of the AS.
type Infos struct {
	mu    sync.RWMutex
	intfs map[common.IFIDType]*Info
	cfg   Config
}

// NewInfos initializes the the infos with the provided interfaces.
func NewInfos(ifInfomap topology.IfInfoMap, cfg Config) *Infos {
	infos := &Infos{
		cfg: cfg,
	}
	infos.cfg.InitDefaults()
	infos.Update(ifInfomap)
	return infos
}

// Update updates the interface mapping. Interfaces no longer present in
// the topology are removed. The state of existing interfaces is preserved.
// New interfaces are added as inactive.
func (infos *Infos) Update(ifInfomap topology.IfInfoMap) {
	infos.mu.Lock()
	defer infos.mu.Unlock()
	m := make(map[common.IFIDType]*Info, len(infos.intfs))
	for ifid, info := range ifInfomap {
		if intf, ok := infos.intfs[ifid]; ok {
			intf.updateTopoInfo(info)
			m[ifid] = intf
		} else {
			m[ifid] = &Info{
				topoInfo:     info,
				state:        Inactive,
				lastActivate: time.Now(),
				cfg:          infos.cfg,
			}
		}
	}
	infos.intfs = m
}

// Reset resets all interface states to inactive. This should be called
// by the beacon server if it is elected leader.
func (infos *Infos) Reset() {
	infos.mu.RLock()
	defer infos.mu.RUnlock()
	for _, intf := range infos.intfs {
		intf.reset()
	}
}

// All returns a copy of the map from interface id to info.
func (infos *Infos) All() map[common.IFIDType]*Info {
	infos.mu.RLock()
	defer infos.mu.RUnlock()
	res := make(map[common.IFIDType]*Info, len(infos.intfs))
	for ifid, intf := range infos.intfs {
		res[ifid] = intf
	}
	return res
}

// Get returns the info for the specified interface id, or nil if not present.
func (infos *Infos) Get(ifid common.IFIDType) *Info {
	infos.mu.RLock()
	defer infos.mu.RUnlock()
	return infos.intfs[ifid]
}

type Info struct {
	mu           sync.RWMutex
	topoInfo     topology.IFInfo
	state        State
	revocation   *path_mgmt.SignedRevInfo
	lastActivate time.Time
	cfg          Config
}

// Activate activates the interface the keep alive is received from when
// necessary, and sets the remote interface id. The return value indicates
// the previous state of the interface.
func (inf *Info) Activate(remote common.IFIDType) State {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	prev := inf.state
	inf.state = Active
	inf.lastActivate = time.Now()
	inf.topoInfo.RemoteIFID = remote
	inf.revocation = nil
	return prev
}

// Expire checks whether the interface has not been activated for a certain
// amount of time. If that is the case and the current state is inactive or
// active, the state changes to Expired. The return value indicates,
// whether the state is expired or revoked when the call returns.
func (inf *Info) Expire() bool {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	if inf.state == Expired || inf.state == Revoked {
		return true
	}
	if time.Now().Sub(inf.lastActivate) > inf.cfg.KeepaliveTimeout {
		inf.state = Expired
		return true
	}
	return false
}

// Revoke changes the state of the interface to revoked and updates the
// revocation, unless the current state is active. In that case, the
// interface has been activated in the meantime and should not be revoked.
// This is indicated through an error.
func (inf *Info) Revoke(rev *path_mgmt.SignedRevInfo) error {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	if inf.state == Active {
		return common.NewBasicError("Interface activated in the meantime", nil)
	}
	inf.state = Revoked
	inf.revocation = rev
	return nil
}

// Revocation returns the revocation.
func (inf *Info) Revocation() *path_mgmt.SignedRevInfo {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.revocation
}

// TopoInfo returns the topology information.
func (inf *Info) TopoInfo() topology.IFInfo {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.topoInfo
}

// State returns the current state of the interface.
func (inf *Info) State() State {
	inf.mu.RLock()
	defer inf.mu.RUnlock()
	return inf.state
}

func (inf *Info) reset() {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	inf.state = Inactive
	inf.revocation = nil
	// Set the starting point for the timeout interval.
	inf.lastActivate = time.Now()
}

func (inf *Info) updateTopoInfo(topoInfo topology.IFInfo) {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	// Keep remote topo info.
	topoInfo.RemoteIFID = inf.topoInfo.RemoteIFID
	inf.topoInfo = topoInfo
}
