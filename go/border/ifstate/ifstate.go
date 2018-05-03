// Copyright 2016 ETH Zurich
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

// This file handles generating periodic Interface State Request (IFStateReq)
// packets that are sent to the local Beacon Service (BS), as well as
// processing the Interface State updates. IFStateReqs are mostly needed on
// startup, to make sure the border router is aware of the status of the local
// interfaces. The BS normally updates the border routers everytime an
// interface state changes, so this is only needed as a fail-safe after
// startup.

package ifstate

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// ifStates is a map of interface IDs to interface states.
type ifStates sync.Map

func (s *ifStates) Delete(key common.IFIDType) {
	(*sync.Map)(s).Delete(key)
}

func (s *ifStates) Load(key common.IFIDType) (*state, bool) {
	val, loaded := (*sync.Map)(s).Load(key)
	if val == nil {
		return nil, loaded
	}
	return val.(*state), loaded
}

func (s *ifStates) Store(key common.IFIDType, val *state) {
	(*sync.Map)(s).Store(key, val)
}

var states ifStates

type state struct {
	// info is a pointer to an Info object.
	info unsafe.Pointer
}

// Info stores state information, as well as the raw revocation info for a given interface.
type Info struct {
	IfID         common.IFIDType
	Active       bool
	SRevInfo     *path_mgmt.SignedRevInfo
	RawSRev      common.RawBytes
	ActiveMetric prometheus.Gauge
}

func NewInfo(ifID common.IFIDType, active bool, srev *path_mgmt.SignedRevInfo,
	rawSRev common.RawBytes) *Info {
	i := &Info{
		IfID:         ifID,
		Active:       active,
		SRevInfo:     srev,
		RawSRev:      rawSRev,
		ActiveMetric: metrics.IFState.WithLabelValues(fmt.Sprintf("intf:%d", ifID)),
	}
	var isActive float64
	if active {
		isActive = 1
	}
	i.ActiveMetric.Set(isActive)

	return i
}

// Process processes Interface State updates from the beacon service.
func Process(ifStates *path_mgmt.IFStateInfos) {
	for _, info := range ifStates.Infos {
		var rawSRev common.RawBytes
		ifid := common.IFIDType(info.IfID)
		if info.SRevInfo != nil {
			var err error
			rawSRev, err = proto.PackRoot(info.SRevInfo)
			if err != nil {
				log.Error("Unable to pack SRevInfo", "err", err)
				return
			}
		}
		stateInfo := NewInfo(ifid, info.Active, info.SRevInfo, rawSRev)
		s, ok := states.Load(ifid)
		if !ok {
			log.Info("IFState: intf added", "ifid", ifid, "active", info.Active)
			s = &state{info: unsafe.Pointer(stateInfo)}
			states.Store(ifid, s)
			continue
		}
		oldInfo := (*Info)(atomic.LoadPointer(&s.info))
		if stateInfo.Active {
			if !oldInfo.Active {
				log.Info("IFState: intf activated", "ifid", ifid)
			}
		} else {
			if oldInfo.Active {
				log.Info("IFState: intf deactivated", "ifid", ifid)
			}
		}
		atomic.StorePointer(&s.info, unsafe.Pointer(stateInfo))
	}
}

// LoadState returns the state info for a given interface ID or nil.
// The bool result indicates whether the state was found in the map.
func LoadState(ifID common.IFIDType) (*Info, bool) {
	s, ok := states.Load(ifID)
	if !ok {
		return nil, ok
	}
	return (*Info)(atomic.LoadPointer(&s.info)), ok
}

// UpdateIfNew atomically updates the state info for a given ifid, if the state has
// not been changed in the meantime. If there is no state info, a new one will be created
// and the new state will be inserted.
func UpdateIfNew(ifID common.IFIDType, old, new *Info) {
	s, ok := states.Load(ifID)
	if ok {
		atomic.CompareAndSwapPointer(&s.info, unsafe.Pointer(old), unsafe.Pointer(new))
		return
	}
	s = &state{}
	atomic.StorePointer(&s.info, unsafe.Pointer(new))
	states.Store(ifID, s)
}

// DeleteState removes the state info for a given interface.
func DeleteState(ifID common.IFIDType) {
	states.Delete(ifID)
}
