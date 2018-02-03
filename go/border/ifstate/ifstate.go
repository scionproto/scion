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

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/proto"
)

// States is a map of interface IDs to interface states.
type States sync.Map

func (s *States) Delete(key common.IFIDType) {
	(*sync.Map)(s).Delete(key)
}

func (s *States) Load(key common.IFIDType) (*State, bool) {
	val, loaded := (*sync.Map)(s).Load(key)
	if val == nil {
		return nil, loaded
	}
	return val.(*State), loaded
}

func (s *States) Store(key common.IFIDType, val *State) {
	(*sync.Map)(s).Store(key, val)
}

// State stores the IFStateInfo capnp message, as well as the raw revocation
// info for a given interface.
type State struct {
	Info   *path_mgmt.IFStateInfo
	RawRev common.RawBytes
}

var states States

// Process processes Interface State updates from the beacon service.
func Process(ifStates *path_mgmt.IFStateInfos) {
	for _, info := range ifStates.Infos {
		var rawRev common.RawBytes
		ifid := common.IFIDType(info.IfID)
		if info.RevInfo != nil {
			var err error
			rawRev, err = proto.PackRoot(info.RevInfo)
			if err != nil {
				log.Error("Unable to pack RevInfo", "err", err)
				return
			}
		}
		s := &State{Info: info, RawRev: rawRev}
		gauge := metrics.IFState.WithLabelValues(fmt.Sprintf("intf:%d", ifid))
		oldState, ok := states.Load(ifid)
		if !ok {
			log.Info("IFState: intf added", "ifid", ifid, "active", info.Active)
		}
		if info.Active {
			if ok && !oldState.Info.Active {
				log.Info("IFState: intf activated", "ifid", ifid)
			}
			gauge.Set(1)
		} else {
			if ok && oldState.Info.Active {
				log.Info("IFState: intf deactivated", "ifid", ifid)
			}
			gauge.Set(0)
		}
		states.Store(ifid, s)
	}
}

// GetState returns the State for a given interface ID or an empty state.
// The bool result indicates whether the state was found in the map.
func GetState(ifID common.IFIDType) (*State, bool) {
	return states.Load(ifID)
}
