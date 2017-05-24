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

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/proto"
)

func init() {
	S = &States{M: make(map[spath.IntfID]State)}
}

// States is a map of interface IDs to interface states, protected by a RWMutex.
type States struct {
	sync.RWMutex
	M map[spath.IntfID]State
}

// State stores the IFStateInfo capnp message, as well as the raw revocation
// info for a given interface.
type State struct {
	P      proto.IFStateInfo
	RawRev common.RawBytes
}

// S contains the interface states.
var S *States

// Process processes Interface State updates from the beacon service.
func Process(ifStates proto.IFStateInfos) {
	infos, serr := ifStates.Infos()
	if serr != nil {
		log.Error("Unable to extract IFStateInfos from message", "err", serr)
		return
	}
	// Convert IFState infos to map
	m := make(map[spath.IntfID]State, infos.Len())
	for i := 0; i < infos.Len(); i++ {
		info := infos.At(i)
		ifid := spath.IntfID(info.IfID())
		revInfo, serr := info.RevInfo()
		if serr != nil {
			log.Error("Unable to extract RevInfo from IFStateInfo", "err", serr, "info", info)
			return
		}
		rawRev, err := proto.StructPack(revInfo.Struct)
		if err != nil {
			log.Error("Unable to pack RevInfo", err.Ctx...)
			return
		}
		m[ifid] = State{P: info, RawRev: rawRev}
		gauge := metrics.IFState.WithLabelValues(fmt.Sprintf("intf:%d", ifid))
		oldState, ok := S.M[ifid]
		if !ok {
			log.Info("IFState: intf added", "ifid", ifid, "active", info.Active())
		}
		if info.Active() {
			if ok && !oldState.P.Active() {
				log.Info("IFState: intf activated", "ifid", ifid)
			}
			gauge.Set(1)
		} else {
			if ok && oldState.P.Active() {
				log.Info("IFState: intf deactivated", "ifid", ifid)
			}
			gauge.Set(0)
		}
	}
	// Lock IFState config for writing, and replace existing map
	S.Lock()
	S.M = m
	S.Unlock()
}

// Activate updates the state of a single interface to active.
func Activate(ifID spath.IntfID) *common.Error {
	S.Lock()
	defer S.Unlock()
	ifState, ok := S.M[ifID]
	if !ok {
		return common.NewError("Trying to activate non-existing interface", "intf", ifID)
	}
	ifState.P.SetActive(true)
	return nil
}
