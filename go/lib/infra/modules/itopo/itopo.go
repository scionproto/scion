// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

// Package itopo stores the static and dynamic topology. Client packages
// that grab a reference with Get are guaranteed to receive a stable
// snapshot of the topology. The returned value is the topology that is
// currently active.
//
// There are two types of topologies, the static and the dynamic topology.
// For more information see lib/discovery.
//
// Initialization
//
// The package must be initialized with Init or InitSvc. In subsequent
// updates through SetStatic or SetDynamic, the new topology is checked
// whether it is compatible with the previous version. The rules differ
// between services.
//
// If the dynamic topology is set, the initializing client should start
// the periodic cleaner to evict expired dynamic topologies.
//
// Updates
//
// The update of the topology is only valid if a set of constraints is
// met. The constraints differ between dynamic and static topology, and
// also between the initialized service type.
//
// In a static topology update, when the diff is empty, the static
// topology is only updated if it expires later than the current static.
// Otherwise, SetStatic succeeds and indicates that the in-memory copy
// has not been updated.
//
// A static topology update can force the dynamic topology to be dropped,
// if it does no longer meet the constraints.
//
// Constraints
//
// The topology is split into four parts. An update is valid under the
// constraints, if the constraints for each part are met.
//
// Immutable:
// This part may not differ from the initial static topology.
//
// Mutable:
// This part may differ from the initial static topology. It may also
// differ between the currently active static and dynamic topology.
//
// Semi-Mutable:
// This part may differ between static topology versions. However, it
// may not differ between the current dynamic and static topology.
// If an update to the static topology modifies this part, the dynamic
// topology is dropped.
//
// Time:
// This part is ignored when validating the constraints. It is used
// to determine if a topology shall be updated if there are no
// differences in the other parts.
//
// Default Topology Split
//
// The topology file for default initialization (calling Init) is split
// into immutable, mutable and time.
//
//  ISD_AS                Immutable
//  Core                  Immutable
//  Overlay               Immutable
//  MTU                   Immutable
//
//  Service Entries       Mutable
//  BorderRouter Entries  Mutable
//
//  Timestamp             Time
//  TimestampHuman        Time
//  TTL                   Time
//
// Service Topology Split
//
// The topology file for services is split into immutable, mutable
// and time.
//
//  ISD_AS                Immutable
//  Core                  Immutable
//  Overlay               Immutable
//  MTU                   Immutable
//  OwnSvcType[OwnID]     Immutable // The service entry for the initialized element.
//
//  Service Entries       Mutable   // Except OwnSvcType[OwnID].
//  BorderRouter Entries  Mutable
//
//  Timestamp             Time
//  TimestampHuman        Time
//  TTL                   Time
//
// Border Router Topology Split
//
// The topology file for border routers is split into immutable,
// semi-mutable, mutable and time.
//
//  ISD_AS                              Immutable
//  Core                                Immutable
//  Overlay                             Immutable
//  MTU                                 Immutable
//  OwnSvcType[OwnID]                   Immutable
//  BorderRouters[OwnId][InternalAddrs] Immutable    // Internal address of initialized router.
//  BorderRouters[OwnId][CtrlAddr]      Immutable    // Control address of initialized router.
//
//  BorderRouters[OwnId][Interfaces]    Semi-Mutable // Interfaces of initialized router.
//
//  Service Entries       Mutable                    // Except BorderRouters[OwnId].
//  BorderRouter Entries  Mutable
//
//  Timestamp             Time
//  TimestampHuman        Time
//  TTL                   Time
//
// Callbacks
//
// The client package can register callbacks to be notified about
// certain events.
package itopo

import (
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	validate    validator
	clbks       Clbks
	topologyMtx sync.RWMutex
	staticTopo  *topology.Topo = nil
	dynamicTopo *topology.Topo = nil
)

// Clbks are callbacks to respond to specific topology update events.
type Clbks struct {
	// CleanDynamic is called whenever dynamic topology is dropped due to expiration.
	CleanDynamic func()
	// DropDynamic is called whenever dynamic topology is dropped due to static update.
	DropDynamic func()
	// UpdateStatic is called whenever the pointer to static topology is updated.
	UpdateStatic func()
}

// Init initializes itopo without a particular element set. When setting the topology,
// only the immutable fields are checked.
func Init(static *topology.Topo, callbacks *Clbks) error {
	return InitSvc("", proto.ServiceType_unset, static, callbacks)
}

// InitSvc initializes itopo with a particular element set. When setting the topology,
// the immutable and semi-mutable fields are checked.
func InitSvc(id string, svc proto.ServiceType, static *topology.Topo, callbacks *Clbks) error {
	if staticTopo != nil {
		return common.NewBasicError("Must not re-initialize itopo", nil)
	}
	switch svc {
	case proto.ServiceType_unset:
		validate = &generalValidator{}
	case proto.ServiceType_br:
		// FIXME(roosd): add validator for border router.
		validate = &generalValidator{}
	default:
		// FIMXE(roosd): add validator for service.
		validate = &generalValidator{}
	}
	if err := validate.General(static); err != nil {
		return common.NewBasicError("Unable to validate initial static topo", err)
	}
	if callbacks != nil {
		clbks = *callbacks
	}
	staticTopo = static
	return nil
}

// Get atomically gets the pointer to the current topology.
func Get() *topology.Topo {
	topologyMtx.Lock()
	defer topologyMtx.Unlock()
	return currTopo()
}

func currTopo() *topology.Topo {
	if dynamicTopo != nil && dynamicTopo.Active(time.Now()) {
		return dynamicTopo
	}
	return staticTopo
}

// SetStatic atomically sets the static topology. Whether semi-mutable fields are
// allowed to change can be specified using semiMutAllowed. The returned
// topology is a pointer to the currently active topology. It might differ from
// the input topology. The second return value indicates whether the in-memory
// copy of the static topology has been updated.
func SetStatic(topo *topology.Topo, semiMutAllowed bool) (*topology.Topo, bool, error) {
	topologyMtx.Lock()
	defer topologyMtx.Unlock()
	if err := validate.General(topo); err != nil {
		return nil, false, err
	}
	if err := validate.Immutable(topo, staticTopo); err != nil {
		return nil, false, err
	}
	if err := validate.SemiMutable(topo, staticTopo, semiMutAllowed); err != nil {
		return nil, false, err
	}
	updated := setStatic(topo, validate.DropDynamic(topo, staticTopo))
	return currTopo(), updated, nil
}

// setStatic sets the static topology and calls the necessary callbacks.
func setStatic(topo *topology.Topo, dropDynamic bool) bool {
	expiresLater := staticTopo.TTL != 0 && (topo.TTL == 0 ||
		topo.Timestamp.Add(topo.TTL).After(staticTopo.Timestamp.Add(staticTopo.TTL)))
	// Only update static topology if the new one is different or longer valid for.
	if cmp.Equal(topo, staticTopo, cmpopts.IgnoreFields(topology.Topo{},
		"Timestamp", "TimestampHuman", "TTL")) && !expiresLater {
		return false
	}
	staticTopo = topo
	// Drop dynamic topology if necessary.
	if dropDynamic && dynamicTopo != nil {
		dynamicTopo = nil
		call(clbks.DropDynamic)
	}
	call(clbks.UpdateStatic)
	return true
}

func call(clbk func()) {
	if clbk != nil {
		go func() {
			defer log.LogPanicAndExit()
			clbk()
		}()
	}
}
