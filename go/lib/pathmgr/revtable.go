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

package pathmgr

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// uifid (Unique IFID) uniquely describes an interface
type uifid struct {
	ia   addr.IAInt
	ifid common.IFIDType
}

func uifidFromValues(isdas addr.IA, ifid common.IFIDType) uifid {
	return uifid{
		ia:   isdas.IAInt(),
		ifid: ifid,
	}
}

func (u uifid) String() string {
	return fmt.Sprintf("%s#%d", u.ia.IA().String(), u.ifid)
}

// revTable tracks for each UIFID the set of spathmeta.AppPaths that contain that
// UIFID.  Revoking an interface consists of grabbing its UIFID, going through
// the set and calling Revoke on each spathmeta.AppPath.
type revTable struct {
	// maps UIFID keys to sets of paths that contain that UIFID
	m map[uifid]spathmeta.AppPathSet
}

// newRevTable creates an empty revocation table.
func newRevTable() *revTable {
	return &revTable{
		m: make(map[uifid]spathmeta.AppPathSet),
	}
}

// updatePathSet updates the information for paths in aps. If a path is new,
// its information is added to the RevTable. If a path already exists (for
// example, because it has been received from SCIOND before), the RevTable
// pointers are updated to track the new path object. This allows revocations
// to always update the live, in-use paths and not old copies that will be soon
// collected by the GC.
func (rt *revTable) updatePathSet(aps spathmeta.AppPathSet) {
	for _, ap := range aps {
		rt.updatePath(ap)
	}
}

func (rt *revTable) updatePath(ap *spathmeta.AppPath) {
	for _, iface := range ap.Entry.Path.Interfaces {
		uifid := uifidFromValues(iface.ISD_AS(), common.IFIDType(iface.IfID))
		aps, ok := rt.m[uifid]
		if !ok {
			// spathmeta.AppPathSet not initialized yet
			aps = make(spathmeta.AppPathSet)
			// Store reference to new map
			rt.m[uifid] = aps
		}
		aps[spathmeta.PathKey(ap.Key())] = ap
	}
}

// revoke deletes all the paths that include uifid
func (rt *revTable) revoke(u uifid) spathmeta.AppPathSet {
	aps := rt.m[u]
	delete(rt.m, u)
	for _, ap := range aps {
		// Delete all references from other UIFIDs to the revoked path,
		// thus allowing the path to be garbage collected
		for _, iface := range ap.Entry.Path.Interfaces {
			ifaceUIFID := uifidFromValues(iface.ISD_AS(), common.IFIDType(iface.IfID))
			pathSet := rt.m[ifaceUIFID]
			delete(pathSet, ap.Key())
			// If the last reference from a UIFID to a path was deleted, we can
			// remove the UIFID from the revTable
			if len(pathSet) == 0 {
				delete(rt.m, ifaceUIFID)
			}
		}
	}
	return aps
}
