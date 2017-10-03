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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type IAPair struct {
	src *addr.ISD_AS
	dst *addr.ISD_AS
}

// UIFID (Unique IFID) is a IFID descriptor with global scope composed of ISDAS
// and local IFID
type UIFID struct {
	isdas *addr.ISD_AS
	ifid  common.IFIDType
}

func UIFIDFromValues(isdas *addr.ISD_AS, ifid common.IFIDType) *UIFID {
	return &UIFID{
		isdas: isdas.Copy(),
		ifid:  ifid,
	}
}

// key returns a unique key that can be used as a map index
func (u *UIFID) key() string {
	return fmt.Sprintf("%s#%d", u.isdas, u.ifid)
}

func (u *UIFID) String() string {
	return u.key()
}

// revTable tracks for each UIFID the set of AppPaths that contain that UIFID.
// Revoking an interface consists of grabbing its UIFID, going through the set
// and calling Revoke on each AppPath.
type revTable struct {
	// maps UIFID keys to sets of paths that contain that UIFID
	m map[string]AppPathSet
}

// newRevTable creats an empty revocation table.
func newRevTable() *revTable {
	return &revTable{m: make(map[string]AppPathSet)}
}

// updatePathSet updates the information for paths in aps. If a path is new,
// its information is added to the RevTable. If a path already exists (for
// example, because it has been received from SCIOND before), the RevTable
// pointers are updated to track the new path object. This allows revocations
// to always update the live, in-use paths and not old copies that will be soon
// collected by the GC.
func (rt *revTable) updatePathSet(aps AppPathSet) {
	for _, ap := range aps {
		rt.updatePath(ap)
	}
}

func (rt *revTable) updatePath(ap *AppPath) {
	for _, iface := range ap.Entry.Path.Interfaces {
		uifid := UIFIDFromValues(iface.ISD_AS(), common.IFIDType(iface.IfID))
		aps, ok := rt.m[uifid.key()]
		if !ok {
			// AppPathSet not initialized yet
			aps = make(AppPathSet)
			// Store reference to new map
			rt.m[uifid.key()] = aps
		}
		aps[PathKey(ap.Key())] = ap
	}
}

// RevokeUIFID deletes all the paths that include uifid
func (rt *revTable) revoke(uifid *UIFID) []*IAPair {
	pairs := make([]*IAPair, 0)
	aps := rt.m[uifid.key()]
	for _, ap := range aps {
		ap.revoke()

		// If the revocation caused all paths between a source and
		// destination to be deleted, return the source and destination
		// to allow callers to requery SCIOND immediately
		if len(ap.parent) == 0 {
			pairs = append(pairs, &IAPair{src: getSrcIA(ap), dst: getDstIA(ap)})
		}

		// Delete all references from other UIFIDs to the revoked path,
		// thus allowing the path to be garbage collected
		for _, iface := range ap.Entry.Path.Interfaces {
			ifaceUIFID := UIFIDFromValues(iface.ISD_AS(), common.IFIDType(iface.IfID))
			pathSet := rt.m[ifaceUIFID.key()]
			delete(pathSet, ap.Key())

			// If the last reference from a UIFID to a path was deleted, we can
			// remove the UIFID from the revTable
			if len(pathSet) == 0 {
				delete(rt.m, ifaceUIFID.key())
			}
		}
	}
	delete(rt.m, uifid.key())
	return nil
}

func getSrcIA(ap *AppPath) *addr.ISD_AS {
	iface := ap.Entry.Path.Interfaces[0]
	return iface.ISD_AS()
}

func getDstIA(ap *AppPath) *addr.ISD_AS {
	length := len(ap.Entry.Path.Interfaces)
	iface := ap.Entry.Path.Interfaces[length-1]
	return iface.ISD_AS()
}
