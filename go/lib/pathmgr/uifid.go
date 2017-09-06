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
)

// UIFID (Unique IFID) is a IFID descriptor with global scope composed of ISDAS
// and local IFID
type UIFID struct {
	isdas *addr.ISD_AS
	ifid  uint64
}

func UIFIDFromValues(isdas *addr.ISD_AS, ifid uint64) *UIFID {
	return &UIFID{
		isdas: isdas.Copy(),
		ifid:  ifid,
	}
}

// key returns a unique key that can be used as a map index
func (u *UIFID) key() string {
	return fmt.Sprintf("%v.%d", u.isdas, u.ifid)
}

func (u *UIFID) String() string {
	return u.key()
}

// revTable tracks for each UIFID the set of AppPaths that contain that UIFID.
// Revoking an interface consists of grabbing its UIFID, going through the set
// and calling Revoke on each AppPath.
type revTable struct {
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
// collected by the GC. Parameter disc can be used to differentiate between
// paths that are identical in binary form, but are kept in different data
// structures. This allows the RevTable to track multiple copies of the same
// path if needed.
func (u *revTable) updatePathSet(aps AppPathSet, disc int) {
	for _, ap := range aps {
		u.updatePath(ap, disc)
	}
}

func (u *revTable) updatePath(ap *AppPath, disc int) {
	for _, iface := range ap.Entry.Path.Interfaces {
		uifid := UIFIDFromValues(iface.ISD_AS(), iface.IfID)
		aps := u.m[uifid.key()]
		if aps == nil {
			// AppPathSet not initialized yet
			aps = make(AppPathSet)
			// Store reference to new map
			u.m[uifid.key()] = aps
		}
		aps[rawKey(fmt.Sprintf("%d.%v", disc, ap.key()))] = ap
	}
}

// RevokeUIFID deletes all the paths that include uifid
func (u *revTable) revoke(uifid *UIFID) {
	aps := u.m[uifid.key()]
	for _, ap := range aps {
		ap.revoke()
	}
	delete(u.m, uifid.key())
}
