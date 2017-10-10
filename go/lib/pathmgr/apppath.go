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
	"crypto/sha256"
	"encoding/binary"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// AppPathSet represents a set of SCIOND path entries, keyed by AppPath.Key()
type AppPathSet map[PathKey]*AppPath

// NewAppPathSet creates a new set of paths from a SCIOND path reply.
func NewAppPathSet(reply *sciond.PathReply) AppPathSet {
	aps := make(AppPathSet)
	for i := range reply.Entries {
		aps.addChildAppPath(&reply.Entries[i])
	}
	return aps
}

// addChildAppPath converts the SCIOND path entry to an AppPath and adds it to the
// set. The set is registered as the new AppPath's parent.
func (aps AppPathSet) addChildAppPath(entry *sciond.PathReplyEntry) *AppPath {
	ap := &AppPath{
		Entry:  entry,
		parent: aps,
	}
	aps[ap.Key()] = ap
	return ap
}

// GetAppPath returns an AppPath from the set.
func (aps AppPathSet) GetAppPath() *AppPath {
	for _, v := range aps {
		return v
	}
	return nil
}

// AppPath contains a SCIOND path entry, together with metadata needed for
// revocations.
type AppPath struct {
	Entry  *sciond.PathReplyEntry
	parent AppPathSet
}

// Key returns a unique PathKey that can be used for map indexing.
func (ap *AppPath) Key() PathKey {
	h := sha256.New()
	for _, iface := range ap.Entry.Path.Interfaces {
		binary.Write(h, common.Order, iface.ISD_AS().IAInt())
		binary.Write(h, common.Order, iface.IfID)
	}
	return PathKey(h.Sum(nil))
}

// duplicateIn adds a shallow copy of ap to aps without setting the parent link.
// FIXME(scrye): The pathmgr revocation mechanism currently uses parent links to
// efficiently revoke paths. However, filtered path sets are updated by (1)
// iterating through the list of revoked paths, (2) grabbing the source and
// destination IA of each revoked path, (3) retrieving the set of available
// paths for the src-dst pair and (4) updating the set of filtered paths to
// match the remaining ones. Parent links are not needed in this case. The path
// manager will be refactored to use a similar approach for all paths, thus
// making parent links no longer needed throughout the path manager.
func (ap *AppPath) duplicateIn(aps AppPathSet) {
	newAP := &AppPath{Entry: ap.Entry}
	aps[ap.Key()] = newAP
}

// revoke removes ap from its parent path set.
func (ap *AppPath) revoke() {
	delete(ap.parent, ap.Key())
}
