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

// Package spathmeta implements basic types for working with SCIOND paths.
package spathmeta

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
)

// AppPathSet represents a set of SCIOND path entries, keyed by AppPath.Key().
type AppPathSet map[PathKey]*AppPath

// NewAppPathSet creates a new set of paths from a SCIOND path reply.
func NewAppPathSet(reply *sciond.PathReply) AppPathSet {
	aps := AppPathSet{}
	if reply == nil {
		return aps
	}
	for i := range reply.Entries {
		aps.Add(&reply.Entries[i])
	}
	return aps
}

// Add converts the SCIOND path entry to an AppPath and adds it to the
// set.
func (aps AppPathSet) Add(entry *sciond.PathReplyEntry) *AppPath {
	ap := &AppPath{
		Entry: entry,
	}
	aps[ap.Key()] = ap
	return ap
}

func (aps AppPathSet) Copy() AppPathSet {
	newAPS := NewAppPathSet(nil)
	for k := range aps {
		newAPS[k] = aps[k].Copy()
	}
	return newAPS
}

// GetAppPath returns an AppPath from the set. It first tries to find
// a path with key pref; if one cannot be found, an arbitrary one
// is returned.
func (aps AppPathSet) GetAppPath(pref PathKey) *AppPath {
	if len(pref) > 0 {
		ap, ok := aps[pref]
		if ok {
			return ap
		}
	}
	for _, v := range aps {
		return v
	}
	return nil
}

func (aps AppPathSet) String() string {
	var desc []string
	for _, path := range aps {
		desc = append(desc, path.Entry.Path.String())
	}
	return "{" + strings.Join(desc, "; ") + "}"
}

// AppPath contains a SCIOND path entry.
type AppPath struct {
	Entry *sciond.PathReplyEntry
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

func (ap *AppPath) Copy() *AppPath {
	// FIXME(scrye): this might need deep copying as well
	return &AppPath{
		Entry: ap.Entry,
	}
}

// Helper type for pretty printing of maps using paths as keys.
type PathKey string

func (pk PathKey) String() string {
	return common.RawBytes(pk).String()
}
