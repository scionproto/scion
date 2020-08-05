// Copyright 2017 ETH Zurich
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

// Package spathmeta implements basic types for working with SCIOND paths.
package spathmeta

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/snet"
)

// AppPathSet represents a set of SCIOND path entries, keyed by AppPath.Key().
type AppPathSet map[snet.PathFingerprint]snet.Path

// NewAppPathSet creates a new set of paths from a SCIOND path reply.
func NewAppPathSet(paths []snet.Path) AppPathSet {
	aps := AppPathSet{}
	if paths == nil {
		return aps
	}
	for _, path := range paths {
		aps.Add(path)
	}
	return aps
}

// Add adds the given path to the path set.
func (aps AppPathSet) Add(path snet.Path) {
	aps[snet.Fingerprint(path)] = path
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
func (aps AppPathSet) GetAppPath(pref snet.PathFingerprint) snet.Path {
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
		desc = append(desc, fmt.Sprintf("%s", path))
	}
	return "{" + strings.Join(desc, "; ") + "}"
}
