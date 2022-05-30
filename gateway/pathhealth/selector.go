// Copyright 2020 Anapaya Systems
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

package pathhealth

import (
	"fmt"
	"sort"

	"github.com/scionproto/scion/pkg/snet"
)

const (
	// rejectedInfo is a string to log about dead paths.
	deadInfo = "dead (probes are not passing through)"
	// rejectedInfo is a string to log about paths rejected by path policies.
	rejectedInfo = "rejected by path policy"
)

// PathPolicy filters the set of paths.
type PathPolicy interface {
	Filter(paths []snet.Path) []snet.Path
}

// FilteringPathSelector selects the best paths from a filtered set of paths.
type FilteringPathSelector struct {
	// PathPolicy is used to determine which paths are eligible and which are not.
	PathPolicy PathPolicy
	// RevocationStore keeps track of the revocations.
	RevocationStore
	// PathCount is the max number of paths to return to the user. Defaults to 1.
	PathCount int
}

// Select selects the best paths.
func (f *FilteringPathSelector) Select(selectables []Selectable, current FingerprintSet) Selection {
	type Allowed struct {
		Fingerprint snet.PathFingerprint
		Path        snet.Path
		Selectable  Selectable
		IsCurrent   bool
		IsRevoked   bool
	}

	// Sort out the paths allowed by the path policy.
	var allowed []Allowed
	var dead []snet.Path
	var rejected []snet.Path
	for _, selectable := range selectables {
		path := selectable.Path()
		if !isPathAllowed(f.PathPolicy, path) {
			rejected = append(rejected, path)
			continue
		}

		state := selectable.State()
		if !state.IsAlive {
			dead = append(dead, path)
			continue
		}
		fingerprint := snet.Fingerprint(path)
		_, isCurrent := current[fingerprint]
		allowed = append(allowed, Allowed{
			Path:        path,
			Fingerprint: fingerprint,
			IsCurrent:   isCurrent,
			IsRevoked:   f.RevocationStore.IsRevoked(path),
		})
	}
	// Sort the allowed paths according the the perf policy.
	sort.SliceStable(allowed, func(i, j int) bool {
		// If some of the paths are alive (probes are passing through), yet still revoked
		// prefer the non-revoked paths as the revoked ones may be flaky.
		switch {
		case allowed[i].IsRevoked && !allowed[j].IsRevoked:
			return false
		case !allowed[i].IsRevoked && allowed[j].IsRevoked:
			return true
		}
		if shorter, ok := isShorter(allowed[i].Path, allowed[j].Path); ok {
			return shorter
		}
		return allowed[i].Fingerprint > allowed[j].Fingerprint
	})

	var pathInfo PathInfo
	for _, a := range allowed {
		pathInfo = append(pathInfo, PathInfoEntry{
			Current: a.IsCurrent,
			Revoked: a.IsRevoked,
			Path:    fmt.Sprintf("%s", a.Path),
		})
	}
	for _, path := range dead {
		pathInfo = append(pathInfo, PathInfoEntry{
			Rejected:     true,
			RejectReason: deadInfo,
			Path:         fmt.Sprintf("%s", path),
		})
	}
	for _, path := range rejected {
		pathInfo = append(pathInfo, PathInfoEntry{
			Rejected:     true,
			RejectReason: rejectedInfo,
			Path:         fmt.Sprintf("%s", path),
		})
	}

	pathCount := f.PathCount
	if pathCount == 0 {
		pathCount = 1
	}
	if pathCount > len(allowed) {
		pathCount = len(allowed)
	}

	paths := make([]snet.Path, 0, pathCount)
	for i := 0; i < pathCount; i++ {
		paths = append(paths, allowed[i].Path)
	}
	return Selection{
		Paths:         paths,
		PathInfo:      pathInfo,
		PathsAlive:    len(allowed),
		PathsDead:     len(dead),
		PathsRejected: len(rejected),
	}
}

// isPathAllowed returns true is path is allowed by the policy.
func isPathAllowed(policy PathPolicy, path snet.Path) bool {
	if policy == nil {
		return true
	}
	return len(policy.Filter([]snet.Path{path})) > 0
}

func isShorter(a, b snet.Path) (bool, bool) {
	mA, mB := a.Metadata(), b.Metadata()
	if mA == nil || mB == nil {
		return false, false
	}
	if lA, lB := len(mA.Interfaces), len(mB.Interfaces); lA != lB {
		return lA < lB, true
	}
	return false, false
}
