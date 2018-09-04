// Copyright 2018 Anapaya Systems
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

package segutil

import (
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/revcache"
)

// NoRevokedHopIntf returns true if there is no on-segment revocation.
func NoRevokedHopIntf(revCache revcache.RevCache, s *seg.PathSegment) bool {
	revKeys := make(map[revcache.Key]struct{})
	addRevKeys([]*seg.PathSegment{s}, revKeys, true)
	for rk := range revKeys {
		if _, ok := revCache.Get(&rk); ok {
			return false
		}
	}
	return true
}

// RelevantRevInfos finds all revocations for the given segments.
func RelevantRevInfos(revCache revcache.RevCache,
	allSegs ...[]*seg.PathSegment) []*path_mgmt.SignedRevInfo {

	revKeys := make(map[revcache.Key]struct{})
	for _, segs := range allSegs {
		addRevKeys(segs, revKeys, false)
	}
	return revcache.GetAll(revCache, revKeys)
}

// addRevKeys adds all revocations keys for the given segments to the keys set.
// If hopOnly is set, only the first hop entry is considered.
func addRevKeys(segs []*seg.PathSegment, keys map[revcache.Key]struct{}, hopOnly bool) {
	for _, s := range segs {
		for _, asEntry := range s.ASEntries {
			for _, entry := range asEntry.HopEntries {
				hf, err := entry.HopField()
				if err != nil {
					// This should not happen, as Validate already checks that it
					// is possible to extract the hop field.
					panic(err)
				}
				if hf.ConsIngress != 0 {
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsIngress)] = struct{}{}
				}
				if hf.ConsEgress != 0 {
					keys[*revcache.NewKey(asEntry.IA(), hf.ConsEgress)] = struct{}{}
				}
				if hopOnly {
					break
				}
			}
		}
	}
}
