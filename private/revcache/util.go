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

package revcache

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/storage/cleaner"
)

// NewCleaner creates a cleaner task that deletes expired revocations.
func NewCleaner(rc RevCache, s string) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		cnt, err := rc.DeleteExpired(ctx)
		return int(cnt), err
	}, s)
}

// NoRevokedHopIntf returns true if there is no on-segment revocation.
func NoRevokedHopIntf(ctx context.Context, revCache RevCache,
	s *seg.PathSegment) (bool, error) {

	revKeys := make(KeySet)
	addRevKeys([]*seg.PathSegment{s}, revKeys, true)
	revs, err := revCache.Get(ctx, revKeys)
	return len(revs) == 0, err
}

// addRevKeys adds all revocations keys for the given segments to the keys set.
// If hopOnly is set, only the first hop entry is considered.
func addRevKeys(segs []*seg.PathSegment, keys KeySet, hopOnly bool) {
	addIntfs := func(ia addr.IA, ingress, egress uint16) {
		if ingress != 0 {
			keys[Key{IA: ia, IfID: common.IfIDType(ingress)}] = struct{}{}
		}
		if egress != 0 {
			keys[Key{IA: ia, IfID: common.IfIDType(egress)}] = struct{}{}
		}
	}
	for _, s := range segs {
		for _, asEntry := range s.ASEntries {
			hop := asEntry.HopEntry.HopField
			addIntfs(asEntry.Local, hop.ConsIngress, hop.ConsEgress)
			if hopOnly {
				continue
			}
			for _, peer := range asEntry.PeerEntries {
				addIntfs(asEntry.Local, peer.HopField.ConsIngress, peer.HopField.ConsEgress)
			}
		}
	}
}
