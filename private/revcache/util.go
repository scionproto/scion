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

	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
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

	for _, asEntry := range s.ASEntries {
		hop := asEntry.HopEntry.HopField
		for _, key := range [2]Key{
			{IA: asEntry.Local, IfID: iface.ID(hop.ConsIngress)},
			{IA: asEntry.Local, IfID: iface.ID(hop.ConsEgress)},
		} {
			rev, err := revCache.Get(ctx, key)
			if err != nil || rev != nil {
				return false, err
			}
		}
	}
	return true, nil
}
