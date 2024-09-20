// Copyright 2019 Anapaya Systems
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

package beacon

import (
	"context"
	"math"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/segment/segverifier"
)

type selectionAlgorithm interface {
	// SelectBeacons selects the `n` best beacons from the provided slice of beacons.
	SelectBeacons(ctx context.Context, beacons []Beacon, resultSize int) []Beacon
}

// baseAlgo implements a very simple selection algorithm that optimizes for
// short paths, but also tries to achieve some path diversity.
type baseAlgo struct{}

// SelectBeacons implements a very simple selection algorithm. The best beacon
// is the one with a shortest path. The slice contains the k-1 shortest
// beacons. The last beacon is either the most diverse beacon from the remaining
// beacons, if the diversity exceeds what has already been served. Or the
// shortest remaining beacon, otherwise.
func (a baseAlgo) SelectBeacons(_ context.Context, beacons []Beacon, resultSize int) []Beacon {
	if len(beacons) <= resultSize {
		return beacons
	}

	result := make([]Beacon, resultSize-1, resultSize)
	copy(result, beacons[:resultSize-1])
	_, diversity := a.selectMostDiverse(result, result[0])

	// Check if we find a more diverse beacon in the rest.
	mostDiverseRest, diversityRest := a.selectMostDiverse(beacons[resultSize-1:], result[0])
	if diversityRest > diversity {
		return append(result, mostDiverseRest)
	}
	// If the most diverse beacon was already served, serve shortest from the
	// rest.
	return append(result, beacons[resultSize-1])
}

// selectMostDiverse selects the most diverse beacon compared to the provided best beacon from all
// provided beacons and returns it and its diversity.
func (baseAlgo) selectMostDiverse(beacons []Beacon, best Beacon) (Beacon, int) {
	if len(beacons) == 0 {
		return Beacon{}, -1
	}

	maxDiversity := -1
	minLen := math.MaxUint16
	var diverse Beacon
	for _, b := range beacons {
		diversity := best.Diversity(b)
		l := len(b.Segment.ASEntries)

		if diversity > maxDiversity || (diversity == maxDiversity && minLen > l) {
			diverse, minLen, maxDiversity = b, l, diversity
		}
	}
	return diverse, maxDiversity
}

type chainsAvailableAlgo struct {
	verifier     chainChecker
	logThrottled *cache.Cache
}

func newChainsAvailableAlgo(engine ChainProvider) chainsAvailableAlgo {
	return chainsAvailableAlgo{
		verifier: chainChecker{
			Engine: engine,
			Cache:  cache.New(defaultCacheHitExpiration, defaultCacheHitExpiration),
		},
		logThrottled: cache.New(defaultCacheHitExpiration, defaultCacheHitExpiration),
	}
}

func (a chainsAvailableAlgo) SelectBeacons(
	ctx context.Context,
	beacons []Beacon,
	resultSize int,
) []Beacon {
	withChain := make([]Beacon, 0, len(beacons))
	for _, b := range beacons {
		err := segverifier.VerifySegment(ctx, a.verifier, nil, b.Segment)
		if err == nil {
			withChain = append(withChain, b)
			continue
		}

		id := b.Segment.GetLoggingID()
		if _, ok := a.logThrottled.Get(id); !ok {
			log.FromCtx(ctx).Info("Ignoring beacon due to missing crypto material",
				"id", id,
				"err", err,
			)
			a.logThrottled.Set(id, struct{}{}, cache.DefaultExpiration)
		}
	}
	return baseAlgo{}.SelectBeacons(ctx, withChain, resultSize)
}
