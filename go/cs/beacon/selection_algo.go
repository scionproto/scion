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

import "math"

type selectionAlgorithm interface {
	// SelectBeacons selects the `n` best beacons from the provided slice of beacons.
	SelectBeacons(beacons []BeaconOrErr, resultSize int) []BeaconOrErr
}

// baseAlgo implements a very simple selection algorithm that optimizes for
// short paths, but also tries to achieve some path diversity.
type baseAlgo struct{}

// SelectBeacons implements a very simple selection algorithm. The best beacon
// is the one with a shortest path. The slice contains the k-1 shortest
// beacons. The last beacon is either the most diverse beacon from the remaining
// beacons, if the diversity exceeds what has already been served. Or the
// shortest remaining beacon, otherwise.
func (alg baseAlgo) SelectBeacons(beacons []BeaconOrErr, resultSize int) []BeaconOrErr {
	results, best, diversity := alg.selectShortestBeacons(beacons, resultSize-1)
	diverseBeacon, ok := alg.selectMostDiverse(beacons[len(results):], best, diversity)
	if ok {
		results = append(results, diverseBeacon)
	}
	return results
}

// serveShortsestBeacons computes the resultSize shortest beacons.
// It returns the shortest beacons, the first beacon and the maximum served diversity.
func (baseAlgo) selectShortestBeacons(beacons []BeaconOrErr,
	resultSize int) ([]BeaconOrErr, Beacon, int) {

	var (
		results      []BeaconOrErr
		best         Beacon
		maxDiversity int

		i = 0
	)
	for _, res := range beacons {
		if res.Err == nil {
			if (best == Beacon{}) {
				best = res.Beacon
			}
			// Compute diversity before serving beacon to avoid data race.
			maxDiversity = max(maxDiversity, best.Diversity(res.Beacon))
			i++
		}
		results = append(results, res)
		if i == resultSize {
			break
		}
	}
	return results, best, maxDiversity
}

// selectMostDiverse selects the most diverse beacon compared to the provided best beacon from all
// provided beacons and returns it if it exceeds the already served diversity. Otherwise, the
// shortest beacon is served.
func (baseAlgo) selectMostDiverse(beacons []BeaconOrErr, best Beacon,
	servedDiversity int) (BeaconOrErr, bool) {

	var err error
	// Most diverse beacon of the remaining beacons.
	var diverse Beacon
	maxDiversity := -1
	minLen := math.MaxUint16
	// First is the shortest beacon and selected if the diversity is below the
	// already served diversity.
	var first Beacon

	for _, res := range beacons {
		if (first == Beacon{}) {
			first = res.Beacon
		}
		if res.Err != nil {
			err = res.Err
			continue
		}
		diversity := best.Diversity(res.Beacon)
		l := len(res.Beacon.Segment.ASEntries)
		if diversity > maxDiversity || (diversity == maxDiversity && minLen > l) {
			diverse, minLen, maxDiversity = res.Beacon, l, diversity
		}
	}
	if (first == Beacon{}) {
		if err != nil {
			return BeaconOrErr{Err: err}, true
		}
		return BeaconOrErr{}, false
	}
	if (diverse != Beacon{}) && maxDiversity > servedDiversity {
		return BeaconOrErr{Beacon: diverse}, true
	}
	return BeaconOrErr{Beacon: first}, true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
