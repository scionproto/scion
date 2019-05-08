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
	// SelectAndServe selects the n best beacons from the beacons channel and
	// serves them on the results channel.
	SelectAndServe(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr, resultSize int)
}

// baseAlgo implements a very simple selection algorithm that optimizes for
// short paths, but also tries to achieve some path diversity.
type baseAlgo struct{}

// selectAndServe implements a very simple selection algorithm. The best beacon
// is the one with a shortest path. The channel is filled with the k-1 shortest
// beacons. The last beacon is either the most diverse beacon from the remaining
// beacons, if the diversity exceeds what has already been served. Or the
// shortest remaining beacon, otherswise.
func (baseAlgo) SelectAndServe(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr,
	resultSize int) {

	best, diversity := baseAlgo{}.serveShortestBeacons(beacons, results, resultSize-1)
	baseAlgo{}.serveMostDiverse(beacons, results, best, diversity)
}

// serveShortsestBeacons serves the resultSize shortest beacons on the result channel.
// It returns the first beacon and the maximum served diversity.
func (baseAlgo) serveShortestBeacons(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr,
	resultSize int) (Beacon, int) {

	var best Beacon
	var maxDiversity int
	i := 0
	for res := range beacons {
		if res.Err == nil {
			if (best == Beacon{}) {
				// Create shallow copy to avoid data race.
				best = Beacon{
					Segment: res.Beacon.Segment.ShallowCopy(),
					InIfId:  res.Beacon.InIfId,
				}
			}
			// Compute diversity before serving beacon to avoid data race.
			maxDiversity = max(maxDiversity, best.Diversity(res.Beacon))
			i++
		}
		results <- res
		if i == resultSize {
			break
		}
	}
	return best, maxDiversity
}

// serveMostDiverse selects the most diverse beacon compared to the provided
// best beacon from all beacons that are in the channel and serves it in the
// result channel if it exceeds the already served diversity. Otherwise, the
// shortest beacon is served.
func (baseAlgo) serveMostDiverse(beacons <-chan BeaconOrErr, results chan<- BeaconOrErr,
	best Beacon, servedDiversity int) {

	var err error
	// Most diverse beacon of the remaining beacons.
	var diverse Beacon
	maxDiversity := -1
	minLen := math.MaxUint16
	// First is the shortest beacon and selected if the diversity is below the
	// already served diversity.
	var first Beacon

	for res := range beacons {
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
			results <- BeaconOrErr{Err: err}
		}
		return
	}
	if (diverse != Beacon{}) && maxDiversity > servedDiversity {
		results <- BeaconOrErr{Beacon: diverse}
		return
	}
	results <- BeaconOrErr{Beacon: first}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
