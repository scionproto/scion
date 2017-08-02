// Copyright 2016 ETH Zurich
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
// See the License for the specific language goeT > ma.fixedDurationverning permissions and
// limitations under the License.

// This file contains the implementation of the moving average used in the
// bandwidth enforcement mechanism. It is implemented using a bucketing approach.
// The buckets are stored in a ring buffer (implemented using an array).

package enforcement

import (
	"time"
)

type MovingAverage struct {
	//buckets contains the actual buckets of the moving average.
	buckets []int64
	// nOfBuckets indicates the number of buckets.
	nOfBuckets int
	// bucketSize is the duration of one bucket.
	bucketSize time.Duration
	// idxCurBucket indicates which is the currently active bucket that arriving packets
	// get added to.
	idxCurBucket int
	// tCurBucket tells at what time this bucket started.
	tCurBucket time.Time
	// sum holds the sum of all buckets.
	sum int64
	// fixedDuration holds bucketSize * nOfBuckets.
	fixedDuration time.Duration
}

func NewMovingAverage(nOfBuckets int, bucketSize time.Duration) *MovingAverage {
	buckets := make([]int64, nOfBuckets)
	fixedDur := bucketSize * time.Duration(nOfBuckets)

	return &MovingAverage{
		buckets:       buckets,
		nOfBuckets:    nOfBuckets,
		bucketSize:    bucketSize,
		idxCurBucket:  0,
		tCurBucket:    time.Now(),
		sum:           0,
		fixedDuration: fixedDur,
	}
}

// getAverage first performs an update of the buckets and then returns the current average in bytes.
func (ma *MovingAverage) getAverage() int64 {
	ma.update()
	duration := (float64(ma.nOfBuckets - 1)) * (ma.bucketSize.Seconds() * 1000)
	duration += time.Since(ma.tCurBucket).Seconds() * 1000
	return int64(float64(1000*ma.sum) / duration)
}

// add() adds nOfBytes to the current active bucket.
func (ma *MovingAverage) add(nOfBytes int) {
	ma.update()
	nOfBytes64 := int64(nOfBytes)
	ma.buckets[ma.idxCurBucket] += nOfBytes64
	ma.sum += nOfBytes64
}

// update() updates the buckets of the moving average. As this is only done on demand, this needs
// to be performed before each getAverage() and add()
func (ma *MovingAverage) update() {
	eT := time.Since(ma.tCurBucket)
	if eT > ma.fixedDuration {
		// The elapsed time eT is larger than the whole time window the average covers.
		// The whole average can be reset to zero.
		for i := 0; i < ma.nOfBuckets; i++ {
			ma.buckets[i] = 0
		}
		ma.idxCurBucket = 0
		ma.tCurBucket = time.Now()
		ma.sum = 0
	} else {
		// The elapsed time eT is smaller than the time window. We have to figure out which one is
		// the current bucket and set the previous buckets to 0.
		bucketsToClear := int(eT / ma.bucketSize)
		newIdx := ma.idxCurBucket
		newTime := ma.tCurBucket

		for i := 1; i < bucketsToClear+1; i++ {
			newIdx = (ma.idxCurBucket + i) % ma.nOfBuckets
			newTime = newTime.Add(ma.bucketSize)
			ma.sum -= int64(ma.buckets[newIdx])
			ma.buckets[newIdx] = 0
		}
		ma.idxCurBucket = newIdx
		ma.tCurBucket = newTime
	}
}
