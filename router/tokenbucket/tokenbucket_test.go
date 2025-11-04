// Copyright 2025 ETH Zurich
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

package tokenbucket_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/router/tokenbucket"
)

type entry struct {
	length      int
	arrivalTime time.Time
	result      bool
}
type test struct {
	name    string
	entries []entry
	bucket  *tokenbucket.TokenBucket
}

// TestTokenBucketAlgorithm checks that the token bucket implementation detects if a given
// amount of bytes exceed the allowance or not.
func TestTokenBucketAlgorithm(t *testing.T) {

	var startTime = time.Unix(0, 0)

	tests := []test{
		{
			name:   "TestApplyDoesAllowArrivalBehindTheLastArrival",
			bucket: tokenbucket.NewTokenBucket(startTime.Add(1), 1024, 1024),
			entries: []entry{
				{
					length:      1,
					arrivalTime: startTime,
					result:      true,
				},
			},
		},
		{
			name:   "FullBandwidthCanBeConsumedAtOnce",
			bucket: tokenbucket.NewTokenBucket(startTime, 1024, 1024),
			entries: []entry{
				{
					length:      1024,
					arrivalTime: startTime,
					result:      true,
				},
				{
					length:      1,
					arrivalTime: startTime,
					result:      false,
				},
			},
		},
		{
			name:   "FullBandwidthCanBeConsumedOverMultiplePackets",
			bucket: tokenbucket.NewTokenBucket(startTime, 1024, 1024),
			entries: []entry{
				{
					length:      512,
					arrivalTime: startTime,
					result:      true,
				},
				{
					length:      512,
					arrivalTime: startTime,
					result:      true,
				},
				{
					length:      1,
					arrivalTime: startTime,
					result:      false,
				},
			},
		},
		{
			name:   "CurrentTokensRegenerate",
			bucket: tokenbucket.NewTokenBucket(startTime, 1024, 1024),
			entries: []entry{
				{
					length:      1024,
					arrivalTime: startTime,
					result:      true,
				},
				{
					length:      512,
					arrivalTime: startTime.Add(500 * time.Millisecond),
					result:      true,
				},
				{
					length:      1,
					arrivalTime: startTime.Add(500 * time.Millisecond),
					result:      false,
				},
			},
		},
		{
			name:   "CurrentTokensIsLimitedByCBS",
			bucket: tokenbucket.NewTokenBucket(startTime, 2048, 1024),
			entries: []entry{
				{
					length:      2049,
					arrivalTime: startTime.Add(1 * time.Second),
					result:      false,
				},
				{
					length:      2048,
					arrivalTime: startTime.Add(1 * time.Second),
					result:      true,
				},
				{
					length:      1,
					arrivalTime: startTime.Add(1 * time.Second),
					result:      false,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, en := range tc.entries {
				assert.Equal(t, en.result, tc.bucket.Apply(en.length, en.arrivalTime), tc.name)
			}
		})
	}
}
