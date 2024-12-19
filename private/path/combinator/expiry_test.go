// Copyright 2018 ETH Zurich
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

package combinator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path"
)

// FIXME(scrye): when more unit tests get added to spath, these should probably
// move there

func TestComputeSegmentExpTime(t *testing.T) {
	testCases := []struct {
		Name               string
		Segment            *segment
		ExpectedExpiration int64
	}{
		{
			Name:               "smallest possible expiration value",
			Segment:            buildTestSegment(0, 0),
			ExpectedExpiration: 337,
		},
		{
			Name:               "non-zero hop ttl field value",
			Segment:            buildTestSegment(0, 1),
			ExpectedExpiration: 675,
		},
		{
			Name:               "two hop fields, min should be taken",
			Segment:            buildTestSegment(0, 4, 0),
			ExpectedExpiration: 337,
		},
		{
			Name:               "maximum ttl selected",
			Segment:            buildTestSegment(0, 255),
			ExpectedExpiration: 24 * 60 * 60,
		},
		{
			Name:               "ttl relative to info field timestamp",
			Segment:            buildTestSegment(100, 1),
			ExpectedExpiration: 775,
		},
		{
			Name:               "ttl relative to maximum info field timestamp",
			Segment:            buildTestSegment(4294967295, 1),
			ExpectedExpiration: 4294967970,
		},
		{
			Name:               "maximum possible value",
			Segment:            buildTestSegment(4294967295, 255),
			ExpectedExpiration: 4295053695,
		},
	}
	t.Log("Expiration values should be correct")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			computedExpiration := tc.Segment.ComputeExpTime()
			assert.Equal(t, tc.ExpectedExpiration, computedExpiration.Unix())
		})

	}
}

func buildTestSegment(timestamp uint32, ttls ...uint8) *segment {
	segment := &segment{}
	segment.InfoField = path.InfoField{
		Timestamp: timestamp,
	}
	for _, ttl := range ttls {
		segment.HopFields = append(segment.HopFields,
			path.HopField{
				ExpTime: ttl,
			},
		)
	}
	return segment
}
