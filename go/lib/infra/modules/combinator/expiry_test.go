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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/spath"
)

// FIXME(scrye): when more unit tests get added to spath, these should probably
// move there

func TestComputeSegmentExpTime(t *testing.T) {
	testCases := []struct {
		Name               string
		Segment            *Segment
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
			ExpectedExpiration: 674,
		},
		{
			Name:               "two hop fields, min should be taken",
			Segment:            buildTestSegment(0, 4, 0),
			ExpectedExpiration: 337,
		},
		{
			Name:               "maximum ttl selected",
			Segment:            buildTestSegment(0, 255),
			ExpectedExpiration: 24*60*60 - 128, // rounding error drift
		},
		{
			Name:               "ttl relative to info field timestamp",
			Segment:            buildTestSegment(100, 1),
			ExpectedExpiration: 774,
		},
		{
			Name:               "ttl relative to maximum info field timestamp",
			Segment:            buildTestSegment(4294967295, 1),
			ExpectedExpiration: 4294967969,
		},
		{
			Name:               "maximum possible value",
			Segment:            buildTestSegment(4294967295, 255),
			ExpectedExpiration: 4295053695 - 128, // rounding error drift
		},
	}
	Convey("Expiration values should be correct", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				computedExpiration := tc.Segment.ComputeExpTime()
				So(computedExpiration.Unix(), ShouldEqual, tc.ExpectedExpiration)
			})
		}
	})
}

func buildTestSegment(timestamp uint32, ttls ...uint8) *Segment {
	segment := &Segment{}
	segment.InfoField = &InfoField{
		InfoField: &spath.InfoField{
			TsInt: timestamp,
		},
	}
	for _, ttl := range ttls {
		segment.HopFields = append(segment.HopFields,
			&HopField{
				HopField: &spath.HopField{
					ExpTime: spath.ExpTimeType(ttl),
				},
			},
		)
	}
	return segment
}
