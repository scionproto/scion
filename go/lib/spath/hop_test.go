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

package spath

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestExpTimeType(t *testing.T) {
	type TimeErrPair struct {
		ExpTime ExpTimeType
		ExpErr  bool
	}
	tests := []struct {
		Name      string
		Duration  time.Duration
		RoundUp   TimeErrPair
		RoundDown TimeErrPair
		Rounded   bool
	}{
		{
			Name:     "Smaller than unit",
			Duration: 300 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 0,
			},
			RoundDown: TimeErrPair{
				ExpErr: true,
			},
			Rounded: true,
		},
		{
			Name:     "Exactly the unit",
			Duration: ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 0,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
			},
		},
		{
			Name:     "Slightly larger than unit",
			Duration: 400 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
			},
			Rounded: true,
		},
		{
			Name:     "Slightly smaller than two units",
			Duration: 650 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
			},
			RoundDown: TimeErrPair{
				ExpTime: 0,
			},
			Rounded: true,
		},
		{
			Name:     "Exactly two units",
			Duration: 2 * ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 1,
			},
			RoundDown: TimeErrPair{
				ExpTime: 1,
			},
		},
		{
			Name:     "Between units",
			Duration: 840 * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: 2,
			},
			RoundDown: TimeErrPair{
				ExpTime: 1,
			},
			Rounded: true,
		},
		{
			Name:     "Maximum expiration time",
			Duration: (time.Duration(MaxTTLField) + 1) * ExpTimeUnit * time.Second,
			RoundUp: TimeErrPair{
				ExpTime: MaxTTLField,
			},
			RoundDown: TimeErrPair{
				ExpTime: MaxTTLField,
			},
		},
		{
			Name:     "Larger than maximum relative expiration",
			Duration: 87000 * time.Second,
			RoundUp: TimeErrPair{
				ExpErr: true,
			},
			RoundDown: TimeErrPair{
				ExpTime: MaxTTLField,
			},
			Rounded: true,
		},
	}
	Convey("Conversion from duration to relative expiration time should be correct", t, func() {
		for _, test := range tests {
			Convey(test.Name, func() {
				Convey("Rounding up", func() {
					expTime, err := ExpTimeFromDuration(test.Duration, true)
					xtest.SoMsgError("err", err, test.RoundUp.ExpErr)
					if !test.RoundUp.ExpErr {
						SoMsg("ExpTime", expTime, ShouldEqual, test.RoundUp.ExpTime)
					}
				})
				Convey("Rounding down", func() {
					expTime, err := ExpTimeFromDuration(test.Duration, false)
					xtest.SoMsgError("err", err, test.RoundDown.ExpErr)
					if !test.RoundDown.ExpErr {
						SoMsg("ExpTime", expTime, ShouldEqual, test.RoundDown.ExpTime)
					}
				})
			})
		}
	})
	Convey("Conversion from relative expiration time to duration should be correct", t, func() {
		for _, test := range tests {
			if !test.Rounded {
				Convey(test.Name, func() {
					SoMsg("ExpTime", test.RoundUp.ExpTime.ToDuration(), ShouldEqual, test.Duration)
				})
			}
		}
	})
}
