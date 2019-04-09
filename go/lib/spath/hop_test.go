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
)

func TestExpTimeType(t *testing.T) {
	tests := []struct {
		Name     string
		Duration time.Duration
		ExpTime  ExpTimeType
		Rounded  bool
	}{
		{
			Name:     "Smaller than unit",
			Duration: 300 * time.Second,
			ExpTime:  0,
			Rounded:  true,
		},
		{
			Name:     "Exactly the unit",
			Duration: 337 * time.Second,
			ExpTime:  0,
		},
		{
			Name:     "Round down to unit",
			Duration: 400 * time.Second,
			ExpTime:  0,
			Rounded:  true,
		},
		{
			Name:     "Maximum expiration time",
			Duration: 86272 * time.Second,
			ExpTime:  255,
		},
		{
			Name:     "Round down maximum expiration time",
			Duration: 87000 * time.Second,
			ExpTime:  255,
			Rounded:  true,
		},
	}
	Convey("Test conversion from duration", t, func() {
		for _, test := range tests {
			Convey(test.Name, func() {
				expTime := ExpTimeFromDuration(test.Duration)
				SoMsg("ExpTime", expTime, ShouldEqual, test.ExpTime)
			})
		}
	})
	Convey("Test conversion to duration", t, func() {
		for _, test := range tests {
			if !test.Rounded {
				Convey(test.Name, func() {
					SoMsg("ExpTime", test.ExpTime.ToDuration(), ShouldEqual, test.Duration)
				})
			}
		}
	})
}
