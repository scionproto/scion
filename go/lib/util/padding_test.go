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
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_CalcPadding(t *testing.T) {
	Convey("CalcPadding should calculate the correct padding (8B block size)", t, func() {
		cases := map[int]int{
			0: 0, 1: 7, 2: 6, 3: 5, 4: 4, 5: 3, 6: 2, 7: 1,
			8: 0, 9: 7, 10: 6, 11: 5, 12: 4, 13: 3, 14: 2, 15: 1,
			16: 0,
		}
		for input, expected := range cases {
			Convey(fmt.Sprintf("Padding for %v should be %v", input, expected), func() {
				So(CalcPadding(input, 8), ShouldEqual, expected)
			})
		}
	})
}
