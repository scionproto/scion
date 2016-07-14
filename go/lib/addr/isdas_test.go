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

package addr

import (
	"fmt"
	"testing"

	"github.com/netsec-ethz/scion/go/lib/test"
	. "github.com/smartystreets/goconvey/convey"
)

func Test_IA_String(t *testing.T) {
	Convey("String() should return ISD-AS", t, func() {
		ia := ISD_AS{33, 55}
		So(ia.String(), ShouldEqual, "33-55")
	})
}

func Test_IA_UnmarshalYAML_YAMLParseError(t *testing.T) {
	Convey("YAML parse error", t, func() {
		ia := ISD_AS{}
		err := fmt.Errorf("failed")
		So(ia.UnmarshalYAML(test.UnmarshalToError(err)), ShouldEqual, err)
	})
}

func Test_IA_UnmarshalYAML_InvalidValues(t *testing.T) {
	Convey("Parse errors", t, func() {
		ia := ISD_AS{}
		cases := []string{"1122", "1-", "-2", "1-12-2", "1a-22", "11-2a"}
		for _, val := range cases {
			Convey(val, func() {
				So(ia.UnmarshalYAML(test.UnmarshalToString(val)), ShouldNotBeNil)
			})
		}
	})
}

func Test_IA_UnmarshalYAML_ValidISDASes(t *testing.T) {
	Convey("Valid ISD-ASes", t, func() {
		ia := ISD_AS{}
		cases := [][2]int{
			{1, 2}, {11, 22}, {111, 222},
		}
		for _, vals := range cases {
			s := fmt.Sprintf("%d-%d", vals[0], vals[1])
			Convey(s, func() {
				So(ia.UnmarshalYAML(test.UnmarshalToString(s)), ShouldBeNil)
				So(ia.isd, ShouldEqual, vals[0])
				So(ia.as, ShouldEqual, vals[1])
			})
		}
	})
}
