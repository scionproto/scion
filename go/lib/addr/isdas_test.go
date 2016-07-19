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

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/yaml.v2"
)

// Interface assertions
var _ fmt.Stringer = (*ISD_AS)(nil)
var _ yaml.Unmarshaler = (*ISD_AS)(nil)

func Test_IA_String(t *testing.T) {
	Convey("String() should return ISD-AS", t, func() {
		ia := ISD_AS{33, 55}
		So(ia.String(), ShouldEqual, "33-55")
	})
}

func Test_IA_UnmarshalYAML_YAMLParseError(t *testing.T) {
	Convey("YAML parse error", t, func() {
		var ia ISD_AS
		So(yaml.Unmarshal([]byte(`a: b`), &ia), ShouldNotBeNil)
		So(ia, ShouldBeZeroValue)
	})
}

func Test_IA_UnmarshalYAML_InvalidValues(t *testing.T) {
	Convey("Parse errors", t, func() {
		var ia ISD_AS
		cases := []string{"1122", "1-", "-2", "1-12-2", "1a-22", "11-2a"}
		for _, val := range cases {
			Convey(val, func() {
				So(yaml.Unmarshal([]byte(val), &ia), ShouldNotBeNil)
				So(ia, ShouldBeZeroValue)
			})
		}
	})
}

func Test_IA_UnmarshalYAML_ValidISDASes(t *testing.T) {
	Convey("Valid ISD-ASes", t, func() {
		var ia ISD_AS
		cases := [][2]int{{1, 2}, {11, 22}, {111, 222}}
		for _, vals := range cases {
			s := fmt.Sprintf("%d-%d", vals[0], vals[1])
			Convey(s, func() {
				So(yaml.Unmarshal([]byte(s), &ia), ShouldBeNil)
				So(ia.I, ShouldEqual, vals[0])
				So(ia.A, ShouldEqual, vals[1])
			})
		}
	})
}
