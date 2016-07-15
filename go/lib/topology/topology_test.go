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

package topology

import (
	"fmt"
	"testing"

	"github.com/netsec-ethz/scion/go/lib/test"
	. "github.com/smartystreets/goconvey/convey"
)

func Test_TopoIP_UnmarshalYAML_YAMLParseError(t *testing.T) {
	Convey("YAML parse error", t, func() {
		tip := TopoIP{}
		err := fmt.Errorf("failed")
		So(tip.UnmarshalYAML(test.UnmarshalToError(err)), ShouldEqual, err)
	})
}

func Test_TopoIP_UnmarshalYAML_IPParseError(t *testing.T) {
	Convey("IP parse error", t, func() {
		tip := TopoIP{}
		So(tip.UnmarshalYAML(test.UnmarshalToString("ip addr")), ShouldNotBeNil)
	})
}

func Test_TopoIP_UnmarshalYAML_ValidIPs(t *testing.T) {
	Convey("Valid IPs", t, func() {
		tip := TopoIP{}
		cases := [][2]string{
			{"127.0.0.1", "8"}, {"198.51.100.0", "24"},
			{"::1", "128"}, {"2001:db8:a0b:12f0::1", "64"},
		}
		for _, ip_mask := range cases {
			full := fmt.Sprintf("%v/%v", ip_mask[0], ip_mask[1])
			Convey(full, func() {
				So(tip.UnmarshalYAML(test.UnmarshalToString(full)), ShouldBeNil)
				So(tip.String(), ShouldEqual, ip_mask[0])
			})
		}
	})
}
