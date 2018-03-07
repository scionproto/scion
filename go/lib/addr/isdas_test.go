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
)

// Interface assertions
var _ fmt.Stringer = (*IA)(nil)

func Test_IAFromRaw(t *testing.T) {
	Convey("IAFromRaw should parse bytes correctly", t, func() {
		input := []byte{0x02, 0x10, 0x00, 0x2c}
		ia := IAFromRaw(input)
		So(ia.I, ShouldEqual, 33)
		So(ia.A, ShouldEqual, 44)
	})
}

func Test_IA_Write(t *testing.T) {
	Convey("ISD_AS.Write() should output bytes correctly", t, func() {
		output := make([]byte, 4)
		ia := &IA{I: 33, A: 44}
		ia.Write(output)
		So(output, ShouldResemble, []byte{0x02, 0x10, 0x00, 0x2c})
	})
}

func Test_IA_String(t *testing.T) {
	Convey("String() should return ISD-AS", t, func() {
		ia := IA{33, 55}
		So(ia.String(), ShouldEqual, "33-55")
	})
}
