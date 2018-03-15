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

var (
	rawIA = []byte{0xF0, 0x11, 0xF2, 0x33, 0x44, 0x55, 0x66, 0x77}
	ia    = IA{I: 0xF011, A: 0xF23344556677}
)

// Interface assertions
var _ fmt.Stringer = (*IA)(nil)

func Test_IAFromRaw(t *testing.T) {
	Convey("IAFromRaw should parse bytes correctly", t, func() {
		ia := IAFromRaw(rawIA)
		So(ia.I, ShouldEqual, ia.I)
		So(ia.A, ShouldEqual, ia.A)
	})
}

func Test_IA_Write(t *testing.T) {
	Convey("ISD_AS.Write() should output bytes correctly", t, func() {
		output := make([]byte, IABytes)
		ia.Write(output)
		So(output, ShouldResemble, rawIA)
	})
}

func Test_IA_String(t *testing.T) {
	Convey("String() should return ISD-AS", t, func() {
		ia := IA{33, 55}
		So(ia.String(), ShouldEqual, "33-55")
	})
}
