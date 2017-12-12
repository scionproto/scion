// Copyright 2017 ETH Zurich
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

package common

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var binOrderCases = []struct {
	width int
	val   uint64
	raw   []byte
}{
	{1, 0x01, []byte{0x01}},
	{2, 0x0102, []byte{0x01, 0x02}},
	{3, 0x010203, []byte{0x01, 0x02, 0x03}},
	{4, 0x01020304, []byte{0x01, 0x02, 0x03, 0x04}},
	{5, 0x0102030405, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	{6, 0x010203040506, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
	{7, 0x01020304050607, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
	{8, 0x0102030405060708, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
}

func Test_binOrder_UintN(t *testing.T) {
	Convey("binOrder.UintN parse correctly", t, func() {
		for _, testC := range binOrderCases {
			ret := Order.UintN(testC.raw, testC.width)
			So(ret, ShouldEqual, testC.val)
		}
	})
}

func Test_binOrder_PutUintN(t *testing.T) {
	Convey("binOrder.PutUintN packs correctly", t, func() {
		for _, testC := range binOrderCases {
			b := make([]byte, testC.width)
			Order.PutUintN(b, testC.val, testC.width)
			So(b, ShouldResemble, testC.raw)
		}
	})
}
