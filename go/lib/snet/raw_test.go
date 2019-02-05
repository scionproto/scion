// Copyright 2019 ETH Zurich
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

package snet

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
)

func TestExtensionSort(t *testing.T) {
	type TestCase struct {
		Description   string
		InputSlice    []common.Extension
		ExpectedSlice []common.Extension
	}
	testCases := []*TestCase{
		{
			Description: "nil list",
		},
		{
			Description:   "empty list",
			InputSlice:    []common.Extension{},
			ExpectedSlice: []common.Extension{},
		},
		{
			Description: "one item",
			InputSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
			ExpectedSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
		},
		{
			Description: "scmp should go first",
			InputSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnSCMP{},
			},
			ExpectedSlice: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
		},
		{
			Description: "HBH extensions go before e2e, in stable fashion",
			InputSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
			ExpectedSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 44},
			},
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				StableSortExtensions(tc.InputSlice)
				So(tc.InputSlice, ShouldResemble, tc.ExpectedSlice)
			})
		}
	})
}
