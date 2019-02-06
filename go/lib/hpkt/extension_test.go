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

package hpkt

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestExtension(t *testing.T) {
	type TestCase struct {
		Description       string
		InputExtensions   []common.Extension
		ExpectedOutputHBH []common.Extension
		ExpectedOutputE2E []common.Extension
		ExpectedError     bool
	}
	testCases := []*TestCase{
		{
			Description: "nil slice",
		},
		{
			Description:     "empty slice",
			InputExtensions: []common.Extension{},
		},
		{
			Description:       "OHP",
			InputExtensions:   []common.Extension{&layers.ExtnOHP{}},
			ExpectedOutputHBH: []common.Extension{&layers.ExtnOHP{}},
		},
		// Disabled for now, see https://github.com/scionproto/scion/issues/2421.
		/*
			{
				Description:     "Duplicate OHP",
				InputExtensions: []common.Extension{&layers.ExtnOHP{}, &layers.ExtnOHP{}},
				ExpectedError:   true,
			},
		*/
		{
			Description:       "SCMP in first position",
			InputExtensions:   []common.Extension{&layers.ExtnSCMP{}},
			ExpectedOutputHBH: []common.Extension{&layers.ExtnSCMP{}},
		},
		{
			Description:     "SCMP not in first position",
			InputExtensions: []common.Extension{&layers.ExtnOHP{}, &layers.ExtnSCMP{}},
			ExpectedError:   true,
		},
		{
			Description: "two unknown extensions, different types",
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
			},
			ExpectedOutputHBH: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
			},
		},
		{
			Description: "unknown E2E",
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
			},
			ExpectedOutputE2E: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
			},
		},
		{
			Description: "bad class",
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: 73, TypeField: 42},
			},
			ExpectedError: true,
		},
		{
			Description: "too many HBH",
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
			},
			ExpectedError: true,
		},
		{
			Description: "HBH limit with SCMP",
			InputExtensions: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
			},
			ExpectedOutputHBH: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
			},
			ExpectedError: false,
		},
		{
			Description: "too many HBH with SCMP",
			InputExtensions: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 46},
			},
			ExpectedError: true,
		},
		{
			Description: "HBH after E2E",
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
			},
			ExpectedError: true,
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				hbh, e2e, err := ValidateExtensions(tc.InputExtensions)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				SoMsg("HBH", hbh, ShouldResemble, tc.ExpectedOutputHBH)
				SoMsg("E2E", e2e, ShouldResemble, tc.ExpectedOutputE2E)
			})
		}
	})
}
