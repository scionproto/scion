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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
)

func TestExtension(t *testing.T) {
	tests := map[string]struct {
		InputExtensions   []common.Extension
		ExpectedOutputHBH []common.Extension
		ExpectedOutputE2E []common.Extension
		Assertion         require.ErrorAssertionFunc
	}{
		"nil slice": {
			Assertion: require.NoError,
		},
		"empty slice": {
			InputExtensions: []common.Extension{},
			Assertion:       require.NoError,
		},
		"OHP": {
			InputExtensions:   []common.Extension{&layers.ExtnOHP{}},
			ExpectedOutputHBH: []common.Extension{&layers.ExtnOHP{}},
			Assertion:         require.NoError,
		},
		"SCMP in first position": {
			InputExtensions:   []common.Extension{&layers.ExtnSCMP{}},
			ExpectedOutputHBH: []common.Extension{&layers.ExtnSCMP{}},
			Assertion:         require.NoError,
		},
		"SCMP not in first position": {
			InputExtensions: []common.Extension{&layers.ExtnOHP{}, &layers.ExtnSCMP{}},
			Assertion:       require.Error,
		},
		"two unknown extensions, different types": {
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
			},
			ExpectedOutputHBH: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
			},
			Assertion: require.NoError,
		},
		"unknown E2E": {
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
			},
			ExpectedOutputE2E: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 42},
			},
			Assertion: require.NoError,
		},
		"bad class": {
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: 73, TypeField: 42},
			},
			Assertion: require.Error,
		},

		"too many HBH": {
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
			},
			Assertion: require.Error,
		},
		"HBH limit with SCMP": {
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
			Assertion: require.NoError,
		},
		"too many HBH with SCMP": {
			InputExtensions: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 45},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 46},
			},
			Assertion: require.Error,
		},
		"HBH after E2E": {
			InputExtensions: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.End2EndClass, TypeField: 43},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 44},
			},
			Assertion: require.Error,
		},
		//// Disabled for now, see https://github.com/scionproto/scion/issues/2421.
		//"Duplicate OHP": {
		//		InputExtensions: []common.Extension{&layers.ExtnOHP{}, &layers.ExtnOHP{}},
		//		Assertion:       require.Error,
		//	},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hbh, e2e, err := ValidateExtensions(test.InputExtensions)
			test.Assertion(t, err)
			assert.Equal(t, hbh, test.ExpectedOutputHBH, "HBH")
			assert.Equal(t, e2e, test.ExpectedOutputE2E, "E2E")
		})
	}
}
