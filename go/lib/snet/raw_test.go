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

package snet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/snet"
)

func TestExtensionSort(t *testing.T) {
	tests := map[string]struct {
		InputSlice    []common.Extension
		ExpectedSlice []common.Extension
	}{
		"nil list": {},
		"empty list": {
			InputSlice:    []common.Extension{},
			ExpectedSlice: []common.Extension{},
		},
		"one item": {
			InputSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
			ExpectedSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
		},
		"scmp should go first": {
			InputSlice: []common.Extension{
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
				&layers.ExtnSCMP{},
			},
			ExpectedSlice: []common.Extension{
				&layers.ExtnSCMP{},
				&layers.ExtnUnknown{ClassField: common.HopByHopClass, TypeField: 42},
			},
		},
		"HBH extensions go before e2e, in stable fashion": {
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
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			snet.StableSortExtensions(test.InputSlice)
			assert.Equal(t, test.ExpectedSlice, test.InputSlice)
		})
	}
}
