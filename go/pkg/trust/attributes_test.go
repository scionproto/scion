// Copyright 2020 Anapaya Systems
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

package trust_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/trust"
)

func TestAttributesSubSet(t *testing.T) {
	testCases := map[string]struct {
		Set          trust.Attribute
		Super        trust.Attribute
		AssertSubset assert.BoolAssertionFunc
	}{
		"true subset": {
			Set:          trust.Authoritative | trust.Core,
			Super:        trust.Authoritative | trust.Core | trust.RootCA,
			AssertSubset: assert.True,
		},
		"equal set": {
			Set:          trust.Authoritative | trust.RootCA,
			Super:        trust.Authoritative | trust.RootCA,
			AssertSubset: assert.True,
		},
		"not subset": {
			Set:          trust.Authoritative | trust.Core,
			Super:        trust.Authoritative | trust.RootCA,
			AssertSubset: assert.False,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.AssertSubset(t, tc.Set.IsSubset(tc.Super))
		})
	}
}
