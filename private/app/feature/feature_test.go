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

package feature_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/private/app/feature"
)

func TestParse(t *testing.T) {
	type NoTag struct {
		Untagged        bool
		NotDiscoverable string
	}

	testCases := map[string]struct {
		Input          []string
		FeatureSet     any
		ErrorAssertion assert.ErrorAssertionFunc
		Expected       any
	}{
		"default": {
			Input:          []string{"header_legacy"},
			FeatureSet:     &feature.Default{},
			ErrorAssertion: assert.NoError,
			Expected: &feature.Default{
				HeaderLegacy: true,
			},
		},
		"custom": {
			Input:          []string{"Untagged"},
			FeatureSet:     &NoTag{},
			ErrorAssertion: assert.NoError,
			Expected:       &NoTag{Untagged: true},
		},
		"unknown features": {
			Input:          []string{"unknown"},
			FeatureSet:     &feature.Default{},
			ErrorAssertion: assert.Error,
			Expected:       &feature.Default{},
		},
		"not discoverable": {
			Input:          []string{"NotDiscoverable"},
			FeatureSet:     &NoTag{},
			ErrorAssertion: assert.Error,
			Expected:       &NoTag{},
		},
		"default nil": {
			Input:          []string{"header_legacy"},
			FeatureSet:     (*feature.Default)(nil),
			ErrorAssertion: assert.Error,
			Expected:       (*feature.Default)(nil),
		},
		"default struct": {
			Input:          []string{"header_legacy"},
			FeatureSet:     feature.Default{},
			ErrorAssertion: assert.Error,
			Expected:       feature.Default{},
		},
		"nil": {
			Input:          []string{"header_legacy"},
			FeatureSet:     nil,
			ErrorAssertion: assert.Error,
			Expected:       nil,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			set := tc.FeatureSet
			err := feature.Parse(tc.Input, set)
			tc.ErrorAssertion(t, err)
			assert.Equal(t, tc.Expected, set)
		})
	}
}

func TestParseDefault(t *testing.T) {
	testCases := map[string]struct {
		Input          []string
		FeatureSet     feature.Default
		ErrorAssertion assert.ErrorAssertionFunc
		Expected       feature.Default
	}{
		"default": {
			Input:          []string{"header_legacy"},
			ErrorAssertion: assert.NoError,
			Expected: feature.Default{
				HeaderLegacy: true,
			},
		},
		"unknown features": {
			Input:          []string{"unknown"},
			ErrorAssertion: assert.Error,
			Expected:       feature.Default{},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			set, err := feature.ParseDefault(tc.Input)
			tc.ErrorAssertion(t, err)
			assert.Equal(t, tc.Expected, set)
		})
	}
}

func TestString(t *testing.T) {
	type Custom struct {
		One             bool
		Two             bool
		NotDiscoverable string
	}

	testCases := map[string]struct {
		FeatureSet any
		Expected   string
	}{
		"default": {
			FeatureSet: feature.Default{},
			Expected:   "header_legacy",
		},
		"default pointer": {
			FeatureSet: &feature.Default{},
			Expected:   "header_legacy",
		},
		"custom": {
			FeatureSet: Custom{},
			Expected:   "One|Two",
		},
		"custom pointer": {
			FeatureSet: &Custom{},
			Expected:   "One|Two",
		},
		"nil": {
			FeatureSet: nil,
			Expected:   "",
		},
		"typed nil": {
			FeatureSet: (*feature.Default)(nil),
			Expected:   "header_legacy",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.Expected, feature.String(tc.FeatureSet, "|"))
		})
	}
}
