// Copyright 2019 Anapaya Systems
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

package scrypto_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
)

func TestValidityContains(t *testing.T) {
	now := time.Now()
	validity := scrypto.Validity{
		NotBefore: util.UnixTime{Time: now},
		NotAfter:  util.UnixTime{Time: now.Add(time.Minute)},
	}
	tests := map[string]struct {
		Time      time.Time
		Contained bool
	}{
		"Before": {
			Time: now.Add(-time.Minute),
		},
		"Same as NotBefore": {
			Time:      now,
			Contained: true,
		},
		"Between NotBefore and NotAfter": {
			Time:      now.Add(30 * time.Second),
			Contained: true,
		},
		"Same as NotAfter": {
			Time:      now.Add(time.Minute),
			Contained: true,
		},
		"After": {
			Time: now.Add(time.Hour),
		},
	}
	for name, test := range tests {
		assert.Equal(t, test.Contained, validity.Contains(test.Time), name)
	}
}

func TestValidityUnmarshal(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Assert assert.ErrorAssertionFunc
	}{
		"invalid type": {
			Input:  `{"a": 10}`,
			Assert: assert.Error,
		},
		"NotBefore missing": {
			Input:  `{"NotAfter": 1356134400}`,
			Assert: assert.Error,
		},
		"NotAfter missing": {
			Input:  `{"NotBefore": 1356048000}`,
			Assert: assert.Error,
		},
		"Unknown field": {
			Input: `
			{
				"UnknownField": "UNKNOWN"
				"NotBefore": 1356048000,
				"NotAfter": 1356134400
			}
			`,
			Assert: assert.Error,
		},
		"Valid": {
			Input: `
			{
				"NotBefore": 1356048000,
				"NotAfter": 1356134400
			}
			`,
			Assert: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var v scrypto.Validity
			err := json.Unmarshal([]byte(test.Input), &v)
			test.Assert(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, util.SecsToTime(1356048000), v.NotBefore.Time)
			assert.Equal(t, util.SecsToTime(1356134400), v.NotAfter.Time)
		})
	}
}

func TestValidityMarshal(t *testing.T) {
	s := struct {
		Validity scrypto.Validity
	}{
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: util.SecsToTime(1356048000)},
			NotAfter:  util.UnixTime{Time: util.SecsToTime(1356134400)},
		},
	}
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, `{"Validity":{"NotBefore":1356048000,"NotAfter":1356134400}}`, string(raw))
}
