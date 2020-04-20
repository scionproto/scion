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

package util_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/util"
)

func TestUnixTimeUnmarshal(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Assert assert.ErrorAssertionFunc
	}{
		"invalid type": {
			Input:  `{"a": 10}`,
			Assert: assert.Error,
		},
		"invalid string": {
			Input:  "111a",
			Assert: assert.Error,
		},
		"negative": {
			Input:  "-1",
			Assert: assert.Error,
		},
		"wrap around": {
			Input:  strconv.FormatUint(1<<63, 10),
			Assert: assert.Error,
		},
		"correct": {
			Input:  "1356091932",
			Assert: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var u util.UnixTime
			err := json.Unmarshal([]byte(test.Input), &u)
			test.Assert(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, util.SecsToTime(1356091932), u.Time)
		})
	}
}

func TestUnixTimeMarshal(t *testing.T) {
	s := struct {
		Unix util.UnixTime
	}{
		Unix: util.UnixTime{
			Time: util.SecsToTime(1356091932),
		},
	}
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, `{"Unix":1356091932}`, string(raw))

}
