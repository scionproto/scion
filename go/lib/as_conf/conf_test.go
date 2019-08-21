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

package as_conf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestASConf tests that loading test config `testdata/basic.yml` works.
func TestASConf(t *testing.T) {
	err := Load("testdata/basic.yml")
	require.NoError(t, err)
	c := CurrConf
	expectedConf := &ASConf{
		1, 21600, 5, true, 60,
	}
	assert.Equal(t, expectedConf, c)
}
