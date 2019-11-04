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

package conf_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf/testdata"
)

func TestTRC(t *testing.T) {
	var v1, v2 bytes.Buffer
	err := testdata.GoldenTRCv1.Encode(&v1)
	require.NoError(t, err)
	err = testdata.GoldenTRCv2.Encode(&v2)
	require.NoError(t, err)

	if *update {
		err = ioutil.WriteFile("testdata/trc-v1.toml", v1.Bytes(), 0644)
		require.NoError(t, err)
		err = ioutil.WriteFile("testdata/trc-v2.toml", v2.Bytes(), 0644)
		require.NoError(t, err)
	}

	t.Run("loaded TRC configs match", func(t *testing.T) {
		parsed, err := conf.LoadTRC("testdata/trc-v1.toml")
		require.NoError(t, err)
		assert.Equal(t, testdata.GoldenTRCv1, parsed)
		parsed, err = conf.LoadTRC("testdata/trc-v2.toml")
		require.NoError(t, err)
		assert.Equal(t, testdata.GoldenTRCv2, parsed)
	})

	t.Run("encoded TRC configs match", func(t *testing.T) {
		raw, err := ioutil.ReadFile("testdata/trc-v1.toml")
		require.NoError(t, err)
		assert.Equal(t, raw, v1.Bytes())
		raw, err = ioutil.ReadFile("testdata/trc-v2.toml")
		require.NoError(t, err)
		assert.Equal(t, raw, v2.Bytes())
	})
}
