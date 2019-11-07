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

func TestAS(t *testing.T) {
	var buf bytes.Buffer
	err := testdata.GoldenAS.Encode(&buf)
	require.NoError(t, err)

	if *update {
		err := ioutil.WriteFile("testdata/as-v1.toml", buf.Bytes(), 0644)
		require.NoError(t, err)
	}

	t.Run("loaded AS certificate config matches", func(t *testing.T) {
		cfg, err := conf.LoadAS("testdata/as-v1.toml")
		require.NoError(t, err)
		assert.Equal(t, testdata.GoldenAS, cfg)
	})

	t.Run("encoded AS certificate config matches", func(t *testing.T) {
		raw, err := ioutil.ReadFile("testdata/as-v1.toml")
		require.NoError(t, err)
		assert.Equal(t, raw, buf.Bytes())
	})
}
