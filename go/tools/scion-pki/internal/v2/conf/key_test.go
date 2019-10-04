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

func TestLoadKeys(t *testing.T) {
	keys, err := conf.LoadKeys("testdata/keys.toml")
	require.NoError(t, err)
	assert.Equal(t, testdata.GoldenKeys, keys)
}

func TestKeysEncode(t *testing.T) {
	var buf bytes.Buffer
	testdata.GoldenKeys.Encode(&buf)
	raw, err := ioutil.ReadFile("testdata/keys.toml")
	require.NoError(t, err)
	assert.Equal(t, raw, buf.Bytes())
}
