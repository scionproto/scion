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

package trcs

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/scion-pki/conf"
)

func TestMarshalPayload(t *testing.T) {
	cfg, err := conf.LoadTRC("testdata/admin/ISD1-B1-S1.toml")
	require.NoError(t, err)
	trc, err := CreatePayload(cfg)
	require.NoError(t, err)
	raw, err := trc.Encode()
	require.NoError(t, err)
	expected, err := ioutil.ReadFile("testdata/admin/ISD1-B1-S1.pld.der")
	assert.Equal(t, expected, raw)
	require.NoError(t, err)
}
