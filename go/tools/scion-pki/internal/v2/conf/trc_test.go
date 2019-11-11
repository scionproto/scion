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

func TestTRCEncode(t *testing.T) {
	tests := map[string]struct {
		File   string
		Config conf.TRC2
	}{
		"v1": {
			File:   "testdata/trc-v1.toml",
			Config: testdata.GoldenTRCv1,
		},
		"v2": {
			File:   "testdata/trc-v2.toml",
			Config: testdata.GoldenTRCv2,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rawGolden, err := ioutil.ReadFile(test.File)
			require.NoError(t, err)

			var buf bytes.Buffer
			err = test.Config.Encode(&buf)
			require.NoError(t, err)
			assert.Equal(t, rawGolden, buf.Bytes())
		})
	}
}

func TestLoadTRC(t *testing.T) {
	tests := map[string]struct {
		File   string
		Config conf.TRC2
	}{
		"v1": {
			File:   "testdata/trc-v1.toml",
			Config: testdata.GoldenTRCv1,
		},
		"v2": {
			File:   "testdata/trc-v2.toml",
			Config: testdata.GoldenTRCv2,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := conf.LoadTRC(test.File)
			require.NoError(t, err)
			assert.Equal(t, test.Config, cfg)
		})
	}
}

// TestUpdateGoldenTRC provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenTRC(t *testing.T) {
	if *update {
		cfgs := map[string]conf.TRC2{
			"testdata/trc-v1.toml": testdata.GoldenTRCv1,
			"testdata/trc-v2.toml": testdata.GoldenTRCv2,
		}
		for file, cfg := range cfgs {
			var buf bytes.Buffer
			err := cfg.Encode(&buf)
			require.NoError(t, err)
			err = ioutil.WriteFile(file, buf.Bytes(), 0644)
			require.NoError(t, err)
		}
	}
}
