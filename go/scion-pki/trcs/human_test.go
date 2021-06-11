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

package trcs_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/scion-pki/trcs"
)

func TestGetHumanEncoding(t *testing.T) {
	trc, err := trcs.DecodeFromFile("testdata/admin/ISD1-B1-S1.trc")
	require.NoError(t, err)
	trcpem, err := trcs.DecodeFromFile("testdata/admin/ISD1-B1-S1.pem.trc")
	require.NoError(t, err)
	testCases := map[string]struct {
		Encoding string
		Raw      []byte
		Golden   string
	}{
		"json signed TRC": {
			Encoding: "json",
			Raw:      trc.Raw,
			Golden:   "testdata/human.signed.json",
		},
		"json TRC": {
			Encoding: "json",
			Raw:      trc.TRC.Raw,
			Golden:   "testdata/human.json",
		},
		"yaml signed TRC": {
			Encoding: "yaml",
			Raw:      trc.Raw,
			Golden:   "testdata/human.signed.yml",
		},
		"yaml TRC": {
			Encoding: "yaml",
			Raw:      trc.TRC.Raw,
			Golden:   "testdata/human.yml",
		},
		"json signed TRC pem": {
			Encoding: "json",
			Raw:      trcpem.Raw,
			Golden:   "testdata/human.signed.json",
		},
		"json TRC pem": {
			Encoding: "json",
			Raw:      trcpem.TRC.Raw,
			Golden:   "testdata/human.json",
		},
		"yaml signed TRC pem": {
			Encoding: "yaml",
			Raw:      trcpem.Raw,
			Golden:   "testdata/human.signed.yml",
		},
		"yaml TRC pem": {
			Encoding: "yaml",
			Raw:      trcpem.TRC.Raw,
			Golden:   "testdata/human.yml",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			enc, err := trcs.GetEncoder(&buf, tc.Encoding)
			require.NoError(t, err)
			h, err := trcs.GetHumanEncoding(tc.Raw, nil, false)
			require.NoError(t, err)
			err = enc.Encode(h)
			require.NoError(t, err)

			if *update {
				err := ioutil.WriteFile(tc.Golden, buf.Bytes(), 0644)
				require.NoError(t, err)
				return
			}

			raw, err := ioutil.ReadFile(tc.Golden)
			require.NoError(t, err)
			assert.Equal(t, string(raw), buf.String())
		})
	}

}
