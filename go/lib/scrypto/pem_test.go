// Copyright 2021 Anapaya Systems
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
	"flag"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestPEMSymmetricKey(t *testing.T) {
	testCases := map[string]struct {
		Key         []byte
		ExpectError assert.ErrorAssertionFunc
	}{
		"nil": {
			Key:         nil,
			ExpectError: assert.Error,
		},
		"empty": {
			Key:         []byte{},
			ExpectError: assert.Error,
		},
		"one": {
			Key:         []byte{1},
			ExpectError: assert.NoError,
		},
		"long": {
			Key: []byte{
				0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
				4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
			},
			ExpectError: assert.NoError,
		},
	}

	for name, tc := range testCases {
		tc := tc
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fileName := "testdata/" + name + ".pem"
			if *update {
				b, err := scrypto.EncodePEMSymmetricKey(tc.Key)
				require.NoError(t, err)

				err = ioutil.WriteFile(fileName, b, 0644)
				require.NoError(t, err)
			}

			b, err := ioutil.ReadFile(fileName)
			require.NoError(t, err)

			key, err := scrypto.ParsePEMSymmetricKey(b)
			tc.ExpectError(t, err)
			if err == nil {
				assert.Equal(t, tc.Key, key)
			}
		})
	}
}

func TestParsePEMSymmetricKeyParseError(t *testing.T) {
	b, err := scrypto.ParsePEMSymmetricKey([]byte{13, 37})
	assert.Error(t, err)
	assert.Nil(t, b)
}
