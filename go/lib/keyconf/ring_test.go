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

package keyconf_test

import (
	"encoding/pem"
	"io/ioutil"
	"path"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestLoadingRingPrivateKey(t *testing.T) {
	block := pemBlock(t)
	tmpDir, cleanF := xtest.MustTempDir("", "test-keyconf-ring")
	defer cleanF()
	file := path.Join(tmpDir, keyconf.PrivateKeyFile(keyconf.ASSigningKey, 2))
	err := ioutil.WriteFile(file, pem.EncodeToMemory(&block), 0644)
	require.NoError(t, err)

	tests := map[string]struct {
		Ring         keyconf.LoadingRing
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Ring: keyconf.LoadingRing{
				Dir: tmpDir,
				IA:  xtest.MustParseIA("1-ff00:0:110"),
			},
			ErrAssertion: assert.NoError,
		},
		"wrong IA": {
			Ring: keyconf.LoadingRing{
				Dir: tmpDir,
				IA:  xtest.MustParseIA("1-ff00:0:111"),
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			k, err := test.Ring.PrivateKey(keyconf.ASSigningKey, 2)
			test.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, block.Type, string(k.Type))
			assert.Equal(t, block.Headers["usage"], string(k.Usage))
			assert.Equal(t, block.Headers["algorithm"], k.Algorithm)
			assert.Equal(t, block.Headers["not_after"],
				util.TimeToCompact(k.Validity.NotAfter.Time))
			assert.Equal(t, block.Headers["not_before"],
				util.TimeToCompact(k.Validity.NotBefore.Time))
			assert.Equal(t, block.Headers["version"], strconv.FormatUint(uint64(k.Version), 10))
			assert.Equal(t, block.Headers["ia"], k.IA.String())
			assert.Equal(t, block.Bytes, k.Bytes)
			assert.Equal(t, block, k.PEM())
		})
	}
}
