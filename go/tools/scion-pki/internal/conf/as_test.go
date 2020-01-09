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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
)

func TestASEncode(t *testing.T) {
	rawGolden, err := ioutil.ReadFile("testdata/as-v1.toml")
	require.NoError(t, err)

	var buf bytes.Buffer
	err = AS().Encode(&buf)
	require.NoError(t, err)
	assert.Equal(t, rawGolden, buf.Bytes())
}

func TestLoadAS(t *testing.T) {
	cfg, err := conf.LoadAS("testdata/as-v1.toml")
	require.NoError(t, err)
	assert.Equal(t, AS(), cfg)
}

// TestUpdateGoldenAS provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenAS(t *testing.T) {
	if *update {
		var buf bytes.Buffer
		err := AS().Encode(&buf)
		require.NoError(t, err)
		err = ioutil.WriteFile("testdata/as-v1.toml", buf.Bytes(), 0644)
		require.NoError(t, err)
	}
}

// AS generates a AS certificate configuration for testing.
func AS() conf.AS {
	s, e, r := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
	return conf.AS{
		Description:          "Testing AS",
		Version:              1,
		SigningKeyVersion:    &s,
		EncryptionKeyVersion: &e,
		RevocationKeyVersion: &r,
		IssuerIA:             xtest.MustParseIA("1-ff00:0:110"),
		IssuerCertVersion:    1,
		OptDistPoints:        []addr.IA{xtest.MustParseIA("2-ff00:0:210")},
		Validity: conf.Validity{
			NotBefore: 42424242,
			Validity:  util.DurWrap{Duration: 3 * 24 * time.Hour},
		},
	}
}
