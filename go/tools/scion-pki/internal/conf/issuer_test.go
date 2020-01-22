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

func TestIssuerEncode(t *testing.T) {
	rawGolden, err := ioutil.ReadFile("testdata/issuer-v1.toml")
	require.NoError(t, err)

	var buf bytes.Buffer
	err = Issuer().Encode(&buf)
	require.NoError(t, err)
	assert.Equal(t, rawGolden, buf.Bytes())

}

func TestLoadIssuer(t *testing.T) {
	cfg, err := conf.LoadIssuer("testdata/issuer-v1.toml")
	require.NoError(t, err)
	assert.Equal(t, Issuer(), cfg)
}

// TestUpdateGoldenIssuer provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenIssuer(t *testing.T) {
	if *update {
		var buf bytes.Buffer
		err := Issuer().Encode(&buf)
		require.NoError(t, err)
		err = ioutil.WriteFile("testdata/issuer-v1.toml", buf.Bytes(), 0644)
		require.NoError(t, err)
	}
}

// Issuer generates a issuer certificate configuration for testing.
func Issuer() conf.Issuer {
	i, r := scrypto.KeyVersion(1), scrypto.KeyVersion(1)
	return conf.Issuer{
		Description:            "Testing Issuer",
		Version:                1,
		IssuingGrantKeyVersion: &i,
		RevocationKeyVersion:   &r,
		TRCVersion:             1,
		OptDistPoints:          []addr.IA{xtest.MustParseIA("2-ff00:0:210")},
		Validity: conf.Validity{
			NotBefore: 42424242,
			Validity:  util.DurWrap{Duration: 3 * 24 * time.Hour},
		},
	}
}
