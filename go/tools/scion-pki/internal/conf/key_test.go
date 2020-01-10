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

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
)

func TestKeysEncode(t *testing.T) {
	rawGolden, err := ioutil.ReadFile("testdata/keys.toml")
	require.NoError(t, err)

	var buf bytes.Buffer
	err = Keys().Encode(&buf)
	require.NoError(t, err)
	assert.Equal(t, rawGolden, buf.Bytes())
}

func TestLoadKeys(t *testing.T) {
	keys, err := conf.LoadKeys("testdata/keys.toml")
	require.NoError(t, err)
	assert.Equal(t, Keys(), keys)
}

// TestUpdateGoldenKeys provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenKeys(t *testing.T) {
	if *update {
		var buf bytes.Buffer
		err := Keys().Encode(&buf)
		require.NoError(t, err)
		err = ioutil.WriteFile("testdata/keys.toml", buf.Bytes(), 0644)
		require.NoError(t, err)
	}
}

// Keys generates a key configuration for testing.
func Keys() conf.Keys {
	return conf.Keys{
		Primary: map[trc.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			trc.IssuingGrantKey: {
				1: keyMeta(scrypto.Ed25519, 42424242, 365*24*time.Hour),
			},
			trc.VotingOfflineKey: {
				1: keyMeta(scrypto.Ed25519, 42424242, 365*24*time.Hour),
			},
			trc.VotingOnlineKey: {
				1: keyMeta(scrypto.Ed25519, 42424242, 365*24*time.Hour),
				2: keyMeta(scrypto.Ed25519, 42424242, 365*24*time.Hour),
			},
		},
		Issuer: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.IssuingKey: {
				1: keyMeta(scrypto.Ed25519, 42424242, 180*24*time.Hour),
			},
			cert.RevocationKey: {
				2: keyMeta(scrypto.Ed25519, 42424242, 180*24*time.Hour),
			},
		},
		AS: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.EncryptionKey: {
				1: keyMeta(scrypto.Curve25519xSalsa20Poly1305, 42424242, 90*24*time.Hour),
			},
			cert.RevocationKey: {
				2: keyMeta(scrypto.Ed25519, 42424242, 90*24*time.Hour),
			},
			cert.SigningKey: {
				3: keyMeta(scrypto.Ed25519, 42424242, 90*24*time.Hour),
			},
		},
	}
}

func keyMeta(algo string, notBefore uint32, validity time.Duration) conf.KeyMeta {
	return conf.KeyMeta{
		Algorithm: algo,
		Validity: conf.Validity{
			NotBefore: notBefore,
			Validity:  util.DurWrap{Duration: validity},
		},
	}
}
