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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestLoadKeyFromFile(t *testing.T) {
	block := pemBlock(t)
	tests := map[string]struct {
		Key          []byte
		Type         keyconf.Type
		ID           keyconf.ID
		ErrAssertion require.ErrorAssertionFunc
	}{
		"valid": {
			Key:  pem.EncodeToMemory(&block),
			Type: keyconf.PrivateKey,
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      xtest.MustParseIA("1-ff00:0:110"),
				Version: 2,
			},
			ErrAssertion: require.NoError,
		},
		"invalid pem": {
			Key:          []byte{},
			ErrAssertion: require.Error,
		},
		"invalid key": {
			Key:          pem.EncodeToMemory(&pem.Block{Type: "garbage"}),
			ErrAssertion: require.Error,
		},
		"invalid type": {
			Key:  pem.EncodeToMemory(&block),
			Type: keyconf.PublicKey,
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Version: 2,
			},
			ErrAssertion: require.Error,
		},
		"invalid IA": {
			Key:  pem.EncodeToMemory(&block),
			Type: keyconf.PrivateKey,
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      xtest.MustParseIA("1-ff00:0:111"),
				Version: 2,
			},
			ErrAssertion: require.Error,
		},
		"invalid Usage": {
			Key:  pem.EncodeToMemory(&block),
			Type: keyconf.PrivateKey,
			ID: keyconf.ID{
				Usage:   keyconf.ASRevocationKey,
				IA:      xtest.MustParseIA("1-ff00:0:110"),
				Version: 2,
			},
			ErrAssertion: require.Error,
		},
		"invalid version": {
			Key:  pem.EncodeToMemory(&block),
			Type: keyconf.PrivateKey,
			ID: keyconf.ID{
				Usage:   keyconf.ASSigningKey,
				IA:      xtest.MustParseIA("1-ff00:0:110"),
				Version: 3,
			},
			ErrAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tmpDir, cleanF := xtest.MustTempDir("", "test-trust")
			defer cleanF()
			file := path.Join(tmpDir, name)
			err := ioutil.WriteFile(file, test.Key, 0644)
			require.NoError(t, err)

			k, err := keyconf.LoadKeyFromFile(file, test.Type, test.ID)
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

func TestKeyFromPEM(t *testing.T) {
	tests := map[string]struct {
		Modify       func(b *pem.Block)
		ErrAssertion require.ErrorAssertionFunc
	}{
		"valid": {
			Modify:       func(_ *pem.Block) {},
			ErrAssertion: require.NoError,
		},
		"public key": {
			Modify: func(b *pem.Block) {
				b.Type = string(keyconf.PublicKey)
			},
			ErrAssertion: require.NoError,
		},
		"invalid type": {
			Modify: func(block *pem.Block) {
				block.Type = "unsupported"
			},
			ErrAssertion: require.Error,
		},
		"invalid usage": {
			Modify: func(block *pem.Block) {
				block.Headers["usage"] = "unsupported"
			},
			ErrAssertion: require.Error,
		},
		"invalid algorithm": {
			Modify: func(block *pem.Block) {
				delete(block.Headers, "algorithm")
			},
			ErrAssertion: require.Error,
		},
		"invalid not_after": {
			Modify: func(block *pem.Block) {
				delete(block.Headers, "not_after")
			},
			ErrAssertion: require.Error,
		},
		"invalid not_before": {
			Modify: func(block *pem.Block) {
				delete(block.Headers, "not_before")
			},
			ErrAssertion: require.Error,
		},
		"invalid version": {
			Modify: func(block *pem.Block) {
				block.Headers["version"] = "unsupported"
			},
			ErrAssertion: require.Error,
		},
		"invalid IA": {
			Modify: func(block *pem.Block) {
				block.Headers["ia"] = "unsupported"
			},
			ErrAssertion: require.Error,
		},
		"missing IA": {
			Modify: func(block *pem.Block) {
				delete(block.Headers, "ia")
			},
			ErrAssertion: require.Error,
		},
		"missing key": {
			Modify: func(block *pem.Block) {
				block.Bytes = nil
			},
			ErrAssertion: require.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			block := pemBlock(t)
			test.Modify(&block)
			k, err := keyconf.KeyFromPEM(&block)
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

func TestKeyFile(t *testing.T) {
	tests := map[string]struct {
		Usage   keyconf.Usage
		Version scrypto.KeyVersion
		IA      addr.IA
		Private string
		Public  string
	}{
		"AS signing key": {
			Usage:   keyconf.ASSigningKey,
			Version: 2,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
			Private: "as-signing-v2.key",
			Public:  "ISD1-ASff00_0_110-as-signing-v2.pub",
		},
		"Issuer revocation key": {
			Usage:   keyconf.IssRevocationKey,
			Version: 1,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
			Private: "issuer-revocation-v1.key",
			Public:  "ISD1-ASff00_0_110-issuer-revocation-v1.pub",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			k := keyconf.Key{
				Type: keyconf.PublicKey,
				ID: keyconf.ID{
					Usage:   test.Usage,
					Version: test.Version,
					IA:      test.IA,
				},
			}
			assert.Equal(t, test.Public, k.File())
			k.Type = keyconf.PrivateKey
			assert.Equal(t, test.Private, k.File())
		})
	}
}

func TestKeyStringRedactsKey(t *testing.T) {
	k := keyconf.Key{
		Type:  keyconf.PublicKey,
		Bytes: xtest.MustParseHexString("7375706572736563757265"),
	}
	assert.Contains(t, k.String(), "7375706572736563757265")
	k.Type = keyconf.PrivateKey
	assert.NotContains(t, k.String(), "7375706572736563757265")
}

func pemBlock(t *testing.T) pem.Block {
	t.Helper()
	return pem.Block{
		Type: string(keyconf.PrivateKey),
		Headers: map[string]string{
			"usage":      string(keyconf.ASSigningKey),
			"algorithm":  scrypto.Ed25519,
			"not_before": util.TimeToCompact(time.Now().Truncate(time.Second)),
			"not_after":  util.TimeToCompact(time.Now().Add(time.Hour).Truncate(time.Second)),
			"version":    "2",
			"ia":         "1-ff00:0:110",
		},
		Bytes: []byte{1, 3, 3, 7},
	}
}
