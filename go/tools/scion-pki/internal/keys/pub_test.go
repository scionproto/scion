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

package keys

import (
	"bytes"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestPubGenRun(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-trust")
	defer cleanF()

	var buf bytes.Buffer
	err := Keys().Encode(&buf)
	require.NoError(t, err)
	file := conf.KeysFile(tmpDir, ia110)
	err = os.MkdirAll(filepath.Dir(file), 0755)
	require.NoError(t, err)
	err = ioutil.WriteFile(file, buf.Bytes(), 0644)
	require.NoError(t, err)

	asMap := map[addr.ISD][]addr.IA{1: {ia110}}
	err = privGen{Dirs: pkicmn.Dirs{Root: tmpDir, Out: tmpDir}}.Run(asMap)
	require.NoError(t, err)
	err = pubGen{Dirs: pkicmn.Dirs{Root: tmpDir, Out: tmpDir}}.Run(asMap)
	require.NoError(t, err)

	files := map[string]struct {
		Algorithm string
		Usage     keyconf.Usage
		Version   scrypto.KeyVersion
		Validity  time.Duration
		PrivFile  string
	}{
		"ISD1-ASff00_0_110-as-signing-v3.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.ASSigningKey,
			Version:   3,
			Validity:  90 * 24 * time.Hour,
			PrivFile:  "as-signing-v3.key",
		},
		"ISD1-ASff00_0_110-as-revocation-v2.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.ASRevocationKey,
			Version:   2,
			Validity:  90 * 24 * time.Hour,
			PrivFile:  "as-revocation-v2.key",
		},
		"ISD1-ASff00_0_110-as-decrypt-v1.pub": {
			Algorithm: scrypto.Curve25519xSalsa20Poly1305,
			Usage:     keyconf.ASDecryptionKey,
			Version:   1,
			Validity:  90 * 24 * time.Hour,
			PrivFile:  "as-decrypt-v1.key",
		},
		"ISD1-ASff00_0_110-issuer-revocation-v2.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.IssRevocationKey,
			Version:   2,
			Validity:  180 * 24 * time.Hour,
			PrivFile:  "issuer-revocation-v2.key",
		},
		"ISD1-ASff00_0_110-issuer-cert-signing-v1.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.IssCertSigningKey,
			Version:   1,
			Validity:  180 * 24 * time.Hour,
			PrivFile:  "issuer-cert-signing-v1.key",
		},
		"ISD1-ASff00_0_110-trc-voting-online-v2.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOnlineKey,
			Version:   2,
			Validity:  365 * 24 * time.Hour,
			PrivFile:  "trc-voting-online-v2.key",
		},
		"ISD1-ASff00_0_110-trc-voting-online-v1.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOnlineKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
			PrivFile:  "trc-voting-online-v1.key",
		},
		"ISD1-ASff00_0_110-trc-voting-offline-v1.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOfflineKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
			PrivFile:  "trc-voting-offline-v1.key",
		},
		"ISD1-ASff00_0_110-trc-issuing-grant-v1.pub": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCIssuingGrantKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
			PrivFile:  "trc-issuing-grant-v1.key",
		},
	}
	for file, exp := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := ioutil.ReadFile(filepath.Join(PublicDir(tmpDir, ia110), file))
			require.NoError(t, err)
			p, _ := pem.Decode(raw)
			require.NotNil(t, p)
			key, err := keyconf.KeyFromPEM(p)
			require.NoError(t, err)
			assert.Equal(t, keyconf.PublicKey, key.Type)
			assert.Equal(t, exp.Usage, key.Usage)
			assert.Equal(t, exp.Algorithm, key.Algorithm)
			assert.Equal(t, exp.Version, key.Version)
			assert.Equal(t, ia110, key.IA)
			assert.True(t, len(key.Bytes) > 1)

			validity := key.Validity.NotAfter.Sub(key.Validity.NotBefore.Time)
			assert.Equal(t, exp.Validity, validity)
			assert.InDelta(t, time.Now().Unix(), key.Validity.NotBefore.Unix(),
				float64(10*time.Second))

			priv := loadKey(t, filepath.Join(PrivateDir(tmpDir, ia110), exp.PrivFile))
			if exp.Algorithm == scrypto.Ed25519 {
				privKey := []byte(ed25519.NewKeyFromSeed(priv.Bytes))
				sig, err := scrypto.Sign([]byte("message"), privKey, priv.Algorithm)
				require.NoError(t, err)
				err = scrypto.Verify([]byte("message"), sig, key.Bytes, key.Algorithm)
				assert.NoError(t, err)
			} else {
				otherPub, otherPriv, err := scrypto.GenKeyPair(scrypto.Curve25519xSalsa20Poly1305)
				require.NoError(t, err)
				enc, err := scrypto.Encrypt([]byte("message"), make([]byte, 24), otherPub,
					priv.Bytes, priv.Algorithm)
				require.NoError(t, err)
				msg, err := scrypto.Decrypt(enc, make([]byte, 24), key.Bytes,
					otherPriv, priv.Algorithm)
				assert.NoError(t, err)
				assert.EqualValues(t, []byte("message"), msg)
			}
		})
	}
}

func TestLoadPublicKey(t *testing.T) {
	tmpDir, clean := xtest.MustTempDir("", "test-keys")
	defer clean()
	protoKey := keyconf.Key{
		ID: keyconf.ID{
			Usage:   keyconf.ASSigningKey,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
			Version: 1,
		},
		Type: keyconf.PublicKey,
	}
	t.Run("load pub file", func(t *testing.T) {
		dir := path.Join(tmpDir, "pub")
		err := os.MkdirAll(PublicDir(dir, protoKey.IA), 0777)
		require.NoError(t, err)
		block := protoKey.PEM()
		err = ioutil.WriteFile(PublicFile(dir, protoKey.ID), pem.EncodeToMemory(&block), 0644)
		require.NoError(t, err)

		_, derived, err := LoadPublicKey(dir, protoKey.ID)
		require.NoError(t, err)
		assert.False(t, derived)
	})
	t.Run("load priv file", func(t *testing.T) {
		dir := path.Join(tmpDir, "priv")
		err := os.MkdirAll(PublicDir(dir, protoKey.IA), 0777)
		require.NoError(t, err)
		block := protoKey.PEM()
		err = ioutil.WriteFile(PublicFile(dir, protoKey.ID), pem.EncodeToMemory(&block), 0644)
		require.NoError(t, err)

		err = os.MkdirAll(PrivateDir(dir, protoKey.IA), 0777)
		require.NoError(t, err)
		priv := keyconf.Key{
			ID:        protoKey.ID,
			Type:      keyconf.PrivateKey,
			Algorithm: scrypto.Ed25519,
			Bytes:     make([]byte, 32),
		}
		block = priv.PEM()
		err = ioutil.WriteFile(PrivateFile(dir, priv.ID), pem.EncodeToMemory(&block), 0644)
		require.NoError(t, err)

		_, derived, err := LoadPublicKey(dir, protoKey.ID)
		require.NoError(t, err)
		assert.True(t, derived)
	})
	t.Run("invalid contents", func(t *testing.T) {
		dir := path.Join(tmpDir, "priv")
		err := os.MkdirAll(PrivateDir(dir, protoKey.IA), 0777)
		require.NoError(t, err)
		priv := keyconf.Key{
			ID:        protoKey.ID,
			Type:      keyconf.PublicKey,
			Algorithm: scrypto.Ed25519,
			Bytes:     make([]byte, 32),
		}
		block := priv.PEM()
		err = ioutil.WriteFile(PrivateFile(dir, priv.ID), pem.EncodeToMemory(&block), 0644)
		require.NoError(t, err)

		_, derived, err := LoadPublicKey(dir, protoKey.ID)
		require.Error(t, err)
		assert.False(t, derived)
	})
	t.Run("no key", func(t *testing.T) {
		_, derived, err := LoadPublicKey(tmpDir, protoKey.ID)
		require.Error(t, err)
		assert.False(t, derived)
	})

}

func loadKey(t *testing.T, file string) keyconf.Key {
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	key, err := keyconf.KeyFromPEM(block)
	require.NoError(t, err)
	return key
}
