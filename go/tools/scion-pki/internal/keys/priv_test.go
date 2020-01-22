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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var ia110 = xtest.MustParseIA("1-ff00:0:110")

func TestPrivGenRun(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-trust")
	defer cleanF()

	// Write keys config.
	var buf bytes.Buffer
	err := Keys().Encode(&buf)
	require.NoError(t, err)
	file := conf.KeysFile(tmpDir, ia110)
	err = os.MkdirAll(filepath.Dir(file), 0755)
	require.NoError(t, err)
	err = ioutil.WriteFile(file, buf.Bytes(), 0644)
	require.NoError(t, err)

	// Generate the key files.
	asMap := map[addr.ISD][]addr.IA{1: {ia110}}
	err = privGen{Dirs: pkicmn.Dirs{Root: tmpDir, Out: tmpDir}}.Run(asMap)
	require.NoError(t, err)

	files := map[string]struct {
		Algorithm string
		Usage     keyconf.Usage
		Version   scrypto.KeyVersion
		Validity  time.Duration
	}{
		"as-signing-v3.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.ASSigningKey,
			Version:   3,
			Validity:  90 * 24 * time.Hour,
		},
		"as-revocation-v2.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.ASRevocationKey,
			Version:   2,
			Validity:  90 * 24 * time.Hour,
		},
		"as-decrypt-v1.key": {
			Algorithm: scrypto.Curve25519xSalsa20Poly1305,
			Usage:     keyconf.ASDecryptionKey,
			Version:   1,
			Validity:  90 * 24 * time.Hour,
		},
		"issuer-revocation-v2.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.IssRevocationKey,
			Version:   2,
			Validity:  180 * 24 * time.Hour,
		},
		"issuer-cert-signing-v1.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.IssCertSigningKey,
			Version:   1,
			Validity:  180 * 24 * time.Hour,
		},
		"trc-voting-online-v2.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOnlineKey,
			Version:   2,
			Validity:  365 * 24 * time.Hour,
		},
		"trc-voting-online-v1.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOnlineKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
		},
		"trc-voting-offline-v1.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCVotingOfflineKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
		},
		"trc-issuing-grant-v1.key": {
			Algorithm: scrypto.Ed25519,
			Usage:     keyconf.TRCIssuingGrantKey,
			Version:   1,
			Validity:  365 * 24 * time.Hour,
		},
	}
	for file, exp := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := ioutil.ReadFile(filepath.Join(PrivateDir(tmpDir, ia110), file))
			require.NoError(t, err)
			p, _ := pem.Decode(raw)
			require.NotNil(t, p)
			key, err := keyconf.KeyFromPEM(p)
			require.NoError(t, err)
			assert.Equal(t, keyconf.PrivateKey, key.Type)
			assert.Equal(t, exp.Usage, key.Usage)
			assert.Equal(t, exp.Algorithm, key.Algorithm)
			assert.Equal(t, exp.Version, key.Version)
			assert.Equal(t, ia110, key.IA)
			assert.True(t, len(key.Bytes) > 1)

			validity := key.Validity.NotAfter.Sub(key.Validity.NotBefore.Time)
			assert.Equal(t, exp.Validity, validity)
			assert.InDelta(t, time.Now().Unix(), key.Validity.NotBefore.Unix(),
				float64(10*time.Second))
		})
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
