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

package conf

import (
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestASSample(t *testing.T) {
	cfg := AS{}
	// Set validity to check it is parsed.
	cfg.Validity.NotBefore = 15

	m, err := toml.Decode(ASSample, &cfg)
	require.NoError(t, err)
	require.Len(t, m.Undecoded(), 0)
	assert.Equal(t, "AS certificate", cfg.Description)
	assert.Equal(t, scrypto.Version(1), cfg.Version)
	assert.Equal(t, scrypto.KeyVersion(1), *cfg.SigningKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(1), *cfg.EncryptionKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(1), *cfg.RevocationKeyVersion)
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), cfg.IssuerIA)
	assert.Equal(t, scrypto.Version(1), cfg.IssuerCertVersion)
	assert.Equal(t, []addr.IA{xtest.MustParseIA("2-ff00:0:210")},
		cfg.OptDistPoints)
	assert.Equal(t, uint32(0), cfg.Validity.NotBefore)
	assert.Equal(t, 3*24*time.Hour, cfg.Validity.Validity.Duration)
}

func TestIssuerSample(t *testing.T) {
	cfg := Issuer{}
	// Set validity to check it is parsed.
	cfg.Validity.NotBefore = 15

	m, err := toml.Decode(IssuerSample, &cfg)
	require.NoError(t, err)
	require.Len(t, m.Undecoded(), 0)
	assert.Equal(t, "Issuer certificate", cfg.Description)
	assert.Equal(t, scrypto.Version(1), cfg.Version)
	assert.Equal(t, scrypto.KeyVersion(1), *cfg.IssuingKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(1), *cfg.RevocationKeyVersion)
	assert.Equal(t, scrypto.Version(1), cfg.TRCVersion)
	assert.Equal(t, []addr.IA{xtest.MustParseIA("2-ff00:0:210")},
		cfg.OptDistPoints)
	assert.Equal(t, uint32(0), cfg.Validity.NotBefore)
	assert.Equal(t, 5*24*time.Hour, cfg.Validity.Validity.Duration)
}

func TestTRCSample(t *testing.T) {
	f := xtest.MustParseAS
	as110, as120, as130 := f("ff00:0:110"), f("ff00:0:120"), f("ff00:0:130")

	tomlCfg := tomlTRC{}
	// Set validity to check it is parsed.
	tomlCfg.Validity.NotBefore = 15

	m, err := toml.Decode(TRCSample, &tomlCfg)
	require.NoError(t, err)
	require.Len(t, m.Undecoded(), 0)

	cfg, err := tomlCfg.TRC()
	require.NoError(t, err)
	assert.Equal(t, "ISD 1", cfg.Description)
	assert.Equal(t, scrypto.Version(2), cfg.Version)
	assert.Equal(t, scrypto.Version(1), cfg.BaseVersion)
	assert.Equal(t, uint16(2), cfg.VotingQuorum)
	assert.Equal(t, 6*time.Hour, cfg.GracePeriod.Duration)
	assert.Equal(t, true, *cfg.TrustResetAllowed)
	assert.Equal(t, []addr.AS{as110, as120}, cfg.Votes)
	assert.Equal(t, uint32(0), cfg.Validity.NotBefore)
	assert.Equal(t, 365*24*time.Hour, cfg.Validity.Validity.Duration)

	entry := cfg.PrimaryASes[as110]
	assert.Equal(t, trc.Attributes{trc.Voting}, entry.Attributes)
	assert.Equal(t, scrypto.KeyVersion(1), *entry.VotingOnlineKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(1), *entry.VotingOfflineKeyVersion)
	assert.Nil(t, entry.IssuingKeyVersion)

	entry = cfg.PrimaryASes[as120]
	assert.Equal(t, trc.Attributes{trc.Core, trc.Authoritative, trc.Issuing,
		trc.Voting}, entry.Attributes)
	assert.Equal(t, scrypto.KeyVersion(1), *entry.VotingOnlineKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(1), *entry.VotingOfflineKeyVersion)
	assert.Equal(t, scrypto.KeyVersion(2), *entry.IssuingKeyVersion)

	entry = cfg.PrimaryASes[as130]
	assert.Equal(t, trc.Attributes{trc.Core, trc.Authoritative},
		entry.Attributes)
	assert.Nil(t, entry.VotingOnlineKeyVersion)
	assert.Nil(t, entry.VotingOfflineKeyVersion)
	assert.Nil(t, entry.IssuingKeyVersion)
}

func TestKeysSample(t *testing.T) {
	var tomlCfg tomlKeys
	m, err := toml.Decode(KeysSample, &tomlCfg)
	require.NoError(t, err)
	require.Len(t, m.Undecoded(), 0)
	cfg, err := tomlCfg.Keys()
	require.NoError(t, err)

	check := func(metas map[scrypto.KeyVersion]KeyMeta, algo string,
		val time.Duration) {

		for _, meta := range metas {
			assert.Equal(t, algo, meta.Algorithm)
			assert.Equal(t, uint32(0), meta.Validity.NotBefore)
			assert.Equal(t, val, meta.Validity.Validity.Duration)
		}
	}
	check(cfg.Primary[trc.IssuingKey], scrypto.Ed25519, 365*24*time.Hour)
	check(cfg.Primary[trc.OfflineKey], scrypto.Ed25519, 5*365*24*time.Hour)
	check(cfg.Primary[trc.OnlineKey], scrypto.Ed25519, 365*24*time.Hour)
	check(cfg.Issuer[cert.IssuingKey], scrypto.Ed25519, 30*7*24*time.Hour)
	check(cfg.Issuer[cert.RevocationKey], scrypto.Ed25519, 30*7*24*time.Hour)
	check(cfg.AS[cert.SigningKey], scrypto.Ed25519, 15*7*24*time.Hour)
	check(cfg.AS[cert.RevocationKey], scrypto.Ed25519, 15*7*24*time.Hour)
	check(cfg.AS[cert.EncryptionKey], scrypto.Curve25519xSalsa20Poly1305,
		15*7*24*time.Hour)

}
