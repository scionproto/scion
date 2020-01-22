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

package tmpl

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")

	ia120 = xtest.MustParseIA("1-ff00:0:120")
	ia130 = xtest.MustParseIA("1-ff00:0:130")
)

func TestTopoGen(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-trust")
	defer cleanF()

	topo := topoFile{
		ASes: map[addr.IA]asEntry{
			ia110: {Core: true, Authoritative: true, Issuing: true, Voting: true},
			ia120: {Voting: true, Issuer: ia110},
			ia130: {Issuing: true},
			ia111: {Issuer: ia110},
			ia112: {Issuer: ia110},
		},
	}
	year := util.DurWrap{Duration: 365 * 24 * time.Hour}
	g := topoGen{
		Dirs: pkicmn.Dirs{
			Root: tmpDir,
			Out:  tmpDir,
		},
		Validity: conf.Validity{
			NotBefore: 424242,
			Validity:  year,
		},
	}
	err := g.Run(topo)
	require.NoError(t, err)

	t.Run("TRC config", func(t *testing.T) {
		cfg, err := conf.LoadTRC(conf.TRCFile(tmpDir, 1, 1))
		require.NoError(t, err)

		assert.Equal(t, "ISD 1", cfg.Description)
		assert.Equal(t, scrypto.Version(1), cfg.Version)
		assert.Equal(t, scrypto.Version(1), cfg.BaseVersion)
		assert.Equal(t, uint16(2), cfg.VotingQuorum)
		assert.Equal(t, util.DurWrap{}, cfg.GracePeriod)
		assert.Equal(t, true, *cfg.TrustResetAllowed)
		assert.Equal(t, []addr.AS{}, cfg.Votes)
		assert.Equal(t, conf.Validity{NotBefore: 424242, Validity: year}, cfg.Validity)
		iss, on, off := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
		exp := map[addr.AS]conf.Primary{
			ia110.A: {
				Attributes: trc.Attributes{trc.Authoritative, trc.Core, trc.Issuing,
					trc.Voting},
				IssuingGrantKeyVersion:  &iss,
				VotingOfflineKeyVersion: &off,
				VotingOnlineKeyVersion:  &on,
			},
			ia120.A: {
				Attributes:              trc.Attributes{trc.Voting},
				VotingOfflineKeyVersion: &off,
				VotingOnlineKeyVersion:  &on,
			},
			ia130.A: {
				Attributes:             trc.Attributes{trc.Issuing},
				IssuingGrantKeyVersion: &iss,
			},
		}
		assert.Equal(t, exp, cfg.PrimaryASes)
	})

	for ia, entry := range topo.ASes {
		t.Run("Keys config "+ia.String(), func(t *testing.T) {
			cfg, err := conf.LoadKeys(conf.KeysFile(tmpDir, ia))
			require.NoError(t, err)

			checkMeta := func(t *testing.T, meta conf.KeyMeta, algo string) {
				t.Helper()
				assert.Equal(t, algo, meta.Algorithm)
				assert.Equal(t, g.Validity, meta.Validity)
			}

			checkMeta(t, cfg.AS[cert.SigningKey][1], scrypto.Ed25519)
			checkMeta(t, cfg.AS[cert.RevocationKey][1], scrypto.Ed25519)
			checkMeta(t, cfg.AS[cert.EncryptionKey][1], scrypto.Curve25519xSalsa20Poly1305)
			if entry.Issuing {
				checkMeta(t, cfg.Issuer[cert.IssuingKey][1], scrypto.Ed25519)
				checkMeta(t, cfg.Primary[trc.IssuingGrantKey][1], scrypto.Ed25519)
			}
			if entry.Voting {
				checkMeta(t, cfg.Primary[trc.VotingOnlineKey][1], scrypto.Ed25519)
				checkMeta(t, cfg.Primary[trc.VotingOfflineKey][1], scrypto.Ed25519)
			}
		})
	}

	for ia, entry := range topo.ASes {
		if !entry.Issuing {
			continue
		}
		t.Run("Issuer config "+ia.String(), func(t *testing.T) {
			cfg, err := conf.LoadIssuer(conf.IssuerFile(tmpDir, ia, 1))
			require.NoError(t, err)

			assert.Contains(t, cfg.Description, "Issuer certificate")
			assert.Equal(t, scrypto.Version(1), cfg.Version)
			assert.Equal(t, scrypto.KeyVersion(1), *cfg.IssuingGrantKeyVersion)
			assert.Nil(t, cfg.RevocationKeyVersion)
			assert.Equal(t, scrypto.Version(1), cfg.TRCVersion)
			assert.Empty(t, cfg.OptDistPoints)
			assert.Equal(t, g.Validity, cfg.Validity)
		})
	}

	for ia, entry := range topo.ASes {
		issuer := entry.Issuer
		if entry.Issuing {
			issuer = ia
		}
		t.Run("AS config "+ia.String(), func(t *testing.T) {
			cfg, err := conf.LoadAS(conf.ASFile(tmpDir, ia, 1))
			require.NoError(t, err)

			assert.Contains(t, cfg.Description, "AS certificate")
			assert.Equal(t, scrypto.Version(1), cfg.Version)
			assert.Equal(t, scrypto.KeyVersion(1), *cfg.SigningKeyVersion)
			assert.Equal(t, scrypto.KeyVersion(1), *cfg.EncryptionKeyVersion)
			assert.Equal(t, scrypto.KeyVersion(1), *cfg.RevocationKeyVersion)
			assert.Equal(t, issuer, cfg.IssuerIA)
			assert.Equal(t, scrypto.Version(1), cfg.IssuerCertVersion)
			assert.Empty(t, cfg.OptDistPoints)
			assert.Equal(t, g.Validity, cfg.Validity)
		})
	}
}
