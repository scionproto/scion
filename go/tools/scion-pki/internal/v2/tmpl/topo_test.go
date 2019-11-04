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
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia111 = xtest.MustParseIA("1-ff00:0:111")
	ia112 = xtest.MustParseIA("1-ff00:0:112")
)

func TestTopoGen(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-trust")
	defer cleanF()

	topo := topoFile{
		ASes: map[addr.IA]asEntry{
			ia110: {Core: true},
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
		assert.Equal(t, uint16(1), cfg.VotingQuorum)
		assert.Equal(t, util.DurWrap{}, cfg.GracePeriod)
		assert.Equal(t, true, *cfg.TrustResetAllowed)
		assert.Equal(t, []addr.AS{}, cfg.Votes)
		assert.Equal(t, conf.Validity{NotBefore: 424242, Validity: year}, cfg.Validity)
		iss, on, off := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
		exp := map[addr.AS]conf.Primary{
			ia110.A: {
				Attributes: trc.Attributes{trc.Authoritative, trc.Core, trc.Issuing,
					trc.Voting},
				IssuingKeyVersion:       &iss,
				VotingOfflineKeyVersion: &off,
				VotingOnlineKeyVersion:  &on,
			},
		}
		assert.Equal(t, exp, cfg.PrimaryASes)
	})

}
