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
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
)

func TestTRCEncode(t *testing.T) {
	tests := map[string]struct {
		File   string
		Config conf.TRC
	}{
		"v1": {
			File:   "testdata/trc-v1.toml",
			Config: TRCv1(),
		},
		"v2": {
			File:   "testdata/trc-v2.toml",
			Config: TRCv2(),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rawGolden, err := ioutil.ReadFile(test.File)
			require.NoError(t, err)

			var buf bytes.Buffer
			err = test.Config.Encode(&buf)
			require.NoError(t, err)
			assert.Equal(t, rawGolden, buf.Bytes())
		})
	}
}

func TestLoadTRC(t *testing.T) {
	tests := map[string]struct {
		File   string
		Config conf.TRC
	}{
		"v1": {
			File:   "testdata/trc-v1.toml",
			Config: TRCv1(),
		},
		"v2": {
			File:   "testdata/trc-v2.toml",
			Config: TRCv2(),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := conf.LoadTRC(test.File)
			require.NoError(t, err)
			assert.Equal(t, test.Config, cfg)
		})
	}
}

// TestUpdateGoldenTRC provides an easy way to update the golden file after
// the format has changed.
func TestUpdateGoldenTRC(t *testing.T) {
	if *update {
		cfgs := map[string]conf.TRC{
			"testdata/trc-v1.toml": TRCv1(),
			"testdata/trc-v2.toml": TRCv2(),
		}
		for file, cfg := range cfgs {
			var buf bytes.Buffer
			err := cfg.Encode(&buf)
			require.NoError(t, err)
			err = ioutil.WriteFile(file, buf.Bytes(), 0644)
			require.NoError(t, err)
		}
	}
}

// TRCv1 generates a TRC configuration for testing.
func TRCv1() conf.TRC {
	t := true
	v1 := scrypto.KeyVersion(1)
	return conf.TRC{
		Description:       "Testing TRC",
		Version:           1,
		BaseVersion:       1,
		VotingQuorum:      1,
		GracePeriod:       util.DurWrap{},
		TrustResetAllowed: &t,
		Votes:             []addr.AS{},
		Validity: conf.Validity{
			NotBefore: 42424242,
			Validity:  util.DurWrap{Duration: 5 * 24 * time.Hour},
		},
		PrimaryASes: map[addr.AS]conf.Primary{
			xtest.MustParseAS("ff00:0:110"): {
				Attributes: []trc.Attribute{trc.Authoritative, trc.Core,
					trc.Issuing, trc.Voting},
				IssuingGrantKeyVersion:  &v1,
				VotingOnlineKeyVersion:  &v1,
				VotingOfflineKeyVersion: &v1,
			},
		},
	}
}

// TRCv2 generates a TRC configuration for testing.
func TRCv2() conf.TRC {
	t := true
	v1 := scrypto.KeyVersion(1)
	v2 := scrypto.KeyVersion(2)
	return conf.TRC{
		Description:       "Testing TRC",
		Version:           2,
		BaseVersion:       1,
		VotingQuorum:      1,
		GracePeriod:       util.DurWrap{Duration: time.Hour},
		TrustResetAllowed: &t,
		Votes:             []addr.AS{xtest.MustParseAS("ff00:0:110")},
		Validity: conf.Validity{
			NotBefore: 42424248,
			Validity:  util.DurWrap{Duration: 5 * 24 * time.Hour},
		},
		PrimaryASes: map[addr.AS]conf.Primary{
			xtest.MustParseAS("ff00:0:110"): {
				Attributes: []trc.Attribute{trc.Authoritative, trc.Core,
					trc.Issuing, trc.Voting},
				IssuingGrantKeyVersion:  &v1,
				VotingOnlineKeyVersion:  &v2,
				VotingOfflineKeyVersion: &v1,
			},
		},
	}
}
