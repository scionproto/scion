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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var (
	as110 = xtest.MustParseAS("ff00:0:110")
	as120 = xtest.MustParseAS("ff00:0:120")
	as130 = xtest.MustParseAS("ff00:0:130")
	as140 = xtest.MustParseAS("ff00:0:140")
	as150 = xtest.MustParseAS("ff00:0:150")

	authoritative = []addr.AS{as110, as120}
	core          = []addr.AS{as110, as120, as130}
	issuing       = []addr.AS{as140, as150}
	voting        = []addr.AS{as110, as130, as140}
)

func TestValidatingTrc(t *testing.T) {
	tests := map[string]struct {
		Modify         func(trc *conf.TRC)
		ExpectedErrMsg string
	}{
		"valid": {
			Modify: func(trc *conf.TRC) {},
		},
		"template TRC": {
			Modify: func(trc *conf.TRC) {
				*trc = *conf.NewTemplateISDCfg().TRC
				trc.AuthoritativeASes = authoritative
				trc.CoreASes = core
				trc.IssuingASes = issuing
				trc.VotingASes = voting
				trc.VotingQuorum = 2
				trc.Update()
			},
		},
		"Version not set": {
			Modify: func(trc *conf.TRC) {
				trc.Version = 0
			},
			ExpectedErrMsg: conf.ErrTrcVersionNotSet,
		},
		"invalid validity duration": {
			Modify: func(trc *conf.TRC) {
				trc.RawValidity = "18"
			},
			ExpectedErrMsg: conf.ErrInvalidValidityDuration,
		},
		"authoritative not set": {
			Modify: func(trc *conf.TRC) {
				trc.RawAuthoritativeASes = []string{}
			},
			ExpectedErrMsg: "invalid AuthoritativeASes",
		},
		"core not set": {
			Modify: func(trc *conf.TRC) {
				trc.RawCoreASes = []string{}
			},
			ExpectedErrMsg: "invalid CoreASes",
		},
		"issuing not set": {
			Modify: func(trc *conf.TRC) {
				trc.RawIssuingASes = []string{}
			},
			ExpectedErrMsg: "invalid IssuingASes",
		},
		"voting not set": {
			Modify: func(trc *conf.TRC) {
				trc.RawVotingASes = []string{}
			},
			ExpectedErrMsg: "invalid VotingASes",
		},
		"malformed voting AS": {
			Modify: func(trc *conf.TRC) {
				trc.RawVotingASes = append(trc.RawVotingASes, "1-0")
			},
			ExpectedErrMsg: "Unable to parse AS",
		},
		"invalid voting AS": {
			Modify: func(trc *conf.TRC) {
				trc.RawVotingASes = append(trc.RawVotingASes, "0")
			},
			ExpectedErrMsg: "invalid AS",
		},
		"authoritative but not core AS": {
			Modify: func(trc *conf.TRC) {
				trc.RawCoreASes = trc.RawCoreASes[:len(trc.RawCoreASes)-2]
			},
			ExpectedErrMsg: conf.ErrAuthoritativeNotCore,
		},
		"VotingQuorum not set": {
			Modify: func(trc *conf.TRC) {
				trc.VotingQuorum = 0
			},
			ExpectedErrMsg: conf.ErrVotingQuorumNotSet,
		},
		"invalid GracePeriod": {
			Modify: func(trc *conf.TRC) {
				trc.RawGracePeriod = "18"
			},
			ExpectedErrMsg: conf.ErrInvalidGracePeriod,
		},
		"base and non-zero GracePeriod": {
			Modify: func(trc *conf.TRC) {
				trc.RawGracePeriod = "6h"
			},
			ExpectedErrMsg: conf.ErrInvalidGracePeriod,
		},
		"VotingQuorum greater than number of voting ASes": {
			Modify: func(trc *conf.TRC) {
				trc.VotingQuorum = len(trc.RawVotingASes) + 1
			},
			ExpectedErrMsg: conf.ErrVotingQuorumGreaterThanVotingASes,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			trc := conf.TRC{
				Version:              1,
				BaseVersion:          1,
				VotingQuorum:         2,
				TrustResetAllowed:    true,
				NotBefore:            0,
				RawValidity:          "180d",
				RawAuthoritativeASes: toRawASes(authoritative),
				RawCoreASes:          toRawASes(core),
				RawIssuingASes:       toRawASes(issuing),
				RawVotingASes:        toRawASes(voting),
			}
			test.Modify(&trc)
			err := trc.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func toRawASes(ases []addr.AS) []string {
	raw := make([]string, 0, len(ases))
	for _, as := range ases {
		raw = append(raw, as.String())
	}
	return raw
}
