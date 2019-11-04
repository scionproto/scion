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

package testdata

import (
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var (
	// GoldenTRCv1 contains the decoded trc-v1.toml file
	GoldenTRCv1 = TRCv1(42424242)
	// GoldenTRCv2 contains the decoded trc-v2.toml file
	GoldenTRCv2 = TRCv2(42424248)
)

// TRCv1 generates a TRC configuration for testing.
func TRCv1(notBefore uint32) conf.TRC2 {
	t := true
	v1 := scrypto.KeyVersion(1)
	return conf.TRC2{
		Description:       "Testing TRC",
		Version:           1,
		BaseVersion:       1,
		VotingQuorum:      1,
		GracePeriod:       util.DurWrap{},
		TrustResetAllowed: &t,
		Votes:             []addr.AS{xtest.MustParseAS("ff00:0:110")},
		Validity: conf.Validity{
			NotBefore: notBefore,
			Validity:  util.DurWrap{Duration: 5 * 24 * time.Hour},
		},
		PrimaryASes: map[addr.AS]conf.Primary{
			xtest.MustParseAS("ff00:0:110"): {
				Attributes: []trc.Attribute{trc.Authoritative, trc.Core,
					trc.Issuing, trc.Voting},
				IssuingKeyVersion:       &v1,
				VotingOnlineKeyVersion:  &v1,
				VotingOfflineKeyVersion: &v1,
			},
		},
	}
}

// TRCv2 generates a TRC configuration for testing.
func TRCv2(notBefore uint32) conf.TRC2 {
	t := true
	v1 := scrypto.KeyVersion(1)
	v2 := scrypto.KeyVersion(2)
	return conf.TRC2{
		Description:       "Testing TRC",
		Version:           2,
		BaseVersion:       1,
		VotingQuorum:      1,
		GracePeriod:       util.DurWrap{Duration: time.Hour},
		TrustResetAllowed: &t,
		Votes:             []addr.AS{xtest.MustParseAS("ff00:0:110")},
		Validity: conf.Validity{
			NotBefore: notBefore,
			Validity:  util.DurWrap{Duration: 5 * 24 * time.Hour},
		},
		PrimaryASes: map[addr.AS]conf.Primary{
			xtest.MustParseAS("ff00:0:110"): {
				Attributes: []trc.Attribute{trc.Authoritative, trc.Core,
					trc.Issuing, trc.Voting},
				IssuingKeyVersion:       &v1,
				VotingOnlineKeyVersion:  &v2,
				VotingOfflineKeyVersion: &v1,
			},
		},
	}
}
