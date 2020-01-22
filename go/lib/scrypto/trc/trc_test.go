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

package trc_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	a110 = xtest.MustParseAS("ff00:0:110")
	a120 = xtest.MustParseAS("ff00:0:120")
	a130 = xtest.MustParseAS("ff00:0:130")
	a140 = xtest.MustParseAS("ff00:0:140")
	a150 = xtest.MustParseAS("ff00:0:150")

	// Fake AS.
	a190 = xtest.MustParseAS("ff00:0:190")
)

func TestTRCValidateInvariant(t *testing.T) {
	tests := map[string]struct {
		Modify         func(base *trc.TRC)
		ExpectedErrMsg error
	}{
		"Valid invariant": {
			Modify: func(_ *trc.TRC) {},
		},
		"Wrong validity period": {
			Modify: func(base *trc.TRC) {
				base.Validity.NotAfter.Time = base.Validity.NotBefore.Time
			},
			ExpectedErrMsg: trc.ErrInvalidValidityPeriod,
		},
		"No Issuing AS": {
			Modify: func(base *trc.TRC) {
				primary := base.PrimaryASes[a110]
				primary.Attributes = trc.Attributes{trc.Core, trc.Voting}
				base.PrimaryASes[a110] = primary

				delete(base.PrimaryASes, a130)
				delete(base.ProofOfPossession, a130)
			},
			ExpectedErrMsg: trc.ErrNoIssuingAS,
		},
		"Zero VotingQuorum": {
			Modify: func(base *trc.TRC) {
				quorum := uint8(0)
				base.VotingQuorumPtr = &quorum
			},
			ExpectedErrMsg: trc.ErrZeroVotingQuorum,
		},
		"VotingQuorum larger than voting ASes": {
			Modify: func(base *trc.TRC) {
				quorum := uint8(base.PrimaryASes.Count(trc.Voting) + 1)
				base.VotingQuorumPtr = &quorum
			},
			ExpectedErrMsg: trc.ErrVotingQuorumTooLarge,
		},
		"PrimaryASes invariant violated": {
			Modify: func(base *trc.TRC) {
				delete(base.PrimaryASes[a110].Keys, trc.VotingOfflineKey)
			},
			ExpectedErrMsg: trc.ErrMissingKey,
		},
		"Zero GracePeriod, TRCVersion != BaseVersion": {
			Modify: func(base *trc.TRC) {
				base.Version = 2
			},
			ExpectedErrMsg: trc.ErrUpdateWithZeroGracePeriod,
		},
		"Non-Zero GracePeriod, TRCVersion == BaseVersion": {
			Modify: func(base *trc.TRC) {
				base.GracePeriod = &trc.Period{Duration: time.Hour}
			},
			ExpectedErrMsg: trc.ErrBaseWithNonZeroGracePeriod,
		},
		"Base missing AS in pops": {
			Modify: func(base *trc.TRC) {
				delete(base.ProofOfPossession, a130)
			},
			ExpectedErrMsg: trc.ErrMissingProofOfPossession,
		},
		"Base missing pop for AS": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a110] = base.ProofOfPossession[a110][:1]
			},
			ExpectedErrMsg: trc.ErrMissingProofOfPossession,
		},
		"Base with votes": {
			Modify: func(base *trc.TRC) {
				base.Votes[a130] = trc.VotingOnlineKey
			},
			ExpectedErrMsg: trc.ErrBaseWithVotes,
		},
		"Base pop for unexpected key": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a130] = append(base.ProofOfPossession[a130],
					trc.VotingOnlineKey)
			},
			ExpectedErrMsg: trc.ErrUnexpectedProofOfPossession,
		},
		"Base pop from unexpected AS": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a190] = []trc.KeyType{trc.VotingOnlineKey}
			},
			ExpectedErrMsg: trc.ErrUnexpectedProofOfPossession,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseTRC(time.Now())
			test.Modify(base)
			err := base.ValidateInvariant()
			xtest.AssertErrorsIs(t, err, test.ExpectedErrMsg)
		})
	}
}

func newBaseTRC(notBefore time.Time) *trc.TRC {
	now := notBefore.Truncate(time.Second)
	quorum := uint8(3)
	trustResetAllowed := true
	t := &trc.TRC{
		ISD:                  1,
		Version:              1,
		BaseVersion:          1,
		Description:          "This is the initial TRC of ISD 1",
		VotingQuorumPtr:      &quorum,
		FormatVersion:        1,
		GracePeriod:          &trc.Period{},
		TrustResetAllowedPtr: &trustResetAllowed,
		Validity: &scrypto.Validity{
			NotBefore: util.UnixTime{Time: now},
			NotAfter:  util.UnixTime{Time: now.Add(8760 * time.Hour)},
		},
		PrimaryASes: trc.PrimaryASes{
			a110: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Authoritative, trc.Core, trc.Voting, trc.Issuing},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.VotingOnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 110, 1},
					},
					trc.VotingOfflineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{1, 110, 1},
					},
					trc.IssuingGrantKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 110, 1},
					},
				},
			},
			a120: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.VotingOnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 120, 1},
					},
					trc.VotingOfflineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{1, 120, 1},
					},
				},
			},
			a130: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Issuing},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.IssuingGrantKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 130, 1},
					},
				},
			},
			a140: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.VotingOnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 140, 1},
					},
					trc.VotingOfflineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{1, 140, 1},
					},
				},
			},
			a150: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Authoritative, trc.Core},
			},
		},
		Votes: make(map[addr.AS]trc.KeyType),
		ProofOfPossession: map[addr.AS][]trc.KeyType{
			a110: {
				trc.VotingOnlineKey,
				trc.VotingOfflineKey,
				trc.IssuingGrantKey,
			},
			a120: {
				trc.VotingOnlineKey,
				trc.VotingOfflineKey,
			},
			a130: {
				trc.IssuingGrantKey,
			},
			a140: {
				trc.VotingOnlineKey,
				trc.VotingOfflineKey,
			},
		},
	}
	return t
}
