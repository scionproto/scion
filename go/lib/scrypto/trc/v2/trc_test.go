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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	trc "github.com/scionproto/scion/go/lib/scrypto/trc/v2"
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
		ExpectedErrMsg string
	}{
		"Valid invariant": {
			Modify: func(_ *trc.TRC) {},
		},
		"Wrong validity period": {
			Modify: func(base *trc.TRC) {
				base.Validity.NotAfter.Time = base.Validity.NotBefore.Time
			},
			ExpectedErrMsg: trc.InvalidValidityPeriod,
		},
		"No Issuing AS": {
			Modify: func(base *trc.TRC) {
				primary := base.PrimaryASes[a110]
				primary.Attributes = trc.Attributes{trc.Core, trc.Voting}
				base.PrimaryASes[a110] = primary

				delete(base.PrimaryASes, a130)
				delete(base.ProofOfPossession, a130)
			},
			ExpectedErrMsg: trc.ErrNoIssuingAS.Error(),
		},
		"Zero VotingQuorum": {
			Modify: func(base *trc.TRC) {
				quorum := uint8(0)
				base.VotingQuorumPtr = &quorum
			},
			ExpectedErrMsg: trc.ErrZeroVotingQuorum.Error(),
		},
		"VotingQuorum larger than voting ASes": {
			Modify: func(base *trc.TRC) {
				quorum := uint8(base.PrimaryASes.Count(trc.Voting) + 1)
				base.VotingQuorumPtr = &quorum
			},
			ExpectedErrMsg: trc.VotingQuorumTooLarge,
		},
		"PrimaryASes invariant violated": {
			Modify: func(base *trc.TRC) {
				delete(base.PrimaryASes[a110].Keys, trc.OfflineKey)
			},
			ExpectedErrMsg: trc.MissingKey,
		},
		"Zero GracePeriod, TRCVersion != BaseVersion": {
			Modify: func(base *trc.TRC) {
				base.Version = 2
			},
			ExpectedErrMsg: trc.ErrUpdateWithZeroGracePeriod.Error(),
		},
		"Non-Zero GracePeriod, TRCVersion == BaseVersion": {
			Modify: func(base *trc.TRC) {
				base.GracePeriod = &trc.Period{Duration: time.Hour}
			},
			ExpectedErrMsg: trc.ErrBaseWithNonZeroGracePeriod.Error(),
		},
		"Base missing AS in pops": {
			Modify: func(base *trc.TRC) {
				delete(base.ProofOfPossession, a130)
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"Base missing pop for AS": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a110] = base.ProofOfPossession[a110][:1]
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"Base with votes": {
			Modify: func(base *trc.TRC) {
				base.Votes[a130] = trc.Vote{
					KeyType:    trc.OnlineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.ErrBaseWithVotes.Error(),
		},
		"Base pop for unexpected key": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a130] = append(base.ProofOfPossession[a130], trc.OnlineKey)
			},
			ExpectedErrMsg: trc.UnexpectedProofOfPossession,
		},
		"Base pop from unexpected AS": {
			Modify: func(base *trc.TRC) {
				base.ProofOfPossession[a190] = []trc.KeyType{trc.OnlineKey}
			},
			ExpectedErrMsg: trc.UnexpectedProofOfPossession,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			base := newBaseTRC()
			test.Modify(base)
			err := base.ValidateInvariant()
			if test.ExpectedErrMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func newBaseTRC() *trc.TRC {
	now := time.Now().Round(time.Second)
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
					trc.OnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 110, 1},
					},
					trc.OfflineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{1, 110, 1},
					},
					trc.IssuingKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 110, 1},
					},
				},
			},
			a120: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.OnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 120, 1},
					},
					trc.OfflineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{1, 120, 1},
					},
				},
			},
			a130: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Issuing},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.IssuingKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 130, 1},
					},
				},
			},
			a140: trc.PrimaryAS{
				Attributes: trc.Attributes{trc.Voting},
				Keys: map[trc.KeyType]scrypto.KeyMeta{
					trc.OnlineKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{0, 140, 1},
					},
					trc.OfflineKey: {
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
		Votes: make(map[addr.AS]trc.Vote),
		ProofOfPossession: map[addr.AS][]trc.KeyType{
			a110: {
				trc.OnlineKey,
				trc.OfflineKey,
				trc.IssuingKey,
			},
			a120: {
				trc.OnlineKey,
				trc.OfflineKey,
			},
			a130: {
				trc.IssuingKey,
			},
			a140: {
				trc.OnlineKey,
				trc.OfflineKey,
			},
		},
	}
	return t
}
