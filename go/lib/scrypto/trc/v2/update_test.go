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
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	trc "github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/util"
)

// TestCommonUpdate tests shared error cases between regular and sensitive updates.
func TestCommonUpdate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(updated, prev *trc.TRC)
		ExpectedErrMsg string
	}{
		"Trust reset": {
			Modify: func(updated, _ *trc.TRC) {
				*updated = *newBaseTRC()
				updated.BaseVersion = updated.Version
			},
			ExpectedErrMsg: trc.ErrBaseNotUpdate.Error(),
		},
		"Invariant violation": {
			Modify: func(updated, _ *trc.TRC) {
				updated.Validity.NotAfter = updated.Validity.NotBefore
			},
			ExpectedErrMsg: trc.InvalidValidityPeriod,
		},
		"Wrong ISD": {
			Modify: func(updated, _ *trc.TRC) {
				updated.ISD = updated.ISD + 1
			},
			ExpectedErrMsg: trc.ImmutableISD,
		},
		"Wrong Version": {
			Modify: func(updated, prev *trc.TRC) {
				updated.Version = prev.Version + 2
			},
			ExpectedErrMsg: trc.InvalidVersionIncrement,
		},
		"Changed TrustResetAllowed": {
			Modify: func(updated, prev *trc.TRC) {
				*updated.TrustResetAllowedPtr = !prev.TrustResetAllowed()
			},
			ExpectedErrMsg: trc.ImmutableTrustResetAllowed,
		},
		"New NotBefore not in Validity": {
			Modify: func(updated, prev *trc.TRC) {
				updated.Validity = &scrypto.Validity{
					NotBefore: util.UnixTime{Time: prev.Validity.NotAfter.Add(time.Hour)},
					NotAfter:  util.UnixTime{Time: prev.Validity.NotAfter.Add(8760 * time.Hour)},
				}
			},
			ExpectedErrMsg: trc.NotInsidePreviousValidityPeriod,
		},
		"Changed BaseVersion": {
			Modify: func(updated, prev *trc.TRC) {
				prev.Version = 5
				updated.Version = 6
				updated.BaseVersion = 2
			},
			ExpectedErrMsg: trc.ImmutableBaseVersion,
		},
	}
	for name, test := range tests {
		run := func(t *testing.T, trcs func() (*trc.TRC, *trc.TRC), updateType trc.UpdateType) {
			updated, prev := trcs()
			test.Modify(updated, prev)
			v := trc.UpdateValidator{
				Prev: prev,
				Next: updated,
			}
			info, err := v.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, updateType, info.Type)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		}
		t.Run(name+" (regular)", func(t *testing.T) {
			run(t, newRegularUpdate, trc.RegularUpdate)
		})
		sensitiveUpdate := func() (*trc.TRC, *trc.TRC) {
			updated, prev := newSensitiveUpdate()
			*updated.VotingQuorumPtr -= 1
			return updated, prev
		}
		t.Run(name+" (sensitive)", func(t *testing.T) {
			run(t, sensitiveUpdate, trc.SensitiveUpdate)
		})
	}
}

func TestSensitiveUpdate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(updated, prev *trc.TRC)
		Info           trc.UpdateInfo
		ExpectedErrMsg string
	}{
		// Valid updates

		"Votes not cast by all": {
			Modify: func(updated, prev *trc.TRC) {
				*prev.VotingQuorumPtr -= 1
				delete(updated.Votes, a110)
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
			},
		},
		"Decreased VotingQuorum": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
			},
		},
		"Add new Issuing and Voting AS": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr += 1
				updated.PrimaryASes[a190] = trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Issuing, trc.Voting},
					Keys: map[trc.KeyType]trc.KeyMeta{
						trc.OnlineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{0, 190, 1},
						},
						trc.OfflineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{1, 190, 1},
						},
						trc.IssuingKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{2, 190, 1},
						},
					},
				}
				updated.ProofOfPossession[a190] = []trc.KeyType{
					trc.OnlineKey, trc.OfflineKey, trc.IssuingKey}
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				KeyChanges: &trc.KeyChanges{
					Fresh: map[trc.KeyType]trc.ASToKeyMeta{
						trc.OnlineKey: {
							a190: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{0, 190, 1},
							},
						},
						trc.OfflineKey: {
							a190: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{1, 190, 1},
							},
						},
						trc.IssuingKey: {
							a190: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{2, 190, 1},
							},
						},
					},
				},
				AttributeChanges: trc.AttributeChanges{
					a190: map[trc.Attribute]trc.AttributeChange{
						trc.Voting:  trc.AttributeAdded,
						trc.Issuing: trc.AttributeAdded,
					},
				},
			},
		},
		"Remove Voting AS": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				delete(updated.PrimaryASes, a140)
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				AttributeChanges: trc.AttributeChanges{
					a140: map[trc.Attribute]trc.AttributeChange{
						trc.Voting: trc.AttributeRemoved,
					},
				},
			},
		},
		"Promote AS to Issuing": {
			Modify: func(updated, _ *trc.TRC) {
				primary := updated.PrimaryASes[a150]
				primary.Attributes = append(primary.Attributes, trc.Issuing)
				primary.Keys = map[trc.KeyType]trc.KeyMeta{
					trc.IssuingKey: {
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 150, 1},
					},
				}
				updated.PrimaryASes[a150] = primary
				updated.ProofOfPossession[a150] = []trc.KeyType{trc.IssuingKey}
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				KeyChanges: &trc.KeyChanges{
					Fresh: map[trc.KeyType]trc.ASToKeyMeta{
						trc.IssuingKey: {
							a150: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{2, 150, 1},
							},
						},
					},
				},
			},
		},
		"Promote AS to Voting": {
			Modify: func(updated, _ *trc.TRC) {
				primary := updated.PrimaryASes[a130]
				primary.Attributes = trc.Attributes{trc.Issuing, trc.Core, trc.Voting}
				primary.Keys[trc.OnlineKey] = trc.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{0, 130, 1},
				}
				primary.Keys[trc.OfflineKey] = trc.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{1, 130, 1},
				}
				updated.PrimaryASes[a130] = primary
				updated.ProofOfPossession[a130] = []trc.KeyType{trc.OfflineKey, trc.OnlineKey}
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				KeyChanges: &trc.KeyChanges{
					Fresh: map[trc.KeyType]trc.ASToKeyMeta{
						trc.OnlineKey: {
							a130: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{0, 130, 1},
							},
						},
						trc.OfflineKey: {
							a130: {
								KeyVersion: 1,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{1, 130, 1},
							},
						},
					},
				},
				AttributeChanges: trc.AttributeChanges{
					a130: map[trc.Attribute]trc.AttributeChange{
						trc.Voting: trc.AttributeAdded,
					},
				},
			},
		},
		"Demote AS from Voting": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				primary := updated.PrimaryASes[a110]
				primary.Attributes = trc.Attributes{trc.Issuing, trc.Core}
				delete(primary.Keys, trc.OnlineKey)
				delete(primary.Keys, trc.OfflineKey)
				updated.PrimaryASes[a110] = primary
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				AttributeChanges: trc.AttributeChanges{
					a110: map[trc.Attribute]trc.AttributeChange{
						trc.Voting: trc.AttributeRemoved,
					},
				},
			},
		},
		"Demote AS from Issuing": {
			Modify: func(updated, _ *trc.TRC) {
				primary := updated.PrimaryASes[a110]
				primary.Attributes = trc.Attributes{trc.Voting, trc.Core}
				delete(primary.Keys, trc.IssuingKey)
				updated.PrimaryASes[a110] = primary
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				AttributeChanges: trc.AttributeChanges{
					a110: map[trc.Attribute]trc.AttributeChange{
						trc.Issuing: trc.AttributeRemoved,
					},
				},
			},
		},
		"Update offline key": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.OfflineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{1, 110, 2},
				}
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.OfflineKey}
			},
			Info: trc.UpdateInfo{
				Type: trc.SensitiveUpdate,
				KeyChanges: &trc.KeyChanges{
					Modified: map[trc.KeyType]trc.ASToKeyMeta{
						trc.OfflineKey: {
							a110: {
								KeyVersion: 2,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{1, 110, 2},
							},
						},
					},
				},
			},
		},

		// Invalid updates

		"VotingQuorum zero": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr = 0
			},
			ExpectedErrMsg: trc.ErrZeroVotingQuorum.Error(),
		},
		"VotingQuorum larger than voting ASes": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr = uint8(updated.PrimaryASes.Count(trc.Voting) + 1)
			},
			ExpectedErrMsg: trc.VotingQuorumTooLarge,
		},
		"Underflow voting quorum": {
			Modify: func(updated, _ *trc.TRC) {
				delete(updated.PrimaryASes, a140)
			},
			ExpectedErrMsg: trc.VotingQuorumTooLarge,
		},
		"Vote quorum too small": {
			Modify: func(updated, _ *trc.TRC) {
				// Make sure this is a sensitive update
				*updated.VotingQuorumPtr = 1
				delete(updated.Votes, a120)
				delete(updated.Votes, a140)
			},
			ExpectedErrMsg: trc.QuorumUnmet,
		},
		"New Voting AS that does not sign with offline key": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a190] = trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Voting, trc.Core},
					Keys: map[trc.KeyType]trc.KeyMeta{
						trc.OnlineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{0, 190, 1},
						},
						trc.OfflineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{1, 190, 1},
						},
					},
				}
				updated.ProofOfPossession[a190] = []trc.KeyType{trc.OnlineKey}
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"New Voting AS that does not sign with online key": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a190] = trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Voting, trc.Core},
					Keys: map[trc.KeyType]trc.KeyMeta{
						trc.OnlineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{0, 190, 1},
						},
						trc.OfflineKey: {
							KeyVersion: 1,
							Algorithm:  scrypto.Ed25519,
							Key:        []byte{1, 190, 1},
						},
					},
				}
				updated.ProofOfPossession[a190] = []trc.KeyType{trc.OnlineKey}
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"Promoted Issuing AS has no key": {
			Modify: func(updated, _ *trc.TRC) {
				primary := updated.PrimaryASes[a150]
				primary.Attributes = append(primary.Attributes, trc.Issuing)
				updated.PrimaryASes[a150] = primary
			},
			ExpectedErrMsg: trc.MissingKey,
		},
		"Demoted AS keeps offline key": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				primary := updated.PrimaryASes[a110]
				primary.Attributes = trc.Attributes{trc.Issuing, trc.Core}
				updated.PrimaryASes[a110] = primary
			},
			ExpectedErrMsg: trc.UnexpectedKey,
		},
		"Unexpected proof of possession": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.OnlineKey}
			},
			ExpectedErrMsg: trc.UnexpectedProofOfPossession,
		},
		"Update offline key without proof of possession": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.OfflineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{1, 110, 2},
				}
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"Increase offline key version without modification": {
			Modify: func(updated, _ *trc.TRC) {
				meta := updated.PrimaryASes[a110].Keys[trc.OfflineKey]
				meta.KeyVersion = 2
				updated.PrimaryASes[a110].Keys[trc.OfflineKey] = meta
				updated.ProofOfPossession[a110] = append(updated.ProofOfPossession[a110],
					trc.OfflineKey)
			},
			ExpectedErrMsg: trc.InvalidKeyVersion,
		},
		"Modify offline key without increasing version": {
			Modify: func(updated, _ *trc.TRC) {
				meta := updated.PrimaryASes[a110].Keys[trc.OfflineKey]
				meta.KeyVersion = 2
				updated.PrimaryASes[a110].Keys[trc.OfflineKey] = meta
				updated.ProofOfPossession[a110] = append(updated.ProofOfPossession[a110],
					trc.OfflineKey)
			},
			ExpectedErrMsg: trc.InvalidKeyVersion,
		},
		"Increase offline key version by 2": {
			Modify: func(updated, _ *trc.TRC) {
				meta := updated.PrimaryASes[a110].Keys[trc.OfflineKey]
				meta.KeyVersion += 2
				meta.Key = []byte{1, 110, uint8(meta.KeyVersion)}
				updated.PrimaryASes[a110].Keys[trc.OfflineKey] = meta
				updated.ProofOfPossession[a110] = append(updated.ProofOfPossession[a110],
					trc.OfflineKey)
			},
			ExpectedErrMsg: trc.InvalidKeyVersion,
		},
		"Signature from non-Voting AS": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				updated.Votes[a130] = trc.Vote{
					Type:       trc.IssuingKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.ErrNoVotingRight.Error(),
		},
		"Signature from unknown AS": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a190] = trc.PrimaryAS{
					Attributes: trc.Attributes{trc.Core},
				}
				updated.Votes[a190] = trc.Vote{
					Type:       trc.OnlineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.ErrUnexpectedVote.Error(),
		},
		"Wrong KeyType on Vote": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OnlineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.WrongVotingKeyType,
		},
		"Wrong KeyVersion": {
			Modify: func(updated, _ *trc.TRC) {
				*updated.VotingQuorumPtr -= 1
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OfflineKey,
					KeyVersion: 10,
				}
			},
			ExpectedErrMsg: trc.WrongVotingKeyVersion,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			updated, prev := newSensitiveUpdate()
			test.Modify(updated, prev)
			v := trc.UpdateValidator{
				Prev: prev,
				Next: updated,
			}
			info, err := v.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, trc.SensitiveUpdate, info.Type)
				initKeyChanges(&test.Info)
				assert.Equal(t, test.Info.KeyChanges, info.KeyChanges)
				//assert.Equal(t, test.Info, info)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestRegularUpdate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(updated, prev *trc.TRC)
		Info           trc.UpdateInfo
		ExpectedErrMsg string
	}{
		// Valid updates

		"No modification": {
			Modify: func(_, _ *trc.TRC) {},
			Info: trc.UpdateInfo{
				Type: trc.RegularUpdate,
			},
		},
		"Update Description": {
			Modify: func(updated, _ *trc.TRC) {
				updated.Description = "This is the updated description"
			},
			Info: trc.UpdateInfo{
				Type: trc.RegularUpdate,
			},
		},
		"Update issuing key": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.IssuingKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{2, 110, 2},
				}
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.IssuingKey}
			},
			Info: trc.UpdateInfo{
				Type: trc.RegularUpdate,
				KeyChanges: &trc.KeyChanges{
					Modified: map[trc.KeyType]trc.ASToKeyMeta{
						trc.IssuingKey: {
							a110: {
								KeyVersion: 2,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{2, 110, 2},
							},
						},
					},
				},
			},
		},
		"Update online key": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.OnlineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{0, 110, 2},
				}
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.OnlineKey}
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OfflineKey,
					KeyVersion: 1,
				}
			},
			Info: trc.UpdateInfo{
				Type: trc.RegularUpdate,
				KeyChanges: &trc.KeyChanges{
					Modified: map[trc.KeyType]trc.ASToKeyMeta{
						trc.OnlineKey: {
							a110: {
								KeyVersion: 2,
								Algorithm:  scrypto.Ed25519,
								Key:        []byte{0, 110, 2},
							},
						},
					},
				},
			},
		},

		// Invalid updates

		"Signature from previous non-Primary AS": {
			Modify: func(updated, _ *trc.TRC) {
				updated.Votes[a190] = trc.Vote{
					Type:       trc.OnlineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.ErrUnexpectedVote.Error(),
		},
		"Signature from non-Voting AS": {
			Modify: func(updated, prev *trc.TRC) {
				updated.Votes[a130] = trc.Vote{
					Type:       trc.OnlineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.ErrNoVotingRight.Error(),
		},
		"Wrong KeyType": {
			Modify: func(updated, _ *trc.TRC) {
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OfflineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.WrongVotingKeyType,
		},
		"Wrong KeyVersion": {
			Modify: func(updated, _ *trc.TRC) {
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OnlineKey,
					KeyVersion: 10,
				}
			},
			ExpectedErrMsg: trc.WrongVotingKeyVersion,
		},
		"Signature Quorum too small": {
			Modify: func(updated, _ *trc.TRC) {
				delete(updated.Votes, a140)
			},
			ExpectedErrMsg: trc.QuorumUnmet,
		},
		"Missing proof of possession": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.OnlineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{0, 110, 2},
				}
				updated.Votes[a110] = trc.Vote{
					Type:       trc.OfflineKey,
					KeyVersion: 1,
				}
			},
			ExpectedErrMsg: trc.MissingProofOfPossession,
		},
		"Unexpected proof of possession": {
			Modify: func(updated, _ *trc.TRC) {
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.IssuingKey}
			},
			ExpectedErrMsg: trc.UnexpectedProofOfPossession,
		},
		"Update online key with online vote": {
			Modify: func(updated, _ *trc.TRC) {
				updated.PrimaryASes[a110].Keys[trc.OnlineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{0, 110, 2},
				}
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.OnlineKey}
			},
			ExpectedErrMsg: trc.WrongVotingKeyType,
		},
		"Update online key without any vote": {
			Modify: func(updated, prev *trc.TRC) {
				*prev.VotingQuorumPtr = 2
				*updated.VotingQuorumPtr = 2
				updated.PrimaryASes[a110].Keys[trc.OnlineKey] = trc.KeyMeta{
					KeyVersion: 2,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{0, 110, 2},
				}
				updated.ProofOfPossession[a110] = []trc.KeyType{trc.OnlineKey}
				delete(updated.Votes, a110)
			},
			ExpectedErrMsg: trc.MissingVote,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			updated, prev := newRegularUpdate()
			test.Modify(updated, prev)
			v := trc.UpdateValidator{
				Prev: prev,
				Next: updated,
			}
			info, err := v.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, trc.RegularUpdate, info.Type)
				initKeyChanges(&test.Info)
				assert.Equal(t, test.Info.KeyChanges, info.KeyChanges)
				//assert.Equal(t, test.Info, info)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func initKeyChanges(info *trc.UpdateInfo) {
	if info.KeyChanges == nil {
		info.KeyChanges = &trc.KeyChanges{}
	}
	initModType := func(m *map[trc.KeyType]trc.ASToKeyMeta) {
		if *m == nil {
			*m = make(map[trc.KeyType]trc.ASToKeyMeta)
		}
		for _, keyType := range []trc.KeyType{trc.OnlineKey, trc.OfflineKey, trc.IssuingKey} {
			if _, ok := (*m)[keyType]; !ok {
				(*m)[keyType] = make(trc.ASToKeyMeta)
			}
		}
	}
	initModType(&info.KeyChanges.Fresh)
	initModType(&info.KeyChanges.Modified)
}

func newRegularUpdate() (*trc.TRC, *trc.TRC) {
	t := newBaseTRC()
	t.Version = 2
	t.GracePeriod = &trc.Period{Duration: 6 * time.Hour}
	t.Votes = map[addr.AS]trc.Vote{
		a110: {Type: trc.OnlineKey, KeyVersion: 1},
		a120: {Type: trc.OnlineKey, KeyVersion: 1},
		a140: {Type: trc.OnlineKey, KeyVersion: 1},
	}
	t.ProofOfPossession = make(map[addr.AS][]trc.KeyType)
	return t, newBaseTRC()
}

// newSensitive creates an update that is signed with the offline keys.
// The caller has to add the sensitive change.
func newSensitiveUpdate() (*trc.TRC, *trc.TRC) {
	t, _ := newRegularUpdate()
	t.Version = 3
	t.GracePeriod = &trc.Period{Duration: 6 * time.Hour}
	t.Votes = map[addr.AS]trc.Vote{
		a110: {Type: trc.OfflineKey, KeyVersion: 1},
		a120: {Type: trc.OfflineKey, KeyVersion: 1},
		a140: {Type: trc.OfflineKey, KeyVersion: 1},
	}
	t.ProofOfPossession = make(map[addr.AS][]trc.KeyType)
	prev, _ := newRegularUpdate()
	return t, prev
}
