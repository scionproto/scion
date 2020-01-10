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

package trc

import (
	"errors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// Update validation errors with context.
const (
	// ErrImmutableBaseVersion indicates an invalid update to the base_version.
	ErrImmutableBaseVersion common.ErrMsg = "base_version is immutable"
	// ErrImmutableISD indicates an invalid update to the ISD identifier.
	ErrImmutableISD common.ErrMsg = "isd is immutable"
	// ErrImmutableTrustResetAllowed indicates an invalid update to trust_reset_allowed.
	ErrImmutableTrustResetAllowed common.ErrMsg = "trust_reset_allowed is immutable"
	// ErrInvalidVersionIncrement indicates an invalid version increment.
	ErrInvalidVersionIncrement common.ErrMsg = "TRC version must be incremented by one"
	// ErrMissingVote indicates an AS has not cast vote during a regular update
	// that changes its online key.
	ErrMissingVote common.ErrMsg = "missing vote"
	// ErrNotInsidePreviousValidityPeriod indicates the validity periods do not overlap.
	ErrNotInsidePreviousValidityPeriod common.ErrMsg = "not inside previous validity period"
	// ErrQuorumUnmet indicates that not enough votes have been cast.
	ErrQuorumUnmet common.ErrMsg = "voting_quorum unmet"
	// ErrWrongVotingKeyType indicates the vote is cast with the wrong key type.
	ErrWrongVotingKeyType common.ErrMsg = "vote with wrong key type"
)

// Update validation error wrappers.
const (
	// ErrInvalidVote indicates an invalid vote.
	ErrInvalidVote common.ErrMsg = "invalid vote"
	// ErrSanityCheck indicates a sanity check error.
	ErrSanityCheck common.ErrMsg = "sanity check error"
)

// Update validation errors.
var (
	// ErrBaseNotUpdate indicates that the new TRC is a base TRC.
	ErrBaseNotUpdate = errors.New("base TRC, not update")
	// ErrNoVotingRight indicates the vote is cast by an AS without voting rights.
	ErrNoVotingRight = errors.New("AS has no voting rights")
	// ErrUnexpectedVote indicates that a TRC has an unexpected vote attached.
	ErrUnexpectedVote = errors.New("unexpected vote")
)

// UpdateInfo contains details about the TRC update.
type UpdateInfo struct {
	// Type indicates the TRC update type.
	Type UpdateType
	// KeyChanges contains all modified keys that have to show proof of possession.
	KeyChanges *KeyChanges
	// AttributeChanges contains all attribute changes.
	AttributeChanges AttributeChanges
}

// UpdateValidator is used to validate TRC updates.
type UpdateValidator struct {
	// Prev is the previous TRC. It's version must be Next.Version - 1.
	Prev *TRC
	// Next is the updated TRC.
	Next *TRC
}

// Validate validates a TRC update. In case it is valid, the key changes and
// attribute changes are returned.
func (v *UpdateValidator) Validate() (UpdateInfo, error) {
	if err := v.sanity(); err != nil {
		return UpdateInfo{}, common.NewBasicError(ErrSanityCheck, err)
	}
	info, err := v.UpdateInfo()
	if err != nil {
		return UpdateInfo{}, err
	}
	if err := v.checkProofOfPossesion(info.KeyChanges); err != nil {
		return info, err
	}
	if err := v.checkVotes(info); err != nil {
		return info, err
	}
	return info, nil
}

func (v *UpdateValidator) sanity() error {
	if v.Next.Base() {
		return ErrBaseNotUpdate
	}
	if err := v.Next.ValidateInvariant(); err != nil {
		return common.NewBasicError(ErrInvariantViolation, err)
	}
	if v.Next.ISD != v.Prev.ISD {
		return common.NewBasicError(ErrImmutableISD, nil,
			"expected", v.Prev.ISD, "actual", v.Next.ISD)
	}
	if v.Next.TrustResetAllowed() != v.Prev.TrustResetAllowed() {
		return common.NewBasicError(ErrImmutableTrustResetAllowed, nil, "expected",
			v.Prev.TrustResetAllowed, "actual", v.Next.TrustResetAllowed)
	}
	if v.Next.Version != v.Prev.Version+1 {
		return common.NewBasicError(ErrInvalidVersionIncrement, nil, "expected", v.Prev.Version+1,
			"actual", v.Next.Version)
	}
	if v.Next.BaseVersion != v.Prev.BaseVersion {
		return common.NewBasicError(ErrImmutableBaseVersion, nil, "expected", v.Prev.BaseVersion,
			"actual", v.Next.BaseVersion)
	}
	if !v.Prev.Validity.Contains(v.Next.Validity.NotBefore.Time) {
		return common.NewBasicError(ErrNotInsidePreviousValidityPeriod, nil,
			"previous validity", v.Prev.Validity, "not_before", v.Next.Validity.NotBefore)
	}
	return nil
}

// UpdateInfo returns information about the TRC update.
func (v *UpdateValidator) UpdateInfo() (UpdateInfo, error) {
	keyChanges, err := v.keyChanges()
	if err != nil {
		return UpdateInfo{}, err
	}
	attrChanges := v.attrChanges()
	info := UpdateInfo{
		Type:             v.updateType(keyChanges, attrChanges),
		KeyChanges:       keyChanges,
		AttributeChanges: attrChanges,
	}
	return info, nil
}

func (v *UpdateValidator) keyChanges() (*KeyChanges, error) {
	c := newKeyChanges()
	for as, primary := range v.Next.PrimaryASes {
		if err := c.insertModifications(as, v.Prev.PrimaryASes[as], primary); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (v *UpdateValidator) attrChanges() AttributeChanges {
	c := make(AttributeChanges)
	// Check all attributes of all ASes that persist or are added.
	for as, primary := range v.Next.PrimaryASes {
		c.insertModifications(as, v.Prev.PrimaryASes[as], primary)
	}
	// Check all attributes of all ASes that are removed.
	for as, prev := range v.Prev.PrimaryASes {
		if empty, ok := v.Next.PrimaryASes[as]; !ok {
			c.insertModifications(as, prev, empty)
		}
	}
	return c
}

func (v *UpdateValidator) updateType(k *KeyChanges, a AttributeChanges) UpdateType {
	if k.Sensitive() || a.Sensitive() || v.Next.VotingQuorum() != v.Prev.VotingQuorum() {
		return SensitiveUpdate
	}
	return RegularUpdate
}

func (v *UpdateValidator) checkProofOfPossesion(keyChanges *KeyChanges) error {
	pv := popValidator{
		TRC:        v.Next,
		KeyChanges: keyChanges,
	}
	return pv.checkProofOfPossession()
}

func (v *UpdateValidator) checkVotes(info UpdateInfo) error {
	switch info.Type {
	case RegularUpdate:
		if err := v.checkVotesRegular(info); err != nil {
			return err
		}
	default:
		if err := v.checkVotesSensitive(info); err != nil {
			return err
		}
	}
	if len(v.Next.Votes) < v.Prev.VotingQuorum() {
		return common.NewBasicError(ErrQuorumUnmet, nil,
			"min", v.Prev.VotingQuorum(), "actual", len(v.Next.Votes))
	}
	return nil
}

func (v *UpdateValidator) checkVotesRegular(info UpdateInfo) error {
	// Check all votes from voting ASes with expected key.
	for as, keyType := range v.Next.Votes {
		expectedKeyType := VotingOnlineKey
		if _, ok := info.KeyChanges.Modified[VotingOnlineKey][as]; ok {
			expectedKeyType = VotingOfflineKey
		}
		if err := v.hasVotingRights(as, keyType, expectedKeyType); err != nil {
			return common.NewBasicError(ErrInvalidVote, err, "as", as,
				"key_type", keyType)
		}
	}
	// Check all ASes with changed online key have cast a vote.
	for as := range info.KeyChanges.Modified[VotingOnlineKey] {
		if _, ok := v.Next.Votes[as]; !ok {
			return common.NewBasicError(ErrMissingVote, nil, "as", as)
		}
	}
	return nil
}

func (v *UpdateValidator) checkVotesSensitive(info UpdateInfo) error {
	// Check all votes from voting ASes with offline keys.
	for as, vote := range v.Next.Votes {
		if err := v.hasVotingRights(as, vote, VotingOfflineKey); err != nil {
			return common.NewBasicError(ErrInvalidVote, err, "as", as, "vote", vote)
		}
	}
	return nil
}

func (v *UpdateValidator) hasVotingRights(as addr.AS,
	actual, expected KeyType) error {

	primary, ok := v.Prev.PrimaryASes[as]
	if !ok {
		return ErrUnexpectedVote
	}
	if !primary.Is(Voting) {
		return ErrNoVotingRight
	}
	if actual != expected {
		return common.NewBasicError(ErrWrongVotingKeyType, nil,
			"expected", expected, "actual", actual)
	}
	return nil
}

const (
	// AttributeAdded indicates an attribute is added.
	AttributeAdded AttributeChange = iota
	// AttributeRemoved indicates an attribute is removed.
	AttributeRemoved
)

// AttributeChange indicates the type of attribute change in a TRC update.
type AttributeChange int

// AttributeChanges contains all attribute changes for a TRC update.
type AttributeChanges map[addr.AS]map[Attribute]AttributeChange

// Sensitive indicates whether the attribute changes are sensitive.
func (c AttributeChanges) Sensitive() bool {
	return len(c) != 0
}

func (c AttributeChanges) insertModifications(as addr.AS, prev, next PrimaryAS) {
	for _, attr := range next.Attributes {
		if !prev.Is(attr) {
			c.insert(as, attr, AttributeAdded)
		}
	}
	for _, attr := range prev.Attributes {
		if !next.Is(attr) {
			c.insert(as, attr, AttributeRemoved)
		}
	}
}

func (c AttributeChanges) insert(as addr.AS, attr Attribute, change AttributeChange) {
	m, ok := c[as]
	if !ok {
		m = make(map[Attribute]AttributeChange)
		c[as] = m
	}
	m[attr] = change
}
