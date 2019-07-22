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
	// ImmutableBaseVersion indicates an invalid update to the BaseVersion.
	ImmutableBaseVersion = "BaseVersion is immutable"
	// ImmutableISD indicates an invalid update to the ISD identifier.
	ImmutableISD = "ISD is immutable"
	// ImmutableTrustResetAllowed indicates an invalid update to TrustResetAllowed.
	ImmutableTrustResetAllowed = "TrustResetAllowed is immutable"
	// InvalidVersionIncrement indicates an invalid version increment.
	InvalidVersionIncrement = "TRC version must be incremented by one"
	// MissingVote indicates an AS has not cast vote during a regular update
	// that changes its online key.
	MissingVote = "missing vote"
	// NotInsidePreviousValidityPeriod indicates the validity periods do not overlap.
	NotInsidePreviousValidityPeriod = "not inside previous validity period"
	// QuorumUnmet indicates that not enough votes have been cast.
	QuorumUnmet = "voting quorum unmet"
	// WrongVotingKeyType indicates the vote is cast with the wrong key type.
	WrongVotingKeyType = "vote with wrong key type"
	// WrongVotingKeyVersion indicates the vote is cast with the wrong key version
	WrongVotingKeyVersion = "vote with wrong key version"
)

// Update validation error wrappers.
const (
	// InvalidVote indicates an invalid vote.
	InvalidVote = "invalid vote"
	// SanityCheckError indicates a sanity check error.
	SanityCheckError = "sanity check error"
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
		return UpdateInfo{}, common.NewBasicError(SanityCheckError, err)
	}
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
	if err := v.checkProofOfPossesion(keyChanges); err != nil {
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
		return common.NewBasicError(InvariantViolation, err)
	}
	if v.Next.ISD != v.Prev.ISD {
		return common.NewBasicError(ImmutableISD, nil, "expected", v.Prev.ISD, "actual", v.Next.ISD)
	}
	if v.Next.TrustResetAllowed() != v.Prev.TrustResetAllowed() {
		return common.NewBasicError(ImmutableTrustResetAllowed, nil, "expected",
			v.Prev.TrustResetAllowed, "actual", v.Next.TrustResetAllowed)
	}
	if v.Next.Version != v.Prev.Version+1 {
		return common.NewBasicError(InvalidVersionIncrement, nil, "expected", v.Prev.Version+1,
			"actual", v.Next.Version)
	}
	if v.Next.BaseVersion != v.Prev.BaseVersion {
		return common.NewBasicError(ImmutableBaseVersion, nil, "expected", v.Prev.BaseVersion,
			"actual", v.Next.BaseVersion)
	}
	if !v.Prev.Validity.Contains(v.Next.Validity.NotBefore.Time) {
		return common.NewBasicError(NotInsidePreviousValidityPeriod, nil,
			"prevValidity", v.Prev.Validity, "NotBefore", v.Next.Validity.NotBefore)
	}
	return nil
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
		return common.NewBasicError(QuorumUnmet, nil,
			"min", v.Prev.VotingQuorum(), "actual", len(v.Next.Votes))
	}
	return nil
}

func (v *UpdateValidator) checkVotesRegular(info UpdateInfo) error {
	// Check all votes from voting ASes with expected key.
	for as, vote := range v.Next.Votes {
		expectedKeyType := OnlineKey
		if _, ok := info.KeyChanges.Modified[OnlineKey][as]; ok {
			expectedKeyType = OfflineKey
		}
		if err := v.hasVotingRights(as, vote, expectedKeyType); err != nil {
			return common.NewBasicError(InvalidVote, err, "AS", as, "vote", vote)
		}
	}
	// Check all ASes with changed online key have cast a vote.
	for as := range info.KeyChanges.Modified[OnlineKey] {
		if _, ok := v.Next.Votes[as]; !ok {
			return common.NewBasicError(MissingVote, nil, "AS", as)
		}
	}
	return nil
}

func (v *UpdateValidator) checkVotesSensitive(info UpdateInfo) error {
	// Check all votes from voting ASes with offline keys.
	for as, vote := range v.Next.Votes {
		if err := v.hasVotingRights(as, vote, OfflineKey); err != nil {
			return common.NewBasicError(InvalidVote, err, "AS", as, "vote", vote)
		}
	}
	return nil
}

func (v *UpdateValidator) hasVotingRights(as addr.AS, vote Vote, keyType KeyType) error {
	primary, ok := v.Prev.PrimaryASes[as]
	if !ok {
		return ErrUnexpectedVote
	}
	if !primary.Is(Voting) {
		return ErrNoVotingRight
	}
	if vote.Type != keyType {
		return common.NewBasicError(WrongVotingKeyType, nil,
			"expected", keyType, "actual", vote.Type)
	}
	if primary.Keys[keyType].KeyVersion != vote.KeyVersion {
		return common.NewBasicError(WrongVotingKeyVersion, nil,
			"expected", primary.Keys[keyType].KeyVersion, "actual", vote.KeyVersion)
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
