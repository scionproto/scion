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
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Invariant errors with context
const (
	// InvariantViolation indicates a TRC invariant violation.
	InvariantViolation = "TRC invariant violation"
	// InvalidValidityPeriod indicates an invalid validity period.
	InvalidValidityPeriod = "invalid validity period"
	// VotingQuorumTooLarge indicates that the number of voting ASes is smaller
	// than the voting quorum.
	VotingQuorumTooLarge = "voting quorum too large"
)

// UnsupportedFormat indicates an invalid TRC format.
const UnsupportedFormat = "unsupported TRC format"

// Invariant errors
var (
	// ErrBaseWithNonZeroGracePeriod indicates a base TRC with a non-zero grace period.
	ErrBaseWithNonZeroGracePeriod = errors.New("trust reset with non-zero grace period")
	// ErrBaseWithVotes indicates a base TRC with votes. This violates the TRC invariant.
	ErrBaseWithVotes = errors.New("base TRC with votes")
	// ErrNoIssuingAS indicates that the TRC has no issuing AS.
	ErrNoIssuingAS = errors.New("missing issuing AS")
	// ErrUpdateWithZeroGracePeriod indicates a TRC update with a zero grace
	// period. A grace period of zero is only allowed in trust resets, that are
	// not covered by TRC updates.
	ErrUpdateWithZeroGracePeriod = errors.New("update with zero grace period")
	// ErrZeroVotingQuorum indicates that the voting quorum is zero.
	ErrZeroVotingQuorum = errors.New("voting quorum of zero")
)

// Parse errors
var (
	// ErrISDNotSet indicates ISD is not set.
	ErrISDNotSet = errors.New("ISD not set")
	// ErrVersionNotSet indicates Version is not set.
	ErrVersionNotSet = errors.New("Version not set")
	// ErrBaseVersionNotSet indicates BaseVersion is not set.
	ErrBaseVersionNotSet = errors.New("BaseVersion not set")
	// ErrDescriptionNotSet indicates Description is not set.
	ErrDescriptionNotSet = errors.New("Description not set")
	// ErrVotingQuorumNotSet indicates VotingQuorum is not set.
	ErrVotingQuorumNotSet = errors.New("VotingQuorum not set")
	// ErrFormatVersionNotSet indicates FormatVersion is not set.
	ErrFormatVersionNotSet = errors.New("FormatVersion not set")
	// ErrGracePeriodNotSet indicates GracePeriod is not set.
	ErrGracePeriodNotSet = errors.New("GracePeriod not set")
	// ErrTrustResetAllowedNotSet indicates TrustResetAllowed is not set.
	ErrTrustResetAllowedNotSet = errors.New("TrustResetAllowed not set")
	// ErrValidityNotSet indicates Validity is not set.
	ErrValidityNotSet = errors.New("Validity not set")
	// ErrPrimaryASesNotSet indicates PrimaryASes is not set.
	ErrPrimaryASesNotSet = errors.New("PrimaryASes not set")
	// ErrVotesNotSet indicates Votes is not set.
	ErrVotesNotSet = errors.New("Votes not set")
	// ErrProofOfPossessionNotSet indicates ProofOfPossession is not set.
	ErrProofOfPossessionNotSet = errors.New("ProofOfPossession not set")

	// ErrTypeNotSet indicates Type is not set.
	ErrTypeNotSet = errors.New("key type not set")
	// ErrKeyVersionNotSet indicates KeyVersion is not set.
	ErrKeyVersionNotSet = errors.New("key version not set")
)

const (
	// RegularUpdate is a TRC update where the VotingQuorum parameter is not
	// changed, and in the PrimaryASes section, only the issuing and online keys
	// can change. No other parts of the PrimaryASes section may change.
	RegularUpdate UpdateType = "regular"
	// SensitiveUpdate is a TRC update that does not qualify as regular.
	SensitiveUpdate UpdateType = "sensitive"
)

// UpdateType indicates the type of TRC update.
type UpdateType string

// trcAlias is necessary to avoid an infinite recursion when unmarshalling.
type trcAlias TRC

// TRC is the trust root configuration for an ISD.
type TRC struct {
	// ISD is the integer identifier from 1 to 4095.
	ISD addr.ISD `json:"ISD"`
	// Version is the version number of the TRC.
	// The value scrypto.LatestVer is reserved and shall not be used.
	Version scrypto.Version `json:"TRCVersion"`
	// BaseVersion indicates the initial TRC version for this TRC chain.
	// If BaseVersion equals TRCVersion this TRC is a base TRC.
	BaseVersion scrypto.Version `json:"BaseVersion"`
	// Description is an human-readable description of the ISD.
	Description string `json:"Description"`
	// VotingQuorum is the number of signatures the next TRC needs from voting
	// ASes in this TRC for an update to be valid. This is a pointer to check
	// the field is set during parsing.
	VotingQuorumPtr *uint8 `json:"VotingQuorum"`
	// FormatVersion is the TRC format version.
	FormatVersion FormatVersion `json:"FormatVersion"`
	// GracePeriod indicates how long the previous unexpired version of the TRC
	// should still be considered active, i.e., TRCvi is still active until the
	// following time has passed (or TRCvi+2 has been announced):
	//  TRC(i+1).Validity.NotBefore + TRC(i+1).GracePeriod
	GracePeriod *Period `json:"GracePeriod"`
	// TrustResetAllowed indicates whether a trust reset is allowed for this ISD.
	TrustResetAllowedPtr *bool `json:"TrustResetAllowed"`
	// Validity indicates the validity period of the TRC.
	Validity *scrypto.Validity `json:"Validity"`
	// PrimaryASes contains all primary ASes in the ISD.
	PrimaryASes PrimaryASes `json:"PrimaryASes"`
	// Votes maps voting ASes to their cast vote.
	Votes map[addr.AS]Vote `json:"Votes"`
	// ProofOfPossession maps ASes to their key types they need to show proof of possession.
	ProofOfPossession map[addr.AS][]KeyType `json:"ProofOfPossession"`
}

// VotingQuorum returns the voting quorum. It provides a convenience wrapper
// around VotingQuorumPtr.
func (t *TRC) VotingQuorum() int {
	return int(*t.VotingQuorumPtr)
}

// TrustResetAllowed returns whether trust resets are allowed according to the
// TRC. It provides a convenience wrapper around TrustResetAllowedPtr.
func (t *TRC) TrustResetAllowed() bool {
	return *t.TrustResetAllowedPtr
}

// Base returns true if this TRC is a base TRC.
func (t *TRC) Base() bool {
	return t.BaseVersion == t.Version
}

// ValidateInvariant ensures that the TRC invariant holds.
func (t *TRC) ValidateInvariant() error {
	if !t.Validity.NotAfter.After(t.Validity.NotBefore.Time) {
		return common.NewBasicError(InvalidValidityPeriod, nil,
			"NotBefore", t.Validity.NotBefore, "NotAfter", t.Validity.NotAfter)
	}
	if t.VotingQuorum() <= 0 {
		return ErrZeroVotingQuorum
	}
	c := t.PrimaryASes.Count(Voting)
	if t.VotingQuorum() > c {
		return common.NewBasicError(VotingQuorumTooLarge, nil, "max", c, "actual", t.VotingQuorum)
	}
	if t.PrimaryASes.Count(Issuing) <= 0 {
		return ErrNoIssuingAS
	}
	if err := t.PrimaryASes.ValidateInvariant(); err != nil {
		return err
	}
	if t.GracePeriod.Duration == 0 && !t.Base() {
		return ErrUpdateWithZeroGracePeriod
	}
	if t.GracePeriod.Duration != 0 && t.Base() {
		return ErrBaseWithNonZeroGracePeriod
	}
	if t.Base() {
		return t.baseInvariant()
	}
	return nil
}

func (t *TRC) baseInvariant() error {
	if len(t.Votes) > 0 {
		return ErrBaseWithVotes
	}
	return t.allProofOfPossesion()
}

func (t *TRC) allProofOfPossesion() error {
	pv := popValidator{
		TRC:        t,
		KeyChanges: newKeyChanges(),
	}
	for as, primary := range t.PrimaryASes {
		for keyType, meta := range primary.Keys {
			pv.KeyChanges.Fresh[keyType][as] = meta
		}
	}
	return pv.checkProofOfPossession()
}

// UnmarshalJSON checks that all fields are set.
func (t *TRC) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode((*trcAlias)(t)); err != nil {
		return err
	}
	return t.checkAllSet()
}

func (t *TRC) checkAllSet() error {
	switch {
	case t.ISD == 0:
		return ErrISDNotSet
	case t.Version == 0:
		return ErrVersionNotSet
	case t.BaseVersion == 0:
		return ErrBaseVersionNotSet
	case t.Description == "":
		return ErrDescriptionNotSet
	case t.VotingQuorumPtr == nil:
		return ErrVotingQuorumNotSet
	case t.FormatVersion == 0:
		return ErrFormatVersionNotSet
	case t.GracePeriod == nil:
		return ErrGracePeriodNotSet
	case t.TrustResetAllowedPtr == nil:
		return ErrTrustResetAllowedNotSet
	case t.Validity == nil:
		return ErrValidityNotSet
	case t.PrimaryASes == nil:
		return ErrPrimaryASesNotSet
	case t.Votes == nil:
		return ErrVotesNotSet
	case t.ProofOfPossession == nil:
		return ErrProofOfPossessionNotSet
	}
	return nil
}

// Vote identifies the expected vote.
type Vote struct {
	// Type is the type of key that is used to issue the signature.
	Type KeyType `json:"Type"`
	// KeyVersion is the key version of the key that is used to issue the signautre.
	KeyVersion scrypto.KeyVersion `json:"KeyVersion"`
}

// UnmarshalJSON checks that all fields are set.
func (v *Vote) UnmarshalJSON(b []byte) error {
	var alias voteAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*v = Vote{
		Type:       *alias.Type,
		KeyVersion: *alias.KeyVersion,
	}
	return nil
}

type voteAlias struct {
	Type       *KeyType            `json:"Type"`
	KeyVersion *scrypto.KeyVersion `json:"KeyVersion"`
}

func (v *voteAlias) checkAllSet() error {
	switch {
	case v.Type == nil:
		return ErrTypeNotSet
	case v.KeyVersion == nil:
		return ErrKeyVersionNotSet
	}
	return nil
}

// FormatVersion indicates the TRC format version. Currently, only format
// version 1 is supported.
type FormatVersion uint8

// UnmarshalJSON checks that the FormatVersion is supported.
func (v *FormatVersion) UnmarshalJSON(b []byte) error {
	parsed, err := strconv.ParseUint(string(b), 10, 8)
	if err != nil {
		return err
	}
	if parsed != 1 {
		return common.NewBasicError(UnsupportedFormat, nil, "fmt", parsed)
	}
	*v = FormatVersion(parsed)
	return nil
}

// Period indicates a time duration.
type Period struct {
	time.Duration
}

// UnmarshalJSON parses seconds expressed as a uint32.
func (t *Period) UnmarshalJSON(b []byte) error {
	seconds, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil {
		return err
	}
	t.Duration = time.Duration(seconds) * time.Second
	return nil
}

// MarshalJSON packs the duration as seconds expressed in a uint32.
func (t Period) MarshalJSON() ([]byte, error) {
	seconds := uint32(t.Duration / time.Second)
	return json.Marshal(seconds)
}
