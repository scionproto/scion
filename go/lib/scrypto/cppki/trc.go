// Copyright 2020 Anapaya Systems
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

package cppki

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrInvalidTRCVersion indicates an invalid TRC version.
	ErrInvalidTRCVersion = serrors.New("invalid TRC version")
	// ErrInvalidID indicates an invalid TRC ID.
	ErrInvalidID = serrors.New("invalid ID")
	// ErrGracePeriodNonZero indicates the grace period is non-zero in a
	// non-base TRC.
	ErrGracePeriodNonZero = serrors.New("grace period non-zero")
	// ErrVotesOnBaseTRC indicates that there are votes on a base TRC.
	ErrVotesOnBaseTRC = serrors.New("non-empty votes on base TRC")
	// ErrInvalidQuorumSize indicates the quorum size is outside of the [1,255]
	// range.
	ErrInvalidQuorumSize = serrors.New("invalid quorum size")
	// ErrNoASes indicates the ASes sequence is empty in the TRC.
	ErrNoASes = serrors.New("no ASes")
	// ErrWildcardAS indicates a wildcard AS.
	ErrWildcardAS = serrors.New("wildcard AS")
	// ErrDuplicateAS indicates an AS is duplicated in the sequence.
	ErrDuplicateAS = serrors.New("duplicate AS")
	// ErrUnclassifiedCertificate indicates a certificate could not be
	// classified as neither sensitive voting, regular voting nor root.
	ErrUnclassifiedCertificate = serrors.New("unclassified certificate")
	// ErrNotEnoughVoters indicates that the number of voters is smaller than
	// the voting quorum.
	ErrNotEnoughVoters = serrors.New("not enough voters")
	// ErrCertForOtherISD indicates a certificate that is for another ISD.
	ErrCertForOtherISD = serrors.New("certificate for other ISD")
	// ErrDuplicate indicates a duplicate certificate in the TRC.
	ErrDuplicate = serrors.New("duplicate certificate")
	// ErrTRCValidityNotCovered indicates that the TRC validity period is not
	// covered by a certificate.
	ErrTRCValidityNotCovered = serrors.New("TRC validity not covered by certificate")
)

// UpdateType indicates the type of update.
type UpdateType int

// Update types.
const (
	unknownUpdate UpdateType = iota
	SensitiveUpdate
	RegularUpdate
)

func (u UpdateType) String() string {
	switch u {
	case SensitiveUpdate:
		return "sensitive"
	case RegularUpdate:
		return "regular"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", u)
	}
}

// TRC is the TRC payload.
type TRC struct {
	// Raw contains the complete ASN.1 DER content.
	Raw []byte
	// Version is the one-indexed format version. This means, that the
	// serialized version 0 is represented as 1. This emulates behavior of the
	// go standard library for the x509 certificate version:
	// https://golang.org/pkg/crypto/x509/#Certificate
	Version           int
	ID                TRCID
	Validity          Validity
	GracePeriod       time.Duration
	NoTrustReset      bool
	Votes             []int
	Quorum            int
	CoreASes          []addr.AS
	AuthoritativeASes []addr.AS
	Description       string
	Certificates      []*x509.Certificate
}

// Validate validates the payload. This does not include validation of TRC
// update restrictions.
func (trc *TRC) Validate() error {
	if trc.Version != 1 {
		return serrors.WithCtx(ErrInvalidTRCVersion, "expected", 1, "actual", trc.Version)
	}
	if err := trc.ID.Validate(); err != nil {
		return serrors.Wrap(ErrInvalidID, err)
	}
	if err := trc.Validity.Validate(); err != nil {
		return err
	}
	if trc.ID.IsBase() && trc.GracePeriod != 0 {
		return serrors.WithCtx(ErrGracePeriodNonZero, "grace_period", trc.GracePeriod)
	}
	if trc.ID.IsBase() && len(trc.Votes) != 0 {
		return serrors.WithCtx(ErrVotesOnBaseTRC, "votes", len(trc.Votes))
	}
	if trc.Quorum == 0 || trc.Quorum > 255 {
		return serrors.WithCtx(ErrInvalidQuorumSize, "voting_quorum", trc.Quorum)
	}
	if err := validateASSequence(trc.CoreASes); err != nil {
		return serrors.WithCtx(err, "field", "coreASes")
	}
	if err := validateASSequence(trc.AuthoritativeASes); err != nil {
		return serrors.WithCtx(err, "field", "authoritativeASes")
	}
	cl, err := classifyCerts(trc.Certificates)
	if err != nil {
		return err
	}
	if len(cl.Sensitive) < trc.Quorum {
		return serrors.WithCtx(ErrNotEnoughVoters,
			"sensitive_voters", len(cl.Sensitive), "quorum", trc.Quorum)
	}
	if len(cl.Regular) < trc.Quorum {
		return serrors.WithCtx(ErrNotEnoughVoters,
			"regular_voters", len(cl.Regular), "quorum", trc.Quorum)
	}
	// Check all certificates for this ISD.
	for i, cert := range trc.Certificates {
		ia, err := findIA(cert.Subject)
		if err != nil {
			return err
		}
		if ia != nil && ia.I != trc.ID.ISD {
			return serrors.WithCtx(ErrCertForOtherISD, "subject", cert.Subject, "index", i)
		}
		if !(Validity{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}).Covers(trc.Validity) {
			return serrors.WithCtx(ErrTRCValidityNotCovered, "subject", cert.Subject, "index", i)
		}
	}
	// Check that issuer-SN pair is unique.
	for i, a := range trc.Certificates {
		for j := i + 1; j < len(trc.Certificates); j++ {
			b := trc.Certificates[j]
			if a.SerialNumber.Cmp(b.SerialNumber) != 0 {
				continue
			}
			if equalName(a.Issuer, b.Issuer) {
				return serrors.WithCtx(ErrDuplicate, "indices", []int{i, j})
			}
		}
	}
	// Check that subjects are unique in the respective categories.
	for _, m := range []map[int]*x509.Certificate{cl.Sensitive, cl.Regular, cl.Root} {
		if err := uniqueSubject(m); err != nil {
			return err
		}
	}
	return nil
}

// RootCerts returns all CP root certificates in this TRC.
func (trc *TRC) RootCerts() ([]*x509.Certificate, error) {
	c, err := classifyCerts(trc.Certificates)
	if err != nil {
		return nil, err
	}
	roots := make([]*x509.Certificate, 0, len(c.Root))
	for _, r := range c.Root {
		roots = append(roots, r)
	}
	return roots, nil
}

// RootPool extracts all CP root certificates in this TRC as a CertPool.
func (trc *TRC) RootPool() (*x509.CertPool, error) {
	roots, err := trc.RootCerts()
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, serrors.New("no root certificate")
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	return rootPool, nil
}

// InGracePeriod indicates if the provided time is in the grace period of this
// TRC.
func (trc *TRC) InGracePeriod(now time.Time) bool {
	if trc.ID.IsBase() {
		return false
	}
	return Validity{
		NotBefore: trc.Validity.NotBefore,
		NotAfter:  trc.Validity.NotBefore.Add(trc.GracePeriod),
	}.Contains(now)
}

// GracePeriodEnd indicates the end of the grace period implied by this TRC.
// In case of a base TRC, the zero value is returned.
func (trc *TRC) GracePeriodEnd() time.Time {
	if trc.ID.IsBase() {
		return time.Time{}
	}
	return trc.Validity.NotBefore.Add(trc.GracePeriod)
}

// IsZero reports whether this TRC represents the zero value.
func (trc *TRC) IsZero() bool {
	return len(trc.Raw) == 0 &&
		trc.Version == 0 &&
		trc.ID == TRCID{} &&
		trc.Validity == Validity{} &&
		trc.GracePeriod == 0 &&
		trc.NoTrustReset == false &&
		len(trc.Votes) == 0 &&
		trc.Quorum == 0 &&
		len(trc.CoreASes) == 0 &&
		len(trc.AuthoritativeASes) == 0 &&
		trc.Description == "" &&
		len(trc.Certificates) == 0
}

// ValidateUpdate validates if this TRC is a valid successor TRC to the provided
// predecessor.
func (trc *TRC) ValidateUpdate(predecessor *TRC) (Update, error) {
	if err := trc.Validate(); err != nil {
		return Update{}, err
	}
	if predecessor == nil {
		return Update{}, serrors.New("predecessor must not be nil for TRC update")
	}
	if predecessor.ID.ISD != trc.ID.ISD {
		return Update{}, serrors.New("ISD mismatch",
			"predecessor", predecessor.ID.ISD, "this", trc.ID.ISD)
	}
	if predecessor.ID.Base != trc.ID.Base {
		return Update{}, serrors.New("base number mismatch",
			"predecessor", predecessor.ID.Base, "this", trc.ID.Base)
	}
	if predecessor.ID.Serial+1 != trc.ID.Serial {
		return Update{}, serrors.New("serial number not an increment",
			"predecessor", predecessor.ID.Serial, "this", trc.ID.Serial)
	}
	if predecessor.NoTrustReset != trc.NoTrustReset {
		return Update{}, serrors.New("noTrustReset changed",
			"predecessor", predecessor.NoTrustReset, "this", trc.NoTrustReset)
	}
	if len(trc.Votes) < predecessor.Quorum {
		return Update{}, serrors.New("number of votes smaller than quorum",
			"quorum", predecessor.Quorum, "votes", len(trc.Votes))
	}
	predCerts, err := classifyCerts(predecessor.Certificates)
	if err != nil {
		return Update{}, serrors.WrapStr("classifying certificates in predecessor", err)
	}
	thisCerts, err := classifyCerts(trc.Certificates)
	if err != nil {
		return Update{}, serrors.WrapStr("classifying certificates", err)
	}

	// All votes in a regular update must be cast with a regular voting
	// certificate from the predecessor TRC. Otherwise, this is a sensitive
	// update.
	if _, ok := predCerts.Regular[trc.Votes[0]]; !ok {
		votes, err := trc.validateSensitive(predCerts)
		if err != nil {
			return Update{}, serrors.WrapStr("validating sensitive update", err)
		}
		return Update{
			Type:      SensitiveUpdate,
			NewVoters: detectNewVoters(predCerts, thisCerts),
			Votes:     votes,
		}, nil
	}
	votes, acks, err := trc.validateRegular(predecessor, predCerts, thisCerts)
	if err != nil {
		return Update{}, serrors.WrapStr("validating regular update", err)
	}
	return Update{
		Type:                RegularUpdate,
		NewVoters:           detectNewVoters(predCerts, thisCerts),
		Votes:               votes,
		RootAcknowledgments: acks,
	}, nil
}

func (trc *TRC) validateSensitive(predCerts classified) ([]*x509.Certificate, error) {
	voters := make([]*x509.Certificate, 0, len(trc.Votes))
	for _, predIdx := range trc.Votes {
		cert, ok := predCerts.Sensitive[predIdx]
		if !ok {
			return nil, serrors.New("vote by non-sensitive voter", "predecessor_index", predIdx)
		}
		voters = append(voters, cert)
	}
	return voters, nil
}

func (trc *TRC) validateRegular(predecessor *TRC, predCerts, thisCerts classified) (
	[]*x509.Certificate, []*x509.Certificate, error) {

	if p, n := predecessor.Quorum, trc.Quorum; p != n {
		return nil, nil, serrors.New("quorum changed", "predecessor", p, "this", n)
	}
	if err := equalASes(predecessor.CoreASes, trc.CoreASes); err != nil {
		return nil, nil, serrors.WrapStr("core ASes changed", err)
	}
	if err := equalASes(predecessor.AuthoritativeASes, trc.AuthoritativeASes); err != nil {
		return nil, nil, serrors.WrapStr("authoritative ASes changed", err)
	}

	// Check all sensitive voting certificates are unchanged.
	if p, n := len(predCerts.Sensitive), len(thisCerts.Sensitive); p != n {
		return nil, nil, serrors.New("number of sensitive voting certificates changed",
			"predecessor", p, "this", n)
	}
	for index, cert := range thisCerts.Sensitive {
		predIdx, unchanged := predCerts.Sensitive.find(cert)
		if predIdx < 0 {
			return nil, nil, serrors.New("modified sensitive voting certificate",
				"index", index, "name", cert.Subject.CommonName)
		}
		if !unchanged {
			return nil, nil, serrors.New("new sensitive voting certificate",
				"index", index, "name", cert.Subject.CommonName)
		}
	}

	// Check that there are only changed and not added/removed root certificates.
	if p, n := len(predCerts.Root), len(thisCerts.Root); p != n {
		return nil, nil, serrors.New("number of root certificates changed",
			"predecessor", p, "this", n)
	}
	var rootAcks []*x509.Certificate
	for index, cert := range thisCerts.Root {
		predIdx, unchanged := predCerts.Root.find(cert)
		if predIdx < 0 {
			return nil, nil, serrors.New("new root certificate",
				"index", index, "name", cert.Subject.CommonName)
		}
		if !unchanged {
			rootAcks = append(rootAcks, predCerts.Root[predIdx])
		}
	}

	// Check that there are only changed and not added/removed regular voting
	// certificates. Furthermore, check that all changed certificates cast a
	// vote.
	if p, n := len(predCerts.Regular), len(thisCerts.Regular); p != n {
		return nil, nil, serrors.New("number of regular voting certificates changed",
			"predecessor", p, "this", n)
	}
	expectedVotes := map[int]struct{}{}
	for index, cert := range thisCerts.Regular {
		predIdx, unchanged := predCerts.Regular.find(cert)
		if predIdx < 0 {
			return nil, nil, serrors.New("new regular voting certificate", "index", index,
				"name", cert.Subject.CommonName)
		}
		if !unchanged {
			expectedVotes[predIdx] = struct{}{}
		}
	}
	voters := make([]*x509.Certificate, 0, len(trc.Votes))
	for _, predIdx := range trc.Votes {
		cert, ok := predCerts.Regular[predIdx]
		if !ok {
			return nil, nil, serrors.New("vote by non-regular voter", "predecessor_index", predIdx)
		}
		voters = append(voters, cert)
		delete(expectedVotes, predIdx)
	}
	if len(expectedVotes) != 0 {
		names := make([]string, 0, len(expectedVotes))
		for predIdx := range expectedVotes {
			names = append(names, predCerts.Regular[predIdx].Subject.CommonName)
		}
		sort.Strings(names)
		return nil, nil, serrors.New("missing votes by modified regular voting certificates",
			"missing", names)
	}
	return voters, rootAcks, nil
}

// Update holds metadata about a TRC update.
type Update struct {
	Type UpdateType
	// NewVoters lists the sensitive and regular voting certificates that were
	// not part of the previous TRC. Either, due to changing an existing
	// voter, or, due to adding a new voter to the set.
	NewVoters []*x509.Certificate
	// Votes lists the sensitive or regular voting certificates that cast a vote
	// in the update.
	Votes []*x509.Certificate
	// RootAcknowledgments lists all the root certificates that need to
	// acknowledge a regular TRC update that changes their root certificate.
	RootAcknowledgments []*x509.Certificate
}

type classified struct {
	Sensitive certMap
	Regular   certMap
	Root      certMap
}

func classifyCerts(certs []*x509.Certificate) (classified, error) {
	c := classified{
		Sensitive: make(certMap),
		Regular:   make(certMap),
		Root:      make(certMap),
	}
	for i, cert := range certs {
		ct, err := ValidateCert(cert)
		if err != nil {
			return classified{}, serrors.WithCtx(ErrUnclassifiedCertificate, "index", i)
		}
		switch ct {
		case Sensitive:
			c.Sensitive[i] = cert
		case Regular:
			c.Regular[i] = cert
		case Root:
			c.Root[i] = cert
		default:
			return classified{}, serrors.WithCtx(ErrInvalidCertType, "cert_type", ct, "index", i)
		}
	}
	return c, nil
}

type certMap map[int]*x509.Certificate

// find searches for a certificate with the same distinguished name. The second
// return value is true, if there exists a certificate with the exact same
// content.
func (m certMap) find(cert *x509.Certificate) (int, bool) {
	for i, pred := range m {
		if !equalName(pred.Subject, cert.Subject) {
			continue
		}
		return i, bytes.Equal(pred.Raw, cert.Raw)
	}
	return -1, false

}

func detectNewVoters(predCerts, nextCerts classified) []*x509.Certificate {
	var newCerts []*x509.Certificate
	for _, cert := range nextCerts.Sensitive {
		if _, unchanged := predCerts.Sensitive.find(cert); !unchanged {
			newCerts = append(newCerts, cert)
		}
	}
	for _, cert := range nextCerts.Regular {
		if _, unchanged := predCerts.Regular.find(cert); !unchanged {
			newCerts = append(newCerts, cert)
		}
	}
	return newCerts
}

func equalASes(pred, next []addr.AS) error {
	if len(pred) != len(next) {
		return serrors.New("unequal sequence length", "predecessor", len(pred), "next", len(next))
	}
	for i, p := range pred {
		if n := next[i]; n != p {
			return serrors.New("different AS number", "index", i, "predecessor", p, "next", n)
		}
	}
	return nil
}

func validateASSequence(ases []addr.AS) error {
	if len(ases) == 0 {
		return ErrNoASes
	}
	for i, as := range ases {
		if as == 0 {
			return ErrWildcardAS
		}
		for j := i + 1; j < len(ases); j++ {
			if as == ases[j] {
				return serrors.WithCtx(ErrDuplicateAS, "as", as)
			}
		}
	}
	return nil
}

func uniqueSubject(certs map[int]*x509.Certificate) error {
	// idx maps from position in cert list l to the index in the TRC payload.
	l, idx := make([]*x509.Certificate, 0, len(certs)), make([]int, 0, len(certs))
	for i, cert := range certs {
		l, idx = append(l, cert), append(idx, i)
	}
	for i, a := range l {
		for j := i + 1; j < len(l); j++ {
			b := l[j]
			if equalName(a.Subject, b.Subject) {
				return serrors.WithCtx(ErrDuplicate, "indices", []int{idx[i], idx[j]})
			}
		}
	}
	return nil
}
