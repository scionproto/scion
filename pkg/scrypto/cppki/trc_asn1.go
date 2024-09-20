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
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
)

// asn1ID is used to encode and decode the TRC ID.
type asn1ID struct {
	ISD    int64 `asn1:"iSD"`
	Serial int64 `asn1:"serialNumber"`
	Base   int64 `asn1:"baseNumber"`
}

type asn1Validity struct {
	NotBefore time.Time `asn1:"notBefore,generalized"`
	NotAfter  time.Time `asn1:"notAfter,generalized"`
}

// asn1TRCPayload is used to encode and decode the TRC payload.
type asn1TRCPayload struct {
	Version           int64           `asn1:"version"`
	ID                asn1ID          `asn1:"iD"`
	Validity          asn1Validity    `asn1:"validity"`
	GracePeriod       int64           `asn1:"gracePeriod"`
	NoTrustReset      bool            `asn1:"noTrustReset"`
	Votes             []int64         `asn1:"votes"`
	Quorum            int64           `asn1:"votingQuorum"`
	CoreASes          []string        `asn1:"coreASes"`
	AuthoritativeASes []string        `as1n:"authoritativeASes"`
	Description       string          `asn1:"description,utf8"`
	Certificates      []asn1.RawValue `asn1:"certificates"`
}

// DecodeTRC parses the payload form ASN.1 DER format. The payload keeps a
// reference to the input data.
func DecodeTRC(raw []byte) (TRC, error) {
	var a asn1TRCPayload
	rest, err := asn1.Unmarshal(raw, &a)
	if err != nil {
		return TRC{}, err
	}
	if len(rest) > 0 {
		return TRC{}, serrors.New("trailing data")
	}
	if a.Version != 0 {
		return TRC{}, serrors.New("unsupported version", "version", a.Version)
	}
	certs, err := decodeCertificates(a.Certificates)
	if err != nil {
		return TRC{}, serrors.Wrap("error parsing certificates", err)
	}
	cores, err := decodeASes(a.CoreASes)
	if err != nil {
		return TRC{}, serrors.Wrap("error parsing core ASes", err)
	}
	auths, err := decodeASes(a.AuthoritativeASes)
	if err != nil {
		return TRC{}, serrors.Wrap("error parsing authoritative ASes", err)
	}
	id, err := decodeID(a.ID)
	if err != nil {
		return TRC{}, serrors.Wrap("error decoding ID", err)
	}
	validity, err := decodeValidity(a.Validity)
	if err != nil {
		return TRC{}, serrors.Wrap("invalid validity", err)
	}
	pld := TRC{
		Raw:               raw,
		Version:           int(a.Version) + 1,
		ID:                id,
		Validity:          validity,
		GracePeriod:       time.Duration(a.GracePeriod) * time.Second,
		NoTrustReset:      a.NoTrustReset,
		Votes:             decodeVotes(a.Votes),
		Quorum:            int(a.Quorum),
		CoreASes:          cores,
		AuthoritativeASes: auths,
		Description:       a.Description,
		Certificates:      certs,
	}
	if err := pld.Validate(); err != nil {
		return TRC{}, err
	}
	return pld, nil
}

// Encode encodes the payload in ASN.1 DER format.
func (pld *TRC) Encode() ([]byte, error) {
	if err := pld.Validate(); err != nil {
		return nil, err
	}
	certs, err := encodeCertificates(pld.Certificates)
	if err != nil {
		return nil, err
	}
	cores, err := encodeASes(pld.CoreASes)
	if err != nil {
		return nil, err
	}
	auths, err := encodeASes(pld.AuthoritativeASes)
	if err != nil {
		return nil, err
	}
	a := asn1TRCPayload{
		Version: int64(pld.Version - 1),
		ID: asn1ID{
			ISD:    int64(pld.ID.ISD),
			Serial: int64(pld.ID.Serial),
			Base:   int64(pld.ID.Base),
		},
		Validity: asn1Validity{
			NotBefore: pld.Validity.NotBefore.UTC().Truncate(time.Second),
			NotAfter:  pld.Validity.NotAfter.UTC().Truncate(time.Second),
		},
		GracePeriod:       int64(pld.GracePeriod / time.Second),
		NoTrustReset:      pld.NoTrustReset,
		Votes:             encodeVotes(pld.Votes),
		Quorum:            int64(pld.Quorum),
		CoreASes:          cores,
		AuthoritativeASes: auths,
		Description:       pld.Description,
		Certificates:      certs,
	}
	return asn1.Marshal(a)
}

func decodeID(raw asn1ID) (TRCID, error) {
	switch {
	case raw.ISD > int64(addr.MaxISD) || raw.ISD == 0:
		return TRCID{}, serrors.New("invalid ISD", "value", raw.ISD)
	case raw.Base == int64(scrypto.LatestVer):
		return TRCID{}, serrors.New("invalid base number")
	case raw.Serial == int64(scrypto.LatestVer):
		return TRCID{}, serrors.New("invalid serial number")
	case raw.Serial < raw.Base:
		return TRCID{}, serrors.New("base greater than serial",
			"base", raw.Base, "serial", raw.Serial)
	}
	id := TRCID{
		ISD:    addr.ISD(raw.ISD),
		Base:   scrypto.Version(raw.Base),
		Serial: scrypto.Version(raw.Serial),
	}
	return id, nil
}

func decodeValidity(a asn1Validity) (Validity, error) {
	validity := Validity(a)
	if err := validity.Validate(); err != nil {
		return Validity{}, err
	}
	return validity, nil
}

func decodeCertificates(rawCerts []asn1.RawValue) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, serrors.Wrap("error decoding certificate", err, "index", i)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func encodeCertificates(certs []*x509.Certificate) ([]asn1.RawValue, error) {
	encoded := make([]asn1.RawValue, 0, len(certs))
	for _, cert := range certs {
		var rv asn1.RawValue
		if _, err := asn1.Unmarshal(cert.Raw, &rv); err != nil {
			return nil, err
		}
		encoded = append(encoded, rv)
	}
	return encoded, nil
}

func decodeASes(rawASes []string) ([]addr.AS, error) {
	ases := make([]addr.AS, 0, len(rawASes))
	for _, rawAs := range rawASes {
		as, err := addr.ParseAS(rawAs)
		if err != nil {
			return nil, serrors.Wrap("error parsing AS", err, "input", rawAs)
		}
		if as == 0 {
			return nil, serrors.Wrap("wildcard AS", err)
		}
		ases = append(ases, as)
	}
	return ases, nil
}

func encodeASes(ases []addr.AS) ([]string, error) {
	encoded := make([]string, 0, len(ases))
	for _, as := range ases {
		if as == 0 || as > addr.MaxAS {
			return nil, serrors.New("invalid AS number")
		}
		encoded = append(encoded, as.String())
	}
	return encoded, nil
}

func decodeVotes(orig []int64) []int {
	votes := make([]int, 0, len(orig))
	for _, vote := range orig {
		votes = append(votes, int(vote))
	}
	return votes
}

func encodeVotes(orig []int) []int64 {
	votes := make([]int64, 0, len(orig))
	for _, vote := range orig {
		votes = append(votes, int64(vote))
	}
	return votes
}
