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
	"errors"
	"sort"

	"github.com/scionproto/scion/go/lib/scrypto/cms/protocol"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SignedTRC represents the parsed signed TRC.
type SignedTRC struct {
	Raw         []byte
	TRC         TRC
	SignerInfos []protocol.SignerInfo
}

// SignedTRCs represents a list of parsed signed TRC.
type SignedTRCs []SignedTRC

// DecodeSignedTRC parses the signed TRC.
func DecodeSignedTRC(raw []byte) (SignedTRC, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return SignedTRC{}, serrors.WrapStr("error parsing ContentInfo", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return SignedTRC{}, serrors.WrapStr("error parsing SignedData", err)
	}
	if sd.Version != 1 {
		return SignedTRC{}, serrors.New("unsupported SignedData version", "version", 1)
	}
	if !sd.EncapContentInfo.IsTypeData() {
		return SignedTRC{}, serrors.WrapStr("unsupported EncapContentInfo type", err,
			"type", sd.EncapContentInfo.EContentType)
	}
	praw, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return SignedTRC{}, serrors.WrapStr("error reading raw payload", err)
	}
	trc, err := DecodeTRC(praw)
	if err != nil {
		return SignedTRC{}, serrors.WrapStr("error parsing TRC payload", err)
	}
	return SignedTRC{Raw: raw, TRC: trc, SignerInfos: sd.SignerInfos}, nil
}

// Encode encodes the signed TRC as CMS signed message in ASN.1 DER format.
func (s *SignedTRC) Encode() ([]byte, error) {
	payload, err := s.TRC.Encode()
	if err != nil {
		return nil, err
	}
	eci, err := protocol.NewDataEncapsulatedContentInfo(payload)
	if err != nil {
		return nil, err
	}
	sd := protocol.SignedData{
		Version:          1,
		EncapContentInfo: eci,
		SignerInfos:      s.SignerInfos,
	}
	for _, info := range s.SignerInfos {
		sd.AddDigestAlgorithm(info.DigestAlgorithm)
	}
	return sd.ContentInfoDER()
}

// Verify verifies the signatures on a signed TRC. In case of a base TRC, the
// predecessor must be nil. In case of a non-base TRC, the predecessor must not
// be nil.
//
// Verifying base TRC: When verifying the base TRC, it is checked that the TRC
// payload is valid, and that all voting certificates have signed the TRC.
//
// Verifying non-base TRC: When verifying a non-base TRC, it is checked that the
// TRC payload is valid. Based on the predecessor TRC, the update is classified
// as regular update, or sensitive update. There are different sets of rules
// that need to be checked based on the update type.
func (s *SignedTRC) Verify(predecessor *TRC) error {
	if !s.TRC.ID.IsBase() {
		return s.verifyUpdate(predecessor)
	}
	if predecessor != nil {
		return serrors.New("predecessor must be nil for base TRC")
	}
	return s.verifyBase()
}

func (s *SignedTRC) verifyBase() error {
	if err := s.TRC.Validate(); err != nil {
		return err
	}
	certs, err := classifyCerts(s.TRC.Certificates)
	if err != nil {
		return err
	}
	if err := s.verifyAll(detectNewVoters(classified{}, certs)); err != nil {
		return serrors.WrapStr("verifying signatures for new voters", err)

	}
	return nil
}

func (s *SignedTRC) verifyUpdate(predecessor *TRC) error {
	update, err := s.TRC.ValidateUpdate(predecessor)
	if err != nil {
		return err
	}
	if err := s.verifyAll(update.NewVoters); err != nil {
		return serrors.WrapStr("verifying signatures by new voters", err, "type", update.Type)
	}
	if err := s.verifyAll(update.RootAcknowledgments); err != nil {
		return serrors.WrapStr("verifying root acknowledgments", err, "type", update.Type)
	}
	if err := s.verifyAll(update.Votes); err != nil {
		return serrors.WrapStr("verifying votes", err, "type", update.Type)
	}
	return nil
}

// verifyAll searches the signer info for all certificates and verifies them.
// If a certificate does not have a corresponding signer info, it is an error.
func (s *SignedTRC) verifyAll(certs []*x509.Certificate) error {
	seen := make(map[*x509.Certificate]struct{}, len(certs))
	for _, si := range s.SignerInfos {
		cert, err := si.FindCertificate(certs)
		if errors.Is(err, protocol.ErrNoCertificate) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.verifySignerInfo(cert, si); err != nil {
			return err
		}
		seen[cert] = struct{}{}
	}
	if len(seen) != len(certs) {
		names := make([]string, 0, len(certs)-len(seen))
		for _, cert := range certs {
			if _, ok := seen[cert]; !ok {
				names = append(names, cert.Subject.CommonName)
			}
		}
		sort.Strings(names)
		return serrors.New("missing signatures", "missing", names)
	}
	return nil
}

// IsZero reports whether this TRC is empty.
func (s *SignedTRC) IsZero() bool {
	return len(s.Raw) == 0 &&
		s.TRC.IsZero() &&
		len(s.SignerInfos) == 0
}

// verifySignerInfo verifies the singer information. The provided certificate is
// trusted and authenticates the public key for the private key that signed the
// signer info.
func (s *SignedTRC) verifySignerInfo(cert *x509.Certificate, si protocol.SignerInfo) error {
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	attrDigest, err := si.GetMessageDigestAttribute()
	if err != nil {
		return err
	}
	actualDigest := hash.New()
	actualDigest.Write(s.TRC.Raw)
	if !bytes.Equal(attrDigest, actualDigest.Sum(nil)) {
		return serrors.New("message digest does not match")
	}
	sigInput, err := si.SignedAttrs.MarshaledForVerifying()
	if err != nil {
		return err
	}
	algo := si.X509SignatureAlgorithm()
	if err := cert.CheckSignature(algo, sigInput, si.Signature); err != nil {
		return err
	}
	return nil
}

// Len returns the number of SignedTRCs.
func (t SignedTRCs) Len() int {
	return len(t)
}

// Less returns if SignedTRC[i] is less than SignedTRC[j] based on isd > base > serial
func (t SignedTRCs) Less(i, j int) bool {
	isdA, isdB := t[i].TRC.ID.ISD, t[j].TRC.ID.ISD
	baseA, baseB := t[i].TRC.ID.Base, t[j].TRC.ID.Base
	serialA, serialB := t[i].TRC.ID.Serial, t[j].TRC.ID.Serial
	switch {
	case isdA != isdB:
		return isdA < isdB
	case baseA != baseB:
		return baseA < baseB
	case serialA != serialB:
		return serialA < serialB
	default:
		return bytes.Compare(t[i].TRC.Raw, t[j].TRC.Raw) == -1
	}
}

// Swap swaps the two elements of SignedTRCs
func (t SignedTRCs) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}
