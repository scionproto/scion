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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	// CertVersion is the x509 certificate version number 3.
	CertVersion = 3
)

// ExtKeyUsage oids.
var (
	OIDExtKeyUsageSensitive = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 3, 1}
	OIDExtKeyUsageRegular   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 3, 2}
	OIDExtKeyUsageRoot      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 3, 3}

	OIDExtKeyUsageServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDExtKeyUsageClientAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	OIDExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)

// DistinguishedName oids.
var (
	OIDNameIA = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}
)

// x.509v3 extension oids.
var (
	OIDExtensionSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtensionAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// Valid SCION signatures
var (
	ValidSCIONSignatureAlgs = []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
)

var (
	// ErrInvalidCertType indicates an invalid certificate type.
	ErrInvalidCertType = serrors.New("invalid certificate type")

	errIANotFound = serrors.New("ISD-AS not found")
)

// CertType describes the type of the SCION certificate.
type CertType int

// Valid SCION certificate types
const (
	Invalid CertType = iota
	Sensitive
	Regular
	Root
	CA
	AS
)

func (ct CertType) String() string {
	switch ct {
	case Invalid:
		return "invalid"
	case Sensitive:
		return "sensitive-voting"
	case Regular:
		return "regular-voting"
	case Root:
		return "cp-root"
	case CA:
		return "cp-ca"
	case AS:
		return "cp-as"
	default:
		return "invalid"
	}
}

// ReadPEMCerts reads the PEM file and parses the certificate blocks in it. Only
// PEM files with only CERTIFICATE blocks are allowed.
func ReadPEMCerts(file string) ([]*x509.Certificate, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, serrors.New("empty")
	}
	var certs []*x509.Certificate
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, serrors.New("error extracting PEM block")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, serrors.New("invalid PEM block in bundle",
				"type", block.Type, "headers", block.Headers)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, serrors.WrapStr("error parsing certificate", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// VerifyOptions contains parameters for certificate chain verification.
type VerifyOptions struct {
	TRC         []*TRC
	CurrentTime time.Time // if zero, the current time is used
}

// VerifyChain attempts to verify the certificate chain against every TRC
// included in opts. Success (nil error) is returned if at least one verification
// succeeds. If all verifications fail, an error containing the details of why
// each verification failed is returned.
//
// The certificate chain is verified by building a trust root based on the Root
// Certificates in each TRC, and searching for a valid verification path.
func VerifyChain(certs []*x509.Certificate, opts VerifyOptions) error {
	var errs []error
	for _, trc := range opts.TRC {
		if err := verifyChain(certs, trc, opts.CurrentTime); err != nil {
			errs = append(errs,
				serrors.WrapStr("verifying chain", err,
					"trc_base", trc.ID.Base,
					"trc_serial", trc.ID.Serial,
				),
			)
		} else {
			return nil
		}
	}
	return serrors.New("chain did not verify against any selected TRC", "errors", errs)
}

func verifyChain(certs []*x509.Certificate, trc *TRC, now time.Time) error {
	if err := ValidateChain(certs); err != nil {
		return serrors.WrapStr("chain validation failed", err)
	}
	if trc == nil || trc.IsZero() {
		return serrors.New("TRC required for chain verification")
	}
	intPool := x509.NewCertPool()
	intPool.AddCert(certs[1])
	rootPool, err := trc.RootPool()
	if err != nil {
		return serrors.WrapStr("failed to extract root certs", err, "trc", trc.ID)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{
		Intermediates: intPool,
		Roots:         rootPool,
		KeyUsages:     certs[0].ExtKeyUsage,
		CurrentTime:   now,
	})
	return err
}

// ValidateChain validates that a slice of SCION certificates can be
// a valid chain.
func ValidateChain(certs []*x509.Certificate) error {
	if len(certs) != 2 {
		return serrors.New("chain must contain two certificates")
	}

	first, err := ValidateCert(certs[0])
	if err != nil {
		return serrors.WrapStr("validating first certificate", err)
	}
	if first != AS {
		return serrors.New("first certificate of invalid type", "expected", AS, "actual", first)
	}
	as := certs[0]

	second, err := ValidateCert(certs[1])
	if err != nil {
		return serrors.WrapStr("validating second certificate", err)
	}
	if second != CA {
		return serrors.New("second certificate of invalid type", "expected", CA, "actual", second)
	}
	ca := certs[1]

	asValidPeriod := Validity{NotBefore: as.NotBefore, NotAfter: as.NotAfter}
	caValidPeriod := Validity{NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	if !caValidPeriod.Covers(asValidPeriod) {
		return serrors.New("CA validity period does not cover AS period",
			"CA", caValidPeriod, "as", asValidPeriod)
	}

	return nil
}

// ValidateCert validates the SCION certificate, as part of this it will
// validate that it is of valid type.
func ValidateCert(c *x509.Certificate) (CertType, error) {
	ct, err := classifyCert(c)
	if err != nil {
		return Invalid, err
	}
	switch ct {
	case Sensitive:
		return ct, validateSensitive(c)
	case Regular:
		return ct, validateRegular(c)
	case Root:
		return ct, validateRoot(c)
	case CA:
		return ct, validateCA(c)
	case AS:
		return ct, validateAS(c)
	default:
		return Invalid, serrors.WithCtx(ErrInvalidCertType, "cert_type", ct)
	}
}

// classifyCert determines the type of the SCION certificate.
func classifyCert(c *x509.Certificate) (CertType, error) {
	if c == nil {
		return Invalid, serrors.New("nil cert can't be classified")
	}
	for _, keyUsage := range c.UnknownExtKeyUsage {
		switch {
		case keyUsage.Equal(OIDExtKeyUsageSensitive):
			return Sensitive, nil
		case keyUsage.Equal(OIDExtKeyUsageRegular):
			return Regular, nil
		case keyUsage.Equal(OIDExtKeyUsageRoot):
			return Root, nil
		}
	}
	if c.KeyUsage&x509.KeyUsageCertSign > 0 {
		return CA, nil
	}
	if (c.KeyUsage&x509.KeyUsageDigitalSignature > 0) && (c.KeyUsage&x509.KeyUsageCertSign == 0) {
		return AS, nil
	}
	return Invalid, serrors.New("not able to classify cert")
}

// validateRoot validates that c is a valid control-plane Root certificate.
// This does not check if the current time is covered by the certificate
// validity period.
func validateRoot(c *x509.Certificate) error {
	if c == nil {
		return serrors.New("nil certificate")
	}

	var errs serrors.List

	if err := generalValidation(c); err != nil {
		errs = append(errs, err)
	}
	if err := commonCAValidation(c, 1); err != nil {
		errs = append(errs, err)
	}
	if len(c.AuthorityKeyId) != 0 && !bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId) {
		errs = append(errs, serrors.New("authorityKeyId is set but does not match subjectKeyID"))
	}
	if !containsOID(c.UnknownExtKeyUsage, OIDExtKeyUsageRoot) {
		errs = append(errs, serrors.New("key usage id-kp-root not set"))
	}

	return errs.ToError()
}

// validateCA validates that c is a valid control-plane CA certificate.
// This does not check if the current time is covered by the certificate
// validity period.
func validateCA(c *x509.Certificate) error {
	if c == nil {
		return serrors.New("nil certificate")
	}

	var errs serrors.List

	if err := generalValidation(c); err != nil {
		errs = append(errs, err)
	}

	if err := commonCAValidation(c, 0); err != nil {
		errs = append(errs, err)
	}
	if len(c.AuthorityKeyId) == 0 {
		errs = append(errs, serrors.New("authorityKeyId must be present"))
	}

	return errs.ToError()
}

// validateAS validates that c is a valid AS certificate.
// This does not check if the current time is covered by the certificate
// validity period.
func validateAS(c *x509.Certificate) error {
	if c == nil {
		return serrors.New("nil certificate")
	}

	var errs serrors.List

	if err := generalValidation(c); err != nil {
		errs = append(errs, err)
	}
	if c.KeyUsage&x509.KeyUsageCertSign != 0 {
		errs = append(errs, serrors.New("key usage CertSign is set"))
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		errs = append(errs, serrors.New("key usage DigitalSign not set"))
	}
	if c.BasicConstraintsValid && c.IsCA {
		errs = append(errs, serrors.New("basic constraints extension has CA set"))
	}
	if err := subjectAndIssuerIASet(c); err != nil {
		errs = append(errs, err)
	}
	if len(c.AuthorityKeyId) == 0 {
		errs = append(errs, serrors.New("authorityKeyId must be present"))
	}

	var found bool
	for _, usage := range c.ExtKeyUsage {
		if usage == x509.ExtKeyUsageTimeStamping {
			found = true
			break
		}
	}
	if !found {
		errs = append(errs, serrors.New("id-kp-timeStamping not set"))
	}

	return errs.ToError()
}

// validateSensitive validates that c can be a valid cert for sensitive voting.
func validateSensitive(c *x509.Certificate) error {
	if c == nil {
		return serrors.New("nil certificate")
	}

	var errs serrors.List

	if err := generalValidation(c); err != nil {
		errs = append(errs, err)
	}
	if err := commonVotingValidation(c); err != nil {
		errs = append(errs, err)
	}
	if !containsOID(c.UnknownExtKeyUsage, OIDExtKeyUsageSensitive) {
		errs = append(errs, serrors.New("no id-kp-sensitive"))
	}
	if containsOID(c.UnknownExtKeyUsage, OIDExtKeyUsageRegular) {
		errs = append(errs, serrors.New("both id-kp-sensitive id-kp-regular not allowed"))
	}

	return errs.ToError()
}

// validateRegular validates that c can be a valid cert for regular voting.
func validateRegular(c *x509.Certificate) error {
	if c == nil {
		return serrors.New("nil certificate")
	}

	var errs serrors.List

	if err := generalValidation(c); err != nil {
		errs = append(errs, err)
	}
	if err := commonVotingValidation(c); err != nil {
		errs = append(errs, err)
	}
	if !containsOID(c.UnknownExtKeyUsage, OIDExtKeyUsageRegular) {
		errs = append(errs, serrors.New("no id-kp-regular"))
	}
	if containsOID(c.UnknownExtKeyUsage, OIDExtKeyUsageSensitive) {
		errs = append(errs, serrors.New("both id-kp-sensitive id-kp-regular not allowed"))
	}

	return errs.ToError()
}

func commonCAValidation(c *x509.Certificate, pathLen int) error {
	var errs serrors.List

	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		errs = append(errs, serrors.New("key usage CertSign not set"))
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		errs = append(errs, serrors.New("key usage DigitalSign set"))
	}
	for _, v := range c.ExtKeyUsage {
		if v == x509.ExtKeyUsageClientAuth {
			errs = append(errs, serrors.New("cannot have id-kp-clientAuth as ExtKeyUsage"))
		}
		if v == x509.ExtKeyUsageServerAuth {
			errs = append(errs, serrors.New("cannot have id-kp-serverAuth as ExtKeyUsage"))
		}
	}
	if v, ok := oidInExtensions(OIDExtensionBasicConstraints, c.Extensions); ok && !v.Critical {
		errs = append(errs, serrors.New("basic constraints not critical"))
	}
	if !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != pathLen {
		errs = append(errs, serrors.New("basic constraints not valid"))
	}
	if err := subjectAndIssuerIASet(c); err != nil {
		errs = append(errs, err)
	}

	return errs.ToError()
}

func generalValidation(c *x509.Certificate) error {
	var errs serrors.List

	if c.Version != CertVersion {
		errs = append(errs, serrors.New("invalid cert version",
			"version", c.Version, "expected", CertVersion))
	}
	if c.SerialNumber == nil {
		errs = append(errs, serrors.New("missing serial number"))
	}
	if err := validateSignatureAlg(c); err != nil {
		errs = append(errs, err)
	}
	if len(c.SubjectKeyId) == 0 {
		errs = append(errs, serrors.New("subjectKeyID is missing"))
	}
	if v, ok := oidInExtensions(OIDExtensionSubjectKeyID, c.Extensions); ok && v.Critical == true {
		errs = append(errs, serrors.New("subjectKeyID is marked as critical"))
	}
	if v, ok := oidInExtensions(OIDExtensionAuthorityKeyID,
		c.Extensions); ok && v.Critical == true {

		errs = append(errs, serrors.New("authKeyId is marked as critical"))
	}

	return errs.ToError()
}

func oidInExtensions(oid asn1.ObjectIdentifier,
	extensions []pkix.Extension) (pkix.Extension, bool) {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func validateSignatureAlg(cert *x509.Certificate) error {
	for _, alg := range ValidSCIONSignatureAlgs {
		if cert.SignatureAlgorithm == alg {
			return nil
		}
	}
	return serrors.New("invalid signature algorithm used",
		"cert_alg", cert.SignatureAlgorithm, "valid_algs", ValidSCIONSignatureAlgs)
}

func containsOID(oids []asn1.ObjectIdentifier, o asn1.ObjectIdentifier) bool {
	for _, v := range oids {
		if v.Equal(o) {
			return true
		}
	}
	return false
}

func subjectAndIssuerIASet(c *x509.Certificate) error {
	var errs serrors.List
	if _, err := ExtractIA(c.Issuer); err != nil {
		errs = append(errs, serrors.WrapStr("extracting issuer ISD-AS", err))
	}
	if _, err := ExtractIA(c.Subject); err != nil {
		errs = append(errs, serrors.WrapStr("extracting subject ISD-AS", err))
	}
	return errs.ToError()
}

// ExtractIA extracts the ISD-AS from the distinguished name. If the ISD-AS
// number is not present in the distinguished name, an error is returned.
func ExtractIA(dn pkix.Name) (addr.IA, error) {
	ia, err := findIA(dn)
	if err != nil {
		return addr.IA{}, err
	}
	if ia == nil {
		return addr.IA{}, errIANotFound
	}
	return *ia, nil
}

// findIA extracts the ISD-AS from the distinguished name if it exists. If the
// ISD-AS number is not present in the distinguished name, it returns nil. If
// the ISD-AS number is not parsable, an error is returned.
func findIA(dn pkix.Name) (*addr.IA, error) {
	for _, name := range dn.Names {
		if !name.Type.Equal(OIDNameIA) {
			continue
		}
		rawIA, ok := name.Value.(string)
		if !ok {
			return nil, serrors.New("invalid ISD-AS value (not string)")
		}
		ia, err := addr.IAFromString(rawIA)
		if err != nil {
			return nil, serrors.WrapStr("invalid ISD-AS value", err)
		}
		if ia.IsWildcard() {
			return nil, serrors.New("wildcard ISD-AS not allowed", "isd_as", ia)
		}
		return &ia, nil
	}
	// not found
	return nil, nil
}

func commonVotingValidation(c *x509.Certificate) error {
	var errs serrors.List

	if len(c.AuthorityKeyId) != 0 && !bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId) {
		errs = append(errs, serrors.New("authorityKeyId is set but does not match subjectKeyID"))
	}
	if c.KeyUsage&x509.KeyUsageCertSign != 0 {
		errs = append(errs, serrors.New("key usage CertSign is set"))
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		errs = append(errs, serrors.New("key usage DigitalSignature set"))
	}

	usages := make(map[x509.ExtKeyUsage]struct{})
	for _, usage := range c.ExtKeyUsage {
		usages[usage] = struct{}{}
	}
	if _, ok := usages[x509.ExtKeyUsageTimeStamping]; !ok {
		errs = append(errs, serrors.New("id-kp-timeStamping not set"))
	}
	if _, ok := usages[x509.ExtKeyUsageClientAuth]; ok {
		errs = append(errs, serrors.New("id-kp-clientAuth is set"))
	}
	if _, ok := usages[x509.ExtKeyUsageServerAuth]; ok {
		errs = append(errs, serrors.New("id-kp-serverAuth is set"))
	}
	if c.BasicConstraintsValid && c.IsCA {
		errs = append(errs, serrors.New("basic constraints exists and CA is true"))
	}
	if _, err := findIA(c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if _, err := findIA(c.Subject); err != nil {
		errs = append(errs, err)
	}

	return errs.ToError()
}
