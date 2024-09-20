// Copyright (c) 2016 Grant Ayers
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// File certinfo.go.go is copied from
// https://github.com/smallstep/certinfo/blob/master/certinfo.go as is on tag
// v1.5.2 the following modifications have been done:
//  - remove certificate transparency (func printSCTSignature and
//	  `else if ext.Id.Equal(oidSignedCertificateTimestampList)` block)
//  - change package to certs
//  - make all public functions private
//  - drop dsa support

package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// Time formats used
const (
	validityTimeFormat = "Jan 2 15:04:05 2006 MST"
)

// Extra ASN1 OIDs that we may need to handle
var (
	oidEmailAddress                 = []int{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent              = []int{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                       = []int{0, 9, 2342, 19200300, 100, 1, 1}
	oidExtensionAuthorityInfoAccess = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidNSComment                    = []int{2, 16, 840, 1, 113730, 1, 13}
	oidStepProvisioner              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	oidStepCertificateAuthority     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}
)

// validity allows unmarshaling the certificate validity date range
type validity struct {
	NotBefore, NotAfter time.Time
}

type stepProvisioner struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

type stepCertificateAuthority struct {
	Type          string
	CertificateID string   `asn1:"optional,omitempty"`
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// publicKeyInfo allows unmarshaling the public key
type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// tbsCertificate allows unmarshaling of the "To-Be-Signed" principle portion
// of the certificate
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// certUniqueIDs extracts the subject and issuer unique IDs which are
// byte strings. These are not common but may be present in x509v2 certificates
// or later under tags 1 and 2 (before x509v3 extensions).
func certUniqueIDs(tbsAsnData []byte) (issuerUniqueID, subjectUniqueID []byte, err error) {
	var tbs tbsCertificate
	rest, err := asn1.Unmarshal(tbsAsnData, &tbs)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) > 0 {
		return nil, nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	iuid := tbs.UniqueID.RightAlign()
	suid := tbs.SubjectUniqueID.RightAlign()
	return iuid, suid, err
}

// printName prints the fields of a distinguished name, which include such
// things as its common name and locality.
func printName(names []pkix.AttributeTypeAndValue, buf *bytes.Buffer) []string {
	values := []string{}
	for _, name := range names {
		oid := name.Type
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
			switch oid[3] {
			case 3:
				values = append(values, fmt.Sprintf("CN=%s", name.Value))
			case 5:
				values = append(values, fmt.Sprintf("SERIALNUMBER=%s", name.Value))
			case 6:
				values = append(values, fmt.Sprintf("C=%s", name.Value))
			case 7:
				values = append(values, fmt.Sprintf("L=%s", name.Value))
			case 8:
				values = append(values, fmt.Sprintf("ST=%s", name.Value))
			case 9:
				values = append(values, fmt.Sprintf("STREET=%s", name.Value))
			case 10:
				values = append(values, fmt.Sprintf("O=%s", name.Value))
			case 11:
				values = append(values, fmt.Sprintf("OU=%s", name.Value))
			case 17:
				values = append(values, fmt.Sprintf("POSTALCODE=%s", name.Value))
			default:
				values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
			}
		} else if oid.Equal(oidEmailAddress) {
			values = append(values, fmt.Sprintf("emailAddress=%s", name.Value))
		} else if oid.Equal(oidDomainComponent) {
			values = append(values, fmt.Sprintf("DC=%s", name.Value))
		} else if oid.Equal(oidUserID) {
			values = append(values, fmt.Sprintf("UID=%s", name.Value))
		} else if oid.Equal(cppki.OIDNameIA) {
			values = append(values, fmt.Sprintf("ISD-AS=%s", name.Value))
		} else {
			values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
		}
	}
	if len(values) > 0 {
		buf.WriteString(values[0])
		for i := 1; i < len(values); i++ {
			buf.WriteString("," + values[i])
		}
		buf.WriteString("\n")
	}
	return values
}

// dsaKeyPrinter formats the Y, P, Q, or G components of a DSA public key.
func dsaKeyPrinter(name string, val *big.Int, buf *bytes.Buffer) {
	buf.WriteString(fmt.Sprintf("%16s%s:", "", name))
	for i, b := range val.Bytes() {
		if (i % 15) == 0 {
			buf.WriteString(fmt.Sprintf("\n%20s", ""))
		}
		buf.WriteString(fmt.Sprintf("%02x", b))
		if i != len(val.Bytes())-1 {
			buf.WriteString(":")
		}
	}
	buf.WriteString("\n")
}

func printVersion(version int, buf *bytes.Buffer) {
	hexVersion := version - 1
	if hexVersion < 0 {
		hexVersion = 0
	}
	buf.WriteString(fmt.Sprintf("%8sVersion: %d (%#x)\n", "", version, hexVersion))
}

func printSubjectInformation(subj *pkix.Name, pkAlgo x509.PublicKeyAlgorithm, pk interface{}, buf *bytes.Buffer) error {
	buf.WriteString(fmt.Sprintf("%8sSubject:", ""))
	if len(subj.Names) > 0 {
		buf.WriteString(" ")
		printName(subj.Names, buf)
	} else {
		buf.WriteString("\n")
	}
	buf.WriteString(fmt.Sprintf("%8sSubject Public Key Info:\n%12sPublic Key Algorithm: ", "", ""))
	switch pkAlgo {
	case x509.RSA:
		buf.WriteString("RSA\n")
		if rsaKey, ok := pk.(*rsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sPublic-Key: (%d bit)\n", "", rsaKey.N.BitLen()))
			// Some implementations (notably OpenSSL) prepend 0x00 to the modulus
			// if its most-significant bit is set. There is no need to do that here
			// because the modulus is always unsigned and the extra byte can be
			// confusing given the bit length.
			buf.WriteString(fmt.Sprintf("%16sModulus:", ""))
			for i, val := range rsaKey.N.Bytes() {
				if (i % 15) == 0 {
					buf.WriteString(fmt.Sprintf("\n%20s", ""))
				}
				buf.WriteString(fmt.Sprintf("%02x", val))
				if i != len(rsaKey.N.Bytes())-1 {
					buf.WriteString(":")
				}
			}
			buf.WriteString(fmt.Sprintf("\n%16sExponent: %d (%#x)\n", "", rsaKey.E, rsaKey.E))
		} else {
			return errors.New("certinfo: Expected rsa.PublicKey for type x509.RSA")
		}
	case x509.ECDSA:
		buf.WriteString("ECDSA\n")
		if ecdsaKey, ok := pk.(*ecdsa.PublicKey); ok {
			buf.WriteString(fmt.Sprintf("%16sPublic-Key: (%d bit)\n", "", ecdsaKey.Params().BitSize))
			dsaKeyPrinter("X", ecdsaKey.X, buf)
			dsaKeyPrinter("Y", ecdsaKey.Y, buf)
			buf.WriteString(fmt.Sprintf("%16sCurve: %s\n", "", ecdsaKey.Params().Name))
		} else {
			return errors.New("certinfo: Expected ecdsa.PublicKey for type x509.DSA")
		}
	case x509.Ed25519:
		buf.WriteString("Ed25519\n")
		if ed25519Key, ok := pk.(ed25519.PublicKey); ok {
			bytes := []byte(ed25519Key)
			buf.WriteString(fmt.Sprintf("%16sPublic-Key: (%d bit)", "", len(bytes)))
			for i, b := range bytes {
				if (i % 15) == 0 {
					buf.WriteString(fmt.Sprintf("\n%20s", ""))
				}
				buf.WriteString(fmt.Sprintf("%02x", b))
				if i != len(bytes)-1 {
					buf.WriteString(":")
				}
			}
			buf.WriteString("\n")
		} else {
			return errors.New("certinfo: Expected ed25519.PublicKey for type x509.ED25519")
		}
	default:
		return errors.New("certinfo: Unknown public key type")
	}
	return nil
}

func printSubjKeyID(ext pkix.Extension, buf *bytes.Buffer) error {
	// subjectKeyIdentifier: RFC 5280, 4.2.1.2
	buf.WriteString(fmt.Sprintf("%12sX509v3 Subject Key Identifier:", ""))
	if ext.Critical {
		buf.WriteString(" critical\n")
	} else {
		buf.WriteString("\n")
	}
	var subjectKeyID []byte
	if _, err := asn1.Unmarshal(ext.Value, &subjectKeyID); err != nil {
		return err
	}
	for i := 0; i < len(subjectKeyID); i++ {
		if i == 0 {
			buf.WriteString(fmt.Sprintf("%16s%02X", "", subjectKeyID[0]))
		} else {
			buf.WriteString(fmt.Sprintf(":%02X", subjectKeyID[i]))
		}
	}
	buf.WriteString("\n")
	return nil
}

func printSubjAltNames(ext pkix.Extension, dnsNames []string, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, buf *bytes.Buffer) error {
	// subjectAltName: RFC 5280, 4.2.1.6
	// TODO: Currently crypto/x509 only extracts DNS, email, and IP addresses.
	// We should add the others to it or implement them here.
	buf.WriteString(fmt.Sprintf("%12sX509v3 Subject Alternative Name:", ""))
	if ext.Critical {
		buf.WriteString(" critical\n")
	} else {
		buf.WriteString("\n")
	}
	if len(dnsNames) > 0 {
		buf.WriteString(fmt.Sprintf("%16sDNS:%s", "", dnsNames[0]))
		for i := 1; i < len(dnsNames); i++ {
			buf.WriteString(fmt.Sprintf(", DNS:%s", dnsNames[i]))
		}
		buf.WriteString("\n")
	}
	if len(emailAddresses) > 0 {
		buf.WriteString(fmt.Sprintf("%16semail:%s", "", emailAddresses[0]))
		for i := 1; i < len(emailAddresses); i++ {
			buf.WriteString(fmt.Sprintf(", email:%s", emailAddresses[i]))
		}
		buf.WriteString("\n")
	}
	if len(ipAddresses) > 0 {
		buf.WriteString(fmt.Sprintf("%16sIP Address:%s", "", ipAddresses[0].String())) // XXX verify string format
		for i := 1; i < len(ipAddresses); i++ {
			buf.WriteString(fmt.Sprintf(", IP Address:%s", ipAddresses[i].String()))
		}
		buf.WriteString("\n")
	}
	if len(uris) > 0 {
		buf.WriteString(fmt.Sprintf("%16sURI:%s", "", uris[0].String()))
		for i := 1; i < len(uris); i++ {
			buf.WriteString(fmt.Sprintf(", URI:%s", uris[i].String()))
		}
		buf.WriteString("\n")
	}
	return nil
}

func printSignature(sigAlgo x509.SignatureAlgorithm, sig []byte, buf *bytes.Buffer) {
	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %s", "", sigAlgo))
	for i, val := range sig {
		if (i % 18) == 0 {
			buf.WriteString(fmt.Sprintf("\n%9s", ""))
		}
		buf.WriteString(fmt.Sprintf("%02x", val))
		if i != len(sig)-1 {
			buf.WriteString(":")
		}
	}
	buf.WriteString("\n")
}

// CertificateShortText returns the human-readable string representation of the
// given cert using a short and friendly format.
func certificateShortText(cert *x509.Certificate) (string, error) {
	return newCertificateShort(cert).String(), nil
}

// CertificateRequestShortText returns the human-readable string representation
// of the given certificate request using a short and friendly format.
func certificateRequestShortText(cr *x509.CertificateRequest) (string, error) {
	return newCertificateRequestShort(cr).String(), nil
}

// CertificateText returns a human-readable string representation
// of the certificate cert. The format is similar (but not identical)
// to the OpenSSL way of printing certificates.
func certificateText(cert *x509.Certificate) (string, error) {
	var buf bytes.Buffer
	buf.Grow(4096) // 4KiB should be enough

	buf.WriteString("Certificate:\n")
	buf.WriteString(fmt.Sprintf("%4sData:\n", ""))
	printVersion(cert.Version, &buf)
	buf.WriteString(fmt.Sprintf("%8sSerial Number: %d (%#x)\n", "", cert.SerialNumber, cert.SerialNumber))
	buf.WriteString(fmt.Sprintf("%4sSignature Algorithm: %s\n", "", cert.SignatureAlgorithm))

	// Issuer information
	buf.WriteString(fmt.Sprintf("%8sIssuer: ", ""))
	printName(cert.Issuer.Names, &buf)

	// Validity information
	buf.WriteString(fmt.Sprintf("%8sValidity\n", ""))
	buf.WriteString(fmt.Sprintf("%12sNot Before: %s\n", "", cert.NotBefore.Format(validityTimeFormat)))
	buf.WriteString(fmt.Sprintf("%12sNot After : %s\n", "", cert.NotAfter.Format(validityTimeFormat)))

	// Subject information
	err := printSubjectInformation(&cert.Subject, cert.PublicKeyAlgorithm, cert.PublicKey, &buf)
	if err != nil {
		return "", err
	}

	// Issuer/Subject Unique ID, typically used in old v2 certificates
	issuerUID, subjectUID, err := certUniqueIDs(cert.RawTBSCertificate)
	if err != nil {
		return "", errors.New(fmt.Sprintf("certinfo: Error parsing TBS unique attributes: %s\n", err.Error()))
	}
	if len(issuerUID) > 0 {
		buf.WriteString(fmt.Sprintf("%8sIssuer Unique ID: %02x", "", issuerUID[0]))
		for i := 1; i < len(issuerUID); i++ {
			buf.WriteString(fmt.Sprintf(":%02x", issuerUID[i]))
		}
		buf.WriteString("\n")
	}
	if len(subjectUID) > 0 {
		buf.WriteString(fmt.Sprintf("%8sSubject Unique ID: %02x", "", subjectUID[0]))
		for i := 1; i < len(subjectUID); i++ {
			buf.WriteString(fmt.Sprintf(":%02x", subjectUID[i]))
		}
		buf.WriteString("\n")
	}

	// Optional extensions for X509v3
	if cert.Version == 3 && len(cert.Extensions) > 0 {
		buf.WriteString(fmt.Sprintf("%8sX509v3 extensions:\n", ""))
		for _, ext := range cert.Extensions {
			if len(ext.Id) == 4 && ext.Id[0] == 2 && ext.Id[1] == 5 && ext.Id[2] == 29 {
				switch ext.Id[3] {
				case 14:
					err = printSubjKeyID(ext, &buf)
				case 15:
					// keyUsage: RFC 5280, 4.2.1.3
					buf.WriteString(fmt.Sprintf("%12sX509v3 Key Usage:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					usages := []string{}
					if cert.KeyUsage&x509.KeyUsageDigitalSignature > 0 {
						usages = append(usages, "Digital Signature")
					}
					if cert.KeyUsage&x509.KeyUsageContentCommitment > 0 {
						usages = append(usages, "Content Commitment")
					}
					if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
						usages = append(usages, "Key Encipherment")
					}
					if cert.KeyUsage&x509.KeyUsageDataEncipherment > 0 {
						usages = append(usages, "Data Encipherment")
					}
					if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
						usages = append(usages, "Key Agreement")
					}
					if cert.KeyUsage&x509.KeyUsageCertSign > 0 {
						usages = append(usages, "Certificate Sign")
					}
					if cert.KeyUsage&x509.KeyUsageCRLSign > 0 {
						usages = append(usages, "CRL Sign")
					}
					if cert.KeyUsage&x509.KeyUsageEncipherOnly > 0 {
						usages = append(usages, "Encipher Only")
					}
					if cert.KeyUsage&x509.KeyUsageDecipherOnly > 0 {
						usages = append(usages, "Decipher Only")
					}
					if len(usages) > 0 {
						buf.WriteString(fmt.Sprintf("%16s%s", "", usages[0]))
						for i := 1; i < len(usages); i++ {
							buf.WriteString(fmt.Sprintf(", %s", usages[i]))
						}
						buf.WriteString("\n")
					} else {
						buf.WriteString(fmt.Sprintf("%16sNone\n", ""))
					}
				case 17:
					err = printSubjAltNames(ext, cert.DNSNames, cert.EmailAddresses, cert.IPAddresses, cert.URIs, &buf)
				case 19:
					// basicConstraints: RFC 5280, 4.2.1.9
					if !cert.BasicConstraintsValid {
						break
					}
					buf.WriteString(fmt.Sprintf("%12sX509v3 Basic Constraints:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					if cert.IsCA {
						buf.WriteString(fmt.Sprintf("%16sCA:TRUE", ""))
					} else {
						buf.WriteString(fmt.Sprintf("%16sCA:FALSE", ""))
					}
					if cert.MaxPathLenZero {
						buf.WriteString(", pathlen:0\n")
					} else if cert.MaxPathLen > 0 {
						buf.WriteString(fmt.Sprintf(", pathlen:%d\n", cert.MaxPathLen))
					} else {
						buf.WriteString("\n")
					}
				case 30:
					// nameConstraints: RFC 5280, 4.2.1.10
					// TODO: Currently crypto/x509 only supports "Permitted" and not "Excluded"
					// subtrees. Furthermore it assumes all types are DNS names which is not
					// necessarily true. This missing functionality should be implemented.
					buf.WriteString(fmt.Sprintf("%12sX509v3 Name Constraints:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					if len(cert.PermittedDNSDomains) > 0 || len(cert.PermittedEmailAddresses) > 0 || len(cert.PermittedURIDomains) > 0 || len(cert.PermittedIPRanges) > 0 {
						buf.WriteString(fmt.Sprintf("%16sPermitted:\n", ""))

						if len(cert.PermittedDNSDomains) > 0 {
							buf.WriteString(fmt.Sprintf("%18sDNS: %s", "", cert.PermittedDNSDomains[0]))
							for i := 1; i < len(cert.PermittedDNSDomains); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.PermittedDNSDomains[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.PermittedEmailAddresses) > 0 {
							buf.WriteString(fmt.Sprintf("%18sEmail: %s", "", cert.PermittedEmailAddresses[0]))
							for i := 1; i < len(cert.PermittedEmailAddresses); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.PermittedEmailAddresses[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.PermittedURIDomains) > 0 {
							buf.WriteString(fmt.Sprintf("%18sURI: %s", "", cert.PermittedURIDomains[0]))
							for i := 1; i < len(cert.PermittedURIDomains); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.PermittedURIDomains[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.PermittedIPRanges) > 0 {
							buf.WriteString(fmt.Sprintf("%18sIP Range: %s", "", cert.PermittedIPRanges[0]))
							for i := 1; i < len(cert.PermittedIPRanges); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.PermittedIPRanges[i]))
							}
							buf.WriteString("\n")
						}
					}
					if len(cert.ExcludedDNSDomains) > 0 || len(cert.ExcludedEmailAddresses) > 0 || len(cert.ExcludedURIDomains) > 0 || len(cert.ExcludedIPRanges) > 0 {
						buf.WriteString(fmt.Sprintf("%16sExcluded:\n", ""))

						if len(cert.ExcludedDNSDomains) > 0 {
							buf.WriteString(fmt.Sprintf("%18sDNS: %s", "", cert.ExcludedDNSDomains[0]))
							for i := 1; i < len(cert.ExcludedDNSDomains); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.ExcludedDNSDomains[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.ExcludedEmailAddresses) > 0 {
							buf.WriteString(fmt.Sprintf("%18sEmail: %s", "", cert.ExcludedEmailAddresses[0]))
							for i := 1; i < len(cert.ExcludedEmailAddresses); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.ExcludedEmailAddresses[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.ExcludedURIDomains) > 0 {
							buf.WriteString(fmt.Sprintf("%18sURI: %s", "", cert.ExcludedURIDomains[0]))
							for i := 1; i < len(cert.ExcludedURIDomains); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.ExcludedURIDomains[i]))
							}
							buf.WriteString("\n")
						}
						if len(cert.ExcludedIPRanges) > 0 {
							buf.WriteString(fmt.Sprintf("%18sIP Range: %s", "", cert.ExcludedIPRanges[0]))
							for i := 1; i < len(cert.ExcludedIPRanges); i++ {
								buf.WriteString(fmt.Sprintf(", %s", cert.ExcludedIPRanges[i]))
							}
							buf.WriteString("\n")
						}
					}

				case 31:
					// CRLDistributionPoints: RFC 5280, 4.2.1.13
					// TODO: Currently crypto/x509 does not fully implement this section,
					// including types and reason flags.
					buf.WriteString(fmt.Sprintf("%12sX509v3 CRL Distribution Points:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					if len(cert.CRLDistributionPoints) > 0 {
						buf.WriteString(fmt.Sprintf("%16sFull Name:\n%18sURI:%s", "", "", cert.CRLDistributionPoints[0]))
						for i := 1; i < len(cert.CRLDistributionPoints); i++ {
							buf.WriteString(fmt.Sprintf(", URI:%s", cert.CRLDistributionPoints[i]))
						}
						buf.WriteString("\n")
					}
				case 32:
					// certificatePoliciesExt: RFC 5280, 4.2.1.4
					// TODO: Currently crypto/x509 does not fully impelment this section,
					// including the Certification Practice Statement (CPS)
					buf.WriteString(fmt.Sprintf("%12sX509v3 Certificate Policies:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					for _, val := range cert.PolicyIdentifiers {
						buf.WriteString(fmt.Sprintf("%16sPolicy: %s\n", "", val.String()))
					}
				case 35:
					// authorityKeyIdentifier: RFC 5280, 4.2.1.1
					buf.WriteString(fmt.Sprintf("%12sX509v3 Authority Key Identifier:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					buf.WriteString(fmt.Sprintf("%16skeyid", ""))
					for _, val := range cert.AuthorityKeyId {
						buf.WriteString(fmt.Sprintf(":%02X", val))
					}
					buf.WriteString("\n")
				case 37:
					// extKeyUsage: RFC 5280, 4.2.1.12
					buf.WriteString(fmt.Sprintf("%12sX509v3 Extended Key Usage:", ""))
					if ext.Critical {
						buf.WriteString(" critical\n")
					} else {
						buf.WriteString("\n")
					}
					var list []string
					for _, val := range cert.ExtKeyUsage {
						switch val {
						case x509.ExtKeyUsageAny:
							list = append(list, "Any Usage")
						case x509.ExtKeyUsageServerAuth:
							list = append(list, "Server Authentication")
						case x509.ExtKeyUsageClientAuth:
							list = append(list, "Client Authentication")
						case x509.ExtKeyUsageCodeSigning:
							list = append(list, "Code Signing")
						case x509.ExtKeyUsageEmailProtection:
							list = append(list, "E-mail Protection")
						case x509.ExtKeyUsageIPSECEndSystem:
							list = append(list, "IPSec End System")
						case x509.ExtKeyUsageIPSECTunnel:
							list = append(list, "IPSec Tunnel")
						case x509.ExtKeyUsageIPSECUser:
							list = append(list, "IPSec User")
						case x509.ExtKeyUsageTimeStamping:
							list = append(list, "Time Stamping")
						case x509.ExtKeyUsageOCSPSigning:
							list = append(list, "OCSP Signing")
						default:
							list = append(list, "UNKNOWN")
						}
					}
					for _, oid := range cert.UnknownExtKeyUsage {
						switch {
						case oid.Equal(cppki.OIDExtKeyUsageSensitive):
							list = append(list, "Sensitive Voting")
						case oid.Equal(cppki.OIDExtKeyUsageRegular):
							list = append(list, "Regular Voting")
						case oid.Equal(cppki.OIDExtKeyUsageRoot):
							list = append(list, "CPPKI Root")
						default:
							list = append(list, oid.String())
						}
					}
					if len(list) > 0 {
						buf.WriteString(fmt.Sprintf("%16s%s", "", list[0]))
						for i := 1; i < len(list); i++ {
							buf.WriteString(fmt.Sprintf(", %s", list[i]))
						}
						buf.WriteString("\n")
					}
				default:
					buf.WriteString(fmt.Sprintf("Unknown extension 2.5.29.%d\n", ext.Id[3]))
				}
				if err != nil {
					return "", err
				}
			} else if ext.Id.Equal(oidExtensionAuthorityInfoAccess) {
				// authorityInfoAccess: RFC 5280, 4.2.2.1
				buf.WriteString(fmt.Sprintf("%12sAuthority Information Access:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				if len(cert.OCSPServer) > 0 {
					buf.WriteString(fmt.Sprintf("%16sOCSP - URI:%s", "", cert.OCSPServer[0]))
					for i := 1; i < len(cert.OCSPServer); i++ {
						buf.WriteString(fmt.Sprintf(",URI:%s", cert.OCSPServer[i]))
					}
					buf.WriteString("\n")
				}
				if len(cert.IssuingCertificateURL) > 0 {
					buf.WriteString(fmt.Sprintf("%16sCA Issuers - URI:%s", "", cert.IssuingCertificateURL[0]))
					for i := 1; i < len(cert.IssuingCertificateURL); i++ {
						buf.WriteString(fmt.Sprintf(",URI:%s", cert.IssuingCertificateURL[i]))
					}
					buf.WriteString("\n")
				}
			} else if ext.Id.Equal(oidNSComment) {
				// Netscape comment
				var comment string
				rest, err := asn1.Unmarshal(ext.Value, &comment)
				if err != nil || len(rest) > 0 {
					return "", errors.New("certinfo: Error parsing OID " + ext.Id.String())
				}
				if ext.Critical {
					buf.WriteString(fmt.Sprintf("%12sNetscape Comment: critical\n%16s%s\n", "", "", comment))
				} else {
					buf.WriteString(fmt.Sprintf("%12sNetscape Comment:\n%16s%s\n", "", "", comment))
				}
			} else if ext.Id.Equal(oidStepProvisioner) {
				buf.WriteString(fmt.Sprintf("%12sX509v3 Step Provisioner:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				val := &stepProvisioner{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					return "", errors.New("certinfo: Error parsing OID " + ext.Id.String())
				}
				var typ string
				switch val.Type {
				case 1:
					typ = "JWK"
				case 2:
					typ = "OIDC"
				case 3:
					typ = "GCP"
				case 4:
					typ = "AWS"
				case 5:
					typ = "Azure"
				case 6:
					typ = "ACME"
				case 7:
					typ = "X5C"
				case 8:
					typ = "K8sSA"
				default:
					typ = fmt.Sprintf("%d (unknown)", val.Type)
				}
				buf.WriteString(fmt.Sprintf("%16sType: %s\n", "", typ))
				buf.WriteString(fmt.Sprintf("%16sName: %s\n", "", string(val.Name)))
				if len(val.CredentialID) != 0 {
					buf.WriteString(fmt.Sprintf("%16sCredentialID: %s\n", "", string(val.CredentialID)))
				}
				var key, value string
				for i, l := 0, len(val.KeyValuePairs); i < l; i += 2 {
					key, value = val.KeyValuePairs[i], "-"
					if i+1 < l {
						value = val.KeyValuePairs[i+1]
					}
					buf.WriteString(fmt.Sprintf("%16s%s: %s\n", "", key, value))
				}
			} else if ext.Id.Equal(oidStepCertificateAuthority) {
				buf.WriteString(fmt.Sprintf("%12sX509v3 Step Registration Authority:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				val := &stepCertificateAuthority{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					return "", errors.New("certinfo: Error parsing OID " + ext.Id.String())
				}
				buf.WriteString(fmt.Sprintf("%16sType: %s\n", "", val.Type))
				if val.CertificateID != "" {
					buf.WriteString(fmt.Sprintf("%16sCertificateID: %s\n", "", val.CertificateID))
				}
				var key, value string
				for i, l := 0, len(val.KeyValuePairs); i < l; i += 2 {
					key, value = val.KeyValuePairs[i], "-"
					if i+1 < l {
						value = val.KeyValuePairs[i+1]
					}
					buf.WriteString(fmt.Sprintf("%16s%s: %s\n", "", key, value))
				}
			} else {
				buf.WriteString(fmt.Sprintf("%12s%s:", "", ext.Id.String()))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				value := bytes.Runes(ext.Value)
				sanitized := make([]rune, len(value))
				for i, r := range value {
					if strconv.IsPrint(r) && r != '�' {
						sanitized[i] = r
					} else {
						sanitized[i] = '.'
					}
				}
				buf.WriteString(fmt.Sprintf("%16s%s\n", "", string(sanitized)))
			}
		}
	}

	// Signature
	printSignature(cert.SignatureAlgorithm, cert.Signature, &buf)

	// Optional: Print the full PEM certificate
	/*
		pemBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		buf.Write(pem.EncodeToMemory(&pemBlock))
	*/

	return buf.String(), nil
}

var (
	oidExtSubjectKeyID     = []int{2, 5, 29, 14}
	oidExtSubjectAltName   = []int{2, 5, 29, 17}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// RFC 5280, 4.2.1.9
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

// RFC 5280, 4.2.1.3
func parseKeyUsage(val []byte) (x509.KeyUsage, error) {
	var usageBits asn1.BitString
	if _, err := asn1.Unmarshal(val, &usageBits); err != nil {
		return 0, err
	}
	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return x509.KeyUsage(usage), nil
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// certificateRequestText returns a human-readable string representation
// of the certificate request csr. The format is similar (but not identical)
// to the OpenSSL way of printing certificates.
func certificateRequestText(csr *x509.CertificateRequest) (string, error) {
	var buf bytes.Buffer
	buf.Grow(4096) // 4KiB should be enough

	buf.WriteString("Certificate Request:\n")
	buf.WriteString(fmt.Sprintf("%4sData:\n", ""))
	printVersion(csr.Version, &buf)

	// Subject information
	err := printSubjectInformation(&csr.Subject, csr.PublicKeyAlgorithm, csr.PublicKey, &buf)
	if err != nil {
		return "", err
	}

	// Optional extensions for PKCS #10, RFC 2986
	if csr.Version == 0 && len(csr.Extensions) > 0 {
		buf.WriteString(fmt.Sprintf("%8sRequested Extensions:\n", ""))
		unknownExts := []pkix.Extension{}
		for _, ext := range csr.Extensions {
			switch {
			case ext.Id.Equal(oidExtSubjectKeyID):
				err = printSubjKeyID(ext, &buf)
			case ext.Id.Equal(oidExtSubjectAltName):
				err = printSubjAltNames(ext, csr.DNSNames, csr.EmailAddresses, csr.IPAddresses, csr.URIs, &buf)
			case ext.Id.Equal(oidExtKeyUsage):
				// keyUsage: RFC 5280, 4.2.1.3
				ku, err := parseKeyUsage(ext.Value)
				if err != nil {
					buf.WriteString(fmt.Sprintf("%12sX509v3 Key Usage: failed to decode\n", ""))
					continue
				}
				buf.WriteString(fmt.Sprintf("%12sX509v3 Key Usage:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				kus := []struct {
					ku   x509.KeyUsage
					desc string
				}{
					{x509.KeyUsageDigitalSignature, "Digital Signature"},
					{x509.KeyUsageContentCommitment, "Content Commitment"},
					{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
					{x509.KeyUsageDataEncipherment, "Data Encipherment"},
					{x509.KeyUsageKeyAgreement, "Key Agreement"},
					{x509.KeyUsageCertSign, "Certificate Sign"},
					{x509.KeyUsageCRLSign, "CRL Sign"},
					{x509.KeyUsageEncipherOnly, "Encipher Only"},
					{x509.KeyUsageDecipherOnly, "Decipher Only"},
				}
				var usages []string
				for _, u := range kus {
					if ku&u.ku > 0 {
						usages = append(usages, u.desc)
					}
				}
				if len(usages) > 0 {
					buf.WriteString(fmt.Sprintf("%16s%s", "", usages[0]))
					for i := 1; i < len(usages); i++ {
						buf.WriteString(fmt.Sprintf(", %s", usages[i]))
					}
					buf.WriteString("\n")
				} else {
					buf.WriteString(fmt.Sprintf("%16sNone\n", ""))
				}
			case ext.Id.Equal(oidExtBasicConstraints):
				// basicConstraints: RFC 5280, 4.2.1.9
				var constraints basicConstraints
				_, err := asn1.Unmarshal(ext.Value, &constraints)
				if err != nil {
					buf.WriteString(fmt.Sprintf("%12sX509v3 Basic Constraints: failed to decode\n", ""))
					continue
				}
				buf.WriteString(fmt.Sprintf("%12sX509v3 Basic Constraints:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				if constraints.IsCA {
					buf.WriteString(fmt.Sprintf("%16sCA:TRUE", ""))
				} else {
					buf.WriteString(fmt.Sprintf("%16sCA:FALSE", ""))
				}
				if constraints.MaxPathLen == 0 {
					buf.WriteString(", pathlen:0\n")
				} else if constraints.MaxPathLen > 0 {
					buf.WriteString(fmt.Sprintf(", pathlen:%d\n", constraints.MaxPathLen))
				} else {
					buf.WriteString("\n")
				}
			case ext.Id.Equal(oidExtNameConstraints):
				// RFC 5280, 4.2.1.10
				// NameConstraints ::= SEQUENCE {
				//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
				//
				// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
				//
				// GeneralSubtree ::= SEQUENCE {
				//      base                    GeneralName,
				//      minimum         [0]     BaseDistance DEFAULT 0,
				//      maximum         [1]     BaseDistance OPTIONAL }
				//
				// BaseDistance ::= INTEGER (0..MAX)
				var constraints nameConstraints
				_, err := asn1.Unmarshal(ext.Value, &constraints)
				if err != nil {
					buf.WriteString(fmt.Sprintf("%12sX509v3 Name Constraints: failed to decode\n", ""))
					continue
				}
				if len(constraints.Excluded) > 0 && ext.Critical {
					buf.WriteString(fmt.Sprintf("%12sX509v3 Name Constraints: failed to decode: unexpected excluded name constraints\n", ""))
					continue
				}
				var permittedDNSDomains []string
				for _, subtree := range constraints.Permitted {
					if len(subtree.Name) == 0 {
						continue
					}
					permittedDNSDomains = append(permittedDNSDomains, subtree.Name)
				}
				buf.WriteString(fmt.Sprintf("%12sX509v3 Name Constraints:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				if len(permittedDNSDomains) > 0 {
					buf.WriteString(fmt.Sprintf("%16sPermitted:\n%18s%s", "", "", permittedDNSDomains[0]))
					for i := 1; i < len(permittedDNSDomains); i++ {
						buf.WriteString(fmt.Sprintf(", %s", permittedDNSDomains[i]))
					}
					buf.WriteString("\n")
				}
			case ext.Id.Equal(oidExtExtendedKeyUsage):
				// extKeyUsage: RFC 5280, 4.2.1.12
				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER
				var keyUsage []asn1.ObjectIdentifier
				if _, err = asn1.Unmarshal(ext.Value, &keyUsage); err != nil {
					buf.WriteString(fmt.Sprintf("%12sX509v3 Extended Key Usage: failed to decode\n", ""))
					continue
				}
				ekus := []struct {
					oid  asn1.ObjectIdentifier
					desc string
				}{
					{oidExtKeyUsageAny, "Any Usage"},
					{oidExtKeyUsageServerAuth, "Server Authentication"},
					{oidExtKeyUsageClientAuth, "Client Authentication"},
					{oidExtKeyUsageCodeSigning, "Code Signing"},
					{oidExtKeyUsageEmailProtection, "E-mail Protection"},
					{oidExtKeyUsageIPSECEndSystem, "IPSec End System"},
					{oidExtKeyUsageIPSECTunnel, "IPSec Tunnel"},
					{oidExtKeyUsageIPSECUser, "IPSec User"},
					{oidExtKeyUsageTimeStamping, "Time Stamping"},
					{oidExtKeyUsageOCSPSigning, "OCSP Signing"},
					{oidExtKeyUsageMicrosoftServerGatedCrypto, "Microsoft Server Gated Crypto"},
					{oidExtKeyUsageNetscapeServerGatedCrypto, "Netscape Server Gated Crypto"},
					{oidExtKeyUsageMicrosoftCommercialCodeSigning, "Microsoft Commercial Code Signing"},
					{oidExtKeyUsageMicrosoftKernelCodeSigning, "Microsoft Kernel Code Signing"},
				}
				var list []string
				for _, u := range keyUsage {
					found := false
					for _, eku := range ekus {
						if u.Equal(eku.oid) {
							list = append(list, eku.desc)
							found = true
						}
					}
					if !found {
						list = append(list, fmt.Sprintf("UNKNOWN(%s)", u.String()))
					}
				}
				buf.WriteString(fmt.Sprintf("%12sX509v3 Extended Key Usage:", ""))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				if len(list) > 0 {
					buf.WriteString(fmt.Sprintf("%16s%s", "", list[0]))
					for i := 1; i < len(list); i++ {
						buf.WriteString(fmt.Sprintf(", %s", list[i]))
					}
					buf.WriteString("\n")
				}
			default:
				unknownExts = append(unknownExts, ext)
			}
			if err != nil {
				return "", err
			}
		}
		if len(unknownExts) > 0 {
			buf.WriteString(fmt.Sprintf("%8sAttributes:\n", ""))
			for _, ext := range unknownExts {
				buf.WriteString(fmt.Sprintf("%12s%s:", "", ext.Id.String()))
				if ext.Critical {
					buf.WriteString(" critical\n")
				} else {
					buf.WriteString("\n")
				}
				value := bytes.Runes(ext.Value)
				sanitized := make([]rune, len(value))
				hasSpecialChar := false
				for i, r := range value {
					if strconv.IsPrint(r) && r != '�' {
						sanitized[i] = r
					} else {
						hasSpecialChar = true
						sanitized[i] = '.'
					}
				}
				buf.WriteString(fmt.Sprintf("%16s%s\n", "", string(sanitized)))
				if hasSpecialChar {
					buf.WriteString(fmt.Sprintf("%16s", ""))
					for i, b := range ext.Value {
						buf.WriteString(fmt.Sprintf("%02x", b))
						if i != len(ext.Value)-1 {
							buf.WriteString(":")
						}
					}
					buf.WriteString("\n")
				}
			}
		}
	}

	// Signature
	printSignature(csr.SignatureAlgorithm, csr.Signature, &buf)

	return buf.String(), nil
}
