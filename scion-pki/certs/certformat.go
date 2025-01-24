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

// File certformat.go is copied from
// https://github.com/smallstep/certinfo/blob/master/certformat.go as is on
// commit c181387 only the package has been modified.

package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// formatBuffer is a helper to write using sprintf.
type formatBuffer struct {
	bytes.Buffer
}

// Writef writes a string formated using fmt.Sprintf.
func (b *formatBuffer) Writef(format string, args ...any) (int, error) {
	return b.Buffer.WriteString(fmt.Sprintf(format, args...))
}

type certificateShort struct {
	Type               string
	PublicKeyAlgorithm string
	SerialNumber       string
	Subject            string
	Issuer             string
	SANs               []string
	Provisioner        *provisioner
	NotBefore          time.Time
	NotAfter           time.Time
}

type provisioner struct {
	ID   string
	Name string
}

func newCertificateShort(cert *x509.Certificate) *certificateShort {
	var typ string
	if cert.IsCA {
		if cert.CheckSignatureFrom(cert) == nil {
			typ = "Root CA"
		} else {
			typ = "Intermediate CA"
		}
	} else {
		typ = "TLS"
	}

	return &certificateShort{
		Type:               typ,
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cert.PublicKeyAlgorithm, cert.PublicKey),
		SerialNumber:       abbreviated(cert.SerialNumber.String()),
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		SANs:               getSANs(cert.Subject.CommonName, cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs),
		Provisioner:        getProvisioner(cert),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
	}
}

// String returns the certificateShort formated as a string.
func (c *certificateShort) String() string {
	var buf formatBuffer
	buf.Writef("X.509v3 %s Certificate (%s) [Serial: %s]\n", c.Type, c.PublicKeyAlgorithm, c.SerialNumber)
	sans := c.SANs
	if len(c.Subject) > 0 {
		sans = append([]string{c.Subject}, sans...)
	}
	if len(sans) == 0 {
		buf.Writef("  Subject: \n")
	} else {
		for i, s := range sans {
			if i == 0 {
				buf.Writef("  Subject:     %s\n", s)
			} else {
				buf.Writef("               %s\n", s)
			}
		}
	}
	buf.Writef("  Issuer:      %s\n", c.Issuer)
	if c.Provisioner != nil {
		if len(c.Provisioner.ID) == 0 {
			buf.Writef("  Provisioner: %s\n", c.Provisioner.Name)
		} else {
			buf.Writef("  Provisioner: %s [ID: %s]\n", c.Provisioner.Name, c.Provisioner.ID)
		}

	}
	buf.Writef("  Valid from:  %s\n", c.NotBefore.Format(time.RFC3339))
	buf.Writef("          to:  %s\n", c.NotAfter.Format(time.RFC3339))
	return buf.String()
}

type certificateRequestShort struct {
	PublicKeyAlgorithm string
	Subject            string
	SANs               []string
}

func newCertificateRequestShort(cr *x509.CertificateRequest) *certificateRequestShort {
	return &certificateRequestShort{
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cr.PublicKeyAlgorithm, cr.PublicKey),
		Subject:            cr.Subject.CommonName,
		SANs:               getSANs(cr.Subject.CommonName, cr.DNSNames, cr.IPAddresses, cr.EmailAddresses, cr.URIs),
	}
}

// String returns the certificateShort formated as a string.
func (c *certificateRequestShort) String() string {
	var buf formatBuffer
	buf.Writef("X.509v3 Certificate Signing Request (%s)\n", c.PublicKeyAlgorithm)
	sans := c.SANs
	if len(c.Subject) > 0 {
		sans = append([]string{c.Subject}, sans...)
	}
	if len(sans) == 0 {
		buf.Writef("  Subject: \n")
	} else {
		for i, s := range sans {
			if i == 0 {
				buf.Writef("  Subject:     %s\n", s)
			} else {
				buf.Writef("               %s\n", s)
			}
		}
	}
	return buf.String()
}

func getSANs(commonName string, dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL) []string {
	var sans []string
	for _, s := range dnsNames {
		if s != commonName {
			sans = append(sans, s)
		}
	}
	for _, ip := range ipAddresses {
		if s := ip.String(); s != commonName {
			sans = append(sans, s)
		}
	}
	for _, s := range emailAddresses {
		if s != commonName {
			sans = append(sans, s)
		}
	}
	for _, uri := range uris {
		if s := uri.String(); s != commonName {
			sans = append(sans, s)
		}
	}
	return sans
}

func getProvisioner(cert *x509.Certificate) *provisioner {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidStepProvisioner) {
			val := &stepProvisioner{}
			rest, err := asn1.Unmarshal(ext.Value, val)
			if err != nil || len(rest) > 0 {
				return nil
			}

			return &provisioner{
				ID:   abbreviated(string(val.CredentialID)),
				Name: string(val.Name),
			}
		}
	}
	return nil
}

func getPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm, key any) string {
	var params string
	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		params = pk.Curve.Params().Name
	case *rsa.PublicKey:
		params = strconv.Itoa(pk.Size() * 8)
	case ed25519.PublicKey:
		params = strconv.Itoa(len(pk) * 8)
	default:
		params = "unknown"
	}
	return fmt.Sprintf("%s %s", algorithm, params)
}

func abbreviated(s string) string {
	l := len(s)
	if l <= 8 {
		return s
	}
	return s[:4] + "..." + s[l-4:]
}
