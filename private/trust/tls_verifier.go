// Copyright 2020 ETH Zurich
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

package trust

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

const defaultTimeout = 5 * time.Second

// TLSCryptoVerifier implements callbacks which will be called during TLS handshake.
type TLSCryptoVerifier struct {
	DB      DB
	Timeout time.Duration
}

// NewTLSCryptoVerifier returns a new instance with the defaultTimeout.
func NewTLSCryptoVerifier(db DB) *TLSCryptoVerifier {
	return &TLSCryptoVerifier{
		DB:      db,
		Timeout: defaultTimeout,
	}
}

// VerifyServerCertificate verifies the certificate presented by the server
// using the CP-PKI.
func (v *TLSCryptoVerifier) VerifyServerCertificate(
	rawCerts [][]byte,
	_ [][]*x509.Certificate,
) error {

	return v.verifyRawPeerCertificate(rawCerts, x509.ExtKeyUsageServerAuth)
}

// VerifyClientCertificate verifies the certificate presented by the client
// using the CP-PKI.
func (v *TLSCryptoVerifier) VerifyClientCertificate(
	rawCerts [][]byte,
	_ [][]*x509.Certificate,
) error {

	return v.verifyRawPeerCertificate(rawCerts, x509.ExtKeyUsageClientAuth)
}

// VerifyParsedClientCertificate verifies the certificate presented by the
// client using the CP-PKI.
// If the certificate is valid, returns the subject IA.
func (v *TLSCryptoVerifier) VerifyParsedClientCertificate(
	chain []*x509.Certificate,
) (addr.IA, error) {

	return v.verifyParsedPeerCertificate(chain, x509.ExtKeyUsageClientAuth)
}

// VerifyConnection callback is intended to be used by the client to verify
// that the certificate presented by the server matches the server name
// the client is trying to connect to.
func (v *TLSCryptoVerifier) VerifyConnection(cs tls.ConnectionState) error {
	serverNameIA := strings.Split(cs.ServerName, ",")[0]
	serverIA, err := addr.ParseIA(serverNameIA)
	if err != nil {
		return serrors.Wrap("extracting IA from server name", err, "connState", cs)
	}
	certIA, err := cppki.ExtractIA(cs.PeerCertificates[0].Subject)
	if err != nil {
		return serrors.Wrap("extracting IA from peer cert", err)
	}
	if !serverIA.Equal(certIA) {
		return serrors.New("extracted IA from cert and server IA do not match",
			"peer IA", certIA, "server IA", serverIA)
	}
	return nil
}

// verifyRawPeerCertificate verifies the certificate presented by the peer during TLS handshake,
// based on the TRC.
func (v *TLSCryptoVerifier) verifyRawPeerCertificate(
	rawCerts [][]byte,
	extKeyUsage x509.ExtKeyUsage,
) error {

	chain := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return serrors.Wrap("parsing peer certificate", err)
		}
		chain[i] = cert
	}
	_, err := v.verifyParsedPeerCertificate(chain, extKeyUsage)
	return err
}

// verifyParsedPeerCertificate verifies the certificate presented by the peer during TLS handshake,
// based on the TRC.
func (v *TLSCryptoVerifier) verifyParsedPeerCertificate(
	chain []*x509.Certificate,
	extKeyUsage x509.ExtKeyUsage,
) (addr.IA, error) {

	if len(chain) == 0 {
		return 0, serrors.New("no peer certificate provided")
	}
	if err := verifyExtendedKeyUsage(chain[0], extKeyUsage); err != nil {
		return 0, err
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return 0, serrors.Wrap("extracting ISD-AS from peer certificate", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), v.Timeout)
	defer cancel()
	trcs, _, err := activeTRCs(ctx, v.DB, ia.ISD())
	if err != nil {
		return 0, serrors.Wrap("loading TRCs", err)
	}
	if err := verifyChain(chain, trcs); err != nil {
		return 0, serrors.Wrap("verifying chains", err)
	}
	return ia, nil
}

func verifyChain(chain []*x509.Certificate, trcs []cppki.SignedTRC) error {
	var errs serrors.List
	for _, trc := range trcs {
		verifyOptions := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
		if err := cppki.VerifyChain(chain, verifyOptions); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return errs.ToError()
}

// verifyExtendedKeyUsage return an error if the certifcate extended key usages do not
// include any requested extended key usage.
func verifyExtendedKeyUsage(cert *x509.Certificate, expectedKeyUsage x509.ExtKeyUsage) error {
	for _, certExtKeyUsage := range cert.ExtKeyUsage {
		if expectedKeyUsage == certExtKeyUsage {
			return nil
		}
	}
	return serrors.New("Invalid certificate key usages")
}
