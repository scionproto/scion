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

type X509KeyPairLoader interface {
	// LoadServerKeyPair provides a certificate to be presented by the server
	// during TLS handshake.
	LoadServerKeyPair(ctx context.Context) (*tls.Certificate, error)
	// LoadClientKeyPair provides a certificate to be presented by the client
	// during TLS handshake.
	LoadClientKeyPair(ctx context.Context) (*tls.Certificate, error)
}

// TLSCryptoManager implements callbacks which will be called during TLS handshake.
type TLSCryptoManager struct {
	Loader  X509KeyPairLoader
	DB      DB
	Timeout time.Duration
}

// NewTLSCryptoManager returns a new instance with the defaultTimeout.
func NewTLSCryptoManager(loader X509KeyPairLoader, db DB) *TLSCryptoManager {
	return &TLSCryptoManager{
		DB:      db,
		Loader:  loader,
		Timeout: defaultTimeout,
	}
}

// GetCertificate retrieves a certificate to be presented during TLS handshake.
func (m *TLSCryptoManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := m.Loader.LoadServerKeyPair(hello.Context())
	if err != nil {
		return nil, serrors.WrapStr("loading server key pair", err)
	}
	return c, nil
}

// GetClientCertificate retrieves a client certificate to be presented during TLS handshake.
func (m *TLSCryptoManager) GetClientCertificate(
	reqInfo *tls.CertificateRequestInfo,
) (*tls.Certificate, error) {

	c, err := m.Loader.LoadClientKeyPair(reqInfo.Context())
	if err != nil {
		return nil, serrors.WrapStr("loading client key pair", err)
	}
	return c, nil
}

// VerifyServerCertificate verifies the certificate presented by the server
// using the CP-PKI.
func (m *TLSCryptoManager) VerifyServerCertificate(
	rawCerts [][]byte,
	_ [][]*x509.Certificate,
) error {

	return m.verifyPeerCertificate(rawCerts, x509.ExtKeyUsageServerAuth)
}

// VerifyClientCertificate verifies the certificate presented by the client
// using the CP-PKI.
func (m *TLSCryptoManager) VerifyClientCertificate(
	rawCerts [][]byte,
	_ [][]*x509.Certificate,
) error {

	return m.verifyPeerCertificate(rawCerts, x509.ExtKeyUsageClientAuth)
}

// VerifyConnection callback is intended to be used by the client to verify
// that the certificate presented by the server matches the server name
// the client is trying to connect to.
func (m *TLSCryptoManager) VerifyConnection(cs tls.ConnectionState) error {
	serverNameIA := strings.Split(cs.ServerName, ",")[0]
	serverIA, err := addr.ParseIA(serverNameIA)
	if err != nil {
		return serrors.WrapStr("extracting IA from server name", err)
	}
	certIA, err := cppki.ExtractIA(cs.PeerCertificates[0].Subject)
	if err != nil {
		return serrors.WrapStr("extracting IA from peer cert", err)
	}
	if !serverIA.Equal(certIA) {
		return serrors.New("extracted IA from cert and server IA do not match",
			"peer IA", certIA, "server IA", serverIA)
	}
	return nil
}

// verifyPeerCertificate verifies the certificate presented by the peer during TLS handshake,
// based on the TRC.
func (m *TLSCryptoManager) verifyPeerCertificate(
	rawCerts [][]byte,
	extKeyUsage x509.ExtKeyUsage,
) error {

	chain := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return serrors.WrapStr("parsing peer certificate", err)
		}
		chain[i] = cert
	}
	if err := verifyExtendedKeyUsage(chain[0], extKeyUsage); err != nil {
		return err
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return serrors.WrapStr("extracting ISD-AS from peer certificate", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.Timeout)
	defer cancel()
	trcs, _, err := activeTRCs(ctx, m.DB, ia.ISD())
	if err != nil {
		return serrors.WrapStr("loading TRCs", err)
	}
	if err := verifyChain(chain, trcs); err != nil {
		return serrors.WrapStr("verifying chains", err)
	}
	return nil
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
