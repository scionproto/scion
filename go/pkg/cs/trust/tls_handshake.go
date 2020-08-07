// Copyright 2020 ETH Zurich

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//   http://www.apache.org/licenses/LICENSE-2.0

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

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
)

// X509KeyPairLoader provides a certificate to be presented during TLS HS.
type X509KeyPairLoader interface {
	LoadX509KeyPair() (*tls.Certificate, error)
}

// TLSCryptoManager implements callbacks which will be called during TLS HS.
type TLSCryptoManager struct {
	Loader X509KeyPairLoader
	DB     trust.DB
}

// GetCertificate retrieves a certificate to be presented during TLS HS.
func (m *TLSCryptoManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := m.Loader.LoadX509KeyPair()
	if err != nil {
		return nil, serrors.WrapStr("Error loading server key pair", err)
	}
	return c, nil
}

// GetClientCertificate retrieves a client certificate to be presented during TLS HS.
func (m *TLSCryptoManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate,
	error) {
	c, err := m.Loader.LoadX509KeyPair()
	if err != nil {
		return nil, serrors.WrapStr("Error loading client key pair", err)
	}
	return c, nil
}

// VerifyPeerCertificate verifies the certificate presented by the peer during TLS HS,
// based on the TRC.
func (m *TLSCryptoManager) VerifyPeerCertificate(rawCerts [][]byte,
	verifiedChains [][]*x509.Certificate) error {

	chain := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return serrors.New("failed to parse peer certificate", "err", err)
		}
		chain[i] = cert
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return serrors.WrapStr("error extracting IA from peer cert", err)
	}
	trc, err := m.DB.SignedTRC(context.Background(), cppki.TRCID{
		ISD:    ia.I,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		return serrors.WrapStr("loading TRC", err)
	}
	if trc.IsZero() {
		return serrors.New("TRC not found")
	}
	opts := cppki.VerifyOptions{TRC: &trc.TRC}
	return cppki.VerifyChain(chain, opts)
}
