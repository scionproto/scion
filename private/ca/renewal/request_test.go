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

package renewal_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/trust"
)

func TestNewChainRenewalRequest(t *testing.T) {
	dir := genCrypto(t)

	var (
		chain = xtest.LoadChain(t, filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"))
		csr   = loadCSR(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.csr"))
	)

	testCases := map[string]struct {
		csr        []byte
		signer     trust.Signer
		verifier   renewal.RequestVerifier
		useCMS     bool
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			csr: csr.Raw,
			signer: trust.Signer{
				PrivateKey: loadKey(t, filepath.Join(dir, "/ASff00_0_110/crypto/as/cp-as.key")),
				Algorithm:  signed.ECDSAWithSHA256,
				IA:         xtest.MustExtractIA(t, chain[0]),
				TRCID: cppki.TRCID{
					ISD:    1,
					Base:   1,
					Serial: 1,
				},
				Chain:        chain,
				SubjectKeyID: chain[0].SubjectKeyId,
				Expiration:   time.Now().Add(2 * time.Hour),
			},
			verifier: renewal.RequestVerifier{
				TRCFetcher: mockTRCFetcher{
					TRCs: []cppki.SignedTRC{
						xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc")),
					},
				},
			},
			assertFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := renewal.NewChainRenewalRequest(
				context.Background(), tc.csr, tc.signer)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			// Check CSR is included.
			ci, err := protocol.ParseContentInfo(got.CmsSignedRequest)
			require.NoError(t, err)
			sd, err := ci.SignedDataContent()
			require.NoError(t, err)
			pld, err := sd.EncapContentInfo.EContentValue()
			require.NoError(t, err)
			csr, err := x509.ParseCertificateRequest(pld)
			require.NoError(t, err)
			assert.Equal(t, tc.csr, csr.Raw)

			// Check request is verifiable.
			_, err = tc.verifier.VerifyCMSSignedRenewalRequest(
				context.Background(),
				got.CmsSignedRequest,
			)
			assert.NoError(t, err)
		})
	}
}

func TestVerifyChainRenewalRequest(t *testing.T) {
	dir := genCrypto(t)

	var (
		bernChain   = xtest.LoadChain(t, filepath.Join(dir, "certs/ISD1-ASff00_0_110.pem"))
		genevaChain = xtest.LoadChain(t, filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem"))
		csr         = loadCSR(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.csr"))
		baseTRC     = xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
		nextTRC     = xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S2.trc"))
	)

	testCases := map[string]struct {
		buildRequest func(t *testing.T) *cppb.ChainRenewalRequest
		TRCFetcher   renewal.TRCFetcher
		assertErr    assert.ErrorAssertionFunc
	}{
		"CSR missing identity": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				rawCSR, err := x509.CreateCertificateRequest(rand.Reader,
					&x509.CertificateRequest{
						Subject: pkix.Name{
							CommonName: "1-ff00:0:111 AS Certificate",
						},
					},
					loadKey(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.key")))
				require.NoError(t, err)
				_, err = x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)

				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), rawCSR,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.Error,
		},
		"CSR invalid identity": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				rawCSR, err := x509.CreateCertificateRequest(rand.Reader,
					&x509.CertificateRequest{
						Subject: pkix.Name{
							CommonName: "1-ff00:0:111 AS Certificate",
							ExtraNames: []pkix.AttributeTypeAndValue{
								{
									Type:  cppki.OIDNameIA,
									Value: "1-ff00:0:111",
								},
							},
						},
					},
					loadKey(t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as1.key")))
				require.NoError(t, err)
				_, err = x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)

				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), rawCSR,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.Error,
		},
		"CSR wrong signature": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				invalid := append([]byte(nil), csr.Raw...)
				invalid[len(invalid)-1] = invalid[len(invalid)-1] ^ 0xFF
				_, err := x509.ParseCertificateRequest(invalid)
				require.NoError(t, err)

				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), invalid,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.Error,
		},
		"invalid CSR": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(),
					[]byte("wrong content"),
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.Error,
		},
		"signature different IA": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), csr.Raw,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_111/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: genevaChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        genevaChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.Error,
		},
		"no TRC": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), csr.Raw,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{},
			},
			assertErr: assert.Error,
		},
		"valid": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), csr.Raw,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC},
			},
			assertErr: assert.NoError,
		},
		"valid - TRC in grace period": {
			buildRequest: func(t *testing.T) *cppb.ChainRenewalRequest {
				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), csr.Raw,
					trust.Signer{
						PrivateKey: loadKey(
							t, filepath.Join(dir, "ASff00_0_110/crypto/as/cp-as.key"),
						),
						Algorithm: signed.ECDSAWithSHA256,

						IA: xtest.MustExtractIA(t, bernChain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bernChain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
						Chain:        bernChain,
					},
				)
				require.NoError(t, err)
				return signedReq
			},
			TRCFetcher: mockTRCFetcher{
				TRCs: []cppki.SignedTRC{baseTRC, nextTRC},
			},
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := tc.buildRequest(t)
			verifier := renewal.RequestVerifier{
				TRCFetcher: tc.TRCFetcher,
			}
			_, err := verifier.VerifyCMSSignedRenewalRequest(context.Background(),
				req.CmsSignedRequest)
			tc.assertErr(t, err)
		})
	}
}

func loadCSR(t *testing.T, file string) *x509.CertificateRequest {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var block *pem.Block
	block, _ = pem.Decode(raw)
	require.NotNil(t, block, "Failed to extract PEM block")
	require.Equal(t, "CERTIFICATE REQUEST", block.Type, "Wrong block type %s", block.Type)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return csr
}

type mockTRCFetcher struct {
	TRCs []cppki.SignedTRC
}

func (f mockTRCFetcher) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	if len(f.TRCs) > 0 && id.Base.IsLatest() && id.Serial.IsLatest() {
		return f.TRCs[len(f.TRCs)-1], nil
	}
	for _, trc := range f.TRCs {
		if trc.TRC.ID.Base == id.Base && trc.TRC.ID.Serial == id.Serial {
			return trc, nil
		}
	}
	return cppki.SignedTRC{}, serrors.New("no TRC found")
}
