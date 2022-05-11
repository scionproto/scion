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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"os/exec"
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
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

var updateNonDeterministic = xtest.UpdateNonDeterminsticGoldenFiles()

var goldenDir = "./testdata/cms"

var csrTmplBern = x509.CertificateRequest{
	Subject: pkix.Name{
		CommonName:         "1-ff00:0:110 AS Certificate",
		Country:            []string{"CH"},
		Province:           []string{"Bern"},
		Locality:           []string{"Bern"},
		Organization:       []string{"1-ff00:0:110"},
		OrganizationalUnit: []string{"1-ff00:0:110 InfoSec Squad"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  cppki.OIDNameIA,
				Value: "1-ff00:0:110",
			},
		},
	},
}

var csrTmplGeneva = x509.CertificateRequest{
	Subject: pkix.Name{
		CommonName:         "1-ff00:0:111 AS Certificate",
		Country:            []string{"CH"},
		Province:           []string{"Geneva"},
		Locality:           []string{"Geneva"},
		Organization:       []string{"1-ff00:0:111"},
		OrganizationalUnit: []string{"1-ff00:0:111 InfoSec Squad"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  cppki.OIDNameIA,
				Value: "1-ff00:0:111",
			},
		},
	},
}

func TestUpdateCrypto(t *testing.T) {
	if !(*updateNonDeterministic) {
		t.Skip("Only runs if -update is specified")
	}

	dir, cleanF := xtest.MustTempDir("", "tmp")
	defer cleanF()

	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/golden.topo",
		"-o", dir,
	})
	err := cmd.Execute()
	require.NoError(t, err)

	// Create keys and CSRs
	// AS110
	asDir := filepath.Join(dir, "ASff00_0_110")
	privKeyBern, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating private key AS110")
	writeKey(t, filepath.Join(asDir, "crypto/as", "cp-as1.key"), privKeyBern)

	csrBern, err := x509.CreateCertificateRequest(rand.Reader, &csrTmplBern, privKeyBern)
	require.NoError(t, err, "generating CSR AS110")
	writeCSR(t, filepath.Join(asDir, "crypto/as", "cp-as1.csr"), csrBern)
	// AS111
	asDir = filepath.Join(dir, "ASff00_0_111")
	privKeyGeneva, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating private key AS111")
	writeKey(t, filepath.Join(asDir, "crypto/as", "cp-as1.key"), privKeyGeneva)

	csrGeneva, err := x509.CreateCertificateRequest(rand.Reader, &csrTmplGeneva, privKeyGeneva)
	require.NoError(t, err, "generating CSR AS111")
	writeCSR(t, filepath.Join(asDir, "crypto/as", "cp-as1.csr"), csrGeneva)

	out, err := exec.Command("rm", "-rf", goldenDir).CombinedOutput()
	require.NoError(t, err, string(out))

	out, err = exec.Command("mv", dir, goldenDir).CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestNewChainRenewalRequest(t *testing.T) {
	chain := xtest.LoadChain(t, "./testdata/cms/certs/ISD1-ASff00_0_110.pem")
	csr := loadCSR(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as1.csr")

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
				PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
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
					TRCs: []cppki.SignedTRC{xtest.LoadTRC(t, "./testdata/cms/trcs/ISD1-B1-S1.trc")},
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
			csr, err = tc.verifier.VerifyCMSSignedRenewalRequest(context.Background(),
				got.CmsSignedRequest)
			assert.NoError(t, err)
		})
	}
}

func TestVerifyChainRenewalRequest(t *testing.T) {
	bernChain := xtest.LoadChain(t, "./testdata/cms/certs/ISD1-ASff00_0_110.pem")
	genevaChain := xtest.LoadChain(t, "./testdata/cms/certs/ISD1-ASff00_0_111.pem")
	csr := loadCSR(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as1.csr")
	baseTRC := xtest.LoadTRC(t, "./testdata/cms/trcs/ISD1-B1-S1.trc")
	nextTRC := cppki.SignedTRC{
		TRC:         baseTRC.TRC,
		SignerInfos: baseTRC.SignerInfos,
	}
	nextTRC.TRC.ID.Serial = 2
	nextTRC.TRC.Validity = cppki.Validity{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(2 * time.Hour),
	}
	nextTRC.TRC.GracePeriod = time.Hour
	nextTRC.TRC.Certificates = nil

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
					loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as1.key"))
				require.NoError(t, err)
				_, err = x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)

				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), rawCSR,
					trust.Signer{
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
					loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as1.key"))
				require.NoError(t, err)
				_, err = x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)

				signedReq, err := renewal.NewChainRenewalRequest(context.Background(), rawCSR,
					trust.Signer{
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_111/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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
						PrivateKey: loadKey(t, "./testdata/cms/ASff00_0_110/crypto/as/cp-as.key"),
						Algorithm:  signed.ECDSAWithSHA256,

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

func loadKey(t *testing.T, file string) crypto.Signer {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.Equal(t, "PRIVATE KEY", block.Type, "Wrong block type %s", block.Type)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(crypto.Signer)
}

func writeKey(t *testing.T, file string, key interface{}) {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: raw,
		},
	)
	require.NoError(t, os.WriteFile(file, keyPEM, 0644))
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

func writeCSR(t *testing.T, file string, csr []byte) {
	t.Helper()
	csrPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr,
		},
	)
	require.NoError(t, os.WriteFile(file, csrPEM, 0644))
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
