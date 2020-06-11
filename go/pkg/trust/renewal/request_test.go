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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/proto"
)

var update = flag.Bool("update", false, "Update all the testdata crypto")

func TestUpdateCrypto(t *testing.T) {
	if !(*update) {
		t.Skip("Only runs if -update is specified")
	}

	dir, cleanF := xtest.MustTempDir("", "trustdbtest")
	defer cleanF()

	testdata, err := filepath.Abs("./testdata")
	require.NoError(t, err)
	root, err := filepath.Abs("../../../../")
	require.NoError(t, err)
	playground, err := filepath.Abs(filepath.Join(root, "scripts", "cryptoplayground"))
	require.NoError(t, err)
	cmd := exec.Command("sh", "-c", filepath.Join("testdata", "update_certs.sh"))
	cmd.Env = []string{
		"SCION_ROOT=" + root,
		"PLAYGROUND=" + playground,
		"SAFEDIR=" + dir,
		"TESTDATA=" + testdata,
		"STARTDATE=20200624120000Z",
		"ENDDATE=20210624120000Z",
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestNewChainRenewalRequest(t *testing.T) {
	chain := loadChainFiles(t, "bern", 1)
	csr := loadCSR(t, "./testdata/bern/cp-as2.csr")

	testCases := map[string]struct {
		csr        []byte
		signer     trust.Signer
		want       *cert_mgmt.ChainRenewalRequest
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			csr: csr.Raw,
			signer: trust.Signer{
				PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
				Hash:       crypto.SHA512,
				IA:         xtest.MustExtractIA(t, chain[0]),
				TRCID: cppki.TRCID{
					ISD:    1,
					Base:   1,
					Serial: 1,
				},
				SubjectKeyID: chain[0].SubjectKeyId,
				Expiration:   time.Now().Add(2 * time.Hour),
			},
			want: &cert_mgmt.ChainRenewalRequest{
				RawCSR: csr.Raw,
			},
			assertFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := renewal.NewChainRenewalRequest(context.Background(), tc.csr, tc.signer)
			tc.assertFunc(t, err)
			if tc.want == nil {
				return
			}
			assert.Equal(t, tc.want.RawCSR, got.RawCSR)

			chains := [][]*x509.Certificate{chain}
			_, err = renewal.VerifyChainRenewalRequest(got, chains)
			assert.NoError(t, err)
		})
	}

}

func TestVerifyChainRenewalRequest(t *testing.T) {
	bern1Chain := loadChainFiles(t, "bern", 1)
	bern2Chain := loadChainFiles(t, "bern", 2)
	geneva1Chain := loadChainFiles(t, "geneva", 1)
	bern2CSR := loadCSR(t, "./testdata/bern/cp-as2.csr")
	bern3CSR := loadCSR(t, "./testdata/bern/cp-as3.csr")

	testCases := map[string]struct {
		request      *cert_mgmt.ChainRenewalRequest
		buildRequest func(t *testing.T) *cert_mgmt.ChainRenewalRequest
		chains       [][]*x509.Certificate
		assertErr    assert.ErrorAssertionFunc
	}{
		"nil request": {
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"CSR missing identity": {
			buildRequest: func(t *testing.T) *cert_mgmt.ChainRenewalRequest {
				// It's really weird how CreateCertificateRequest works, the
				// subject contains the IA in the name, but when creating a
				// CertificateRequest we need to put it into extra names.
				// So by just recreating we drop the IA.
				subject := bern2CSR.Subject
				rawCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					SignatureAlgorithm: bern2CSR.SignatureAlgorithm,
					Subject:            subject,
					DNSNames:           bern2CSR.DNSNames,
					EmailAddresses:     bern2CSR.EmailAddresses,
					IPAddresses:        bern2CSR.IPAddresses,
					URIs:               bern2CSR.URIs,
					ExtraExtensions:    bern2CSR.ExtraExtensions,
				},
					loadKey(t, "./testdata/bern/cp-as2.key"))
				require.NoError(t, err)
				csr, err := x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)
				return &cert_mgmt.ChainRenewalRequest{
					RawCSR: csr.Raw,
					Signature: sign(t, trust.Signer{
						PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
						Hash:       crypto.SHA512,
						IA:         xtest.MustExtractIA(t, bern1Chain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bern1Chain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
					}, csr.Raw),
				}
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"CSR invalid identity": {
			buildRequest: func(t *testing.T) *cert_mgmt.ChainRenewalRequest {
				// It's really weird how CreateCertificateRequest works, the
				// subject contains the IA in the name, but when creating a
				// CertificateRequest we need to put it into extra names.
				subject := bern2CSR.Subject
				subject.ExtraNames = append(subject.ExtraNames, pkix.AttributeTypeAndValue{
					Type:  cppki.OIDNameIA,
					Value: "fooBar",
				})
				rawCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					SignatureAlgorithm: bern2CSR.SignatureAlgorithm,
					Subject:            subject,
					DNSNames:           bern2CSR.DNSNames,
					EmailAddresses:     bern2CSR.EmailAddresses,
					IPAddresses:        bern2CSR.IPAddresses,
					URIs:               bern2CSR.URIs,
					ExtraExtensions:    bern2CSR.Extensions,
				},
					loadKey(t, "./testdata/bern/cp-as2.key"))
				require.NoError(t, err)
				csr, err := x509.ParseCertificateRequest(rawCSR)
				require.NoError(t, err)
				return &cert_mgmt.ChainRenewalRequest{
					RawCSR: csr.Raw,
					Signature: sign(t, trust.Signer{
						PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
						Hash:       crypto.SHA512,
						IA:         xtest.MustExtractIA(t, bern1Chain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bern1Chain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
					}, csr.Raw),
				}
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"CSR wrong signature": {
			buildRequest: func(t *testing.T) *cert_mgmt.ChainRenewalRequest {
				invalidCSRRaw := append([]byte(nil), bern2CSR.Raw...)
				invalidCSRRaw[len(invalidCSRRaw)-1] = invalidCSRRaw[len(invalidCSRRaw)-1] ^ 0xFF
				invalidCSR, err := x509.ParseCertificateRequest(invalidCSRRaw)
				require.NoError(t, err)
				return &cert_mgmt.ChainRenewalRequest{
					RawCSR: invalidCSR.Raw,
					Signature: sign(t, trust.Signer{
						PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
						Hash:       crypto.SHA512,
						IA:         xtest.MustExtractIA(t, bern1Chain[0]),
						TRCID: cppki.TRCID{
							ISD:    1,
							Base:   1,
							Serial: 1,
						},
						SubjectKeyID: bern1Chain[0].SubjectKeyId,
						Expiration:   time.Now().Add(2 * time.Hour),
					}, invalidCSR.Raw),
				}
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"signature src invalid": {
			buildRequest: func(t *testing.T) *cert_mgmt.ChainRenewalRequest {
				signature := sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern2CSR.Raw)
				signature.Src = nil
				return &cert_mgmt.ChainRenewalRequest{
					RawCSR:    bern2CSR.Raw,
					Signature: signature,
				}
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"no chains": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern2CSR.Raw),
			},
			assertErr: assert.Error,
		},
		"missing signature": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"signature wrong key": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as2.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern2CSR.Raw),
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"signature wrong content": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, []byte("not the CSR")),
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"invalid CSR": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: []byte("invalid CSR"),
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, []byte("invalid CSR")),
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.Error,
		},
		"signature different IA": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/geneva/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, geneva1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: geneva1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern2CSR.Raw),
			},
			// since we don't know what the calling code will use to identify
			// the chain, let's provide both.
			chains:    [][]*x509.Certificate{bern1Chain, geneva1Chain},
			assertErr: assert.Error,
		},
		"valid": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern2CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as1.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern1Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern1Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern2CSR.Raw),
			},
			chains:    [][]*x509.Certificate{bern1Chain},
			assertErr: assert.NoError,
		},
		"valid chain overlap": {
			request: &cert_mgmt.ChainRenewalRequest{
				RawCSR: bern3CSR.Raw,
				Signature: sign(t, trust.Signer{
					PrivateKey: loadKey(t, "./testdata/bern/cp-as2.key"),
					Hash:       crypto.SHA512,
					IA:         xtest.MustExtractIA(t, bern2Chain[0]),
					TRCID: cppki.TRCID{
						ISD:    1,
						Base:   1,
						Serial: 1,
					},
					SubjectKeyID: bern2Chain[0].SubjectKeyId,
					Expiration:   time.Now().Add(2 * time.Hour),
				}, bern3CSR.Raw),
			},
			chains:    [][]*x509.Certificate{bern1Chain, bern2Chain},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := tc.request
			if req == nil && tc.buildRequest != nil {
				req = tc.buildRequest(t)
			}
			_, err := renewal.VerifyChainRenewalRequest(req, tc.chains)
			tc.assertErr(t, err)
		})
	}
}

func sign(t *testing.T, signer trust.Signer, msg []byte) *proto.SignS {
	s, err := signer.Sign(context.Background(), msg)
	require.NoError(t, err)
	return s
}

func loadKey(t *testing.T, file string) crypto.Signer {
	t.Helper()
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.Equal(t, "PRIVATE KEY", block.Type, "Wrong block type %s", block.Type)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(crypto.Signer)
}

func loadCSR(t *testing.T, file string) *x509.CertificateRequest {
	t.Helper()
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	var block *pem.Block
	block, _ = pem.Decode(raw)
	require.NotNil(t, block, "Failed to extract PEM block")
	require.Equal(t, "CERTIFICATE REQUEST", block.Type, "Wrong block type %s", block.Type)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return csr
}

func loadChainFiles(t *testing.T, org string, asVersion int) []*x509.Certificate {
	t.Helper()
	return []*x509.Certificate{
		xtest.LoadChain(t, filepath.Join("testdata",
			org, fmt.Sprintf("cp-as%d.crt", asVersion)))[0],
		xtest.LoadChain(t, filepath.Join("testdata", org, "cp-ca.crt"))[0],
	}
}
