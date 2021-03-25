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

package certs

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestCSRTemplate(t *testing.T) {
	wantSubject := pkix.Name{
		CommonName:         "1-ff00:0:111 AS Certificate",
		Country:            []string{"CH"},
		Organization:       []string{"1-ff00:0:111"},
		OrganizationalUnit: []string{"1-ff00:0:111 InfoSec Squad"},
		Locality:           []string{"Zürich"},
		Province:           []string{"Zürich"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1},
				Value: "1-ff00:0:111",
			},
		},
	}
	key, err := readECKey("testdata/renew/cp-as.key")
	require.NoError(t, err)
	chain, err := cppki.ReadPEMCerts("testdata/renew/ISD1-ASff00_0_111.pem")
	require.NoError(t, err)

	testCases := map[string]struct {
		File         string
		Expected     pkix.Name
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			File:         "testdata/renew/ISD1-ASff00_0_111.csr.json",
			Expected:     wantSubject,
			ErrAssertion: assert.NoError,
		},
		"from chain": {
			File:         "",
			Expected:     wantSubject,
			ErrAssertion: assert.NoError,
		},
		"no ISD-AS": {
			File:         "testdata/renew/no_isd_as.json",
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			csr, err := csrTemplate(chain[0], key.Public(), tc.File)
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, x509.UnknownSignatureAlgorithm, csr.SignatureAlgorithm)
			assert.Equal(t, tc.Expected.String(), csr.Subject.String())
		})
	}
}

func TestExtractChain(t *testing.T) {
	chain := xtest.LoadChain(t, "testdata/renew/ISD1-ASff00_0_111.pem")

	caChain := xtest.LoadChain(t, "testdata/renew/ISD1-ASff00_0_110.pem")
	key, err := readECKey("testdata/renew/cp-as-110.key")
	require.NoError(t, err)
	caSigner := trust.Signer{
		PrivateKey:   key,
		Algorithm:    signed.ECDSAWithSHA256,
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		SubjectKeyID: caChain[0].SubjectKeyId,
		Expiration:   time.Now().Add(20 * time.Hour),
		Chain:        caChain,
	}

	testCases := map[string]struct {
		Response     func(t *testing.T) *cppb.ChainRenewalResponse
		Expected     []*x509.Certificate
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"legacy only": {
			Response: func(t *testing.T) *cppb.ChainRenewalResponse {
				rawBody, err := proto.Marshal(&cppb.ChainRenewalResponseBody{
					Chain: &cppb.Chain{
						AsCert: chain[0].Raw,
						CaCert: chain[1].Raw,
					},
				})
				require.NoError(t, err)
				signedMsg, err := caSigner.Sign(context.Background(), rawBody)
				require.NoError(t, err)
				return &cppb.ChainRenewalResponse{
					SignedResponse: signedMsg,
				}
			},
			Expected:     chain,
			ErrAssertion: assert.NoError,
		},
		"cms only": {
			Response: func(t *testing.T) *cppb.ChainRenewalResponse {
				rawBody := append(chain[0].Raw, chain[1].Raw...)
				signedCMS, err := caSigner.SignCMS(context.Background(), rawBody)
				require.NoError(t, err)
				return &cppb.ChainRenewalResponse{
					CmsSignedResponse: signedCMS,
				}
			},
			Expected:     chain,
			ErrAssertion: assert.NoError,
		},
		"combined, prefer cms": {
			Response: func(t *testing.T) *cppb.ChainRenewalResponse {
				rawBody, err := proto.Marshal(&cppb.ChainRenewalResponseBody{
					// Use CA chain to see which chain is returned.
					Chain: &cppb.Chain{
						AsCert: caChain[0].Raw,
						CaCert: caChain[1].Raw,
					},
				})
				require.NoError(t, err)
				signedMsg, err := caSigner.Sign(context.Background(), rawBody)
				require.NoError(t, err)

				rawBody = append(chain[0].Raw, chain[1].Raw...)
				signedCMS, err := caSigner.SignCMS(context.Background(), rawBody)
				require.NoError(t, err)
				return &cppb.ChainRenewalResponse{
					SignedResponse:    signedMsg,
					CmsSignedResponse: signedCMS,
				}
			},
			Expected:     chain,
			ErrAssertion: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			rep := tc.Response(t)
			renewed, err := extractChain(rep)
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.Expected, renewed)
		})
	}
}
