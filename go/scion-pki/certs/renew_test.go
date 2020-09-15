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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	mock_cp "github.com/scionproto/scion/go/pkg/proto/control_plane/mock_control_plane"
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
			csr, err := csrTemplate(chain, tc.File)
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, x509.ECDSAWithSHA512, csr.SignatureAlgorithm)
			assert.Equal(t, tc.Expected.String(), csr.Subject.String())
		})
	}
}

func TestRenew(t *testing.T) {
	trc := xtest.LoadTRC(t, "testdata/renew/ISD1-B1-S1.trc")
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	csr := []byte("dummy")

	testCases := map[string]struct {
		Remote addr.IA
		Server func(t *testing.T, mctrl *gomock.Controller) *mock_cp.MockChainRenewalServiceServer
	}{
		"valid": {
			Remote: xtest.MustParseIA("1-ff00:0:110"),
			Server: func(t *testing.T,
				mctrl *gomock.Controller) *mock_cp.MockChainRenewalServiceServer {

				c := xtest.LoadChain(t, "testdata/renew/ISD1-ASff00_0_111.pem")
				body := cppb.ChainRenewalResponseBody{
					Chain: &cppb.Chain{
						AsCert: c[0].Raw,
						CaCert: c[1].Raw,
					},
				}
				rawBody, err := proto.Marshal(&body)
				require.NoError(t, err)

				signer := trust.Signer{
					PrivateKey:   key,
					Algorithm:    signed.ECDSAWithSHA512,
					IA:           xtest.MustParseIA("1-ff00:0:110"),
					TRCID:        trc.TRC.ID,
					SubjectKeyID: []byte("subject-key-id"),
					Expiration:   time.Now().Add(20 * time.Hour),
				}
				signedMsg, err := signer.Sign(context.Background(), rawBody)
				require.NoError(t, err)
				// TODO(karampok). Build matchers instead of gomock.Any()
				// we have to verify that the req is valid signature wise.
				srv := mock_cp.NewMockChainRenewalServiceServer(mctrl)
				srv.EXPECT().ChainRenewal(gomock.Any(), gomock.Any()).Return(
					&cppb.ChainRenewalResponse{
						SignedResponse: signedMsg,
					}, nil,
				)
				return srv
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			signer := trust.Signer{
				PrivateKey:   key,
				Algorithm:    signed.ECDSAWithSHA512,
				IA:           xtest.MustParseIA("1-ff00:0:111"),
				TRCID:        trc.TRC.ID,
				SubjectKeyID: []byte("subject-key-id"),
				Expiration:   time.Now().Add(20 * time.Hour),
			}

			svc := xtest.NewGRPCService()
			cppb.RegisterChainRenewalServiceServer(svc.Server(), tc.Server(t, mctrl))
			stop := svc.Start()
			defer stop()

			chain, err := renew(context.Background(), csr, tc.Remote, signer, svc)
			require.NoError(t, err)
			err = cppki.ValidateChain(chain)
			require.NoError(t, err)
		})
	}
}

type ctxMatcher struct{}

func (m ctxMatcher) Matches(x interface{}) bool {
	_, ok := x.(context.Context)
	return ok
}

func (m ctxMatcher) String() string {
	return fmt.Sprintf("it should be context.context")
}
