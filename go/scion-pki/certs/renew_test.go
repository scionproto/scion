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
	"crypto"
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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/xtest"
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

func TestBuildMsgr(t *testing.T) {
	testCases := map[string]struct {
		dp            reliable.Dispatcher
		sd            sciond.Service
		local, remote string
	}{
		"valid": {
			dp:     reliable.NewDispatcher("[127.0.0.19]:30255"),
			sd:     sciond.NewService("/run/shm/dispatcher/default.sock"),
			local:  "1-ff00:0:111,[127.0.0.18]:0",
			remote: "1-ff00:0:110,[127.0.0.11]:4001",
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			local, err := snet.ParseUDPAddr(tc.local)
			require.NoError(t, err)
			remote, err := snet.ParseUDPAddr(tc.remote)
			require.NoError(t, err)
			_, err = buildMsgr(context.Background(), tc.dp, tc.sd, local, remote)
			require.Error(t, err)
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
		Msgr   func(t *testing.T, mctrl *gomock.Controller) infra.Messenger
	}{
		"valid": {
			Remote: xtest.MustParseIA("1-ff00:0:110"),
			Msgr: func(t *testing.T, mctrl *gomock.Controller) infra.Messenger {
				c := xtest.LoadChain(t, "testdata/renew/ISD1-ASff00_0_111.pem")
				raw := []byte{}
				raw = append(raw, c[0].Raw...)
				raw = append(raw, c[1].Raw...)

				signer := trust.Signer{
					PrivateKey:   key,
					Hash:         crypto.SHA512,
					IA:           xtest.MustParseIA("1-ff00:0:110"),
					TRCID:        trc.TRC.ID,
					SubjectKeyID: []byte("subject-key-id"),
					Expiration:   time.Now().Add(20 * time.Hour),
				}
				meta, err := signer.Sign(context.Background(), raw)
				require.NoError(t, err)

				rep := &cert_mgmt.ChainRenewalReply{
					RawChain:  raw,
					Signature: meta,
				}

				// TODO(karampok). Build matchers instead of gomock.Any()
				// we have to verify that the req is valid signature wise.
				m := mock_infra.NewMockMessenger(mctrl)
				m.EXPECT().RequestChainRenewal(ctxMatcher{}, gomock.Any(), gomock.Any(),
					gomock.Any()).Return(rep, nil)
				return m
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
				Hash:         crypto.SHA512,
				IA:           xtest.MustParseIA("1-ff00:0:111"),
				TRCID:        trc.TRC.ID,
				SubjectKeyID: []byte("subject-key-id"),
				Expiration:   time.Now().Add(20 * time.Hour),
			}

			chain, err := renew(context.Background(), csr, tc.Remote, signer, tc.Msgr(t, mctrl))
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
