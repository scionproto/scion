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
	"encoding/json"
	"fmt"
	"path/filepath"
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
	"github.com/scionproto/scion/go/proto"
)

func TestCreateCSR(t *testing.T) {
	input := `
{
	"common_name": "bern",
	"country": "CH",
	"organization": "bern",
	"organizational_unit": "bern InfoSec Squad",
	"locality": "bern",
	"isd_as": "1-ff00:0:110"
}
`
	wantSubject := pkix.Name{
		CommonName:         "bern",
		Country:            []string{"CH"},
		Locality:           []string{"bern"},
		Organization:       []string{"bern"},
		OrganizationalUnit: []string{"bern InfoSec Squad"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1},
				Value: "1-ff00:0:110",
			},
		},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testCases := map[string]struct {
		input []byte
		want  pkix.Name
	}{
		"valid": {
			input: []byte(input),
			want:  wantSubject,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n := subjectVars{}
			require.NoError(t, json.Unmarshal(tc.input, &n))

			csr, err := buildCSR(n, key)
			require.NoError(t, err)

			got, err := x509.ParseCertificateRequest(csr)
			require.NoError(t, err)
			ia, err := cppki.ExtractIA(got.Subject)
			require.NoError(t, err)
			assert.Equal(t, "1-ff00:0:110", ia.String())
			assert.Equal(t, x509.ECDSAWithSHA512, got.SignatureAlgorithm)
			// TODO(karampok). compare pkixName
			// assert.Equal(t, tc.want, got.Subject)
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

func TestRunRenew(t *testing.T) {
	goldenDir := "testdata/renew"

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1-B1-S1.trc"))
	validSignS := func(msg []byte, rawIA string) *proto.SignS {
		ia, _ := addr.IAFromString(rawIA)
		signer := trust.Signer{
			PrivateKey:   key,
			Hash:         crypto.SHA512,
			IA:           ia,
			TRCID:        trc.TRC.ID,
			SubjectKeyID: []byte("subject-key-id"),
			Expiration:   time.Now().Add(20 * time.Hour),
		}
		meta, err := signer.Sign(context.Background(), msg)
		require.NoError(t, err)
		return meta
	}

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	testCases := map[string]struct {
		csr                         []byte
		input                       string
		localIA, remoteIA           addr.IA
		msgr                        func() infra.Messenger
		transportCert, transportKey string
	}{
		"valid": {
			csr:           []byte("dummy"),
			localIA:       xtest.MustParseIA("1-ff00:0:111"),
			remoteIA:      xtest.MustParseIA("1-ff00:0:110"),
			transportCert: "testdata/renew/ISD1-ASff00_0_111.pem",
			transportKey:  "testdata/renew/cp-as.key",
			msgr: func() infra.Messenger {
				c := [][]*x509.Certificate{xtest.LoadChain(t,
					filepath.Join(goldenDir, "ISD1-ASff00_0_111.pem"))}
				raw := []byte{}
				raw = append(raw, c[0][0].Raw...)
				raw = append(raw, c[0][1].Raw...)
				sign := validSignS(raw, "1-ff00:0:111")
				rep := &cert_mgmt.ChainRenewalReply{
					RawChain:  raw,
					Signature: sign,
				}
				// TODO(karampok). Build matchers instead of gomock.Any()
				// we have to verify that the req is valid signature wise.
				m := mock_infra.NewMockMessenger(mctrl)
				m.EXPECT().RequestChainRenewal(ctxMatcher{},
					gomock.Any(), gomock.Any(), gomock.Any()).Return(rep, nil).Times(1)
				return m
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			chain, err := runRenew(context.Background(), tc.csr, tc.localIA, tc.remoteIA,
				trc, tc.transportCert, tc.transportKey, tc.msgr())
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
