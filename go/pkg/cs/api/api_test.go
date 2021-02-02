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

package api

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	pkgapi "github.com/scionproto/scion/go/pkg/api"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/cs/trust/mock_trust"
	"github.com/scionproto/scion/go/pkg/trust"
)

// update is a cmd line flag that enables golden file updates. To update the
// golden files simply run 'go test -update ./...'.
var update = flag.Bool("update", false, "set to true to regenerate golden files")

// TestAPI tests the API response generation of the endpoints implemented in the
// api package
func TestAPI(t *testing.T) {
	type args struct {
		apiCfg pkgapi.Config
		cfg    interface{}
		signer cstrust.RenewingSigner
		ca     cstrust.ChainBuilder
	}
	testCases := map[string]struct {
		Handler            func(t *testing.T, ctrl *gomock.Controller) http.Handler
		RequestURL         string
		ResponseFile       string
		Status             int
		IgnoreResponseBody bool
	}{
		"signer": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					trust.Signer{
						IA:           xtest.MustParseIA("1-ff00:0:110"),
						Algorithm:    signed.ECDSAWithSHA512,
						SubjectKeyID: []byte("лучший учитель"),
						TRCID: cppki.TRCID{
							ISD:    1,
							Serial: 42,
							Base:   1,
						},
						Expiration: time.Unix(1611061121, 0).UTC(),
						ChainValidity: cppki.Validity{
							NotBefore: time.Unix(1611051121, 0).UTC(),
							NotAfter:  time.Unix(1611061121, 0).UTC(),
						},
						InGrace: true,
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/signer-response.json",
			RequestURL:   "/signer",
			Status:       200,
		},
		"signer error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					trust.Signer{
						IA:           xtest.MustParseIA("1-ff00:0:110"),
						Algorithm:    signed.ECDSAWithSHA512,
						SubjectKeyID: []byte(""),
						TRCID: cppki.TRCID{
							ISD:    1,
							Serial: 42,
							Base:   1,
						},
						Expiration: time.Unix(1611061121, 0).UTC(),
						ChainValidity: cppki.Validity{
							NotBefore: time.Unix(1611051121, 0).UTC(),
							NotAfter:  time.Unix(1611061121, 0).UTC(),
						},
						InGrace: true,
					}, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:         "/signer",
			Status:             500,
			IgnoreResponseBody: true,
		},
		"ca": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: cstrust.ChainBuilder{
						PolicyGen: g,
					},
				}
				validCert, _ := cppki.ReadPEMCerts(filepath.Join("testdata", "cp-ca.crt"))
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					cppki.CAPolicy{
						Validity:    3 * 24 * time.Hour,
						Certificate: validCert[0],
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/ca.json",
			RequestURL:   "/ca",
			Status:       200,
		},
		"ca error (empty certificate)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: cstrust.ChainBuilder{
						PolicyGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					cppki.CAPolicy{
						Validity:    3 * 24 * time.Hour,
						Certificate: &x509.Certificate{},
						CurrentTime: time.Now(),
					}, nil,
				)
				return Handler(s)
			},
			RequestURL:         "/ca",
			Status:             500,
			IgnoreResponseBody: true,
		},
		"ca error (no signer)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: cstrust.ChainBuilder{
						PolicyGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					cppki.CAPolicy{
						Validity:    3 * 24 * time.Hour,
						Certificate: &x509.Certificate{},
						CurrentTime: time.Now(),
					}, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:         "/ca",
			Status:             500,
			IgnoreResponseBody: true,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			req, err := http.NewRequest("GET", tc.RequestURL, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			tc.Handler(t, ctrl).ServeHTTP(rr, req)

			assert.Equal(t, tc.Status, rr.Result().StatusCode)

			if tc.IgnoreResponseBody {
				return
			}
			if *update {
				require.NoError(t, ioutil.WriteFile(tc.ResponseFile, rr.Body.Bytes(), 0666))
			}
			golden, err := ioutil.ReadFile(tc.ResponseFile)
			require.NoError(t, err)
			assert.Equal(t, string(golden), rr.Body.String())
		})
	}
}
