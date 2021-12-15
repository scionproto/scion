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
	"crypto/x509/pkix"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	beaconlib "github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/ca/renewal"
	"github.com/scionproto/scion/go/pkg/ca/renewal/mock_renewal"
	"github.com/scionproto/scion/go/pkg/cs/api/mock_api"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/cs/trust/mock_trust"
	"github.com/scionproto/scion/go/pkg/storage/beacon"
	"github.com/scionproto/scion/go/pkg/trust"
)

var update = xtest.UpdateGoldenFiles()

// TestAPI tests the API response generation of the endpoints implemented in the
// api package.
func TestAPI(t *testing.T) {
	testCases := map[string]struct {
		Handler            func(t *testing.T, ctrl *gomock.Controller) http.Handler
		RequestURL         string
		Status             int
		IgnoreResponseBody bool
	}{
		"beacons": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{},
				).AnyTimes().Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons",
			Status:     200,
		},
		"beacons non-existing sort": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{},
				).Times(0).Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons?sort=invalid",
			Status:     400,
		},
		"beacons sort owner": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{},
				).Times(1).Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons?sort=ingress_interface_id",
			Status:     200,
		},
		"beacons descending order": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{},
				).Times(1).Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons?desc=true",
			Status:     200,
		},
		"beacons non-existing usages": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{},
				).Times(0).Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons?usages=up_registration&usages=Invalid",
			Status:     400,
		},
		"beacons existing usages": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_api.NewMockBeaconStore(ctrl)
				s := &Server{
					Beacons: bs,
				}
				dbresult := createBeacons(t)
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{
						Usages: []beaconlib.Usage{beaconlib.UsageCoreReg | beaconlib.UsageUpReg},
					},
				).Times(1).Return(dbresult, nil)
				return Handler(s)
			},
			RequestURL: "/beacons?usages=up_registration&usages=core_registration",
			Status:     200,
		},
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
						IA:        xtest.MustParseIA("1-ff00:0:110"),
						Algorithm: signed.ECDSAWithSHA512,
						Subject: pkix.Name{
							Country:    []string{"CH"},
							CommonName: "1-ff00:0:110 AS Certificate",
						},
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
			RequestURL: "/signer",
			Status:     200,
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
					trust.Signer{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL: "/signer",
			Status:     500,
		},
		"signer blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				validCert, _ := cppki.ReadPEMCerts(filepath.Join("testdata", "signer-chain.crt"))
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					trust.Signer{
						Chain: validCert,
					}, nil,
				)
				return Handler(s)
			},
			RequestURL: "/signer/blob",
			Status:     200,
		},
		"signer blob error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					trust.Signer{}, nil,
				)
				return Handler(s)
			},
			RequestURL: "/signer/blob",
			Status:     500,
		},
		"ca": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: renewal.ChainBuilder{
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
			RequestURL: "/ca",
			Status:     200,
		},
		"ca error (empty certificate)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: renewal.ChainBuilder{
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
			RequestURL: "/ca",
			Status:     500,
		},
		"ca error (no signer)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &Server{
					CA: renewal.ChainBuilder{
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
			RequestURL: "/ca",
			Status:     500,
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
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				require.NoError(t, ioutil.WriteFile(goldenFile, rr.Body.Bytes(), 0666))
			}
			golden, err := ioutil.ReadFile(goldenFile)
			require.NoError(t, err)
			assert.Equal(t, string(golden), rr.Body.String())
		})
	}
}

func createBeacons(t *testing.T) []beacon.Beacon {
	return []beacon.Beacon{
		{
			Beacon: beaconlib.Beacon{
				Segment: &seg.PathSegment{
					Info: seg.Info{
						Timestamp: time.Date(2021, 1, 1, 8, 0, 0, 0, time.UTC),
					},
					ASEntries: []seg.ASEntry{{
						Local: addr.IA{I: 0, A: 0},
						Next:  addr.IA{I: 1, A: 1},
					}}},
				InIfId: 2,
			},
			Usage:       beaconlib.UsageCoreReg | beaconlib.UsageDownReg,
			LastUpdated: time.Date(2021, 1, 2, 8, 0, 0, 0, time.UTC),
		},
		{
			Beacon: beaconlib.Beacon{
				Segment: &seg.PathSegment{
					Info: seg.Info{
						Timestamp: time.Date(2021, 2, 1, 8, 0, 0, 0, time.UTC),
					},
					ASEntries: []seg.ASEntry{{
						Local: addr.IA{I: 2, A: 2},
						Next:  addr.IA{I: 3, A: 3},
					}}},
				InIfId: 1,
			},
			Usage:       beaconlib.UsageCoreReg | beaconlib.UsageDownReg,
			LastUpdated: time.Date(2021, 2, 2, 8, 0, 0, 0, time.UTC),
		},
	}
}
