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

package mgmtapi_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	beaconlib "github.com/scionproto/scion/control/beacon"
	api "github.com/scionproto/scion/control/mgmtapi"
	"github.com/scionproto/scion/control/mgmtapi/mock_mgmtapi"
	cstrust "github.com/scionproto/scion/control/trust"
	"github.com/scionproto/scion/control/trust/mock_trust"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/ca/renewal"
	"github.com/scionproto/scion/private/ca/renewal/mock_renewal"
	"github.com/scionproto/scion/private/storage/beacon"
	"github.com/scionproto/scion/private/trust"
)

var update = xtest.UpdateGoldenFiles()

// TestAPI tests the API response generation of the endpoints implemented in the
// api package.
func TestAPI(t *testing.T) {
	now := time.Now()
	beacons := createBeacons(t)
	testCases := map[string]struct {
		Handler            func(t *testing.T, ctrl *gomock.Controller) http.Handler
		RequestURL         string
		Status             int
		IgnoreResponseBody bool
		TimestampOffset    time.Duration
	}{
		"beacons": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					matchQuery(&beacon.QueryParams{}),
				).AnyTimes().Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons",
			Status:     200,
		},
		"beacons non-existing sort": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					matchQuery(&beacon.QueryParams{}),
				).Times(0).Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons?sort=invalid",
			Status:     400,
		},
		"beacons sort by ingress interface": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					matchQuery(&beacon.QueryParams{}),
				).Times(1).Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons?sort=ingress_interface",
			Status:     200,
		},
		"beacons descending order": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					matchQuery(&beacon.QueryParams{}),
				).Times(1).Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons?desc=true",
			Status:     200,
		},
		"beacons non-existing usages": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					gomock.Any(),
				).Times(0).Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons?usages=up_registration&usages=Invalid",
			Status:     400,
		},
		"beacons existing usages": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					matchQuery(&beacon.QueryParams{
						Usages: []beaconlib.Usage{beaconlib.UsageDownReg | beaconlib.UsageUpReg},
					}),
				).Times(1).Return(beacons[:1], nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons?usages=up_registration&usages=down_registration",
			Status:     200,
		},
		"beacon": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{beacons[0].Beacon.Segment.ID()}},
				).AnyTimes().Return(beacons[:1], nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons/" + hex.EncodeToString(beacons[0].Beacon.Segment.ID()),
			Status:     200,
		},
		"beacon id prefix": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{beacons[0].Beacon.Segment.ID()[:10]}},
				).AnyTimes().Return(beacons[:1], nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons/" + hex.EncodeToString(beacons[0].Beacon.Segment.ID()[:10]),
			Status:     200,
		},
		"beacon no matches": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{[]byte("1234")}},
				).AnyTimes().Return([]beacon.Beacon{}, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons/" + hex.EncodeToString([]byte("1234")),
			Status:     400,
		},
		"beacon no unique match": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{[]byte("1234")}},
				).AnyTimes().Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: "/beacons/" + hex.EncodeToString([]byte("1234")),
			Status:     400,
		},
		"beacon blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{beacons[0].Beacon.Segment.ID()}},
				).AnyTimes().Return(beacons[:1], nil)
				return api.Handler(s)
			},
			RequestURL: fmt.Sprintf(
				"/beacons/%s/blob",
				hex.EncodeToString(beacons[0].Beacon.Segment.ID()),
			),
			Status: 200,
		},
		"beacon id prefix blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{beacons[0].Beacon.Segment.ID()[:10]}},
				).AnyTimes().Return(beacons[:1], nil)
				return api.Handler(s)
			},
			RequestURL: fmt.Sprintf(
				"/beacons/%s/blob",
				hex.EncodeToString(beacons[0].Beacon.Segment.ID()[:10]),
			),
			Status: 200,
		},
		"beacon no matches blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{[]byte("1234")}},
				).AnyTimes().Return([]beacon.Beacon{}, nil)
				return api.Handler(s)
			},
			RequestURL: fmt.Sprintf("/beacons/%s/blob", hex.EncodeToString([]byte("1234"))),
			Status:     400,
		},
		"beacon no unique match blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				bs := mock_mgmtapi.NewMockBeaconStore(ctrl)
				s := &api.Server{
					Beacons: bs,
				}
				bs.EXPECT().GetBeacons(
					gomock.Any(),
					&beacon.QueryParams{SegIDs: [][]byte{[]byte("1234")}},
				).AnyTimes().Return(beacons, nil)
				return api.Handler(s)
			},
			RequestURL: fmt.Sprintf("/beacons/%s/blob", hex.EncodeToString([]byte("1234"))),
			Status:     400,
		},
		"signer": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &api.Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				notBefore := time.Unix(1611051121, 0).UTC()
				notAfter := time.Unix(1611061121, 0).UTC()
				now := notBefore.Add(time.Minute)
				s.SetNowProvider(func() time.Time { return now })
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					[]trust.Signer{{
						IA:        addr.MustParseIA("1-ff00:0:110"),
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
						Expiration: notAfter,
						ChainValidity: cppki.Validity{
							NotBefore: notBefore,
							NotAfter:  notAfter,
						},
						InGrace: true,
					}}, nil,
				)
				return api.Handler(s)
			},
			RequestURL: "/signer",
			Status:     200,
		},
		"signer error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &api.Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					nil, serrors.New("internal"),
				)
				return api.Handler(s)
			},
			RequestURL: "/signer",
			Status:     500,
		},
		"signer blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &api.Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				validCert, _ := cppki.ReadPEMCerts(filepath.Join("testdata", "signer-chain.crt"))
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					[]trust.Signer{{
						Chain:      validCert,
						Expiration: time.Now().Add(time.Hour),
						ChainValidity: cppki.Validity{
							NotBefore: time.Now(),
							NotAfter:  time.Now().Add(time.Hour),
						},
					}}, nil,
				)
				return api.Handler(s)
			},
			RequestURL: "/signer/blob",
			Status:     200,
		},
		"signer blob error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_trust.NewMockSignerGen(ctrl)
				s := &api.Server{
					Signer: cstrust.RenewingSigner{
						SignerGen: g,
					},
				}
				g.EXPECT().Generate(gomock.Any()).AnyTimes().Return(
					[]trust.Signer{{}}, nil,
				)
				return api.Handler(s)
			},
			RequestURL: "/signer/blob",
			Status:     500,
		},
		"ca": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &api.Server{
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
				return api.Handler(s)
			},
			RequestURL: "/ca",
			Status:     200,
		},
		"ca error (empty certificate)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &api.Server{
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
				return api.Handler(s)
			},
			RequestURL: "/ca",
			Status:     500,
		},
		"ca error (no signer)": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				g := mock_renewal.NewMockPolicyGen(ctrl)
				s := &api.Server{
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
				return api.Handler(s)
			},
			RequestURL: "/ca",
			Status:     500,
		},
		"health": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health expired signer": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(-10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: -10 * time.Hour,
			Status:          200,
		},
		"health trc fails": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: true,
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health trc error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound:       true,
						TRCNotFoundDetail: "internal",
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health signer error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: true,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: true,
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health signer fails": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: true,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 2 * time.Hour,
			Status:          200,
		},
		"health signer degraded": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(3 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						}},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 3 * time.Hour,
			Status:          200,
		},
		"health signer grace period": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(2 * time.Hour),
						InGrace:       true,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 2 * time.Hour,
			Status:          200,
		},
		"health signer degraded trc fails": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(2 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: true,
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 2 * time.Hour,
			Status:          200,
		},
		"health signer grace period trc fails": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(2 * time.Hour),
						InGrace:       true,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: true,
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 2 * time.Hour,
			Status:          200,
		},
		"health signer fails trc fails": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: true,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: true,
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Available, true,
				)
				return api.Handler(s)
			},
			RequestURL: "/health",
			Status:     200,
		},
		"health ca starting": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Starting, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health ca stopping": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Stopping, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health ca unavailable": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Unavailable, true,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
		},
		"health ca check not run": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				h := mock_mgmtapi.NewMockHealther(ctrl)
				s := &api.Server{
					Healther: h,
				}
				h.EXPECT().GetSignerHealth(gomock.Any()).Return(
					api.SignerHealthData{
						SignerMissing: false,
						Expiration:    now.Add(10 * time.Hour),
						InGrace:       false,
					},
				)
				h.EXPECT().GetTRCHealth(gomock.Any()).Return(
					api.TRCHealthData{
						TRCNotFound: false,
						TRCID: cppki.TRCID{
							Base:   2,
							Serial: 1,
							ISD:    12,
						},
					},
				)
				h.EXPECT().GetCAHealth(gomock.Any()).Return(
					api.Unavailable, false,
				)
				return api.Handler(s)
			},
			RequestURL:      "/health",
			TimestampOffset: 10 * time.Hour,
			Status:          200,
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
			expiresAt := now.Add(tc.TimestampOffset).Format(time.RFC3339)
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				raw := strings.ReplaceAll(rr.Body.String(), expiresAt, "EXPIRES_AT")
				require.NoError(t, os.WriteFile(goldenFile, []byte(raw), 0666))
			}
			goldenRaw, err := os.ReadFile(goldenFile)
			require.NoError(t, err)
			golden := strings.ReplaceAll(string(goldenRaw), "EXPIRES_AT", expiresAt)
			assert.Equal(t, golden, rr.Body.String())
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
					ASEntries: []seg.ASEntry{
						{
							Local: addr.MustParseIA("1-ff00:0:110"),
							Next:  addr.MustParseIA("1-ff00:0:111"),
							HopEntry: seg.HopEntry{
								HopField: seg.HopField{
									ConsIngress: 0,
									ConsEgress:  1,
								},
								IngressMTU: 1200,
							},
						},
						{
							Local: addr.MustParseIA("1-ff00:0:111"),
							Next:  addr.MustParseIA("1-ff00:0:112"),
							HopEntry: seg.HopEntry{
								HopField: seg.HopField{
									ConsIngress: 2,
									ConsEgress:  3,
								},
								IngressMTU: 1200,
							},
						},
					},
				},
				InIfID: 2,
			},
			Usage:       beaconlib.UsageUpReg | beaconlib.UsageDownReg,
			LastUpdated: time.Date(2021, 1, 2, 8, 0, 0, 0, time.UTC),
		},
		{
			Beacon: beaconlib.Beacon{
				Segment: &seg.PathSegment{
					Info: seg.Info{
						Timestamp: time.Date(2021, 2, 1, 8, 0, 0, 0, time.UTC),
					},
					ASEntries: []seg.ASEntry{
						{
							Local: addr.MustParseIA("2-ff00:0:220"),
							Next:  addr.MustParseIA("3-ff00:0:330"),
							HopEntry: seg.HopEntry{
								HopField: seg.HopField{
									ConsIngress: 0,
									ConsEgress:  5,
								},
							},
						},
						{
							Local: addr.MustParseIA("3-ff00:0:330"),
							Next:  addr.MustParseIA("4-ff00:0:440"),
							HopEntry: seg.HopEntry{
								HopField: seg.HopField{
									ConsIngress: 6,
									ConsEgress:  7,
								},
							},
						},
					},
				},
				InIfID: 1,
			},
			Usage:       beaconlib.UsageCoreReg,
			LastUpdated: time.Date(2021, 2, 2, 8, 0, 0, 0, time.UTC),
		},
	}
}

type queryMatcher struct {
	query        *beacon.QueryParams
	creationTime time.Time
}

// matchQuery creates a matcher that matches the QueryParams with validAt time
// that needs to be within 10s of the creation.
func matchQuery(q *beacon.QueryParams) gomock.Matcher {
	return queryMatcher{
		query:        q,
		creationTime: time.Now(),
	}
}

func (m queryMatcher) Matches(x any) bool {
	p, ok := x.(*beacon.QueryParams)
	if !ok {
		return false
	}
	validAt := p.ValidAt
	// check that validAt is roughly the same, be lenient and give a 10s window,
	// for CI.
	if !assert.WithinDuration(&testing.T{}, m.creationTime, validAt, 10*time.Second) {
		return false
	}
	p.ValidAt = time.Time{}
	// return whether the rest is equal.
	return assert.ObjectsAreEqual(m.query, p)
}

func (m queryMatcher) String() string {
	return fmt.Sprintf("%v with ValidAt around %s", m.query, m.creationTime)
}
