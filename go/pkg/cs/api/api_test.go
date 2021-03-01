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
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/cs/api/mock_api"
	cstrust "github.com/scionproto/scion/go/pkg/cs/trust"
	"github.com/scionproto/scion/go/pkg/cs/trust/mock_trust"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
)

// segment id constants
const (
	id1 = "50ddb5ffa058302aad1593fc82e3c75531d33b0406cf9ef8f175aa9b00a3959e"
	id2 = "023dc0cff0be7a9e29fc1ce517dd96face947a7af78d399d210eab0a7cb779ef"
)

// update is a cmd line flag that enables golden file updates. To update the
// golden files simply run 'go test -update ./...'.
var update = flag.Bool("update", false, "set to true to regenerate golden files")

// TestAPI tests the API response generation of the endpoints implemented in the
// api package
func TestAPI(t *testing.T) {
	testCases := map[string]struct {
		Handler            func(t *testing.T, ctrl *gomock.Controller) http.Handler
		RequestURL         string
		ResponseFile       string
		Status             int
		IgnoreResponseBody bool
	}{
		"segments": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				seg.EXPECT().Get(gomock.Any(), &query.Params{}).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments.json",
			RequestURL:   "/segments",
			Status:       200,
		},
		"segments error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				seg.EXPECT().Get(gomock.Any(), &query.Params{}).AnyTimes().Return(
					[]*query.Result{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:   "/segments",
			ResponseFile: "testdata/segments-error.json",
			Status:       500,
		},
		"segments start and dest as": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				q := query.Params{
					StartsAt: []addr.IA{xtest.MustParseIA("1-ff00:0:110")},
					EndsAt:   []addr.IA{xtest.MustParseIA("1-ff00:0:112")},
				}
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult[:1], nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-filtered.json",
			RequestURL:   "/segments?start_isd_as=1-ff00:0:110&end_isd_as=1-ff00:0:112",
			Status:       200,
		},
		"segments malformed query parameters": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				return Handler(s)
			},
			ResponseFile: "testdata/segments-malformed-query.json",
			RequestURL:   "/segments?start_isd_as=1-ff001:0:110&end_isd_as=1-ff000:0:112",
			Status:       400,
		},
		"segment": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{
						xtest.MustParseHexString(id1),
						xtest.MustParseHexString(id2)},
				}
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-by-id.json",
			RequestURL:   "/segments/" + id1 + "," + id2,
			Status:       200,
		},
		"segment invalid id": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{
						xtest.MustParseHexString(id1),
						xtest.MustParseHexString(id2)},
				}
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-by-id-parse-error.json",
			RequestURL:   "/segments/r",
			Status:       400,
		},
		"segment blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{
						xtest.MustParseHexString(id1),
						xtest.MustParseHexString(id2)},
				}
				s := &Server{
					Segments: seg,
				}
				signer := mock_seg.NewMockSigner(ctrl)
				signer.EXPECT().Sign(
					gomock.Any(),
					gomock.Any(),
					gomock.Any()).AnyTimes().DoAndReturn(
					func(_ interface{},
						msg []byte,
						associatedData ...[]byte) (*cryptopb.SignedMessage, error) {
						inputHdr := &cryptopb.Header{
							SignatureAlgorithm: 3,
							VerificationKeyId:  []byte("id"),
						}
						rawHdr, err := proto.Marshal(inputHdr)
						if err != nil {
							return nil, serrors.WrapStr("packing header", err)
						}
						hdrAndBody := &cryptopb.HeaderAndBodyInternal{
							Header: rawHdr,
							Body:   msg,
						}
						rawHdrAndBody, err := proto.Marshal(hdrAndBody)
						if err != nil {
							return nil, serrors.WrapStr("packing signature input", err)
						}
						return &cryptopb.SignedMessage{
							HeaderAndBody: rawHdrAndBody,
							Signature:     []byte("signature"),
						}, nil
					},
				)

				dbresult := createSegs(t, signer)
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-blob-by-id.txt",
			RequestURL:   "/segments/" + id1 + "," + id2 + "/blob",
			Status:       200,
		},
		"segment blob error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentsStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{
						xtest.MustParseHexString(id1),
						xtest.MustParseHexString(id2)},
				}
				s := &Server{
					Segments: seg,
				}
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					query.Results{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-blob-by-id-error.json",
			RequestURL:   "/segments/" + id1 + "," + id2 + "/blob",
			Status:       500,
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
					trust.Signer{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			ResponseFile: "testdata/signer-response-error.json",
			RequestURL:   "/signer",
			Status:       500,
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
			ResponseFile: "testdata/signer-blob-response.txt",
			RequestURL:   "/signer/blob",
			Status:       200,
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
			ResponseFile: "testdata/signer-blob-response-error.txt",
			RequestURL:   "/signer/blob",
			Status:       500,
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
			ResponseFile: "testdata/ca-error-empty-certificate.json",
			RequestURL:   "/ca",
			Status:       500,
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
			ResponseFile: "testdata/ca-error-no-signer.json",
			RequestURL:   "/ca",
			Status:       500,
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

func createSegs(t *testing.T, signer seg.Signer) query.Results {
	asEntry1 := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x11}, 6),
				ConsEgress: 1,
			},
		},
	}
	asEntry2 := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:111"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x12}, 5),
				ConsIngress: 1,
				ConsEgress:  2},
		},
	}
	asEntry3 := seg.ASEntry{
		Local: xtest.MustParseIA("1-ff00:0:113"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: bytes.Repeat([]byte{0x12}, 5),
				ConsIngress: 2},
		},
	}
	ps1, _ := seg.CreateSegment(time.Unix(1611051121, 0).UTC(), 1337)
	ps2, _ := seg.CreateSegment(time.Unix(1611051121, 0).UTC(), 1337)
	addEntry := func(ps *seg.PathSegment, asEntry seg.ASEntry) {
		err := ps.AddASEntry(context.Background(), asEntry, signer)
		require.NoError(t, err)
	}
	addEntry(ps1, asEntry1)
	addEntry(ps1, asEntry2)
	addEntry(ps1, asEntry3)
	asEntry1.HopEntry.HopField.ConsEgress = 2
	asEntry3.HopEntry.HopField.ConsIngress = 1
	addEntry(ps2, asEntry1)
	addEntry(ps2, asEntry3)
	return query.Results{
		&query.Result{
			Type:       seg.TypeDown,
			Seg:        ps1,
			LastUpdate: time.Unix(1611051125, 0).UTC(),
		},
		&query.Result{
			Type:       seg.TypeUp,
			Seg:        ps2,
			LastUpdate: time.Unix(1611051126, 0).UTC(),
		},
	}
}
