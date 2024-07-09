// Copyright 2021 Anapaya Systems
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
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/storage/mock_storage"
	truststorage "github.com/scionproto/scion/private/storage/trust"
)

var update = xtest.UpdateGoldenFiles()

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
		"trcs": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				q := truststorage.TRCsQuery{Latest: true}
				sto.EXPECT().SignedTRCs(gomock.Any(), q).AnyTimes().Return(
					cppki.SignedTRCs{
						{
							TRC: cppki.TRC{
								ID: cppki.TRCID{
									ISD:    1,
									Serial: 2,
									Base:   1,
								},
							},
						},
						{
							TRC: cppki.TRC{
								ID: cppki.TRCID{
									ISD:    2,
									Serial: 1,
									Base:   2,
								},
							},
						},
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trcs.json",
			RequestURL:   "/trcs",
			Status:       200,
		},
		"trcs all and isd": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				q := truststorage.TRCsQuery{
					ISD:    []addr.ISD{1},
					Latest: false,
				}
				sto.EXPECT().SignedTRCs(gomock.Any(), q).AnyTimes().Return(
					cppki.SignedTRCs{
						{
							TRC: cppki.TRC{
								ID: cppki.TRCID{
									ISD:    1,
									Serial: 2,
									Base:   1,
								},
							},
						},
						{
							TRC: cppki.TRC{
								ID: cppki.TRCID{
									ISD:    1,
									Serial: 1,
									Base:   1,
								},
							},
						},
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trcs-all-and-isd.json",
			RequestURL:   "/trcs?all=true&isd=1",
			Status:       200,
		},
		"trcs internal error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				q := truststorage.TRCsQuery{
					ISD:    []addr.ISD{1},
					Latest: false,
				}
				sto.EXPECT().SignedTRCs(gomock.Any(), q).AnyTimes().Return(
					nil, serrors.New("internal"),
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trcs-internal-error.json",
			RequestURL:   "/trcs?all=true&isd=1",
			Status:       500,
		},
		"inexistent trcs error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				q := truststorage.TRCsQuery{
					ISD:    []addr.ISD{1},
					Latest: false,
				}
				sto.EXPECT().SignedTRCs(gomock.Any(), q).AnyTimes().Return(
					nil, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trcs-inexistent-error.json",
			RequestURL:   "/trcs?all=true&isd=1",
			Status:       404,
		},
		"trc": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				sto.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{
					ISD:    addr.ISD(1),
					Serial: scrypto.Version(3),
					Base:   scrypto.Version(2),
				}).AnyTimes().Return(
					cppki.SignedTRC{
						TRC: cppki.TRC{
							CoreASes: []addr.AS{
								addr.MustParseIA("1-ff00:0:130").AS(),
								addr.MustParseIA("1-ff00:0:131").AS(),
								addr.MustParseIA("1-ff00:0:132").AS(),
							},
							AuthoritativeASes: []addr.AS{
								addr.MustParseIA("1-ff00:0:131").AS(),
								addr.MustParseIA("1-ff00:0:132").AS(),
							},
							Description: "trc description",
							ID: cppki.TRCID{
								ISD:    1,
								Serial: 3,
								Base:   2,
							},
						},
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trc.json",
			RequestURL:   "/trcs/isd1-b2-s3",
			Status:       200,
		},
		"trc inexistent": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				sto.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{
					ISD:    addr.ISD(1),
					Serial: scrypto.Version(1),
					Base:   scrypto.Version(2),
				}).AnyTimes().Return(
					cppki.SignedTRC{}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trc-inexistent.json",
			RequestURL:   "/trcs/isd1-b2-s1",
			Status:       404,
		},
		"trc error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				sto.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{
					ISD:    addr.ISD(1),
					Serial: scrypto.Version(1),
					Base:   scrypto.Version(2),
				}).AnyTimes().Return(
					cppki.SignedTRC{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trc-error.json",
			RequestURL:   "/trcs/isd1-b2-s1",
			Status:       500,
		},
		"trc blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				sto := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: sto}
				sto.EXPECT().SignedTRC(gomock.Any(), cppki.TRCID{
					ISD:    addr.ISD(1),
					Serial: scrypto.Version(1),
					Base:   scrypto.Version(1),
				}).AnyTimes().Return(
					cppki.SignedTRC{
						TRC: cppki.TRC{
							ID: cppki.TRCID{
								ISD:    1,
								Serial: 1,
								Base:   1,
							},
							Raw: bytes.Repeat([]byte{0x11}, 6),
						},
					}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/trc-blob.pem",
			RequestURL:   "/trcs/isd1-b1-s1/blob",
			Status:       200,
		},
		"certificates": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}

				chain, err := cppki.ReadPEMCerts(filepath.Join("testdata", "signer-chain.crt"))
				require.NoError(t, err)

				db.EXPECT().Chains(gomock.Any(), gomock.Any()).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/certificates.json",
			RequestURL:   "/certificates",
			Status:       200,
		},
		"certificates malformed": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}
				return Handler(s)
			},
			ResponseFile: "testdata/certificates-malformed.json",
			RequestURL:   "/certificates?isd_as=garbage",
			Status:       http.StatusBadRequest,
		},
		"certificates chainID": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}

				chain, err := cppki.ReadPEMCerts(filepath.Join("testdata", "signer-chain.crt"))
				require.NoError(t, err)

				expectedChainID, err := hex.DecodeString("aabbcc")
				require.NoError(t, err)

				db.EXPECT().Chain(gomock.Any(), expectedChainID).Return(
					chain, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/certificate.json",
			RequestURL:   "/certificates/aabbcc",
			Status:       200,
		},
		"chainID malformed": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}
				return Handler(s)
			},
			ResponseFile: "testdata/certificate-malformed.json",
			RequestURL:   "/certificates/garbage",
			Status:       http.StatusBadRequest,
		},
		"Certificates blob": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}

				chain, err := cppki.ReadPEMCerts(filepath.Join("testdata", "signer-chain.crt"))
				require.NoError(t, err)
				expectedChainID, err := hex.DecodeString("aabbcc")
				require.NoError(t, err)

				db.EXPECT().Chain(gomock.Any(), expectedChainID).Return(
					chain, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/certificates-blob-response.txt",
			RequestURL:   "/certificates/aabbcc/blob",
			Status:       200,
		},
		"chainID blob malformed": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				db := mock_storage.NewMockTrustDB(ctrl)
				s := &Server{TrustDB: db}
				return Handler(s)
			},
			ResponseFile: "testdata/certificate-blob-malformed.txt",
			RequestURL:   "/certificates/garbage/blob",
			Status:       http.StatusBadRequest,
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
				require.NoError(t, os.WriteFile(tc.ResponseFile, rr.Body.Bytes(), 0666))
			}
			golden, err := os.ReadFile(tc.ResponseFile)
			require.NoError(t, err)
			assert.Equal(t, string(golden), rr.Body.String())
		})
	}
}
