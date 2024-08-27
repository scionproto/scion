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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/mock_seg"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/mgmtapi/segments/api/mock_api"
	"github.com/scionproto/scion/private/pathdb/query"
)

// segment id constants.
const (
	id1 = "50ddb5ffa058302aad1593fc82e3c75531d33b0406cf9ef8f175aa9b00a3959e"
	id2 = "023dc0cff0be7a9e29fc1ce517dd96face947a7af78d399d210eab0a7cb779ef"
)

var update = xtest.UpdateGoldenFiles()

// TestAPI tests the API response generation of the endpoints implemented in the
// api package.
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
				seg := mock_api.NewMockSegmentStore(ctrl)
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
				seg := mock_api.NewMockSegmentStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				seg.EXPECT().Get(gomock.Any(), &query.Params{}).AnyTimes().Return(
					query.Results{}, serrors.New("internal"),
				)
				return Handler(s)
			},
			RequestURL:   "/segments",
			ResponseFile: "testdata/segments-error.json",
			Status:       500,
		},
		"segments start and dest as": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentStore(ctrl)
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				q := query.Params{
					StartsAt: []addr.IA{addr.MustParseIA("1-ff00:0:110")},
					EndsAt:   []addr.IA{addr.MustParseIA("1-ff00:0:112")},
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
				seg := mock_api.NewMockSegmentStore(ctrl)
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
				seg := mock_api.NewMockSegmentStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{xtest.MustParseHexString(id1)},
				}
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())[:1]
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-by-id.json",
			RequestURL:   "/segments/" + id1,
			Status:       200,
		},
		"segment invalid id": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{
						xtest.MustParseHexString(id1),
						xtest.MustParseHexString(id2)},
				}
				s := &Server{
					Segments: seg,
				}
				dbresult := createSegs(t, graph.NewSigner())
				seg.EXPECT().Get(gomock.Any(), &q).Times(0).Return(
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
				seg := mock_api.NewMockSegmentStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{xtest.MustParseHexString(id1)},
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
							return nil, serrors.Wrap("packing header", err)
						}
						hdrAndBody := &cryptopb.HeaderAndBodyInternal{
							Header: rawHdr,
							Body:   msg,
						}
						rawHdrAndBody, err := proto.Marshal(hdrAndBody)
						if err != nil {
							return nil, serrors.Wrap("packing signature input", err)
						}
						return &cryptopb.SignedMessage{
							HeaderAndBody: rawHdrAndBody,
							Signature:     []byte("signature"),
						}, nil
					},
				)

				dbresult := createSegs(t, signer)[:1]
				seg.EXPECT().Get(gomock.Any(), &q).AnyTimes().Return(
					dbresult, nil,
				)
				return Handler(s)
			},
			ResponseFile: "testdata/segments-blob-by-id.txt",
			RequestURL:   "/segments/" + id1 + "/blob",
			Status:       200,
		},
		"segment blob error": {
			Handler: func(t *testing.T, ctrl *gomock.Controller) http.Handler {
				seg := mock_api.NewMockSegmentStore(ctrl)
				q := query.Params{
					SegIDs: [][]byte{xtest.MustParseHexString(id1)},
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
			RequestURL:   "/segments/" + id1 + "/blob",
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
				require.NoError(t, os.WriteFile(tc.ResponseFile, rr.Body.Bytes(), 0666))
			}
			golden, err := os.ReadFile(tc.ResponseFile)
			require.NoError(t, err)
			assert.Equal(t, string(golden), rr.Body.String())
		})
	}
}

func createSegs(t *testing.T, signer seg.Signer) query.Results {
	asEntry1 := seg.ASEntry{
		Local: addr.MustParseIA("1-ff00:0:110"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: [path.MacLen]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
				ConsEgress: 1,
			},
		},
	}
	asEntry2 := seg.ASEntry{
		Local: addr.MustParseIA("1-ff00:0:111"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: [path.MacLen]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12},
				ConsIngress: 1,
				ConsEgress:  2},
		},
	}
	asEntry3 := seg.ASEntry{
		Local: addr.MustParseIA("1-ff00:0:113"),
		HopEntry: seg.HopEntry{
			HopField: seg.HopField{MAC: [path.MacLen]byte{0x13, 0x13, 0x13, 0x13, 0x13, 0x13},
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
