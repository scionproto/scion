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

package grpc_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/grpc"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/pkg/private/serrors"
	hspb "github.com/scionproto/scion/pkg/proto/hidden_segment"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	infra "github.com/scionproto/scion/private/segment/verifier"
	mock_infra "github.com/scionproto/scion/private/segment/verifier/mock_verifier"
)

func TestSegmentServerHiddenSegments(t *testing.T) {
	segsMeta, wantPB := createSegs(t)

	testCases := map[string]struct {
		createCtx     func(t *testing.T) context.Context
		lookuper      func(ctrl *gomock.Controller) hiddenpath.Lookuper
		request       *hspb.HiddenSegmentsRequest
		want          *hspb.HiddenSegmentsResponse
		authoritative bool
		assertErr     assert.ErrorAssertionFunc
	}{
		"lookup error": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				ret := mock_hiddenpath.NewMockLookuper(ctrl)
				ret.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    addr.MustParseIA("1-ff00:0:110"),
				}).Return(nil, serrors.New("error")).Times(1)
				return ret
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"valid": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				ret := mock_hiddenpath.NewMockLookuper(ctrl)
				ret.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    addr.MustParseIA("1-ff00:0:110"),
				}).Return(segsMeta, nil).Times(1)
				return ret
			},
			request: &hspb.HiddenSegmentsRequest{
				GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
				DstIsdAs: mustIA("1-ff00:0:110"),
			},
			want:      wantPB,
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			server := &grpc.SegmentServer{
				Lookup: tc.lookuper(ctrl),
			}
			got, err := server.HiddenSegments(tc.createCtx(t), tc.request)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAuthoritativeSegmentServerAuthoritativeHiddenSegments(t *testing.T) {
	segsMeta, _ := createSegs(t)

	marshalBody := func(t *testing.T, body *hspb.HiddenSegmentsRequest) []byte {
		r, err := proto.Marshal(body)
		require.NoError(t, err)
		return r
	}

	testCases := map[string]struct {
		createCtx     func(t *testing.T) context.Context
		lookuper      func(ctrl *gomock.Controller) hiddenpath.Lookuper
		verifier      func(ctrl *gomock.Controller) infra.Verifier
		want          *hspb.AuthoritativeHiddenSegmentsResponse
		authoritative bool
		assertErr     assert.ErrorAssertionFunc
	}{
		"context without peer": {
			createCtx: func(t *testing.T) context.Context { return context.Background() },
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				return mock_hiddenpath.NewMockLookuper(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				return mock_infra.NewMockVerifier(ctrl)
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"context with invalid peer": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.UDPAddr{
					IP: net.ParseIP("127.0.0.1"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				return mock_hiddenpath.NewMockLookuper(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				return mock_infra.NewMockVerifier(ctrl)
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"verification error": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: addr.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				return mock_hiddenpath.NewMockLookuper(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:14")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, serrors.New("verification error"))
				return v
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"lookuper error": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: addr.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				lookuper := mock_hiddenpath.NewMockLookuper(ctrl)
				lookuper.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    addr.MustParseIA("1-ff00:0:110"),
					Peer:     addr.MustParseIA("1-ff00:0:14"),
				}).Return(nil, serrors.New("test error"))
				return lookuper
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				body := marshalBody(t, &hspb.HiddenSegmentsRequest{
					GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
					DstIsdAs: mustIA("1-ff00:0:110"),
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:14")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
			},
			authoritative: true,
			want:          nil,
			assertErr:     assert.Error,
		},
		"valid": {
			createCtx: func(t *testing.T) context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{Addr: &snet.UDPAddr{
					IA: addr.MustParseIA("1-ff00:0:14"),
				}})
			},
			lookuper: func(ctrl *gomock.Controller) hiddenpath.Lookuper {
				lookuper := mock_hiddenpath.NewMockLookuper(ctrl)
				lookuper.EXPECT().Segments(gomock.Any(), hiddenpath.SegmentRequest{
					GroupIDs: mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5"),
					DstIA:    addr.MustParseIA("1-ff00:0:110"),
					Peer:     addr.MustParseIA("1-ff00:0:14"),
				}).Return(segsMeta, nil)
				return lookuper
			},
			verifier: func(ctrl *gomock.Controller) infra.Verifier {
				body := marshalBody(t, &hspb.HiddenSegmentsRequest{
					GroupIds: groupIDsToInts(mustParseGroupIDs(t, "ff00:0:22-1", "ff00:0:42-5")),
					DstIsdAs: mustIA("1-ff00:0:110"),
				})
				v := mock_infra.NewMockVerifier(ctrl)
				v.EXPECT().WithServer(gomock.Any()).Return(v)
				v.EXPECT().WithIA(addr.MustParseIA("1-ff00:0:14")).Return(v)
				v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(&signed.Message{
					Body: body,
				}, nil)
				return v
			},
			authoritative: true,
			want: &hspb.AuthoritativeHiddenSegmentsResponse{
				Segments: grpc.ToHSPB(segsMeta),
			},
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			server := &grpc.AuthoritativeSegmentServer{
				Lookup:   tc.lookuper(ctrl),
				Verifier: tc.verifier(ctrl),
			}
			got, err := server.AuthoritativeHiddenSegments(tc.createCtx(t),
				&hspb.AuthoritativeHiddenSegmentsRequest{})
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mustIA(s string) uint64 {
	return uint64(addr.MustParseIA(s))
}

func mustParseGroupIDs(t *testing.T, ids ...string) []hiddenpath.GroupID {
	t.Helper()

	result := make([]hiddenpath.GroupID, 0, len(ids))
	for _, id := range ids {
		result = append(result, mustParseGroupID(t, id))
	}
	return result
}

func mustParseGroupID(t *testing.T, s string) hiddenpath.GroupID {
	t.Helper()

	id, err := hiddenpath.ParseGroupID(s)
	require.NoError(t, err)
	return id
}

func groupIDsToInts(ids []hiddenpath.GroupID) []uint64 {
	result := make([]uint64, 0, len(ids))
	for _, id := range ids {
		result = append(result, id.ToUint64())
	}
	return result
}

func createSegs(t *testing.T) ([]*seg.Meta, *hspb.HiddenSegmentsResponse) {
	t.Helper()

	s := createSeg(t)
	ret1 := []*seg.Meta{&s}
	ret2 := &hspb.HiddenSegmentsResponse{
		Segments: grpc.ToHSPB(ret1),
	}
	return ret1, ret2
}
