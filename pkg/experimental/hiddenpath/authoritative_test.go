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

package hiddenpath_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

func TestAuthoritativeServerSegments(t *testing.T) {
	local := addr.MustParseIA("1-ff00:0:14")
	testCases := map[string]struct {
		request   hiddenpath.SegmentRequest
		local     addr.IA
		db        func(ctrl *gomock.Controller) hiddenpath.Store
		groups    func() map[hiddenpath.GroupID]*hiddenpath.Group
		want      []*seg.Meta
		assertErr assert.ErrorAssertionFunc
	}{
		"no groups in request": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: nil,
				DstIA:    addr.MustParseIA("2-ff00:0:22"),
				Peer:     addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return nil
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"unknown group in request": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:404")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
				Peer:  addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return nil
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"not reader in group": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:111")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
				Peer:  addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return nil
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:111")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:25"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"non authoritative for group": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:111")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
				Peer:  addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return nil
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:111")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:404"): {}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"db error": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:111")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
				Peer:  addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				db := mock_hiddenpath.NewMockStore(ctrl)
				db.EXPECT().Get(gomock.Any(), addr.MustParseIA("2-ff00:0:22"),
					[]hiddenpath.GroupID{
						{OwnerAS: addr.MustParseAS("ff00:0:110")},
						{OwnerAS: addr.MustParseAS("ff00:0:111")},
					}).Return(nil, serrors.New("test error"))
				return db
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:111")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
				}
			},
			want:      nil,
			assertErr: assert.Error,
		},
		"valid": {
			request: hiddenpath.SegmentRequest{
				GroupIDs: []hiddenpath.GroupID{
					{OwnerAS: addr.MustParseAS("ff00:0:110")},
					{OwnerAS: addr.MustParseAS("ff00:0:111")},
				},
				DstIA: addr.MustParseIA("2-ff00:0:22"),
				Peer:  addr.MustParseIA("1-ff00:0:13"),
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				db := mock_hiddenpath.NewMockStore(ctrl)
				db.EXPECT().Get(gomock.Any(), addr.MustParseIA("2-ff00:0:22"),
					[]hiddenpath.GroupID{
						{OwnerAS: addr.MustParseAS("ff00:0:110")},
						{OwnerAS: addr.MustParseAS("ff00:0:111")},
					}).Return([]*seg.Meta{{Type: seg.TypeDown}}, nil)
				return db
			},
			groups: func() map[hiddenpath.GroupID]*hiddenpath.Group {
				return map[hiddenpath.GroupID]*hiddenpath.Group{
					{OwnerAS: addr.MustParseAS("ff00:0:110")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:110")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
					{OwnerAS: addr.MustParseAS("ff00:0:111")}: {
						ID:         hiddenpath.GroupID{OwnerAS: addr.MustParseAS("ff00:0:111")},
						Readers:    map[addr.IA]struct{}{addr.MustParseIA("1-ff00:0:13"): {}},
						Registries: map[addr.IA]struct{}{local: {}},
					},
				}
			},
			want:      []*seg.Meta{{Type: seg.TypeDown}},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			server := hiddenpath.AuthoritativeServer{
				Groups:  tc.groups(),
				DB:      tc.db(ctrl),
				LocalIA: local,
			}
			got, err := server.Segments(context.Background(), tc.request)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
