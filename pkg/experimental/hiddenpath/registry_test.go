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
	"github.com/scionproto/scion/pkg/snet"
)

func TestRegistryRegister(t *testing.T) {
	localIA := addr.MustParseIA("1-ff00:0:114")
	writer := addr.MustParseIA("2-ff00:0:221")
	groups := map[hiddenpath.GroupID]*hiddenpath.Group{
		mustParseGroupID(t, "ff00:0:4-5"): {
			Writers:    map[addr.IA]struct{}{writer: {}},
			Registries: map[addr.IA]struct{}{localIA: {}},
		},
		mustParseGroupID(t, "ff00:0:4-404"): {
			Writers:    map[addr.IA]struct{}{writer: {}},
			Registries: map[addr.IA]struct{}{writer: {}},
		},
		mustParseGroupID(t, "ff00:0:4-405"): {
			Writers:    map[addr.IA]struct{}{localIA: {}},
			Registries: map[addr.IA]struct{}{localIA: {}},
		},
	}
	testCases := map[string]struct {
		reg       hiddenpath.Registration
		db        func(*gomock.Controller) hiddenpath.Store
		verifier  func(*gomock.Controller) hiddenpath.Verifier
		assertErr assert.ErrorAssertionFunc
	}{
		"unknown group": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-1"),
				Segments: []*seg.Meta{{Type: seg.TypeCore}},
				Peer:     &snet.SVCAddr{IA: writer},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return mock_hiddenpath.NewMockStore(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				return mock_hiddenpath.NewMockVerifier(ctrl)
			},
			assertErr: assert.Error,
		},
		"peer not writer": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-405"),
				Segments: []*seg.Meta{{Type: seg.TypeCore}},
				Peer:     &snet.SVCAddr{IA: writer},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return mock_hiddenpath.NewMockStore(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				return mock_hiddenpath.NewMockVerifier(ctrl)
			},
			assertErr: assert.Error,
		},
		"local not registry": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-404"),
				Segments: []*seg.Meta{{Type: seg.TypeCore}},
				Peer:     &snet.SVCAddr{IA: writer},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return mock_hiddenpath.NewMockStore(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				return mock_hiddenpath.NewMockVerifier(ctrl)
			},
			assertErr: assert.Error,
		},
		"invalid seg type": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-5"),
				Segments: []*seg.Meta{{Type: seg.TypeCore}},
				Peer:     &snet.SVCAddr{IA: writer},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return mock_hiddenpath.NewMockStore(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				return mock_hiddenpath.NewMockVerifier(ctrl)
			},
			assertErr: assert.Error,
		},
		"verification error": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-5"),
				Segments: []*seg.Meta{{Type: seg.TypeDown}},
				Peer:     &snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				return mock_hiddenpath.NewMockStore(ctrl)
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				verifier := mock_hiddenpath.NewMockVerifier(ctrl)
				verifier.EXPECT().Verify(gomock.Any(),
					[]*seg.Meta{{Type: seg.TypeDown}},
					&snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
				).Return(serrors.New("test err"))
				return verifier
			},
			assertErr: assert.Error,
		},
		"db writer error": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-5"),
				Segments: []*seg.Meta{{Type: seg.TypeDown}},
				Peer:     &snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				db := mock_hiddenpath.NewMockStore(ctrl)
				db.EXPECT().Put(gomock.Any(), []*seg.Meta{{Type: seg.TypeDown}},
					mustParseGroupID(t, "ff00:0:4-5")).Return(serrors.New("test"))
				return db
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				verifier := mock_hiddenpath.NewMockVerifier(ctrl)
				verifier.EXPECT().Verify(gomock.Any(),
					[]*seg.Meta{{Type: seg.TypeDown}},
					&snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
				)
				return verifier
			},
			assertErr: assert.Error,
		},
		"valid": {
			reg: hiddenpath.Registration{
				GroupID:  mustParseGroupID(t, "ff00:0:4-5"),
				Segments: []*seg.Meta{{Type: seg.TypeDown}},
				Peer:     &snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
			},
			db: func(ctrl *gomock.Controller) hiddenpath.Store {
				db := mock_hiddenpath.NewMockStore(ctrl)
				db.EXPECT().Put(gomock.Any(), []*seg.Meta{{Type: seg.TypeDown}},
					mustParseGroupID(t, "ff00:0:4-5"))
				return db
			},
			verifier: func(ctrl *gomock.Controller) hiddenpath.Verifier {
				verifier := mock_hiddenpath.NewMockVerifier(ctrl)
				verifier.EXPECT().Verify(gomock.Any(),
					[]*seg.Meta{{Type: seg.TypeDown}},
					&snet.SVCAddr{IA: writer, SVC: addr.SvcCS},
				)
				return verifier
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

			h := hiddenpath.RegistryServer{
				Groups:   groups,
				DB:       tc.db(ctrl),
				Verifier: tc.verifier(ctrl),
				LocalIA:  localIA,
			}
			err := h.Register(context.Background(), tc.reg)
			tc.assertErr(t, err)
		})
	}
}
