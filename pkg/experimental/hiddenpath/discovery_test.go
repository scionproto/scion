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
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func TestRegistrationResolverResolve(t *testing.T) {
	testCases := map[string]struct {
		router     func(*gomock.Controller) snet.Router
		discoverer func(*gomock.Controller) hiddenpath.Discoverer
		assertErr  assert.ErrorAssertionFunc
		want       net.Addr
	}{
		"router error": {
			router: func(ctrl *gomock.Controller) snet.Router {
				router := mock_snet.NewMockRouter(ctrl)
				router.EXPECT().Route(gomock.Any(), addr.MustParseIA("1-ff00:0:110")).
					Return(nil, serrors.New("test"))
				return router
			},
			discoverer: func(ctrl *gomock.Controller) hiddenpath.Discoverer {
				return mock_hiddenpath.NewMockDiscoverer(ctrl)
			},
			assertErr: assert.Error,
			want:      nil,
		},
		"no paths found": {
			router: func(ctrl *gomock.Controller) snet.Router {
				router := mock_snet.NewMockRouter(ctrl)
				router.EXPECT().Route(gomock.Any(), addr.MustParseIA("1-ff00:0:110")).
					Return(nil, nil)
				return router
			},
			discoverer: func(ctrl *gomock.Controller) hiddenpath.Discoverer {
				return mock_hiddenpath.NewMockDiscoverer(ctrl)
			},
			assertErr: assert.Error,
			want:      nil,
		},
		"disco error": {
			router: func(ctrl *gomock.Controller) snet.Router {
				router := mock_snet.NewMockRouter(ctrl)
				path := mock_snet.NewMockPath(ctrl)
				path.EXPECT().Dataplane().Return(snetpath.SCION{Raw: []byte("path")}).AnyTimes()
				path.EXPECT().UnderlayNextHop().AnyTimes().Return(
					xtest.MustParseUDPAddr(t, "10.1.0.1:404"))
				router.EXPECT().Route(gomock.Any(), addr.MustParseIA("1-ff00:0:110")).
					Return(path, nil)
				return router
			},
			discoverer: func(ctrl *gomock.Controller) hiddenpath.Discoverer {
				d := mock_hiddenpath.NewMockDiscoverer(ctrl)
				d.EXPECT().Discover(gomock.Any(), addrMatcher{svc: &snet.SVCAddr{
					IA:      addr.MustParseIA("1-ff00:0:110"),
					NextHop: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
					Path:    snetpath.SCION{Raw: []byte("path")},
					SVC:     addr.SvcDS,
				}}).Return(hiddenpath.Servers{}, serrors.New("test"))
				return d
			},
			assertErr: assert.Error,
			want:      nil,
		},
		"no server": {
			router: func(ctrl *gomock.Controller) snet.Router {
				router := mock_snet.NewMockRouter(ctrl)
				path := mock_snet.NewMockPath(ctrl)
				path.EXPECT().Dataplane().Return(snetpath.SCION{Raw: []byte("path")}).AnyTimes()
				path.EXPECT().UnderlayNextHop().AnyTimes().Return(
					xtest.MustParseUDPAddr(t, "10.1.0.1:404"))
				router.EXPECT().Route(gomock.Any(), addr.MustParseIA("1-ff00:0:110")).
					Return(path, nil)
				return router
			},
			discoverer: func(ctrl *gomock.Controller) hiddenpath.Discoverer {
				d := mock_hiddenpath.NewMockDiscoverer(ctrl)
				d.EXPECT().Discover(gomock.Any(), addrMatcher{svc: &snet.SVCAddr{
					IA:      addr.MustParseIA("1-ff00:0:110"),
					NextHop: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
					Path:    snetpath.SCION{Raw: []byte("path")},
					SVC:     addr.SvcDS,
				}}).Return(hiddenpath.Servers{}, nil)
				return d
			},
			assertErr: assert.Error,
			want:      nil,
		},
		"valid": {
			router: func(ctrl *gomock.Controller) snet.Router {
				router := mock_snet.NewMockRouter(ctrl)
				path := mock_snet.NewMockPath(ctrl)
				path.EXPECT().Dataplane().Return(snetpath.SCION{Raw: []byte("path")}).AnyTimes()
				path.EXPECT().UnderlayNextHop().AnyTimes().Return(
					xtest.MustParseUDPAddr(t, "10.1.0.1:404"))
				router.EXPECT().Route(gomock.Any(), addr.MustParseIA("1-ff00:0:110")).
					Return(path, nil)
				return router
			},
			discoverer: func(ctrl *gomock.Controller) hiddenpath.Discoverer {
				d := mock_hiddenpath.NewMockDiscoverer(ctrl)
				d.EXPECT().Discover(gomock.Any(), addrMatcher{svc: &snet.SVCAddr{
					IA:      addr.MustParseIA("1-ff00:0:110"),
					NextHop: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
					Path:    snetpath.SCION{Raw: []byte("path")},
					SVC:     addr.SvcDS,
				}}).Return(hiddenpath.Servers{
					Registration: []*net.UDPAddr{
						xtest.MustParseUDPAddr(t, "10.1.0.5:42"),
					},
				}, nil)
				return d
			},
			assertErr: assert.NoError,
			want: &snet.UDPAddr{
				IA:      addr.MustParseIA("1-ff00:0:110"),
				Host:    xtest.MustParseUDPAddr(t, "10.1.0.5:42"),
				NextHop: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
				Path:    snetpath.SCION{Raw: []byte("path")},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			r := hiddenpath.RegistrationResolver{
				Router:     tc.router(ctrl),
				Discoverer: tc.discoverer(ctrl),
			}
			got, err := r.Resolve(context.Background(), addr.MustParseIA("1-ff00:0:110"))
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)

		})
	}
}
