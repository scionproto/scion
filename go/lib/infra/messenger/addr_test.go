// Copyright 2019 ETH Zurich, Anapaya Systems
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

package messenger_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/messenger/mock_messenger"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestRedirectQUIC(t *testing.T) {
	testCases := map[string]struct {
		input                 net.Addr
		wantAddr              net.Addr
		wantRedirect          bool
		SVCResolutionFraction float64
		assertErr             assert.ErrorAssertionFunc
	}{
		"nil addr, no error": {
			input:     nil,
			wantAddr:  nil,
			assertErr: assert.NoError,
		},
		"disabling SVC resolution, returns unchanged": {
			input:                 &snet.Addr{Host: newSVCAppAddr(addr.SvcBS)},
			wantAddr:              &snet.Addr{Host: newSVCAppAddr(addr.SvcBS)},
			SVCResolutionFraction: 0.0,
			assertErr:             assert.NoError,
		},
		"not nil invalid addr, error": {
			input:                 &net.TCPAddr{},
			wantAddr:              nil,
			wantRedirect:          false,
			SVCResolutionFraction: 1.0,
			assertErr:             assert.Error,
		},
		"valid empty UDP, ?error": {
			input:                 newUDPAppAddr(&net.UDPAddr{}),
			wantAddr:              nil,
			wantRedirect:          false,
			SVCResolutionFraction: 1.0,
			assertErr:             assert.Error,
		},
		"valid UDPAddr, returns unchanged": {
			input: &snet.Addr{
				Host: newUDPAppAddr(&net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1}),
			},
			wantAddr: &snet.Addr{
				Host: newUDPAppAddr(&net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1}),
			},
			SVCResolutionFraction: 1.0,
			wantRedirect:          false,
			assertErr:             assert.NoError,
		},
	}
	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			router := mock_snet.NewMockRouter(ctrl)
			router.EXPECT().Route(gomock.Any(), gomock.Any()).Times(0)
			resolver := mock_messenger.NewMockResolver(ctrl)
			resolver.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			aw := messenger.AddressRewriter{
				Resolver:              resolver,
				Router:                router,
				SVCResolutionFraction: tc.SVCResolutionFraction,
			}

			a, r, err := aw.RedirectToQUIC(context.Background(), tc.input)
			tc.assertErr(t, err)
			assert.Equal(t, a, tc.wantAddr)
			assert.Equal(t, r, tc.wantRedirect)
		})
	}
}

func TestBuildFullAddress(t *testing.T) {
	testCases := map[string]struct {
		input     net.Addr
		want      net.Addr
		assertErr assert.ErrorAssertionFunc
	}{
		"non-snet address": {
			input:     &net.UDPAddr{},
			assertErr: assert.Error,
		},
		"snet address without host": {
			input:     &snet.Addr{},
			assertErr: assert.Error,
		},
		"snet address without L3": {
			input:     &snet.Addr{Host: &addr.AppAddr{}},
			assertErr: assert.Error,
		},
		"snet address with bad L3 type": {
			input: &snet.Addr{
				Host: &addr.AppAddr{
					L3: &addr.HostNone{},
					L4: 5,
				},
			},
			assertErr: assert.Error,
		},
	}
	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			router := mock_snet.NewMockRouter(ctrl)
			resolver := mock_messenger.NewMockResolver(ctrl)
			aw := messenger.AddressRewriter{
				Resolver: resolver,
				Router:   router,
			}

			a, err := aw.BuildFullAddress(context.Background(), tc.input)
			assert.Equal(t, a, tc.want)
			tc.assertErr(t, err)
		})
	}

	t.Run("snet address without path, error retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		input := &snet.Addr{
			IA:   remoteIA,
			Host: newSVCAppAddr(addr.SvcBS),
		}
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("err"))
		_, err := aw.BuildFullAddress(context.Background(), input)
		assert.Error(t, err)
	})

	t.Run("snet address with path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		input := &snet.Addr{
			IA:   remoteIA,
			Host: newSVCAppAddr(addr.SvcBS),
			Path: &spath.Path{},
		}
		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Equal(t, a, input)
		assert.NoError(t, err)
	})

	t.Run("snet address without path, successful retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Path().Return(&spath.Path{})
		path.EXPECT().OverlayNextHop().Return(&net.UDPAddr{})
		path.EXPECT().Fingerprint().Return("foo")
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
		input := &snet.Addr{
			IA:   remoteIA,
			Host: newSVCAppAddr(addr.SvcBS),
		}
		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Equal(t, a, &snet.Addr{
			IA:      remoteIA,
			Host:    newSVCAppAddr(addr.SvcBS),
			Path:    &spath.Path{},
			NextHop: &net.UDPAddr{},
		})
		assert.NoError(t, err)
	})

	t.Run("snet address in local AS, overlay address extraction succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		localIA := xtest.MustParseIA("1-ff00:0:1")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		overlayAddr := &net.UDPAddr{
			IP:   net.IP{192, 168, 0, 1},
			Port: 10,
		}
		svcRouter.EXPECT().GetOverlay(addr.SvcBS).Return(overlayAddr, nil)

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Fingerprint()
		path.EXPECT().Path()
		path.EXPECT().OverlayNextHop()
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)

		input := &snet.Addr{
			IA:   localIA,
			Host: newSVCAppAddr(addr.SvcBS),
		}

		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Equal(t, a, &snet.Addr{
			IA:      localIA,
			Host:    newSVCAppAddr(addr.SvcBS),
			NextHop: overlayAddr,
		})
		assert.NoError(t, err)
	})

	t.Run("snet address in local AS, overlay address extraction fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		localIA := xtest.MustParseIA("1-ff00:0:1")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := messenger.AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		svcRouter.EXPECT().GetOverlay(addr.SvcBS).Return(nil, errors.New("err"))

		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Fingerprint()
		path.EXPECT().Path()
		path.EXPECT().OverlayNextHop()
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)

		input := &snet.Addr{
			IA:   localIA,
			Host: newSVCAppAddr(addr.SvcBS),
		}

		a, err := aw.BuildFullAddress(context.Background(), input)
		assert.Nil(t, a)
		assert.Error(t, err)
	})
}

func TestResolve(t *testing.T) {
	testCases := map[string]struct {
		input                 addr.HostSVC
		ResolverSetup         func(*mock_messenger.MockResolver)
		SVCResolutionFraction float64
		wantPath              snet.Path
		want                  *net.UDPAddr
		wantQUICRedirect      bool
		assertErr             assert.ErrorAssertionFunc
	}{
		"svc address, lookup fails": {
			input: addr.SvcBS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 1.0,
			assertErr:             assert.Error,
		},
		"svc address, half time allowed for resolution, lookup fails": {
			input: addr.SvcBS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 0.5,
			want:                  nil,
			assertErr:             assert.NoError,
		},
		"svc address, lookup succeeds": {
			input: addr.SvcBS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(
						&svc.Reply{
							Transports: map[svc.Transport]string{
								svc.QUIC: "192.168.1.1:8000",
							},
							ReturnPath: &testPath{},
						},
						nil,
					)
			},
			SVCResolutionFraction: 1.0,
			wantPath:              &testPath{},
			want:                  &net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000},
			wantQUICRedirect:      true,
			assertErr:             assert.NoError,
		},
		"svc address, half time allowed for resolution, lookup succeeds": {
			input: addr.SvcBS,
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(
						&svc.Reply{
							Transports: map[svc.Transport]string{
								svc.QUIC: "192.168.1.1:8000",
							},
						},
						nil,
					)
			},
			SVCResolutionFraction: 0.5,
			want:                  &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8000},
			wantQUICRedirect:      true,
			assertErr:             assert.NoError,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			resolver := mock_messenger.NewMockResolver(ctrl)
			path := mock_snet.NewMockPath(ctrl)
			path.EXPECT().Destination().Return(addr.IA{}).AnyTimes()
			aw := messenger.AddressRewriter{
				Resolver:              resolver,
				SVCResolutionFraction: tc.SVCResolutionFraction,
			}
			initResolver(resolver, tc.ResolverSetup)
			p, a, redirect, err := aw.ResolveSVC(context.Background(), path, tc.input)
			assert.Equal(t, p, tc.wantPath)
			assert.Equal(t, a.String(), tc.want.String())
			assert.Equal(t, redirect, tc.wantQUICRedirect)
			tc.assertErr(t, err)
		})
	}
}

func TestParseReply(t *testing.T) {
	testCases := map[string]struct {
		mockReply *svc.Reply
		want      *net.UDPAddr
		assertErr assert.ErrorAssertionFunc
	}{
		"nil reply": {
			assertErr: assert.Error,
		},
		"empty reply": {
			mockReply: &svc.Reply{},
			assertErr: assert.Error,
		},
		"key not found in reply": {
			mockReply: &svc.Reply{Transports: map[svc.Transport]string{svc.UDP: "foo"}},
			assertErr: assert.Error,
		},
		"key found in reply, but parsing fails": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "foo",
				},
			},
			assertErr: assert.Error,
		},
		"key found in reply, IPv4 address": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "192.168.1.1:8000",
				},
			},
			want:      &net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000},
			assertErr: assert.NoError,
		},
		"key found in reply, IPv6 address": {
			mockReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "[2001:db8::1]:8000",
				},
			},
			want:      &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8000},
			assertErr: assert.NoError,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			a, err := messenger.ParseReply(tc.mockReply)
			tc.assertErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, a.String(), tc.want.String())
		})
	}
}

func initResolver(resolver *mock_messenger.MockResolver, f func(*mock_messenger.MockResolver)) {
	if f != nil {
		f(resolver)
	}
}

type testPath struct{}

func (t *testPath) Fingerprint() string {
	panic("not implemented")
}

func (t *testPath) OverlayNextHop() *net.UDPAddr {
	panic("not implemented")
}

func (t *testPath) Path() *spath.Path {
	panic("not implemented")
}

func (t *testPath) Interfaces() []snet.PathInterface {
	panic("not implemented")
}

func (t *testPath) Destination() addr.IA {
	panic("not implemented")
}

func (t *testPath) MTU() uint16 {
	panic("not implemented")
}

func (t *testPath) Expiry() time.Time {
	panic("not implemented")
}

func (t *testPath) Copy() snet.Path {
	panic("not implemented")
}

func newSVCAppAddr(svc addr.HostSVC) *addr.AppAddr {
	return &addr.AppAddr{
		L3: svc,
	}
}
func newUDPAppAddr(u *net.UDPAddr) *addr.AppAddr {
	return &addr.AppAddr{
		L3: addr.HostFromIP(u.IP),
		L4: uint16(u.Port),
	}
}
