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

package messenger

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
	"github.com/scionproto/scion/go/lib/infra/messenger/mock_messenger"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestBuildFullAddress(t *testing.T) {
	testCases := []struct {
		dscr  string
		input net.Addr
		want  *snet.Addr
		af    assert.ErrorAssertionFunc
	}{
		{
			dscr:  "non-snet address",
			input: &net.UDPAddr{},
			af:    assert.Error,
		},
		{
			dscr:  "snet address without host",
			input: &snet.Addr{},
			af:    assert.Error,
		},
		{
			dscr:  "snet address without L3",
			input: &snet.Addr{Host: &addr.AppAddr{}},
			af:    assert.Error,
		},
		{
			dscr: "snet address with bad L3 type",
			input: &snet.Addr{
				Host: &addr.AppAddr{
					L3: &addr.HostNone{},
					L4: 5,
				},
			},
			af: assert.Error,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.dscr, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			router := mock_snet.NewMockRouter(ctrl)
			resolver := mock_messenger.NewMockResolver(ctrl)
			aw := AddressRewriter{
				Resolver: resolver,
				Router:   router,
			}

			a, err := aw.buildFullAddress(context.Background(), tc.input)
			assert.Equal(t, a, tc.want)
			tc.af(t, err)
		})
	}

	t.Run("snet address without path, error retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		input := &snet.Addr{
			IA:   remoteIA,
			Host: addr.NewSVCUDPAppAddr(addr.SvcBS),
		}
		router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("err"))
		_, err := aw.buildFullAddress(context.Background(), input)
		assert.Error(t, err)
	})

	t.Run("snet address with path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := AddressRewriter{
			Router:    router,
			SVCRouter: svcRouter,
		}

		input := &snet.Addr{
			IA:   remoteIA,
			Host: addr.NewSVCUDPAppAddr(addr.SvcBS),
			Path: &spath.Path{},
		}
		a, err := aw.buildFullAddress(context.Background(), input)
		assert.Equal(t, a, input)
		assert.NoError(t, err)
	})

	t.Run("snet address without path, successful retrieving path", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		remoteIA := xtest.MustParseIA("1-ff00:0:2")
		svcRouter := mock_messenger.NewMockLocalSVCRouter(ctrl)
		aw := AddressRewriter{
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
			Host: addr.NewSVCUDPAppAddr(addr.SvcBS),
		}
		a, err := aw.buildFullAddress(context.Background(), input)
		assert.Equal(t, a, &snet.Addr{
			IA:      remoteIA,
			Host:    addr.NewSVCUDPAppAddr(addr.SvcBS),
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
		aw := AddressRewriter{
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
			Host: addr.NewSVCUDPAppAddr(addr.SvcBS),
		}

		a, err := aw.buildFullAddress(context.Background(), input)
		assert.Equal(t, a, &snet.Addr{
			IA:      localIA,
			Host:    addr.NewSVCUDPAppAddr(addr.SvcBS),
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
		aw := AddressRewriter{
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
			Host: addr.NewSVCUDPAppAddr(addr.SvcBS),
		}

		a, err := aw.buildFullAddress(context.Background(), input)
		assert.Nil(t, a)
		assert.Error(t, err)
	})
}

func TestResolveIfSVC(t *testing.T) {
	testCases := []struct {
		dscr                  string
		input                 *addr.AppAddr
		ResolverSetup         func(*mock_messenger.MockResolver)
		SVCResolutionFraction float64
		wantPath              snet.Path
		want                  *addr.AppAddr
		wantQUICRedirect      bool
		af                    assert.ErrorAssertionFunc
	}{
		{
			dscr: "non-svc address does not trigger lookup",
			input: addr.NewUDPAppAddr(
				&net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1}),
			SVCResolutionFraction: 1.0,
			want: addr.NewUDPAppAddr(&net.UDPAddr{
				IP: net.IP{192, 168, 0, 1}, Port: 1}),
			af: assert.NoError,
		},
		{
			dscr:                  "disabling SVC resolution does not trigger lookup, same addr",
			input:                 addr.NewSVCUDPAppAddr(addr.SvcBS),
			SVCResolutionFraction: 0.0,
			want:                  addr.NewSVCUDPAppAddr(addr.SvcBS),
			af:                    assert.NoError,
		},
		{
			dscr:  "svc address, lookup fails",
			input: addr.NewSVCUDPAppAddr(addr.SvcBS),
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 1.0,
			af:                    assert.Error,
		},
		{
			dscr:  "svc address, half time allowed for resolution, lookup fails",
			input: addr.NewSVCUDPAppAddr(addr.SvcBS),
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 0.5,
			want:                  addr.NewSVCUDPAppAddr(addr.SvcBS),
			af:                    assert.NoError,
		},
		{
			dscr:  "svc address, lookup succeeds",
			input: addr.NewSVCUDPAppAddr(addr.SvcBS),
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
			want: addr.NewUDPAppAddr(
				&net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000}),
			wantQUICRedirect: true,
			af:               assert.NoError,
		},
		{
			dscr:  "svc address, half time allowed for resolution, lookup succeeds",
			input: addr.NewSVCUDPAppAddr(addr.SvcBS),
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
			want: addr.NewUDPAppAddr(
				&net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000}),
			wantQUICRedirect: true,
			af:               assert.NoError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.dscr, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			resolver := mock_messenger.NewMockResolver(ctrl)
			path := mock_snet.NewMockPath(ctrl)
			path.EXPECT().Destination().Return(addr.IA{}).AnyTimes()
			aw := AddressRewriter{
				Resolver:              resolver,
				SVCResolutionFraction: tc.SVCResolutionFraction,
			}
			initResolver(resolver, tc.ResolverSetup)
			p, a, redirect, err := aw.resolveIfSVC(context.Background(), path, tc.input)
			assert.Equal(t, p, tc.wantPath)
			assert.Equal(t, a, tc.want)
			assert.Equal(t, redirect, tc.wantQUICRedirect)
			tc.af(t, err)
		})
	}
}

func TestParseReply(t *testing.T) {
	testCases := []struct {
		dscr  string
		Reply *svc.Reply
		want  *net.UDPAddr
		af    assert.ErrorAssertionFunc
	}{
		{
			dscr: "nil reply",
			af:   assert.Error,
		},
		{
			dscr:  "empty reply",
			Reply: &svc.Reply{},
			af:    assert.Error,
		},
		{
			dscr:  "key not found in reply",
			Reply: &svc.Reply{Transports: map[svc.Transport]string{svc.UDP: "foo"}},
			af:    assert.Error,
		},
		{
			dscr: "key found in reply, but parsing fails",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "foo",
				},
			},
			af: assert.Error,
		},
		{
			dscr: "key found in reply, IPv4 address",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "192.168.1.1:8000",
				},
			},
			want: &net.UDPAddr{IP: net.IP{192, 168, 1, 1}, Port: 8000},
			af:   assert.NoError,
		},
		{
			dscr: "key found in reply, IPv6 address",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "[2001:db8::1]:8000",
				},
			},
			want: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8000},
			af:   assert.NoError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.dscr, func(t *testing.T) {
			a, err := parseReply(tc.Reply)
			tc.af(t, err)
			if err != nil {
				return
			}
			want := addr.NewUDPAppAddr(tc.want)
			assert.Equal(t, a, want)
		})
	}
}

func TestBuildReply(t *testing.T) {
	testCases := []struct {
		dscr  string
		input *addr.AppAddr
		want  *svc.Reply
	}{
		{
			dscr: "nil app address",
			want: &svc.Reply{},
		},
		{
			dscr:  "nil L3",
			input: &addr.AppAddr{L4: 1},
			want:  &svc.Reply{},
		},
		{
			dscr:  "nil L4",
			input: addr.NewSVCUDPAppAddr(addr.SvcBS),
			want:  &svc.Reply{},
		},
		{
			dscr:  "IPv4 L3, UDP L4",
			input: addr.NewUDPAppAddr(&net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1}),
			want: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.UDP: "192.168.0.1:1",
				},
			},
		},
		{
			dscr:  "IPv6 L3, UDP L4",
			input: addr.NewUDPAppAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1}),
			want: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.UDP: "[2001:db8::1]:1",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.dscr, func(t *testing.T) {
			got := BuildReply(tc.input)
			assert.Equal(t, got, tc.want)
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
