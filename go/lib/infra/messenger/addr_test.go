// Copyright 2019 ETH Zurich
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
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/messenger/mock_messenger"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestBuildFullAddress(t *testing.T) {
	testCases := []struct {
		Description     string
		InputAddress    net.Addr
		ExpectedAddress *snet.Addr
		ExpectedError   bool
	}{
		{
			Description:   "non-snet address",
			InputAddress:  &net.UDPAddr{},
			ExpectedError: true,
		},
		{
			Description:   "snet address without host",
			InputAddress:  &snet.Addr{},
			ExpectedError: true,
		},
		{
			Description:   "snet address without L3",
			InputAddress:  &snet.Addr{Host: &addr.AppAddr{}},
			ExpectedError: true,
		},
		{
			Description:   "snet address without L4",
			InputAddress:  &snet.Addr{Host: &addr.AppAddr{L3: addr.SvcBS}},
			ExpectedError: true,
		},
		{
			Description: "snet address with bad L3 type",
			InputAddress: &snet.Addr{
				Host: &addr.AppAddr{
					L3: &addr.HostNone{},
					L4: addr.NewL4UDPInfo(5),
				},
			},
			ExpectedError: true,
		},
		{
			Description: "snet address with bad L4 type",
			InputAddress: &snet.Addr{
				Host: &addr.AppAddr{
					L3: addr.SvcBS,
					L4: addr.NewL4TCPInfo(5),
				},
			},
			ExpectedError: true,
		},
	}
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		resolver := mock_messenger.NewMockResolver(ctrl)
		aw := AddressRewriter{
			Resolver: resolver,
			Router:   router,
		}
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				a, err := aw.buildFullAddress(context.Background(), tc.InputAddress)
				SoMsg("addr", a, ShouldResemble, tc.ExpectedAddress)
				xtest.SoMsgError("err", err, tc.ExpectedError)
			})
		}
	})
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		router := mock_snet.NewMockRouter(ctrl)
		aw := AddressRewriter{
			Router: router,
		}
		Convey("snet address without path, error retrieving path", func() {
			inputAddress := &snet.Addr{
				Host: &addr.AppAddr{
					L3: addr.SvcBS,
					L4: addr.NewL4UDPInfo(1),
				},
			}
			router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("err"))
			_, err := aw.buildFullAddress(context.Background(), inputAddress)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("snet address with path", func() {
			inputAddress := &snet.Addr{
				Host: &addr.AppAddr{
					L3: addr.SvcBS,
					L4: addr.NewL4UDPInfo(1),
				},
				Path: &spath.Path{},
			}
			a, err := aw.buildFullAddress(context.Background(), inputAddress)
			SoMsg("addr", a, ShouldResemble, inputAddress)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("snet address without path, successful retrieving path", func() {
			path := mock_snet.NewMockPath(ctrl)
			path.EXPECT().Path().Return(&spath.Path{})
			path.EXPECT().OverlayNextHop().Return(&overlay.OverlayAddr{})
			router.EXPECT().Route(gomock.Any(), gomock.Any()).Return(path, nil)
			inputAddress := &snet.Addr{
				Host: &addr.AppAddr{
					L3: addr.SvcBS,
					L4: addr.NewL4UDPInfo(1),
				},
			}
			a, err := aw.buildFullAddress(context.Background(), inputAddress)
			SoMsg("addr", a, ShouldResemble, &snet.Addr{
				Host: &addr.AppAddr{
					L3: addr.SvcBS,
					L4: addr.NewL4UDPInfo(1),
				},
				Path:    &spath.Path{},
				NextHop: &overlay.OverlayAddr{},
			})
			SoMsg("err", err, ShouldBeNil)
		})
	})
}

func TestResolveIfSVC(t *testing.T) {
	testCases := []struct {
		Description           string
		InputAddress          *addr.AppAddr
		ResolverSetup         func(*mock_messenger.MockResolver)
		SVCResolutionFraction float64
		ExpectedAddress       *addr.AppAddr
		ExpectedQUICRedirect  bool
		ExpectedError         bool
	}{
		{
			Description: "non-svc address does not trigger lookup",
			InputAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4: addr.NewL4UDPInfo(1),
			},
			SVCResolutionFraction: 1.0,
			ExpectedAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4: addr.NewL4UDPInfo(1),
			},
		},
		{
			Description: "disabling SVC resolution does not trigger lookup, same addr is returned",
			InputAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
			SVCResolutionFraction: 0.0,
			ExpectedAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
		},
		{
			Description: "svc address, lookup fails",
			InputAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 1.0,
			ExpectedError:         true,
		},
		{
			Description: "svc address, half time allowed for resolution, lookup fails",
			InputAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
			ResolverSetup: func(r *mock_messenger.MockResolver) {
				r.EXPECT().LookupSVC(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("err"))
			},
			SVCResolutionFraction: 0.5,
			ExpectedAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
		},
		{
			Description: "svc address, lookup succeeds",
			InputAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
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
			SVCResolutionFraction: 1.0,
			ExpectedAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 1, 1}),
				L4: addr.NewL4UDPInfo(8000),
			},
			ExpectedQUICRedirect: true,
		},
		{
			Description: "svc address, half time allowed for resolution, lookup succeeds",
			InputAddress: &addr.AppAddr{
				L3: addr.SvcBS,
				L4: addr.NewL4UDPInfo(1),
			},
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
			ExpectedAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 1, 1}),
				L4: addr.NewL4UDPInfo(8000),
			},
			ExpectedQUICRedirect: true,
		},
	}

	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		resolver := mock_messenger.NewMockResolver(ctrl)
		path := mock_snet.NewMockPath(ctrl)
		path.EXPECT().Destination().Return(addr.IA{}).AnyTimes()
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				aw := AddressRewriter{
					Resolver:              resolver,
					SVCResolutionFraction: tc.SVCResolutionFraction,
				}
				initResolver(resolver, tc.ResolverSetup)
				a, redirect, err := aw.resolveIfSVC(context.Background(), path, tc.InputAddress)
				SoMsg("addr", a, ShouldResemble, tc.ExpectedAddress)
				SoMsg("redirect", redirect, ShouldEqual, tc.ExpectedQUICRedirect)
				xtest.SoMsgError("err", err, tc.ExpectedError)
			})
		}
	})
}

func TestParseReply(t *testing.T) {
	testCases := []struct {
		Description     string
		Reply           *svc.Reply
		ExpectedAddress *addr.AppAddr
		ExpectedError   bool
	}{
		{
			Description:   "nil reply",
			ExpectedError: true,
		},
		{
			Description:   "empty reply",
			Reply:         &svc.Reply{},
			ExpectedError: true,
		},
		{
			Description:   "key not found in reply",
			Reply:         &svc.Reply{Transports: map[svc.Transport]string{svc.UDP: "foo"}},
			ExpectedError: true,
		},
		{
			Description: "key found in reply, but parsing fails",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "foo",
				},
			},
			ExpectedError: true,
		},
		{
			Description: "key found in reply, IPv4 address",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "192.168.1.1:8000",
				},
			},
			ExpectedAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 1, 1}),
				L4: addr.NewL4UDPInfo(8000),
			},
			ExpectedError: false,
		},
		{
			Description: "key found in reply, IPv6 address",
			Reply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.QUIC: "[2001:db8::1]:8000",
				},
			},
			ExpectedAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.ParseIP("2001:db8::1")),
				L4: addr.NewL4UDPInfo(8000),
			},
			ExpectedError: false,
		},
	}

	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				a, err := parseReply(tc.Reply)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				SoMsg("addr", a, ShouldResemble, tc.ExpectedAddress)
			})
		}
	})
}

func TestBuildReply(t *testing.T) {
	testCases := []struct {
		Description   string
		InputAddress  *addr.AppAddr
		ExpectedReply *svc.Reply
	}{
		{
			Description:   "nil app address",
			ExpectedReply: &svc.Reply{},
		},
		{
			Description:   "nil L3",
			InputAddress:  &addr.AppAddr{L4: addr.NewL4UDPInfo(1)},
			ExpectedReply: &svc.Reply{},
		},
		{
			Description:   "nil L4",
			InputAddress:  &addr.AppAddr{L3: addr.SvcBS},
			ExpectedReply: &svc.Reply{},
		},
		{
			Description: "IPv4 L3, UDP L4",
			InputAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.IP{192, 168, 0, 1}),
				L4: addr.NewL4UDPInfo(1),
			},
			ExpectedReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.UDP: "192.168.0.1:1",
				},
			},
		},
		{
			Description: "IPv6 L3, UDP L4",
			InputAddress: &addr.AppAddr{
				L3: addr.HostFromIP(net.ParseIP("2001:db8::1")),
				L4: addr.NewL4UDPInfo(1),
			},
			ExpectedReply: &svc.Reply{
				Transports: map[svc.Transport]string{
					svc.UDP: "[2001:db8::1]:1",
				},
			},
		},
	}

	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				So(BuildReply(tc.InputAddress), ShouldResemble, tc.ExpectedReply)
			})
		}
	})
}

func initResolver(resolver *mock_messenger.MockResolver, f func(*mock_messenger.MockResolver)) {
	if f != nil {
		f(resolver)
	}
}
