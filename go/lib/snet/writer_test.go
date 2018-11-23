// Copyright 2018 ETH Zurich
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

package snet

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/mocks/mock_net"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr/mock_pathmgr"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor/mock_ctxmonitor"
	"github.com/scionproto/scion/go/lib/snet/internal/pathsource/mock_pathsource"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
)

func buildNullMonitorMock(ctrl *gomock.Controller) ctxmonitor.Monitor {
	monitor := mock_ctxmonitor.NewMockMonitor(ctrl)
	monitor.EXPECT().WithTimeout(gomock.Any(), gomock.Any()).AnyTimes().
		Return(context.Background(), func() {})
	return monitor
}

func TestConnRemoteAddressResolver(t *testing.T) {
	Convey("Given a remote address resolver", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		resolver := &remoteAddressResolver{monitor: buildNullMonitorMock(ctrl)}
		Convey("If both addresses are unknown, error out", func() {
			address, err := resolver.resolveAddrPair(nil, nil)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("address", address, ShouldBeNil)
		})
		Convey("If both address are known, error out", func() {
			connRemoteAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
			argRemoteAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
			address, err := resolver.resolveAddrPair(connRemoteAddress, argRemoteAddress)
			SoMsg("err", err, ShouldNotBeNil)
			SoMsg("address", address, ShouldBeNil)
		})
	})
}

func TestRemoteAddressResolver(t *testing.T) {
	Convey("Given a single remote address resolver", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		pathSource := mock_pathsource.NewMockPathSource(ctrl)
		resolver := &remoteAddressResolver{
			localIA:      xtest.MustParseIA("1-ff00:0:110"),
			pathResolver: pathSource,
			monitor:      buildNullMonitorMock(ctrl),
		}
		Convey("error if address is nil", func() {
			address, err := resolver.resolveAddr(nil)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrAddressIsNil)
			SoMsg("address", address, ShouldBeNil)
		})
		Convey("error if app address is unset", func() {
			address := &Addr{}
			address, err := resolver.resolveAddr(address)
			SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrNoApplicationAddress)
			SoMsg("address", address, ShouldBeNil)
		})
		Convey("if destination is in local AS", func() {
			inAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
			Convey("error if path set.", func() {
				inAddress.Path = &spath.Path{}
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrExtraPath)
				SoMsg("address", outAddress, ShouldBeNil)
			})
			Convey("return same address if path unset, and overlay address set.", func() {
				inAddress.NextHop = &overlay.OverlayAddr{}
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", outAddress, ShouldEqual, inAddress)
			})
			Convey("inherit overlay data if overlay address unset.", func() {
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", outAddress, ShouldNotBeNil)
				SoMsg("overlay addr", outAddress.NextHop.L3(), ShouldResemble, outAddress.Host.L3)
				SoMsg("overlay port", outAddress.NextHop.L4().Port(), ShouldResemble,
					uint16(overlay.EndhostPort))
			})
		})
		Convey("if destination is not in local AS", func() {
			inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
			Convey("error if path set but overlay address unset.", func() {
				inAddress.Path = &spath.Path{}
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrBadOverlay)
				SoMsg("address", outAddress, ShouldBeNil)
			})
			Convey("error if overlay set but path unset.", func() {
				inAddress.NextHop = &overlay.OverlayAddr{}
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrMustHavePath)
				SoMsg("address", outAddress, ShouldBeNil)
			})
			Convey("return same address if path and overlay set.", func() {
				inAddress.Path = &spath.Path{}
				inAddress.NextHop = &overlay.OverlayAddr{}
				outAddress, err := resolver.resolveAddr(inAddress)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("address", outAddress, ShouldResemble, inAddress)
			})
			Convey("request path if path and overlay unset", func() {
				Convey("if request not successful, error.", func() {
					pathSource.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
						Return(nil, nil, fmt.Errorf("some error"))
					outAddress, err := resolver.resolveAddr(inAddress)
					SoMsg("err", common.GetErrorMsg(err), ShouldEqual, ErrPath)
					SoMsg("address", outAddress, ShouldBeNil)
				})
				Convey("if request successful, return address.", func() {
					path := &spath.Path{}
					overlayAddr := &overlay.OverlayAddr{}
					pathSource.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
						Return(overlayAddr, path, nil)
					outAddress, err := resolver.resolveAddr(inAddress)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("address", outAddress, ShouldNotBeNil)
					SoMsg("path", outAddress.Path, ShouldEqual, path)
					SoMsg("overlay", outAddress.NextHop, ShouldEqual, overlayAddr)
				})
			})
		})
	})
}

func TestSetDeadline(t *testing.T) {
	Convey("Given an snet write connection", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		done := make(chan struct{}, 3)

		resolverMock := mock_pathmgr.NewMockResolver(ctrl)
		resolverMock.EXPECT().Query(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, _, _ interface{}) spathmeta.AppPathSet {
				select {
				case <-ctx.Done():
					done <- struct{}{}
				}
				return nil
			},
		).AnyTimes()
		connMock := mock_net.NewMockPacketConn(ctrl)
		connMock.EXPECT().SetWriteDeadline(gomock.Any()).AnyTimes().Return(nil)

		conn := newScionConnWriter(&scionConnBase{
			laddr: MustParseAddr("2-ff00:0:1,[127.0.0.1]:80"),
		}, resolverMock, connMock)
		Convey("And writes to multiple destinations for which path resolution is slow", func() {
			addresses := []*Addr{
				MustParseAddr("1-ff00:0:1,[127.0.0.1]:80"),
				MustParseAddr("1-ff00:0:2,[127.0.0.1]:80"),
				MustParseAddr("1-ff00:0:3,[127.0.0.1]:80"),
			}
			for _, address := range addresses {
				go conn.WriteTo([]byte{1, 2, 3}, address)
			}
			Convey("Setting the deadline in the past unlocks all writers", func() {
				conn.SetWriteDeadline(time.Now().Add(-time.Second))
				for range addresses {
					xtest.AssertReadReturnsBefore(t, done, time.Second)
				}
			})
		})
	})
}

func MustParseAddr(str string) *Addr {
	address, err := AddrFromString(str)
	if err != nil {
		panic(fmt.Sprintf("cannot parse address %s", str))
	}
	return address
}
