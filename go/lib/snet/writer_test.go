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
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/pathmgr/mock_pathmgr"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor"
	"github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor/mock_ctxmonitor"
	"github.com/scionproto/scion/go/lib/snet/internal/pathsource/mock_pathsource"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
)

func buildNullMonitorMock(ctrl *gomock.Controller) ctxmonitor.Monitor {
	monitor := mock_ctxmonitor.NewMockMonitor(ctrl)
	monitor.EXPECT().WithTimeout(gomock.Any(), gomock.Any()).AnyTimes().
		Return(context.Background(), func() {})
	return monitor
}

func TestConnRemoteAddressResolver(t *testing.T) {
	t.Log("Given a remote address resolver")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	resolver := &remoteAddressResolver{monitor: buildNullMonitorMock(ctrl)}
	t.Run("If both addresses are unknown, error out", func(t *testing.T) {
		address, err := resolver.resolveAddrPair(nil, nil)
		assert.Error(t, err, "err")
		assert.Nil(t, address, "address")
	})
	t.Run("If both address are known, error out", func(t *testing.T) {
		connRemoteAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
		argRemoteAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
		address, err := resolver.resolveAddrPair(connRemoteAddress, argRemoteAddress)
		assert.Error(t, err, "err")
		assert.Nil(t, address, "address")
	})
}

func TestRemoteAddressResolver(t *testing.T) {
	t.Log("Given a single remote address resolver")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pathSource := mock_pathsource.NewMockPathSource(ctrl)
	resolver := &remoteAddressResolver{
		localIA:      xtest.MustParseIA("1-ff00:0:110"),
		pathResolver: pathSource,
		monitor:      buildNullMonitorMock(ctrl),
	}

	t.Run("error if address is nil", func(t *testing.T) {
		address, err := resolver.resolveAddr(nil)
		assert.EqualError(t, err, string(ErrAddressIsNil))
		assert.Nil(t, address, "address")
	})

	t.Run("error if app address is unset", func(t *testing.T) {
		address := &Addr{}
		address, err := resolver.resolveAddr(address)
		assert.EqualError(t, err, string(ErrNoApplicationAddress))
		assert.Nil(t, address, "address")
	})

	t.Run("if destination is in local AS", func(t *testing.T) {
		t.Run("error if path set.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
			inAddress.Path = &spath.Path{}
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.EqualError(t, err, string(ErrExtraPath))
			assert.Nil(t, outAddress, "address")
		})
		t.Run("return same address if path unset, and overlay address set.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
			inAddress.NextHop = &net.UDPAddr{}
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.NoError(t, err, "err")
			assert.Equal(t, outAddress, inAddress)
		})
		t.Run("inherit overlay data if overlay address unset.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:110,[127.0.0.1]:80")
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.NoError(t, err)
			assert.NotNil(t, outAddress)
			assert.Equal(t, outAddress.NextHop.IP, outAddress.Host.L3.IP(), "overlay addr")
			assert.Equal(t, outAddress.NextHop.Port, topology.EndhostPort, "overlay port")
		})
	})
	t.Run("if destination is not in local AS", func(t *testing.T) {
		t.Run("error if path set but overlay address unset.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
			inAddress.Path = &spath.Path{}
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.EqualError(t, err, string(ErrBadOverlay))
			assert.Nil(t, outAddress, "address")
		})
		t.Run("error if overlay set but path unset.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
			inAddress.NextHop = &net.UDPAddr{}
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.EqualError(t, err, string(ErrMustHavePath))
			assert.Nil(t, outAddress, "address")
		})
		t.Run("return same address if path and overlay set.", func(t *testing.T) {
			inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
			inAddress.Path = &spath.Path{}
			inAddress.NextHop = &net.UDPAddr{}
			outAddress, err := resolver.resolveAddr(inAddress)
			assert.NoError(t, err, "err")
			assert.Equal(t, outAddress, inAddress)
		})
		t.Run("request path if path and overlay unset", func(t *testing.T) {
			t.Run("if request not successful, error.", func(t *testing.T) {
				inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
				pathSource.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, nil, fmt.Errorf("some error"))
				outAddress, err := resolver.resolveAddr(inAddress)
				assert.EqualError(t, err, string(ErrPath))
				assert.Nil(t, outAddress, "address")
			})
			t.Run("if request successful, return address.", func(t *testing.T) {
				inAddress := MustParseAddr("1-ff00:0:113,[127.0.0.1]:80")
				path := &spath.Path{}
				overlayAddr := &net.UDPAddr{}
				pathSource.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(overlayAddr, path, nil)
				outAddress, err := resolver.resolveAddr(inAddress)
				assert.NoError(t, err)
				assert.NotNil(t, outAddress)
				assert.Equal(t, outAddress.Path, path)
				assert.Equal(t, outAddress.NextHop, overlayAddr)
			})
		})
	})
}

func TestSetDeadline(t *testing.T) {
	t.Log("Given an snet write connection")
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	done := make(chan struct{}, 3)

	resolverMock := mock_pathmgr.NewMockResolver(ctrl)
	resolverMock.EXPECT().Query(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).DoAndReturn(

		func(ctx context.Context, _, _, _ interface{}) spathmeta.AppPathSet {
			select {
			case <-ctx.Done():
				done <- struct{}{}
			}
			return nil
		},
	).AnyTimes()
	connMock := mock_net.NewMockPacketConn(ctrl)
	connMock.EXPECT().SetWriteDeadline(gomock.Any()).AnyTimes().Return(nil)
	packetConn := NewSCIONPacketConn(connMock, nil)

	conn := newScionConnWriter(&scionConnBase{
		laddr: MustParseAddr("2-ff00:0:1,[127.0.0.1]:80"),
	}, resolverMock, packetConn)
	t.Run("And writes to multiple destinations for which path resolution is slow",
		func(t *testing.T) {
			addresses := []*Addr{
				MustParseAddr("1-ff00:0:1,[127.0.0.1]:80"),
				MustParseAddr("1-ff00:0:2,[127.0.0.1]:80"),
				MustParseAddr("1-ff00:0:3,[127.0.0.1]:80"),
			}
			for _, address := range addresses {
				go conn.WriteTo([]byte{1, 2, 3}, address)
			}
			t.Run("Setting the deadline in the past unlocks all writers", func(t *testing.T) {
				conn.SetWriteDeadline(time.Now().Add(-time.Second))
				for range addresses {
					xtest.AssertReadReturnsBefore(t, done, time.Second)
				}
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
