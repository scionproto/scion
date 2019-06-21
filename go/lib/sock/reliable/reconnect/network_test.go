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

package reconnect_test

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/mocks/net/mock_net"
	"github.com/scionproto/scion/go/lib/sock/reliable/mock_reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

func TestReconnect(t *testing.T) {
	Convey("Reconnections must conserve local and bind addresses", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcherService(ctrl)
		Convey("Given a mocked underlying connection with local and bind", func() {
			mockConn := mock_net.NewMockPacketConn(ctrl)
			Convey("Allocated ports are reused on subsequent attempts", func() {
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localNoPortAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(80), nil)
				newExpectedAddr := localNoPortAddr.Host.Copy()
				newExpectedAddr.L4 = addr.NewL4UDPInfo(80)
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, newExpectedAddr, bindAddr, svc, timeout).
					Return(mockConn, uint16(80), nil)

				network := reconnect.NewDispatcherService(mockNetwork)
				packetConn, _, _ := network.RegisterTimeout(localAddr.IA,
					localNoPortAddr.Host, bindAddr, svc, timeout)
				packetConn.(*reconnect.PacketConn).Reconnect()
			})
		})
	})
}

func TestNetworkFatalError(t *testing.T) {
	Convey("Given a network running over an underlying mocked network", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		err := common.NewBasicError("Not dispatcher dead error, e.g., malformed register msg", nil)
		mockNetwork := mock_reliable.NewMockDispatcherService(ctrl)
		network := reconnect.NewDispatcherService(mockNetwork)
		Convey("The network returns non-dispatcher dial errors from the mock", func() {
			mockNetwork.EXPECT().
				RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), err)
			_, _, err := network.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("The network returns non-dispatcher listen errors from the mock", func() {
			mockNetwork.EXPECT().
				RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), err)
			_, _, err := network.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

func TestNetworkDispatcherDeadError(t *testing.T) {
	dispatcherError := &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	Convey("Listen and Dial should reattempt to connect on dispatcher down errors", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcherService(ctrl)
		network := reconnect.NewDispatcherService(mockNetwork)
		Convey("Dial tries to reconnect if no timeout set", func() {
			mockConn := mock_net.NewMockPacketConn(ctrl)
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, uint16(0), nil),
			)
			_, _, err := network.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Dial only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					MinTimes(2).MaxTimes(5),
			)
			_, _, err := network.RegisterTimeout(addr.IA{},
				nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Listen tries to reconnect if no timeout set", func() {
			mockConn := mock_net.NewMockPacketConn(ctrl)
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, uint16(0), nil),
			)
			_, _, err := network.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Listen only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					MinTimes(3).MaxTimes(5),
			)
			_, _, err := network.RegisterTimeout(addr.IA{},
				nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}
