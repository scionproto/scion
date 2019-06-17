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

package snetproxy_test

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/sock/reliable/mock_reliable"
)

func TestReconnect(t *testing.T) {
	Convey("Reconnections must conserve local and bind addresses", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockNetwork := mock_reliable.NewMockDispatcherService(ctrl)
		Convey("Given a mocked underlying connection with local and bind", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, svc)
			Convey("If local address and bind address do not change", func() {
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(0), nil)
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(0), nil)
				Convey("reconnect must not return error.", func() {
					proxyNetwork := snetproxy.NewReconnectingDispatcherService(mockNetwork)
					proxyConn, _, _ := proxyNetwork.RegisterTimeout(localAddr.IA,
						localAddr.Host, bindAddr, svc, timeout)
					_, _, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldBeNil)
				})
			})
			Convey("If local address changes", func() {
				secondConn := NewMockConnWithAddrs(ctrl, otherLocalAddr, nil, nil, svc)
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(0), nil)
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(secondConn, uint16(0), nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewReconnectingDispatcherService(mockNetwork)
					proxyConn, _, _ := proxyNetwork.RegisterTimeout(localAddr.IA,
						localAddr.Host, bindAddr, svc, timeout)
					_, _, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
			Convey("If allocated port changes", func() {
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(1), nil)
				mockNetwork.EXPECT().
					RegisterTimeout(localAddr.IA, localAddr.Host, bindAddr, svc, timeout).
					Return(mockConn, uint16(2), nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewReconnectingDispatcherService(mockNetwork)
					proxyConn, _, _ := proxyNetwork.RegisterTimeout(localAddr.IA,
						localAddr.Host, bindAddr, svc, timeout)
					_, _, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
		})
	})
}

func TestNetworkFatalError(t *testing.T) {
	Convey("Given a proxy network running over an underlying mocked network", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		err := common.NewBasicError("Not dispatcher dead error, e.g., malformed register msg", nil)
		mockNetwork := mock_reliable.NewMockDispatcherService(ctrl)
		proxyNetwork := snetproxy.NewReconnectingDispatcherService(mockNetwork)
		Convey("The proxy network returns non-dispatcher dial errors from the mock", func() {
			mockNetwork.EXPECT().
				RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), err)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("The proxy network returns non-dispatcher listen errors from the mock", func() {
			mockNetwork.EXPECT().
				RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
				Return(nil, uint16(0), err)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
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
		proxyNetwork := snetproxy.NewReconnectingDispatcherService(mockNetwork)
		Convey("Dial tries to reconnect if no timeout set", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, remoteAddr, nil, addr.SvcNone)
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, uint16(0), nil),
			)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Dial only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					MinTimes(2).MaxTimes(5),
			)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{},
				nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Listen tries to reconnect if no timeout set", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, nil, addr.SvcNone)
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, uint16(0), nil),
			)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{}, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Listen only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					RegisterTimeout(Any(), Any(), Any(), Any(), Any()).
					Return(nil, uint16(0), dispatcherError).
					MinTimes(3).MaxTimes(5),
			)
			_, _, err := proxyNetwork.RegisterTimeout(addr.IA{},
				nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}
