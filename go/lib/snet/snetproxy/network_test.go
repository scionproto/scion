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
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
)

func TestReconnect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Reconnections must conserve local and bind addresses", t, func() {
		mockNetwork := mock_snet.NewMockNetwork(ctrl)
		Convey("Given a mocked underlying connection with local and bind", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, bindAddr, svc)
			Convey("If local address and bind address do not change", func() {
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				Convey("reconnect must not return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.ListenSCIONWithBindSVC("udp4",
						localAddr, bindAddr, svc, timeout)
					_, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldBeNil)
				})
			})
			Convey("If local address changes", func() {
				secondConn := NewMockConnWithAddrs(ctrl, otherLocalAddr, nil, nil, svc)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(secondConn, nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.ListenSCIONWithBindSVC("udp4",
						localAddr, bindAddr, svc, timeout)
					_, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
			Convey("If bind address changes", func() {
				secondConn := NewMockConnWithAddrs(ctrl, localAddr, nil, otherBindAddr, svc)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, bindAddr, svc, timeout).
					Return(secondConn, nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.ListenSCIONWithBindSVC("udp4",
						localAddr, bindAddr, svc, timeout)
					_, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
		})
		Convey("Given a mocked underlying connection with local, remote, bind and svc", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, remoteAddr, bindAddr, svc)
			Convey("If local address and bind address do not change", func() {
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				Convey("reconnect must not return error.", func() {
					network := snetproxy.NewProxyNetwork(mockNetwork)
					conn, _ := network.DialSCIONWithBindSVC("udp4",
						localAddr, remoteAddr, bindAddr, svc, timeout)
					_, err := conn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldBeNil)
				})
			})
			Convey("If local address changes", func() {
				secondConn := NewMockConnWithAddrs(ctrl,
					otherLocalAddr, remoteAddr, bindAddr, addr.SvcNone)
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(secondConn, nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.DialSCIONWithBindSVC("udp4",
						localAddr, remoteAddr, bindAddr, svc, timeout)
					_, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
			Convey("If bind address changes", func() {
				secondConn := NewMockConnWithAddrs(ctrl, localAddr, remoteAddr, otherBindAddr, svc)
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC("udp4", localAddr, remoteAddr, bindAddr, svc, timeout).
					Return(secondConn, nil)
				Convey("reconnect must return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.DialSCIONWithBindSVC("udp4",
						localAddr, remoteAddr, bindAddr, svc, timeout)
					_, err := proxyConn.(*snetproxy.ProxyConn).Reconnect()
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
		})
	})
}

func TestNetworkFatalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	Convey("Given a proxy network running over an underlying mocked network", t, func() {
		err := common.NewBasicError("Not dispatcher dead error, e.g., malformed register msg", nil)
		mockNetwork := mock_snet.NewMockNetwork(ctrl)
		proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
		Convey("The proxy network returns non-dispatcher dial errors from the mock", func() {
			mockNetwork.EXPECT().
				DialSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any(), Any()).
				Return(nil, err)
			_, err := proxyNetwork.DialSCIONWithBindSVC("udp4", nil, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("The proxy network returns non-dispatcher listen errors from the mock", func() {
			mockNetwork.EXPECT().
				ListenSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any()).
				Return(nil, err)
			_, err := proxyNetwork.ListenSCIONWithBindSVC("udp4", nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

func TestNetworkDispatcherDeadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	dispatcherError := &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	Convey("Listen and Dial should reattempt to connect on dispatcher down errors", t, func() {
		mockNetwork := mock_snet.NewMockNetwork(ctrl)
		proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
		Convey("Dial tries to reconnect if no timeout set", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, remoteAddr, nil, addr.SvcNone)
			gomock.InOrder(
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any(), Any()).
					Return(nil, dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, nil),
			)
			_, err := proxyNetwork.DialSCIONWithBindSVC("udp4", nil, nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Dial only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					DialSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any(), Any()).
					Return(nil, dispatcherError).
					MinTimes(3).MaxTimes(5),
			)
			_, err := proxyNetwork.DialSCIONWithBindSVC("udp4",
				nil, nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Listen tries to reconnect if no timeout set", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, nil, addr.SvcNone)
			gomock.InOrder(
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any()).
					Return(nil, dispatcherError).
					Times(2),
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any()).
					Return(mockConn, nil),
			)
			_, err := proxyNetwork.ListenSCIONWithBindSVC("udp4", nil, nil, addr.SvcNone, 0)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Listen only retries for limited time if timeout set", func() {
			gomock.InOrder(
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC(Any(), Any(), Any(), Any(), Any()).
					Return(nil, dispatcherError).
					MinTimes(3).MaxTimes(5),
			)
			_, err := proxyNetwork.ListenSCIONWithBindSVC("udp4",
				nil, nil, addr.SvcNone, tickerMultiplier(4))
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}
