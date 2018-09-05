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
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet/snetproxy"
	"github.com/scionproto/scion/go/lib/snet/snetproxy/mock_snetproxy"
)

func TestReconnect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	FocusConvey("Reconnections must conserve local and bind addresses", t, func() {
		mockNetwork := mock_snetproxy.NewMockNetwork(ctrl)
		FocusConvey("Build mocks for listen", func() {
			mockConn := NewMockConnWithAddrs(ctrl, localAddr, nil, nil, svc)
			Convey("If local address and bind address do not change", func() {
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, nil, svc, timeout).
					Return(mockConn, nil)
				mockNetwork.EXPECT().
					ListenSCIONWithBindSVC("udp4", localAddr, nil, svc, timeout).
					Return(mockConn, nil)
				Convey("reconnect must not return error.", func() {
					proxyNetwork := snetproxy.NewProxyNetwork(mockNetwork)
					proxyConn, _ := proxyNetwork.ListenSCIONWithBindSVC("udp4",
						localAddr, nil, svc, timeout)
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
		Convey("Build mocks for dial", func() {
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
