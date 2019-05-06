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

package svc_test

import (
	"errors"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/svc/mock_svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSVCResolutionServer(t *testing.T) {
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
		mockPacketDispatcherService := mock_snet.NewMockPacketDispatcherService(ctrl)
		mockReqHandler := mock_svc.NewMockRequestHandler(ctrl)

		Convey("Underlying dispatcher service fails to set up underlying conn", func() {
			mockPacketDispatcherService.EXPECT().RegisterTimeout(
				gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			).Return(nil, uint16(0), errors.New("conn error"))

			dispatcherService := svc.NewResolverPacketDispatcher(mockPacketDispatcherService,
				mockReqHandler)
			conn, port, err := dispatcherService.RegisterTimeout(addr.IA{}, &addr.AppAddr{},
				&overlay.OverlayAddr{}, addr.SvcPS, 0)
			SoMsg("conn", conn, ShouldBeNil)
			SoMsg("port", port, ShouldEqual, 0)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Given an established resolver conn", func() {
			mockPacketDispatcherService.EXPECT().RegisterTimeout(gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any(), gomock.Any()).Return(mockPacketConn, uint16(1337), nil)

			dispatcherService := svc.NewResolverPacketDispatcher(mockPacketDispatcherService,
				mockReqHandler)
			conn, port, err := dispatcherService.RegisterTimeout(addr.IA{}, &addr.AppAddr{},
				&overlay.OverlayAddr{}, addr.SvcPS, 0)
			SoMsg("conn", conn, ShouldNotBeNil)
			SoMsg("port", port, ShouldEqual, 1337)
			SoMsg("err", err, ShouldBeNil)

			var pkt snet.SCIONPacket
			var ov overlay.OverlayAddr
			Convey("If handler fails, caller sees error", func() {
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcPS,
						}
						return nil
					},
				)
				mockReqHandler.EXPECT().Handle(gomock.Any()).
					Return(svc.Error, errors.New("err")).AnyTimes()

				err = conn.ReadFrom(&pkt, &ov)
				SoMsg("read err", err.Error(), ShouldContainSubstring, "err")
			})
			Convey("If handler returns forward, caller sees data", func() {
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcPS,
						}
						return nil
					},
				)
				mockReqHandler.EXPECT().Handle(gomock.Any()).
					Return(svc.Forward, nil).AnyTimes()
				err = conn.ReadFrom(&pkt, &ov)
				SoMsg("read err", err, ShouldBeNil)
			})
			Convey("If handler succeeds", func() {
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcPS,
						}
						return nil
					},
				)
				mockReqHandler.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				Convey("return from conn with no error next internal read yields data", func() {
					mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
						func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
							pkt.Destination = snet.SCIONAddress{
								Host: addr.HostIPv4(net.IP{192, 168, 0, 1}),
							}
							return nil
						},
					)
					err := conn.ReadFrom(&pkt, &ov)
					SoMsg("err", err, ShouldBeNil)
				})
				Convey("return from socket with error if next internal read fails", func() {
					mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
						func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
							return common.NewBasicError("forced exit", nil)
						},
					)
					err := conn.ReadFrom(&pkt, &ov)
					SoMsg("err", err, ShouldNotBeNil)
				})
			})
			Convey("Multicast SVC packets get delivered to caller", func() {
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.SCIONPacket, ov *overlay.OverlayAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcBS.Multicast(),
						}
						return nil
					},
				)
				// test succeeds because there are no calls to the mock request handler
				err := conn.ReadFrom(&pkt, &ov)
				SoMsg("err", err, ShouldBeNil)
			})
		})
	})
}

func TestDefaultHandler(t *testing.T) {
	Convey("Input packets are processed correctly", t, func() {
		testCases := []struct {
			Description    string
			ReplySource    snet.SCIONAddress
			ReplyPayload   []byte
			InputPacket    *snet.SCIONPacket
			ExpectedPacket *snet.SCIONPacket
			ExpectedError  bool
		}{
			{
				Description: "path cannot be reversed",
				InputPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Path: spath.New(common.RawBytes{0x00, 0x01, 0x02, 0x03}),
					},
				},
				ExpectedError: true,
			},
			{
				Description: "nil l4 header, success",
				InputPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{},
				},
				ExpectedPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Source: snet.SCIONAddress{},
					},
				},
				ExpectedError: false,
			},
			{
				Description: "L4 header with ports",
				InputPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						L4Header: &l4.UDP{SrcPort: 42, DstPort: 73},
					},
				},
				ExpectedPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						L4Header: &l4.UDP{SrcPort: 73, DstPort: 42},
					},
				},
			},
			{
				Description:  "Non-nil payload",
				ReplyPayload: []byte{1, 2, 3, 4},
				InputPacket:  &snet.SCIONPacket{},
				ExpectedPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Payload: common.RawBytes{1, 2, 3, 4},
					},
				},
			},
			{
				Description: "Source address override",
				ReplySource: snet.SCIONAddress{Host: addr.HostIPv4(net.IP{192, 168, 0, 1})},
				InputPacket: &snet.SCIONPacket{},
				ExpectedPacket: &snet.SCIONPacket{
					SCIONPacketInfo: snet.SCIONPacketInfo{
						Source: snet.SCIONAddress{Host: addr.HostIPv4(net.IP{192, 168, 0, 1})},
					},
				},
			},
		}

		for _, tc := range testCases {
			Convey(tc.Description, func() {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				conn := mock_snet.NewMockPacketConn(ctrl)
				if !tc.ExpectedError {
					conn.EXPECT().WriteTo(tc.ExpectedPacket, gomock.Any()).Times(1)
				}
				sender := &svc.BaseHandler{
					Message: tc.ReplyPayload,
				}

				_, err := sender.Handle(
					&svc.Request{
						Packet: tc.InputPacket,
						Source: tc.ReplySource,
						Conn:   conn,
					},
				)
				xtest.SoMsgError("err", err, tc.ExpectedError)
			})
		}
	})

	Convey("Overlay addresses are forwarded", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		conn := mock_snet.NewMockPacketConn(ctrl)
		packet := &snet.SCIONPacket{}
		ov, err := overlay.NewOverlayAddr(
			addr.HostIPv4(net.IP{192, 168, 0, 1}),
			addr.NewL4UDPInfo(0x29a),
		)
		xtest.FailOnErr(t, err)
		conn.EXPECT().WriteTo(packet, ov).Times(1)
		sender := &svc.BaseHandler{}

		request := &svc.Request{
			Conn:    conn,
			Source:  snet.SCIONAddress{},
			Packet:  packet,
			Overlay: ov,
		}
		_, err = sender.Handle(request)
		So(err, ShouldBeNil)
	})
}
