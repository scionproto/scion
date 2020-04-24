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

package svc_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/svc/mock_svc"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestResolver(t *testing.T) {
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		srcIA := xtest.MustParseIA("1-ff00:0:1")
		dstIA := xtest.MustParseIA("1-ff00:0:2")
		mockPath := mock_snet.NewMockPath(ctrl)
		mockPath.EXPECT().Path().Return(nil).AnyTimes()
		mockPath.EXPECT().UnderlayNextHop().Return(nil).AnyTimes()
		mockPath.EXPECT().Destination().Return(dstIA).AnyTimes()

		Convey("If opening up port fails, return error and no reply", func() {
			mockPacketDispatcherService := mock_snet.NewMockPacketDispatcherService(ctrl)
			mockPacketDispatcherService.EXPECT().Register(gomock.Any(), gomock.Any(),
				gomock.Any(), gomock.Any()).
				Return(nil, uint16(0), errors.New("no conn"))
			resolver := &svc.Resolver{
				LocalIA:     srcIA,
				ConnFactory: mockPacketDispatcherService,
			}

			reply, err := resolver.LookupSVC(context.Background(), mockPath, addr.SvcCS)
			SoMsg("reply", reply, ShouldBeNil)
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Local machine information is used to build conns", func() {
			mockPacketDispatcherService := mock_snet.NewMockPacketDispatcherService(ctrl)
			mockConn := mock_snet.NewMockPacketConn(ctrl)
			mockPacketDispatcherService.EXPECT().Register(gomock.Any(), srcIA,
				&net.UDPAddr{IP: net.IP{192, 0, 2, 1}},
				addr.SvcNone).Return(mockConn, uint16(42), nil)
			mockRoundTripper := mock_svc.NewMockRoundTripper(ctrl)
			mockRoundTripper.EXPECT().RoundTrip(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any())

			resolver := &svc.Resolver{
				LocalIA:      srcIA,
				ConnFactory:  mockPacketDispatcherService,
				LocalIP:      net.IP{192, 0, 2, 1},
				RoundTripper: mockRoundTripper,
			}
			resolver.LookupSVC(context.Background(), mockPath, addr.SvcCS)
		})
	})
}

func TestRoundTripper(t *testing.T) {
	testReply := &svc.Reply{
		Transports: map[svc.Transport]string{"foo": "bar"},
	}
	testCases := []struct {
		Description   string
		InputPacket   *snet.Packet
		InputUnderlay *net.UDPAddr
		ExpectedError bool
		ExpectedReply *svc.Reply
		ConnSetup     func(*mock_snet.MockPacketConn)
	}{
		{
			Description:   "nil packet returns error",
			InputUnderlay: &net.UDPAddr{},
			ExpectedError: true,
		},
		{
			Description:   "nil underlay returns error",
			InputPacket:   &snet.Packet{},
			ExpectedError: true,
		},
		{
			Description:   "if write fails, return error",
			InputPacket:   &snet.Packet{},
			InputUnderlay: &net.UDPAddr{},
			ExpectedError: true,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(errors.New("write err"))
			},
		},
		{
			Description:   "if read fails, return error",
			InputPacket:   &snet.Packet{},
			InputUnderlay: &net.UDPAddr{},
			ExpectedError: true,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).Return(errors.New("read err"))
			},
		},
		{
			Description:   "if bad payload type, return error",
			InputPacket:   &snet.Packet{},
			InputUnderlay: &net.UDPAddr{},
			ExpectedError: true,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, _ *net.UDPAddr) error {
						pkt.Payload = &ctrl.SignedPld{}
						return nil
					},
				)
			},
		},
		{
			Description:   "if reply cannot be parsed, return error",
			InputPacket:   &snet.Packet{},
			InputUnderlay: &net.UDPAddr{},
			ExpectedError: true,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, _ *net.UDPAddr) error {
						pkt.Payload = common.RawBytes{42}
						return nil
					},
				)
			},
		},
		{
			Description:   "successful operation",
			InputPacket:   &snet.Packet{},
			InputUnderlay: &net.UDPAddr{},
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, _ *net.UDPAddr) error {
						buf := &bytes.Buffer{}
						if err := testReply.SerializeTo(buf); err != nil {
							panic(err)
						}
						pkt.Payload = common.RawBytes(buf.Bytes())
						return nil
					},
				)
			},
			ExpectedReply: testReply,
		},
	}
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		conn := mock_snet.NewMockPacketConn(ctrl)

		for _, tc := range testCases {
			Convey(tc.Description, func() {
				if tc.ConnSetup != nil {
					tc.ConnSetup(conn)
				}
				roundTripper := svc.DefaultRoundTripper()
				reply, err := roundTripper.RoundTrip(context.Background(), conn, tc.InputPacket,
					tc.InputUnderlay)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				// FIXME(scrye): also test that paths are processed correctly
				if reply != nil {
					SoMsg("reply", reply.Transports, ShouldResemble, tc.ExpectedReply.Transports)
				}
			})
		}
	})
}
