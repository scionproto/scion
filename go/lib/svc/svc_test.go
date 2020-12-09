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
	"context"
	"errors"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/svc"
	"github.com/scionproto/scion/go/lib/svc/mock_svc"
)

func TestSVCResolutionServer(t *testing.T) {
	testCases := map[string]struct {
		DispService func(ctrl *gomock.Controller) snet.PacketDispatcherService
		ReqHandler  func(ctrl *gomock.Controller) svc.RequestHandler
		ErrRegister assert.ErrorAssertionFunc
		ErrConnRead assert.ErrorAssertionFunc
	}{
		"Underlying dispatcher service fails to set up underlying conn": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(nil, uint16(0), errors.New("conn error"))
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				return mock_svc.NewMockRequestHandler(ctrl)
			},
			ErrRegister: assert.Error,
		},
		"If handler fails, caller sees error": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcCS,
						}
						return nil
					},
				)

				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(mockPacketConn, uint16(1337), nil)
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Error, errors.New("err")).AnyTimes()
				return h
			},
			ErrRegister: assert.NoError,
			ErrConnRead: assert.Error,
		},
		"If handler returns forward, caller sees data": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcCS,
						}
						return nil
					},
				)

				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(mockPacketConn, uint16(1337), nil)
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Forward, nil).AnyTimes()
				return h
			},
			ErrRegister: assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"return from conn with no error next internal read yields data": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostIPv4(net.IP{192, 168, 0, 1}),
						}
						return nil
					},
				)

				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(mockPacketConn, uint16(1337), nil)
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			ErrRegister: assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"return from socket with error if next internal read fails": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						return serrors.New("forced exit")
					},
				)

				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(mockPacketConn, uint16(1337), nil)
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			ErrRegister: assert.NoError,
			ErrConnRead: assert.Error,
		},
		"Multicast SVC packets get delivered to caller": {
			DispService: func(ctrl *gomock.Controller) snet.PacketDispatcherService {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.SvcCS.Multicast(),
						}
						return nil
					},
				)

				s := mock_snet.NewMockPacketDispatcherService(ctrl)
				s.EXPECT().Register(
					gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
				).Return(mockPacketConn, uint16(1337), nil)
				return s
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			ErrRegister: assert.NoError,
			ErrConnRead: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			disp := svc.NewResolverPacketDispatcher(tc.DispService(ctrl), tc.ReqHandler(ctrl))
			conn, port, err := disp.Register(context.Background(), addr.IA{}, &net.UDPAddr{},
				addr.SvcCS)

			tc.ErrRegister(t, err)
			if err != nil {
				assert.Nil(t, conn)
				assert.Zero(t, port)
				return
			} else {
				assert.NotNil(t, conn)
				assert.Equal(t, port, uint16(1337))
			}
			err = conn.ReadFrom(&snet.Packet{}, &net.UDPAddr{})
			tc.ErrConnRead(t, err)
		})
	}
}

func TestDefaultHandler(t *testing.T) {

	testCases := map[string]struct {
		ReplySource    snet.SCIONAddress
		ReplyPayload   []byte
		InputPacket    *snet.Packet
		ExpectedPacket *snet.Packet
		AssertErr      assert.ErrorAssertionFunc
		ExpectedError  bool
	}{
		"path cannot be reversed": {
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Path: spath.Path{
						Raw:  []byte{0x00, 0x01, 0x02, 0x03},
						Type: scion.PathType,
					},
					Payload: snet.UDPPayload{},
				},
			},
			ExpectedError: true,
		},
		"empty UDP payload, success": {
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source:  snet.SCIONAddress{},
					Payload: snet.UDPPayload{},
				},
			},
		},
		"UDP payload with ports": {
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{SrcPort: 42, DstPort: 73},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{SrcPort: 73, DstPort: 42},
				},
			},
		},
		"Non-nil payload": {
			ReplyPayload: []byte{1, 2, 3, 4},
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{Payload: []byte{1, 2, 3, 4}},
				},
			},
		},
		"Source address override": {
			ReplySource: snet.SCIONAddress{Host: addr.HostIPv4(net.IP{192, 168, 0, 1})},
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source:  snet.SCIONAddress{Host: addr.HostIPv4(net.IP{192, 168, 0, 1})},
					Payload: snet.UDPPayload{},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
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
			if tc.ExpectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("Underlay addresses are forwarded", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		conn := mock_snet.NewMockPacketConn(ctrl)
		packet := &snet.Packet{
			PacketInfo: snet.PacketInfo{
				Payload: snet.UDPPayload{},
			},
		}
		ov := &net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 0x29a}
		conn.EXPECT().WriteTo(packet, ov).Times(1)
		sender := &svc.BaseHandler{}

		request := &svc.Request{
			Conn:     conn,
			Source:   snet.SCIONAddress{},
			Packet:   packet,
			Underlay: ov,
		}
		_, err := sender.Handle(request)
		assert.NoError(t, err)
	})
}
