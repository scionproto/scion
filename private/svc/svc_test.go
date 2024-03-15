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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/svc"
	"github.com/scionproto/scion/private/svc/mock_svc"
)

func TestSVCResolutionServer(t *testing.T) {
	testCases := map[string]struct {
		Connector   func(ctrl *gomock.Controller) snet.Connector
		ReqHandler  func(ctrl *gomock.Controller) svc.RequestHandler
		SVC         addr.SVC
		ErrOpen     assert.ErrorAssertionFunc
		ErrConnRead assert.ErrorAssertionFunc
	}{
		"Underlying service fails to set up underlying conn": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(nil, errors.New("conn error"))
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				return mock_svc.NewMockRequestHandler(ctrl)
			},
			ErrOpen: assert.Error,
		},
		"If handler fails, caller doesn't see an error": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Error, errors.New("err")).AnyTimes()
				return h
			},
			SVC:         addr.SvcCS,
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"SVC mismatch doesn't cause an error": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Error, errors.New("err")).AnyTimes()
				return h
			},
			SVC:         addr.SvcDS,
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"If handler returns forward, caller sees data": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Forward, nil).AnyTimes()
				return h
			},
			SVC:         addr.SvcCS,
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"Handler returns forward with SVCWildcard": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Forward, nil).AnyTimes()
				return h
			},
			SVC:         addr.SvcWildcard,
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"return from conn with no error next internal read yields data": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.MustParseHost("192.168.0.1"),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"return from socket with error if next internal read fails": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						return serrors.New("forced exit")
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.Error,
		},
		"Multicast SVC packets get delivered to caller": {
			Connector: func(ctrl *gomock.Controller) snet.Connector {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS.Multicast()),
						}
						return nil
					},
				)

				c := mock_snet.NewMockConnector(ctrl)
				c.EXPECT().OpenUDP(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil).AnyTimes()
				return h
			},
			SVC:         addr.SvcWildcard,
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			connector := &svc.ResolverPacketConnector{
				Connector: tc.Connector(ctrl),
				Handler:   tc.ReqHandler(ctrl),
				SVC:       tc.SVC,
			}

			conn, err := connector.OpenUDP(
				context.Background(),
				&net.UDPAddr{IP: xtest.MustParseIP(t, "127.0.0.1")},
			)

			tc.ErrOpen(t, err)
			if err != nil {
				assert.Nil(t, conn)
				return
			} else {
				assert.NotNil(t, conn)
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
					Path: path.SCION{
						Raw: []byte{0x00, 0x01, 0x02, 0x03},
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
					Path:    snet.RawPath{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source:  snet.SCIONAddress{},
					Payload: snet.UDPPayload{},
					Path: snet.RawReplyPath{
						Path: empty.Path{},
					},
				},
			},
		},
		"UDP payload with ports": {
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{SrcPort: 42, DstPort: 73},
					Path:    snet.RawPath{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{SrcPort: 73, DstPort: 42},
					Path: snet.RawReplyPath{
						Path: empty.Path{},
					},
				},
			},
		},
		"Non-nil payload": {
			ReplyPayload: []byte{1, 2, 3, 4},
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{},
					Path:    snet.RawPath{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{Payload: []byte{1, 2, 3, 4}},
					Path: snet.RawReplyPath{
						Path: empty.Path{},
					},
				},
			},
		},
		"Source address override": {
			ReplySource: snet.SCIONAddress{Host: addr.MustParseHost("192.168.0.1")},
			InputPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Payload: snet.UDPPayload{},
					Path:    snet.RawPath{},
				},
			},
			ExpectedPacket: &snet.Packet{
				PacketInfo: snet.PacketInfo{
					Source:  snet.SCIONAddress{Host: addr.MustParseHost("192.168.0.1")},
					Payload: snet.UDPPayload{},
					Path: snet.RawReplyPath{
						Path: empty.Path{},
					},
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
				Path:    snet.RawPath{},
			},
		}
		expectedPacket := &snet.Packet{
			PacketInfo: snet.PacketInfo{
				Payload: snet.UDPPayload{},
				Path: snet.RawReplyPath{
					Path: empty.Path{},
				},
			},
		}
		ov := &net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 0x29a}
		conn.EXPECT().WriteTo(expectedPacket, ov).Times(1)
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
