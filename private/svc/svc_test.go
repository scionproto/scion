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
		Network     func(ctrl *gomock.Controller) snet.Network
		ReqHandler  func(ctrl *gomock.Controller) svc.RequestHandler
		ErrOpen     assert.ErrorAssertionFunc
		ErrConnRead assert.ErrorAssertionFunc
	}{
		"Underlying service fails to set up underlying conn": {
			Network: func(ctrl *gomock.Controller) snet.Network {
				c := mock_snet.NewMockNetwork(ctrl)
				c.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).Return(nil, errors.New("conn error"))
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				return mock_svc.NewMockRequestHandler(ctrl)
			},
			ErrOpen: assert.Error,
		},
		"If handler fails, caller doesn't see an error": {
			Network: func(ctrl *gomock.Controller) snet.Network {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				firstCall := mockPacketConn.EXPECT().ReadFrom(
					gomock.Any(),
					gomock.Any(),
				).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				)
				mockPacketConn.EXPECT().ReadFrom(
					gomock.Any(),
					gomock.Any(),
				).After(firstCall).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.MustParseHost("127.0.0.1"),
						}
						return nil
					},
				)

				c := mock_snet.NewMockNetwork(ctrl)
				c.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				h.EXPECT().Handle(gomock.Any()).Return(svc.Error, errors.New("err"))
				return h
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"If non-SVC addr, caller receives request": {
			Network: func(ctrl *gomock.Controller) snet.Network {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.MustParseHost("127.0.0.1"),
						}
						return nil
					},
				)

				c := mock_snet.NewMockNetwork(ctrl)
				c.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				return mock_svc.NewMockRequestHandler(ctrl)
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"handled first, keep reading forwards following packet to caller": {
			Network: func(ctrl *gomock.Controller) snet.Network {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						pkt.Destination = snet.SCIONAddress{
							Host: addr.HostSVC(addr.SvcCS),
						}
						return nil
					},
				).AnyTimes()

				c := mock_snet.NewMockNetwork(ctrl)
				c.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				h := mock_svc.NewMockRequestHandler(ctrl)
				firstCall := h.EXPECT().Handle(gomock.Any()).Return(svc.Handled, nil)
				h.EXPECT().Handle(gomock.Any()).After(firstCall).Return(svc.Forward, nil)
				return h
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.NoError,
		},
		"Return from socket with error if next internal read fails": {
			Network: func(ctrl *gomock.Controller) snet.Network {
				mockPacketConn := mock_snet.NewMockPacketConn(ctrl)
				mockPacketConn.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, ov *net.UDPAddr) error {
						return serrors.New("forced exit")
					},
				)

				c := mock_snet.NewMockNetwork(ctrl)
				c.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).Return(mockPacketConn, nil)
				return c
			},
			ReqHandler: func(ctrl *gomock.Controller) svc.RequestHandler {
				return mock_svc.NewMockRequestHandler(ctrl)
			},
			ErrOpen:     assert.NoError,
			ErrConnRead: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			pconn, err := tc.Network(ctrl).OpenRaw(
				context.Background(),
				&net.UDPAddr{IP: xtest.MustParseIP(t, "127.0.0.1")},
			)
			tc.ErrOpen(t, err)
			if err != nil {
				assert.Nil(t, pconn)
				return
			} else {
				assert.NotNil(t, pconn)
			}

			resolvedPacketConn := &svc.ResolverPacketConn{
				PacketConn: pconn,
				Handler:    tc.ReqHandler(ctrl),
			}

			err = resolvedPacketConn.ReadFrom(&snet.Packet{}, &net.UDPAddr{})
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
					Destination: snet.SCIONAddress{
						Host: addr.HostSVC(addr.SvcCS),
					},
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
					Destination: snet.SCIONAddress{
						Host: addr.HostSVC(addr.SvcCS),
					},
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
					Destination: snet.SCIONAddress{
						Host: addr.HostSVC(addr.SvcCS),
					},
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
					Destination: snet.SCIONAddress{
						Host: addr.HostSVC(addr.SvcCS),
					},
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
					Destination: snet.SCIONAddress{
						Host: addr.HostSVC(addr.SvcCS),
					},
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
				Destination: snet.SCIONAddress{
					Host: addr.HostSVC(addr.SvcCS),
				},
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
