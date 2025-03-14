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
	// . "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/svc"
	"github.com/scionproto/scion/private/svc/mock_svc"
)

func TestResolver(t *testing.T) {
	ctrl := gomock.NewController(t)

	srcIA := addr.MustParseIA("1-ff00:0:1")
	dstIA := addr.MustParseIA("1-ff00:0:2")
	mockPath := mock_snet.NewMockPath(ctrl)
	mockPath.EXPECT().Dataplane().Return(path.SCION{}).AnyTimes()
	mockPath.EXPECT().UnderlayNextHop().Return(nil).AnyTimes()
	mockPath.EXPECT().Destination().Return(dstIA).AnyTimes()

	t.Run("If opening up port fails, return error and no reply", func(t *testing.T) {
		mockNet := mock_snet.NewMockNetwork(ctrl)
		mockNet.EXPECT().OpenRaw(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("no conn"))
		resolver := &svc.Resolver{
			LocalIA: srcIA,
			LocalIP: xtest.MustParseIP(t, "127.0.0.1"),
			Network: mockNet,
		}

		reply, err := resolver.LookupSVC(context.Background(), mockPath, addr.SvcCS)
		assert.Error(t, err)
		assert.Nil(t, reply)
	})
	t.Run("Local machine information is used to build conns", func(t *testing.T) {
		mockNet := mock_snet.NewMockNetwork(ctrl)
		mockConn := mock_snet.NewMockPacketConn(ctrl)
		mockConn.EXPECT().LocalAddr().Return(&net.UDPAddr{
			IP: net.IP{192, 0, 2, 1}, Port: 30001,
		})
		mockNet.EXPECT().OpenRaw(gomock.Any(), &net.UDPAddr{
			IP: net.IP{192, 0, 2, 1},
		}).Return(mockConn, nil)
		mockConn.EXPECT().Close().Return(nil)
		mockRoundTripper := mock_svc.NewMockRoundTripper(ctrl)
		mockRoundTripper.EXPECT().RoundTrip(gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any()).Do(
			func(_, _ any, pkt *snet.Packet, _ any) {
				pld := pkt.Payload.(snet.UDPPayload)
				require.NoError(t, proto.Unmarshal(pld.Payload, &cppb.ServiceResolutionRequest{}))
			})

		resolver := &svc.Resolver{
			LocalIA:      srcIA,
			Network:      mockNet,
			LocalIP:      net.IP{192, 0, 2, 1},
			RoundTripper: mockRoundTripper,
		}
		_, err := resolver.LookupSVC(context.Background(), mockPath, addr.SvcCS)
		assert.NoError(t, err)
	})
}

func TestRoundTripper(t *testing.T) {
	testReply := &svc.Reply{
		Transports: map[svc.Transport]string{"foo": "bar"},
	}
	testCases := []struct {
		Description    string
		InputPacket    *snet.Packet
		InputUnderlay  *net.UDPAddr
		ErrorAssertion require.ErrorAssertionFunc
		ExpectedReply  *svc.Reply
		ConnSetup      func(*mock_snet.MockPacketConn)
	}{
		{
			Description:    "nil packet returns error",
			InputUnderlay:  &net.UDPAddr{},
			ErrorAssertion: require.Error,
		},
		{
			Description:    "nil underlay returns error",
			InputPacket:    &snet.Packet{},
			ErrorAssertion: require.Error,
		},
		{
			Description:    "if write fails, return error",
			InputPacket:    &snet.Packet{},
			InputUnderlay:  &net.UDPAddr{},
			ErrorAssertion: require.Error,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(errors.New("write err"))
			},
		},
		{
			Description:    "if read fails, return error",
			InputPacket:    &snet.Packet{},
			InputUnderlay:  &net.UDPAddr{},
			ErrorAssertion: require.Error,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).Return(errors.New("read err"))
			},
		},
		{
			Description:    "if reply cannot be parsed, return error",
			InputPacket:    &snet.Packet{},
			InputUnderlay:  &net.UDPAddr{},
			ErrorAssertion: require.Error,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, _ *net.UDPAddr) error {
						pkt.Payload = snet.UDPPayload{Payload: []byte{42}}
						return nil
					},
				)
			},
		},
		{
			Description:    "successful operation",
			InputPacket:    &snet.Packet{},
			InputUnderlay:  &net.UDPAddr{},
			ErrorAssertion: require.NoError,
			ConnSetup: func(c *mock_snet.MockPacketConn) {
				c.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Return(nil)
				c.EXPECT().ReadFrom(gomock.Any(), gomock.Any()).DoAndReturn(
					func(pkt *snet.Packet, _ *net.UDPAddr) error {
						raw, err := testReply.Marshal()
						if err != nil {
							panic(err)
						}
						pkt.Payload = snet.UDPPayload{Payload: raw}
						pkt.Path = snet.RawPath{}
						return nil
					},
				)
			},
			ExpectedReply: testReply,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			conn := mock_snet.NewMockPacketConn(ctrl)

			if tc.ConnSetup != nil {
				tc.ConnSetup(conn)
			}
			roundTripper := svc.DefaultRoundTripper()
			reply, err := roundTripper.RoundTrip(context.Background(), conn, tc.InputPacket,
				tc.InputUnderlay)
			tc.ErrorAssertion(t, err)
			// FIXME(scrye): also test that paths are processed correctly
			if tc.ExpectedReply != nil {
				assert.Equal(t, tc.ExpectedReply.Transports, reply.Transports)
			} else {
				assert.Nil(t, reply)
			}
		})
	}
}
