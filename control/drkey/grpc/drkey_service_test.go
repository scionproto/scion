// Copyright 2022 ETH Zurich
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

package grpc_test

import (
	"context"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"inet.af/netaddr"

	"github.com/scionproto/scion/control/config"
	dk_grpc "github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/control/drkey/grpc/mock_grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
)

var (
	ia111    = xtest.MustParseIA("1-ff00:0:111")
	ia112    = xtest.MustParseIA("1-ff00:0:112")
	tcpHost1 = netaddr.MustParseIPPort("127.0.0.1:12345")
	tcpHost2 = netaddr.MustParseIPPort("127.0.0.2:12345")
)

var _ cppb.DRKeyInterServiceServer = &dk_grpc.Server{}
var _ cppb.DRKeyIntraServiceServer = &dk_grpc.Server{}

func TestDRKeySV(t *testing.T) {
	sv, targetResp := getSVandResp(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	serviceStore := mock_grpc.NewMockEngine(ctrl)
	serviceStore.EXPECT().GetSecretValue(gomock.Any(), gomock.Any()).Return(sv, nil)

	testCases := map[string]struct {
		ctx        context.Context
		list       map[config.HostProto]struct{}
		request    *cppb.DRKeySecretValueRequest
		assertFunc assert.ErrorAssertionFunc
		targetResp *cppb.DRKeySecretValueResponse
	}{
		"allowed host": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: tcpHost1.TCPAddr(),
			}),
			list: map[config.HostProto]struct{}{
				{
					Host:  tcpHost1.IP(),
					Proto: drkey.SCMP,
				}: {},
			},
			request: &cppb.DRKeySecretValueRequest{
				ValTime:    timestamppb.Now(),
				ProtocolId: drkeypb.Protocol_PROTOCOL_SCMP,
			},
			assertFunc: assert.NoError,
			targetResp: targetResp,
		},
		"not allowed host": {
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: tcpHost2.TCPAddr(),
			}),
			list: map[config.HostProto]struct{}{
				{
					Host:  tcpHost1.IP(),
					Proto: drkey.SCMP,
				}: {},
			},
			request: &cppb.DRKeySecretValueRequest{
				ValTime:    timestamppb.Now(),
				ProtocolId: drkeypb.Protocol_PROTOCOL_SCMP,
			},
			assertFunc: assert.Error,
			targetResp: nil,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

		})
		server := dk_grpc.Server{
			LocalIA:            ia111,
			Engine:             serviceStore,
			AllowedSVHostProto: tc.list,
		}
		resp, err := server.DRKeySecretValue(tc.ctx, tc.request)
		tc.assertFunc(t, err)
		assert.EqualValues(t, tc.targetResp, resp)
	}
}

func TestValidateASHost(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.ASHostMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				SrcIA: ia111,
				DstIA: ia112,
			},
			LocalIA:   ia112,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				DstHost: tcpHost1.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.ASHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				DstHost: tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.Error,
		},
		"valid host": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.ASHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				DstHost: tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateASHostReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateHostASReq(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.HostASMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				SrcIA: ia111,
				DstIA: ia112,
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostASMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.String(),
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"valid src": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostASMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateHostASReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateHostHostReq(t *testing.T) {
	testCases := map[string]struct {
		peerAddr  net.Addr
		req       drkey.HostHostMeta
		LocalIA   addr.IA
		assertErr assert.ErrorAssertionFunc
	}{
		"no host": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				SrcIA: ia111,
				DstIA: ia112,
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"no localIA": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
				DstHost: tcpHost2.IP().String(),
			},
			assertErr: assert.Error,
		},
		"mismatch addr": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
				DstHost: tcpHost2.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.Error,
		},
		"valid src": {
			peerAddr: tcpHost1.TCPAddr(),
			req: drkey.HostHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
				DstHost: tcpHost2.IP().String(),
			},
			LocalIA:   ia111,
			assertErr: assert.NoError,
		},
		"valid dst": {
			peerAddr: tcpHost2.TCPAddr(),
			req: drkey.HostHostMeta{
				SrcIA:   ia111,
				DstIA:   ia112,
				SrcHost: tcpHost1.IP().String(),
				DstHost: tcpHost2.IP().String(),
			},
			LocalIA:   ia112,
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			err := dk_grpc.ValidateHostHostReq(tc.req, tc.LocalIA, tc.peerAddr)
			tc.assertErr(t, err)
		})
	}
}

func TestLevel1(t *testing.T) {
	// TODO(JordiSubira): Extend this test with more cases
	grpcServer := dk_grpc.Server{}

	request := cppb.DRKeyLevel1Request{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	_, err := grpcServer.DRKeyLevel1(ctx, &request)
	assert.Error(t, err)
}

func TestASHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine := mock_grpc.NewMockEngine(ctrl)
	engine.EXPECT().DeriveASHost(gomock.Any(), gomock.Any()).Return(
		drkey.ASHostKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia112,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &cppb.DRKeyASHostRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		DstHost:    "127.0.0.1",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.DRKeyASHost(ctx, request)
	assert.NoError(t, err)

	request.ProtocolId = drkeypb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.DRKeyASHost(ctx, request)
	assert.NoError(t, err)
}

func TestHostAS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine := mock_grpc.NewMockEngine(ctrl)
	engine.EXPECT().DeriveHostAS(gomock.Any(), gomock.Any()).Return(
		drkey.HostASKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia111,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &cppb.DRKeyHostASRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		SrcHost:    "127.0.0.1",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.DRKeyHostAS(ctx, request)
	assert.NoError(t, err)

	request.ProtocolId = drkeypb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.DRKeyHostAS(ctx, request)
	assert.NoError(t, err)
}

func TestHostHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine := mock_grpc.NewMockEngine(ctrl)
	engine.EXPECT().DeriveHostHost(gomock.Any(), gomock.Any()).Return(
		drkey.HostHostKey{}, nil).AnyTimes()

	grpcServer := dk_grpc.Server{
		LocalIA: ia111,
		Engine:  engine,
	}
	remotePeer := peer.Peer{
		Addr: tcpHost1.TCPAddr(),
	}
	request := &cppb.DRKeyHostHostRequest{
		ProtocolId: 200,
		ValTime:    timestamppb.Now(),
		SrcIa:      uint64(ia111),
		DstIa:      uint64(ia112),
		SrcHost:    "127.0.0.1",
		DstHost:    "127.0.0.2",
	}
	ctx := peer.NewContext(context.Background(), &remotePeer)
	_, err := grpcServer.DRKeyHostHost(ctx, request)
	assert.NoError(t, err)

	request.ProtocolId = drkeypb.Protocol_PROTOCOL_SCMP
	_, err = grpcServer.DRKeyHostHost(ctx, request)
	assert.NoError(t, err)
}

func getSVandResp(t *testing.T) (drkey.SecretValue, *cppb.DRKeySecretValueResponse) {
	k := xtest.MustParseHexString("d29d00c39398b7588c0d31a4ffc77841")

	sv := drkey.SecretValue{
		Epoch:   drkey.NewEpoch(0, 1),
		ProtoId: drkey.SCMP,
	}
	copy(sv.Key[:], k)

	targetResp := &cppb.DRKeySecretValueResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}
	return sv, targetResp
}
