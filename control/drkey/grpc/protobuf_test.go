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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
)

var (
	dstIA   = addr.MustParseIA("1-ff00:0:110")
	srcIA   = addr.MustParseIA("1-ff00:0:111")
	k       = xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a key
	strAddr = "127.0.0.1"
)

func TestKeyToLevel1Resp(t *testing.T) {
	lvl1Key := drkey.Level1Key{
		Epoch: drkey.NewEpoch(0, 1),
		SrcIA: srcIA,
		DstIA: dstIA,
	}
	copy(lvl1Key.Key[:], k)

	targetResp := &cppb.DRKeyLevel1Response{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}

	pbResp := grpc.KeyToLevel1Resp(lvl1Key)
	assert.Equal(t, targetResp, pbResp)

}

func TestRequestToASHostMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)

	req := &cppb.DRKeyASHostRequest{
		ProtocolId: drkeypb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		DstHost:    strAddr,
	}

	targetLvl2Req := drkey.ASHostMeta{
		ProtoId:  drkey.Generic,
		Validity: now,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		DstHost:  strAddr,
	}

	lvl2Req, err := grpc.RequestToASHostMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestRequestToHostASMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)

	req := &cppb.DRKeyHostASRequest{
		ProtocolId: drkeypb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		SrcHost:    strAddr,
	}

	targetLvl2Req := drkey.HostASMeta{
		ProtoId:  drkey.Generic,
		Validity: now,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  strAddr,
	}

	lvl2Req, err := grpc.RequestToHostASMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestRequestToHostHostMeta(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)

	req := &cppb.DRKeyHostHostRequest{
		ProtocolId: drkeypb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		DstIa:      uint64(dstIA),
		SrcIa:      uint64(srcIA),
		ValTime:    valTime,
		SrcHost:    strAddr,
		DstHost:    strAddr,
	}

	targetLvl2Req := drkey.HostHostMeta{
		ProtoId:  drkey.Generic,
		Validity: now,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  strAddr,
		DstHost:  strAddr,
	}

	lvl2Req, err := grpc.RequestToHostHostMeta(req)
	require.NoError(t, err)
	assert.Equal(t, targetLvl2Req, lvl2Req)
}

func TestKeyToASHostResp(t *testing.T) {
	asHostKey := drkey.ASHostKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		DstHost: strAddr,
	}
	copy(asHostKey.Key[:], k)

	targetResp := &cppb.DRKeyASHostResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        asHostKey.Key[:],
	}

	resp := grpc.KeyToASHostResp(asHostKey)
	assert.Equal(t, targetResp, resp)
}

func TestKeyToHostASResp(t *testing.T) {
	key := drkey.HostASKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		SrcHost: strAddr,
	}
	copy(key.Key[:], k)

	targetResp := &cppb.DRKeyHostASResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        key.Key[:],
	}

	resp := grpc.KeyToHostASResp(key)
	assert.Equal(t, targetResp, resp)
}

func TestKeyToHostHostResp(t *testing.T) {
	key := drkey.HostHostKey{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
		SrcHost: strAddr,
		DstHost: strAddr,
	}
	copy(key.Key[:], k)

	targetResp := &cppb.DRKeyHostHostResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        key.Key[:],
	}

	resp := grpc.KeyToHostHostResp(key)
	assert.Equal(t, targetResp, resp)
}

func TestSVtoProtoResp(t *testing.T) {
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

	resp := grpc.SecretToProtoResp(sv)
	require.Equal(t, targetResp, resp)
}
