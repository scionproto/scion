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

package translation_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/control/drkey/grpc/translation"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
)

var (
	dstIA   = xtest.MustParseIA("1-ff00:0:110")
	srcIA   = xtest.MustParseIA("1-ff00:0:111")
	k       = xtest.MustParseHexString("c584cad32613547c64823c756651b6f5") // just a key
	strAddr = "127.0.0.1"
)

func TestLevel1MetaToProtoRequest(t *testing.T) {
	now := time.Now().UTC()
	valTime := timestamppb.New(now)

	pbReq := &cppb.DRKeyLevel1Request{
		ValTime: valTime,
	}

	lvl1Meta := drkey.Level1Meta{
		Validity: now,
	}

	req, err := translation.Level1MetaToProtoRequest(lvl1Meta)
	require.NoError(t, err)
	assert.Equal(t, pbReq, req)
}

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

	pbResp, err := translation.KeyToLevel1Resp(lvl1Key)
	require.NoError(t, err)
	assert.Equal(t, targetResp, pbResp)

}

func TestGetLevel1KeyFromReply(t *testing.T) {
	resp := &cppb.DRKeyLevel1Response{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}
	lvl1meta := drkey.Level1Meta{
		ProtoId: drkey.SCMP,
		SrcIA:   srcIA,
		DstIA:   dstIA,
	}

	targetLevel1Key := drkey.Level1Key{
		ProtoId: drkey.SCMP,
		Epoch:   drkey.NewEpoch(0, 1),
		SrcIA:   srcIA,
		DstIA:   dstIA,
	}
	copy(targetLevel1Key.Key[:], k)

	lvl1Key, err := translation.GetLevel1KeyFromReply(lvl1meta, resp)
	require.NoError(t, err)
	assert.Equal(t, targetLevel1Key, lvl1Key)

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

	lvl2Req, err := translation.RequestToASHostMeta(req)
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

	lvl2Req, err := translation.RequestToHostASMeta(req)
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

	lvl2Req, err := translation.RequestToHostHostMeta(req)
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

	resp, err := translation.KeyToASHostResp(asHostKey)
	require.NoError(t, err)
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

	resp, err := translation.KeyToHostASResp(key)
	require.NoError(t, err)
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

	resp, err := translation.KeyToHostHostResp(key)
	require.NoError(t, err)
	assert.Equal(t, targetResp, resp)
}

func SVMetaToProtoRequest(t *testing.T) {
	now := time.Now().UTC()
	svReq := drkey.SecretValueMeta{
		ProtoId:  drkey.Generic,
		Validity: now,
	}
	valTime := timestamppb.New(now)
	targetProtoReq := &cppb.DRKeySecretValueRequest{
		ProtocolId: drkeypb.Protocol_PROTOCOL_GENERIC_UNSPECIFIED,
		ValTime:    valTime,
	}
	protoReq, err := translation.SVMetaToProtoRequest(svReq)
	require.NoError(t, err)
	require.Equal(t, targetProtoReq, protoReq)
}

func TestGetSVFromReply(t *testing.T) {
	proto := drkey.SCMP

	resp := &cppb.DRKeySecretValueResponse{
		EpochBegin: timestamppb.New(util.SecsToTime(0)),
		EpochEnd:   timestamppb.New(util.SecsToTime(1)),
		Key:        k,
	}

	targetSV := drkey.SecretValue{
		Epoch:   drkey.NewEpoch(0, 1),
		ProtoId: proto,
	}
	copy(targetSV.Key[:], k)
	sv, err := translation.GetSVFromReply(proto, resp)
	require.NoError(t, err)
	require.Equal(t, targetSV, sv)
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

	resp, err := translation.SVtoProtoResp(sv)
	require.NoError(t, err)
	require.Equal(t, targetResp, resp)
}
