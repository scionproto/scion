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

package grpc

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
)

func secretRequestToMeta(req *cppb.DRKeySecretValueRequest) (drkey.SecretValueMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.SecretValueMeta{}, serrors.WrapStr("invalid valTime from request", err)
	}
	return drkey.SecretValueMeta{
		Validity: req.ValTime.AsTime(),
		ProtoId:  drkey.Protocol(req.ProtocolId),
	}, nil
}

func secretToProtoResp(drkey drkey.SecretValue) *cppb.DRKeySecretValueResponse {
	return &cppb.DRKeySecretValueResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}

func keyToLevel1Resp(drkey drkey.Level1Key) *cppb.DRKeyLevel1Response {
	return &cppb.DRKeyLevel1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}

func keyToASASResp(drkey drkey.Level1Key) *cppb.DRKeyIntraLevel1Response {
	return &cppb.DRKeyIntraLevel1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}

func requestToASHostMeta(req *cppb.DRKeyASHostRequest) (drkey.ASHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.ASHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.ASHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		DstHost:  req.DstHost,
	}, nil
}

func keyToASHostResp(drkey drkey.ASHostKey) *cppb.DRKeyASHostResponse {
	return &cppb.DRKeyASHostResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}

func requestToHostASMeta(req *cppb.DRKeyHostASRequest) (drkey.HostASMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostASMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostASMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
	}, nil
}

func keyToHostASResp(drkey drkey.HostASKey) *cppb.DRKeyHostASResponse {
	return &cppb.DRKeyHostASResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}

func requestToHostHostMeta(req *cppb.DRKeyHostHostRequest) (drkey.HostHostMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.HostHostMeta{}, serrors.WrapStr("invalid valTime from pb request", err)
	}
	return drkey.HostHostMeta{
		ProtoId:  drkey.Protocol(req.ProtocolId),
		Validity: req.ValTime.AsTime(),
		SrcIA:    addr.IA(req.SrcIa),
		DstIA:    addr.IA(req.DstIa),
		SrcHost:  req.SrcHost,
		DstHost:  req.DstHost,
	}, nil
}

func keyToHostHostResp(drkey drkey.HostHostKey) *cppb.DRKeyHostHostResponse {
	return &cppb.DRKeyHostHostResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}
}
