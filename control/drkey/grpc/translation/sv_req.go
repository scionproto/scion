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

package translation

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// SVMetaToProtoRequest parses the SVReq to a protobuf SVRequest.
func SVMetaToProtoRequest(meta drkey.SecretValueMeta) (*cppb.DRKeySecretValueRequest, error) {
	return &cppb.DRKeySecretValueRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
	}, nil
}

// SVRequestToMeta parses the SVReq to a protobuf SVRequest.
func SVRequestToMeta(req *cppb.DRKeySecretValueRequest) (drkey.SecretValueMeta, error) {
	err := req.ValTime.CheckValid()
	if err != nil {
		return drkey.SecretValueMeta{}, serrors.WrapStr("invalid valTime from request", err)
	}
	return drkey.SecretValueMeta{
		Validity: req.ValTime.AsTime(),
		ProtoId:  drkey.Protocol(req.ProtocolId),
	}, nil
}

// GetSVFromReply extracts the SV from the reply.
func GetSVFromReply(
	proto drkey.Protocol,
	rep *cppb.DRKeySecretValueResponse,
) (drkey.SecretValue, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.SecretValue{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.SecretValue{
		ProtoId: proto,
		Epoch:   epoch,
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

// SVtoProtoResp builds a SVResponse provided a SV.
func SVtoProtoResp(drkey drkey.SecretValue) (*cppb.DRKeySecretValueResponse, error) {
	return &cppb.DRKeySecretValueResponse{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}
