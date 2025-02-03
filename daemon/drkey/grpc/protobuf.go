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

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
)

func asHostMetaToProtoRequest(meta drkey.ASHostMeta) *cppb.DRKeyASHostRequest {
	return &cppb.DRKeyASHostRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
	}
}

func getASHostKeyFromReply(
	rep *cppb.DRKeyASHostResponse,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		NotBefore: rep.EpochBegin.AsTime(),
		NotAfter:  rep.EpochEnd.AsTime(),
	}

	returningKey := drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		DstHost: meta.DstHost,
	}

	if len(rep.Key) != 16 {
		return drkey.ASHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func hostASMetaToProtoRequest(meta drkey.HostASMeta) *cppb.DRKeyHostASRequest {
	return &cppb.DRKeyHostASRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		SrcHost:    meta.SrcHost,
	}
}

func getHostASKeyFromReply(
	rep *cppb.DRKeyHostASResponse,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		NotBefore: rep.EpochBegin.AsTime(),
		NotAfter:  rep.EpochEnd.AsTime(),
	}

	returningKey := drkey.HostASKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostASKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

func hostHostMetaToProtoRequest(meta drkey.HostHostMeta) *cppb.DRKeyHostHostRequest {
	return &cppb.DRKeyHostHostRequest{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
		DstHost:    meta.DstHost,
		SrcHost:    meta.SrcHost,
	}
}

func getHostHostKeyFromReply(
	rep *cppb.DRKeyHostHostResponse,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		NotBefore: rep.EpochBegin.AsTime(),
		NotAfter:  rep.EpochEnd.AsTime(),
	}

	returningKey := drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
	}
	if len(rep.Key) != 16 {
		return drkey.HostHostKey{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
