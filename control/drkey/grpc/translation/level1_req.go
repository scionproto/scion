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

func Level1MetaToProtoRequest(meta drkey.Level1Meta) (*cppb.DRKeyLevel1Request, error) {
	return &cppb.DRKeyLevel1Request{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
	}, nil
}

// GetLevel1KeyFromReply extracts the level 1 drkey from the reply.
func GetLevel1KeyFromReply(meta drkey.Level1Meta,
	rep *cppb.DRKeyLevel1Response) (drkey.Level1Key, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.Level1Key{
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		ProtoId: meta.ProtoId,
	}
	if len(rep.Key) != 16 {
		return drkey.Level1Key{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}

// KeyToLevel1Resp builds a Level1Resp provided a Level1Key.
func KeyToLevel1Resp(drkey drkey.Level1Key) (*cppb.DRKeyLevel1Response, error) {
	return &cppb.DRKeyLevel1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}

func IntraLevel1ToProtoRequest(meta drkey.Level1Meta) (*cppb.DRKeyIntraLevel1Request, error) {
	return &cppb.DRKeyIntraLevel1Request{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: drkeypb.Protocol(meta.ProtoId),
		DstIa:      uint64(meta.DstIA),
		SrcIa:      uint64(meta.SrcIA),
	}, nil
}

// KeyToASASResp builds a ASASResp provided a Level1Key.
func KeyToASASResp(drkey drkey.Level1Key) (*cppb.DRKeyIntraLevel1Response, error) {
	return &cppb.DRKeyIntraLevel1Response{
		EpochBegin: timestamppb.New(drkey.Epoch.NotBefore),
		EpochEnd:   timestamppb.New(drkey.Epoch.NotAfter),
		Key:        drkey.Key[:],
	}, nil
}

func GetASASKeyFromReply(
	meta drkey.Level1Meta,
	rep *cppb.DRKeyIntraLevel1Response,
) (drkey.Level1Key, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.Level1Key{
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		ProtoId: meta.ProtoId,
	}
	if len(rep.Key) != 16 {
		return drkey.Level1Key{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
