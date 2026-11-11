// Copyright 2026 ETH Zurich
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

package endhost

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	drpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/proto/endhost/v1/endhostconnect"
)

type DRKeyService struct {
	url    string
	client endhostconnect.DRKeyServiceClient
}

func NewDRKeyService(url string, httpClient *http.Client) *DRKeyService {
	d := &DRKeyService{
		url:    url,
		client: endhostconnect.NewDRKeyServiceClient(httpClient, url),
	}
	return d
}

func (d *DRKeyService) ASHostKey(ctx context.Context, req drkey.ASHostMeta) (
	*drkey.ASHostKey, error) {

	rep, err := d.client.DRKeyASHost(ctx, &connect.Request[endhost.DRKeyASHostRequest]{
		Msg: &endhost.DRKeyASHostRequest{
			ValTime:    timestamppb.New(req.Validity),
			ProtocolId: drpb.Protocol(req.ProtoId),
			SrcIa:      uint64(req.SrcIA),
			DstIa:      uint64(req.DstIA),
			DstHost:    req.DstHost,
		},
	})
	metricASHostKeyTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on ASHostKey", err)
	}
	return &drkey.ASHostKey{
		ProtoId: req.ProtoId,
		Epoch: drkey.NewEpoch(uint32(rep.Msg.EpochBegin.Seconds),
			uint32(rep.Msg.EpochEnd.Seconds)),
		SrcIA:   req.SrcIA,
		DstIA:   req.DstIA,
		DstHost: req.DstHost,
		Key:     drkey.Key(rep.Msg.Key),
	}, nil
}

func (d *DRKeyService) HostASKey(ctx context.Context, req drkey.HostASMeta) (
	*drkey.HostASKey, error) {

	rep, err := d.client.DRKeyHostAS(ctx, &connect.Request[endhost.DRKeyHostASRequest]{
		Msg: &endhost.DRKeyHostASRequest{
			ValTime:    timestamppb.New(req.Validity),
			ProtocolId: drpb.Protocol(req.ProtoId),
			SrcIa:      uint64(req.SrcIA),
			DstIa:      uint64(req.DstIA),
			SrcHost:    req.SrcHost,
		},
	})
	metricHostASKeyTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on HostASKey", err)
	}
	return &drkey.HostASKey{
		ProtoId: req.ProtoId,
		Epoch: drkey.NewEpoch(uint32(rep.Msg.EpochBegin.Seconds),
			uint32(rep.Msg.EpochEnd.Seconds)),
		SrcIA:   req.SrcIA,
		DstIA:   req.DstIA,
		SrcHost: req.SrcHost,
		Key:     drkey.Key(rep.Msg.Key),
	}, nil
}

func (d *DRKeyService) HostHostKey(ctx context.Context, req drkey.HostHostMeta) (
	*drkey.HostHostKey, error) {

	rep, err := d.client.DRKeyHostHost(ctx,
		&connect.Request[endhost.DRKeyHostHostRequest]{
			Msg: &endhost.DRKeyHostHostRequest{
				ValTime:    timestamppb.New(req.Validity),
				ProtocolId: drpb.Protocol(req.ProtoId),
				SrcIa:      uint64(req.SrcIA),
				DstIa:      uint64(req.DstIA),
				SrcHost:    req.SrcHost,
				DstHost:    req.DstHost,
			},
		})
	metricHostHostKeyTotal.Increment(err)
	if err != nil {
		return nil, serrors.Wrap("on HostHostKey", err)
	}
	return &drkey.HostHostKey{
		ProtoId: req.ProtoId,
		Epoch: drkey.NewEpoch(uint32(rep.Msg.EpochBegin.Seconds),
			uint32(rep.Msg.EpochEnd.Seconds)),
		SrcIA:   req.SrcIA,
		DstIA:   req.DstIA,
		SrcHost: req.SrcHost,
		DstHost: req.DstHost,
		Key:     drkey.Key(rep.Msg.Key),
	}, nil
}
