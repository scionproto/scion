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
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	sc_grpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/snet"
)

// Fetcher obtains end-host key from the local CS.
type Fetcher struct {
	Dialer sc_grpc.Dialer
}

func (f *Fetcher) ASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {

	conn, err := f.Dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq := asHostMetaToProtoRequest(meta)
	rep, err := client.DRKeyASHost(ctx, protoReq)
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("requesting AS-HOST key", err)
	}

	key, err := getASHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.ASHostKey{}, serrors.Wrap("obtaining AS-HOST key from reply", err)
	}

	return key, nil
}

func (f *Fetcher) HostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {

	conn, err := f.Dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq := hostASMetaToProtoRequest(meta)
	rep, err := client.DRKeyHostAS(ctx, protoReq)
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("requesting HOST-AS key", err)
	}

	key, err := getHostASKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostASKey{}, serrors.Wrap("obtaining HOST-AS key from reply", err)
	}

	return key, nil
}

func (f *Fetcher) HostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {

	conn, err := f.Dialer.Dial(ctx, &snet.SVCAddr{SVC: addr.SvcCS})
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewDRKeyIntraServiceClient(conn)
	protoReq := hostHostMetaToProtoRequest(meta)
	rep, err := client.DRKeyHostHost(ctx, protoReq)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("requesting Host-Host key", err)
	}

	key, err := getHostHostKeyFromReply(rep, meta)
	if err != nil {
		return drkey.HostHostKey{}, serrors.Wrap("obtaining Host-Host key from reply", err)
	}

	return key, nil
}
