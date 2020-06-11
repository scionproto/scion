// Copyright 2020 Anapaya Systems
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

package tcp

import (
	"context"
	"net"

	capnp "zombiezen.com/go/capnproto2"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/rpc"
	"github.com/scionproto/scion/go/proto"
)

// client is the client side of the messenger.
type client struct{}

// Request sends the request pld to the given address and returns the reply.
func (c client) Request(ctx context.Context, pld *ctrl.Pld, address net.Addr) (*ctrl.Pld, error) {
	signedPld, err := pld.SignedPld(ctx, infra.NullSigner)
	if err != nil {
		return nil, err
	}
	msg, err := messenger.SignedPldToMsg(signedPld)
	if err != nil {
		return nil, err
	}
	request := &rpc.Request{Message: msg}
	reply, err := c.requestRPC(ctx, request, address)
	if err != nil {
		return nil, err
	}
	replySignedPld, err := messenger.MsgToSignedPld(reply.Message)
	if err != nil {
		return nil, err
	}

	replyPld, err := replySignedPld.UnsafePld()
	if err != nil {
		return nil, err
	}
	return replyPld, nil
}

func (c client) requestRPC(ctx context.Context, request *rpc.Request,
	address net.Addr) (*rpc.Reply, error) {
	dialer := net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", address.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	err = capnp.NewEncoder(conn).Encode(request.Message)
	if err != nil {
		return nil, err
	}
	msg, err := proto.SafeDecode(capnp.NewDecoder(conn))
	if err != nil {
		return nil, err
	}
	return &rpc.Reply{Message: msg}, nil
}
