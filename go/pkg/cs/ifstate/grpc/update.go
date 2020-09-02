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

package grpc

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// StateSender sends interface states using gRPC.
type StateSender struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

// SendStateUpdate sends the state update.
func (s StateSender) SendStateUpdate(ctx context.Context, states []ifstate.InterfaceState,
	server net.Addr) error {

	conn, err := s.Dialer.Dial(ctx, server)
	if err != nil {
		return serrors.WrapStr("dialing", err)
	}
	defer conn.Close()
	client := cppb.NewInterfaceStateConsumerServiceClient(conn)
	request, err := toIfStateMessage(states)
	if err != nil {
		return serrors.WrapStr("converting interface states", err)
	}
	_, err = client.InterfaceStateConsume(ctx, request)
	return err
}

func toIfStateMessage(states []ifstate.InterfaceState) (*cppb.InterfaceStateConsumeRequest, error) {
	cStates := make([]*cppb.InterfaceState, 0, len(states))
	for _, s := range states {
		var rawRev []byte
		if s.Revocation != nil {
			raw, err := s.Revocation.Pack()
			if err != nil {
				return nil, serrors.WrapStr("packing revocation", err, "if_id", s.ID)
			}
			rawRev = raw
		}
		cStates = append(cStates, &cppb.InterfaceState{
			Id:        uint64(s.ID),
			SignedRev: rawRev,
		})
	}
	return &cppb.InterfaceStateConsumeRequest{
		States: cStates,
	}, nil
}
