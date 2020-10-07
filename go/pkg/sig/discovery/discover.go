// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package discovery

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/pkg/grpc"
	dspb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

// Service can be used to discover remote gateways.
type Service struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

// Gateway represents a remote gateway.
//
// TODO(lukedirtwalker): What is the best type for the Addresses? It could also
// be net.Addr, but should it be a snet Address or just net.UDPAddr? I depends
// on the implementation that uses the API and should be adapted at that point.
type Gateway struct {
	ControlAddress string
	DataAddress    string
}

// Gateways discovers gateways in the remote's AS.
func (s Service) Gateways(ctx context.Context, remote net.Addr) ([]Gateway, error) {
	conn, err := s.Dialer.Dial(ctx, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := dspb.NewDiscoveryServiceClient(conn)
	reply, err := client.Gateways(ctx, &dspb.GatewaysRequest{})
	if err != nil {
		return nil, err
	}
	gateways := make([]Gateway, 0, len(reply.Gateways))
	for _, g := range reply.Gateways {
		gateways = append(gateways, Gateway{
			ControlAddress: g.ControlAddress,
			DataAddress:    g.DataAddress,
		})
	}
	return gateways, nil
}
