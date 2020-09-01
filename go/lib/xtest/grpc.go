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

package xtest

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type GRPCService struct {
	listener *bufconn.Listener
	server   *grpc.Server
}

func NewGRPCService() *GRPCService {
	return &GRPCService{
		listener: bufconn.Listen(1024 * 1024),
		server:   grpc.NewServer(),
	}
}

func (s *GRPCService) Server() *grpc.Server {
	return s.server
}

func (s *GRPCService) Start() func() {
	go func() { s.server.Serve(s.listener) }()
	return s.server.Stop
}

func (s *GRPCService) Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr.String(),
		grpc.WithContextDialer(
			func(context.Context, string) (net.Conn, error) {
				return s.listener.Dial()
			},
		),
		grpc.WithInsecure(),
	)
}
