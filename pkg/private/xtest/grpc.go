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
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type grpcServiceOptions struct {
	clientCredentials credentials.TransportCredentials
	serverCredentials credentials.TransportCredentials
}

type GRPCServiceOption func(*grpcServiceOptions)

func WithCredentials(client, server credentials.TransportCredentials) func(*grpcServiceOptions) {
	return func(opts *grpcServiceOptions) {
		opts.clientCredentials = client
		opts.serverCredentials = server
	}
}

func WithInsecureCredentials() func(*grpcServiceOptions) {
	return func(opts *grpcServiceOptions) {
		opts.clientCredentials = insecure.NewCredentials()
	}
}

type GRPCService struct {
	listener          *bufconn.Listener
	server            *grpc.Server
	clientCredentials credentials.TransportCredentials
}

func NewGRPCService(options ...GRPCServiceOption) *GRPCService {
	opts := grpcServiceOptions{}
	for _, opt := range options {
		opt(&opts)
	}
	return &GRPCService{
		listener:          bufconn.Listen(1024 * 1024),
		server:            grpc.NewServer(grpc.Creds(opts.serverCredentials)),
		clientCredentials: opts.clientCredentials,
	}
}

func (s *GRPCService) Server() *grpc.Server {
	return s.server
}

func (s *GRPCService) Start(t *testing.T) {
	var bg errgroup.Group
	bg.Go(func() error {
		return s.server.Serve(s.listener)
	})
	t.Cleanup(func() {
		s.server.Stop()
		err := bg.Wait()
		if errors.Is(err, grpc.ErrServerStopped) {
			// Can (only) occur if Stop in the test cleanup is called before
			// server has started. This can happen if the test does not
			// actually use the server.
			return
		}
		assert.NoError(t, err)
	})
}

func (s *GRPCService) Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	transportSecurity := grpc.WithInsecure()
	if s.clientCredentials != nil {
		transportSecurity = grpc.WithTransportCredentials(s.clientCredentials)
	}
	return grpc.DialContext(ctx, addr.String(),
		grpc.WithContextDialer(
			func(context.Context, string) (net.Conn, error) {
				return s.listener.Dial()
			},
		),
		transportSecurity,
	)
}
