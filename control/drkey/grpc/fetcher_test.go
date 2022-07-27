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

package grpc_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	csdrkey "github.com/scionproto/scion/control/drkey"
	dk_grpc "github.com/scionproto/scion/control/drkey/grpc"
	"github.com/scionproto/scion/control/drkey/grpc/mock_grpc"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
	"github.com/scionproto/scion/scion-pki/testcrypto"
)

var _ csdrkey.Fetcher = (*dk_grpc.Fetcher)(nil)

func TestLevel1KeyFetching(t *testing.T) {
	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	tlsCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "/certs/ISD1-ASff00_0_111.pem"),
		filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/cp-as.key"),
	)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	lvl1db := mock_grpc.NewMockEngine(ctrl)
	lvl1db.EXPECT().DeriveLevel1(gomock.Any()).Return(drkey.Level1Key{}, nil)

	mgrdb := mock_trust.NewMockDB(ctrl)
	mgrdb.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).AnyTimes().Return(trc, nil)
	loader := mock_trust.NewMockX509KeyPairLoader(ctrl)
	loader.EXPECT().LoadClientKeyPair(gomock.Any()).AnyTimes().Return(&tlsCert, nil)
	loader.EXPECT().LoadServerKeyPair(gomock.Any()).AnyTimes().Return(&tlsCert, nil)
	mgr := trust.NewTLSCryptoManager(loader, mgrdb)

	serverCreds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify:    true,
		GetCertificate:        mgr.GetCertificate,
		VerifyPeerCertificate: mgr.VerifyClientCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
	})
	clientCreds := credentials.NewTLS(&tls.Config{
		InsecureSkipVerify:    true,
		GetClientCertificate:  mgr.GetClientCertificate,
		VerifyPeerCertificate: mgr.VerifyServerCertificate,
		VerifyConnection:      mgr.VerifyConnection,
	})

	server := newGRPCService(serverCreds, clientCreds)
	cppb.RegisterDRKeyInterServiceServer(server.Server(), &dk_grpc.Server{
		Engine: lvl1db,
	})
	server.Start(t)

	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Dataplane().Return(nil)
	path.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{})

	router := mock_snet.NewMockRouter(ctrl)
	router.EXPECT().AllRoutes(gomock.Any(), gomock.Any()).Return([]snet.Path{path}, nil)

	fetcher := dk_grpc.Fetcher{
		Dialer:     server,
		Router:     router,
		MaxRetries: 10,
	}

	meta := drkey.Level1Meta{
		ProtoId:  drkey.Generic,
		Validity: time.Now(),
		SrcIA:    xtest.MustParseIA("1-ff00:0:111"),
	}
	_, err = fetcher.Level1(context.Background(), meta)
	require.NoError(t, err)
}

type grpcService struct {
	listener          *bufconn.Listener
	server            *grpc.Server
	clientCredentials credentials.TransportCredentials
}

func newGRPCService(serverCreds, clientCreds credentials.TransportCredentials) *grpcService {
	return &grpcService{
		listener:          bufconn.Listen(1024 * 1024),
		server:            grpc.NewServer(grpc.Creds(serverCreds)),
		clientCredentials: clientCreds,
	}
}

func (s *grpcService) Server() *grpc.Server {
	return s.server
}

func (s *grpcService) Start(t *testing.T) {
	go func() {
		err := s.server.Serve(s.listener)
		require.NoError(t, err)
	}()
	t.Cleanup(s.server.Stop)
}

func (s *grpcService) Dial(ctx context.Context, addr net.Addr) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr.String(),
		grpc.WithContextDialer(
			func(context.Context, string) (net.Conn, error) {
				return s.listener.Dial()
			},
		),
		grpc.WithTransportCredentials(s.clientCredentials),
	)
}

func genCrypto(t testing.TB) string {
	dir := t.TempDir()

	var buf bytes.Buffer
	cmd := testcrypto.Cmd(command.StringPather(""))
	cmd.SetArgs([]string{
		"-t", "testdata/golden.topo",
		"-o", dir,
		"--isd-dir",
		"--as-validity", "1y",
	})
	cmd.SetOutput(&buf)
	err := cmd.Execute()
	require.NoError(t, err, buf.String())

	buf.Reset()
	cmd.SetArgs([]string{"update", "-o", dir})
	err = cmd.Execute()
	require.NoError(t, err, buf.String())

	return dir
}
