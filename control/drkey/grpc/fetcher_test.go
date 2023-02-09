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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"

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
	// In this test, we request the Level1 key from the local AS. This never
	// happens in the real system.
	// This test uses grpc's TLS stack, unlike the  real system, where the TLS of
	// the QUIC session is used.
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
	lvl1db.EXPECT().DeriveLevel1(gomock.Any()).AnyTimes().Return(drkey.Level1Key{}, nil)

	db := mock_trust.NewMockDB(ctrl)
	db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).AnyTimes().Return(trc, nil)
	verifier := trust.NewTLSCryptoVerifier(db)

	path := mock_snet.NewMockPath(ctrl)
	path.EXPECT().Metadata().AnyTimes().Return(&snet.PathMetadata{
		Interfaces: []snet.PathInterface{},
	})
	path.EXPECT().Dataplane().AnyTimes().Return(nil)
	path.EXPECT().UnderlayNextHop().AnyTimes().Return(&net.UDPAddr{})

	router := mock_snet.NewMockRouter(ctrl)
	router.EXPECT().AllRoutes(gomock.Any(), gomock.Any()).AnyTimes().Return([]snet.Path{path}, nil)

	testCases := map[string]struct {
		omitClientCert bool
		assertErr      assert.ErrorAssertionFunc
	}{
		"ok": {
			omitClientCert: false,
			assertErr:      assert.NoError,
		},
		"no certificate": {
			omitClientCert: true,
			assertErr:      assert.Error,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			// TODO(matzf): change xtest library to allow specifying the client
			// credentials for individual calls so that server does not need to be
			// recreated here.
			serverCreds := credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &tlsCert, nil
				},
				VerifyPeerCertificate: nil, // certificate verified in the service
				ClientAuth:            tls.RequestClientCert,
			})

			clientTLSConfig := &tls.Config{
				InsecureSkipVerify: true,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &tlsCert, nil
				},
				VerifyPeerCertificate: verifier.VerifyServerCertificate,
				VerifyConnection:      verifier.VerifyConnection,
			}
			if tc.omitClientCert {
				clientTLSConfig.GetClientCertificate = nil
			}
			clientCreds := credentials.NewTLS(clientTLSConfig)

			server := xtest.NewGRPCService(xtest.WithCredentials(clientCreds, serverCreds))
			cppb.RegisterDRKeyInterServiceServer(server.Server(), &dk_grpc.Server{
				Engine:                    lvl1db,
				ClientCertificateVerifier: verifier,
			})
			server.Start(t)

			fetcher := dk_grpc.Fetcher{
				Dialer:     server,
				Router:     router,
				MaxRetries: 1,
			}

			meta := drkey.Level1Meta{
				ProtoId:  drkey.Generic,
				Validity: time.Now(),
				SrcIA:    xtest.MustParseIA("1-ff00:0:111"),
			}
			_, err = fetcher.Level1(context.Background(), meta)
			tc.assertErr(t, err)
		})
	}
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
