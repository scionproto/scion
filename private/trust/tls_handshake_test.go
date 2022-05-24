// Copyright 2020 ETH Zurich
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

package trust_test

import (
	"crypto/tls"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/mock_trust"
)

func TestTLSCryptoManagerVerifyPeerCertificate(t *testing.T) {
	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	crt111File := filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem")

	out, _ := exec.Command("tree", dir).CombinedOutput()
	t.Log(string(out))

	testCases := map[string]struct {
		db        func(ctrl *gomock.Controller) trust.DB
		assertErr assert.ErrorAssertionFunc
	}{
		"valid": {
			db: func(ctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(ctrl)
				db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).Return(trc, nil)
				return db
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			db := tc.db(ctrl)
			mgr := trust.TLSCryptoManager{
				DB:      db,
				Timeout: 5 * time.Second,
			}
			rawChain := loadRawChain(t, crt111File)
			err := mgr.VerifyPeerCertificate(rawChain, nil)
			tc.assertErr(t, err)
		})
	}
}

func TestHandshake(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	dir := genCrypto(t)

	trc := xtest.LoadTRC(t, filepath.Join(dir, "trcs/ISD1-B1-S1.trc"))
	crt111File := filepath.Join(dir, "certs/ISD1-ASff00_0_111.pem")
	key111File := filepath.Join(dir, "ISD1/ASff00_0_111/crypto/as/cp-as.key")

	tlsCert, err := tls.LoadX509KeyPair(crt111File, key111File)
	require.NoError(t, err)
	chain, err := cppki.ReadPEMCerts(crt111File)
	require.NoError(t, err)

	db := mock_trust.NewMockDB(ctrl)
	db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).MaxTimes(2).Return(trc, nil)
	loader := mock_trust.NewMockX509KeyPairLoader(ctrl)
	loader.EXPECT().LoadX509KeyPair().MaxTimes(2).Return(&tlsCert, nil)

	mgr := trust.NewTLSCryptoManager(loader, db)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify:    true,
		GetClientCertificate:  mgr.GetClientCertificate,
		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
	})
	server := tls.Server(serverConn, &tls.Config{
		InsecureSkipVerify:    true,
		GetCertificate:        mgr.GetCertificate,
		VerifyPeerCertificate: mgr.VerifyPeerCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
	})

	connCheck := func(w, r net.Conn) {
		msg := []byte("hello")

		go func() {
			_, err := w.Write(msg)
			require.NoError(t, err)
		}()

		buf := make([]byte, 100)
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, msg, buf[:n])
	}

	connCheck(server, client)

	assert.Equal(t, chain, client.ConnectionState().PeerCertificates)
	assert.Equal(t, chain, server.ConnectionState().PeerCertificates)
	assert.True(t, client.ConnectionState().HandshakeComplete)
	assert.True(t, server.ConnectionState().HandshakeComplete)
}

func loadRawChain(t *testing.T, file string) [][]byte {
	var chain [][]byte
	for _, cert := range xtest.LoadChain(t, file) {
		chain = append(chain, cert.Raw)
	}
	return chain
}
