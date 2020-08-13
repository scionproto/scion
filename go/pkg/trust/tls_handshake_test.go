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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestTLSCryptoManagerVerifyPeerCertificate(t *testing.T) {
	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
	crt111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"

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
	trc := xtest.LoadTRC(t, "testdata/common/trcs/ISD1-B1-S1.trc")
	crt111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/ISD1-ASff00_0_111.pem"
	key111File := "testdata/common/ISD1/ASff00_0_111/crypto/as/cp-as.key"
	tlsCert, err := tls.LoadX509KeyPair(crt111File, key111File)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db := mock_trust.NewMockDB(ctrl)
	db.EXPECT().SignedTRC(gomock.Any(), gomock.Any()).MaxTimes(2).Return(trc, nil)
	loader := mock_trust.NewMockX509KeyPairLoader(ctrl)
	loader.EXPECT().LoadX509KeyPair().MaxTimes(2).Return(&tlsCert, nil)

	serverMgr := trust.NewTLSCryptoManager(loader, db)
	srvConfig := &tls.Config{
		InsecureSkipVerify:    true,
		GetCertificate:        serverMgr.GetCertificate,
		VerifyPeerCertificate: serverMgr.VerifyPeerCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:8884", srvConfig)
	require.NoError(t, err)

	clientMgr := trust.NewTLSCryptoManager(loader, db)
	clientConfig := &tls.Config{
		InsecureSkipVerify:    true,
		GetClientCertificate:  clientMgr.GetClientCertificate,
		VerifyPeerCertificate: clientMgr.VerifyPeerCertificate,
	}

	go func() {
		clientConn, err := tls.Dial("tcp", "127.0.0.1:8884", clientConfig)
		assert.NoError(t, err)
		defer clientConn.Close()
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()

	tlsCon, _ := conn.(*tls.Conn)
	err = tlsCon.Handshake()
	assert.NoError(t, err)
	assert.NotEmpty(t, tlsCon.ConnectionState().PeerCertificates)
	assert.True(t, tlsCon.ConnectionState().HandshakeComplete)

}

func loadRawChain(t *testing.T, file string) [][]byte {
	var chain [][]byte
	for _, cert := range xtest.LoadChain(t, file) {
		chain = append(chain, cert.Raw)
	}
	return chain
}
