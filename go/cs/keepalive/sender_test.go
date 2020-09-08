// Copyright 2019 Anapaya Systems
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

package keepalive

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestSenderRun(t *testing.T) {
	t.Log("Run sends ifid packets on all interfaces")
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
	conn := mock_snet.NewMockPacketConn(mctrl)
	s := Sender{
		Sender: &onehop.Sender{
			IA:   xtest.MustParseIA("1-ff00:0:111"),
			Conn: conn,
			Addr: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 4242,
			},
			MAC: mac,
		},
		Signer:       createTestSigner(t, priv),
		TopoProvider: topoProvider,
	}
	pkts := make([]*snet.Packet, 0, len(topoProvider.Get().IFInfoMap()))
	conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Times(cap(pkts)).DoAndReturn(
		func(ipkts, _ interface{}) error {
			pkts = append(pkts, ipkts.(*snet.Packet))
			return nil
		},
	)
	// Start keepalive messages.
	s.Run(nil)
	// Check packets are correct.
	for _, pkt := range pkts {
		spld, err := ctrl.NewSignedPldFromRaw(pkt.Payload.(common.RawBytes))
		assert.NoError(t, err, "SPldErr")
		pld, err := spld.GetVerifiedPld(nil, testVerifier{pubKey: pub})
		assert.NoError(t, err, "PldErr")
		_, ok := topoProvider.Get().IFInfoMap()[pld.IfID.OrigIfID]
		assert.True(t, ok)
	}
}

func createTestSigner(t *testing.T, key crypto.Signer) ctrl.Signer {
	return trust.Signer{
		PrivateKey: key,
		Algorithm:  signed.ECDSAWithSHA512,
		IA:         xtest.MustParseIA("1-ff00:0:84"),
		TRCID: cppki.TRCID{
			ISD:    1,
			Base:   1,
			Serial: 21,
		},
		SubjectKeyID: []byte("skid"),
		Expiration:   time.Now().Add(time.Hour),
	}
}

type testVerifier struct {
	pubKey crypto.PublicKey
}

func (t testVerifier) VerifyPld(_ context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	src, err := ctrl.NewX509SignSrc(spld.Sign.Src)
	if err != nil {
		return nil, serrors.WrapStr("cannot parse payload", err)
	}
	if src.IA != xtest.MustParseIA("1-ff00:0:84") {
		return nil, serrors.New("wrong src.IA")
	}
	if src.Base != 1 {
		return nil, serrors.New("wrong src.Base")
	}
	if src.Serial != 21 {
		return nil, serrors.New("wrong src.Serial")
	}
	if !bytes.Equal(src.SubjectKeyID, []byte("skid")) {
		return nil, serrors.New("wrong src.SKID")
	}
	pld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, serrors.WrapStr("Cannot parse payload", err)
	}
	return pld, verifyecdsa(spld.Sign.SigInput(spld.Blob, false), spld.Sign.Signature, t.pubKey)
}

func verifyecdsa(input, signature []byte, pubKey crypto.PublicKey) error {
	var ecdsaSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &ecdsaSig); err != nil {
		return err
	}
	if !ecdsa.Verify(pubKey.(*ecdsa.PublicKey), input, ecdsaSig.R, ecdsaSig.S) {
		return serrors.New("verification failure")
	}
	return nil
}
