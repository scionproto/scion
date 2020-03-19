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
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSenderRun(t *testing.T) {
	t.Log("Run sends ifid packets on all interfaces")
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)
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
		pld, err := spld.GetVerifiedPld(nil, testVerifier(pub))
		assert.NoError(t, err, "PldErr")
		_, ok := topoProvider.Get().IFInfoMap()[pld.IfID.OrigIfID]
		assert.True(t, ok)
	}
}

func createTestSigner(t *testing.T, key common.RawBytes) infra.Signer {
	signer, err := trust.NewSigner(
		trust.SignerConf{
			ChainVer: 42,
			TRCVer:   21,
			Validity: scrypto.Validity{NotAfter: util.UnixTime{Time: time.Now().Add(time.Hour)}},
			Key: keyconf.Key{
				Type:      keyconf.PrivateKey,
				Algorithm: scrypto.Ed25519,
				Bytes:     key,
				ID:        keyconf.ID{IA: xtest.MustParseIA("1-ff00:0:84")},
			},
		},
	)
	require.NoError(t, err)
	return signer
}

var _ ctrl.Verifier = testVerifier{}

type testVerifier common.RawBytes

func (t testVerifier) VerifyPld(_ context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	src, err := ctrl.NewSignSrcDefFromRaw(spld.Sign.Src)
	if err != nil {
		return nil, common.NewBasicError("Cannot parse payload", err)
	}
	if src.IA != xtest.MustParseIA("1-ff00:0:84") {
		return nil, common.NewBasicError("Wrong src.IA", err)
	}
	if src.TRCVer != 21 {
		return nil, common.NewBasicError("Wrong src.TRCVer", err)
	}
	pld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, common.NewBasicError("Cannot parse payload", err)
	}
	return pld, scrypto.Verify(spld.Sign.SigInput(spld.Blob, false), spld.Sign.Signature,
		common.RawBytes(t), scrypto.Ed25519)
}
