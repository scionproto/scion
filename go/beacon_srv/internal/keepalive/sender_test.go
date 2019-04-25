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
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/mock_snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestSenderRun(t *testing.T) {
	setupItopo(t)
	Convey("Run sends ifid packets on all interfaces", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		mac, err := scrypto.InitMac(make(common.RawBytes, 16))
		xtest.FailOnErr(t, err)
		pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
		xtest.FailOnErr(t, err)
		conn := mock_snet.NewMockPacketConn(mctrl)
		s := Sender{
			Sender: &onehop.Sender{
				IA:   xtest.MustParseIA("1-ff00:0:111"),
				Conn: conn,
				Addr: &addr.AppAddr{
					L3: addr.HostFromIPStr("127.0.0.1"),
					L4: addr.NewL4UDPInfo(4242),
				},
				MAC: mac,
			},
			Signer: createTestSigner(t, priv),
		}
		pkts := make([]*snet.SCIONPacket, 0, len(itopo.Get().IFInfoMap))
		conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Times(cap(pkts)).DoAndReturn(
			func(ipkts, _ interface{}) error {
				pkts = append(pkts, ipkts.(*snet.SCIONPacket))
				return nil
			},
		)
		// Start keepalive messages.
		s.Run(nil)
		// Check packets are correct.
		for _, pkt := range pkts {
			spld, err := ctrl.NewSignedPldFromRaw(pkt.Payload.(common.RawBytes))
			SoMsg("SPldErr", err, ShouldBeNil)
			pld, err := spld.GetVerifiedPld(nil, testVerifier(pub))
			SoMsg("PldErr", err, ShouldBeNil)
			_, ok := itopo.Get().IFInfoMap[pld.IfID.OrigIfID]
			SoMsg("Intf", ok, ShouldBeTrue)
		}
	})
}

func setupItopo(t *testing.T) {
	itopo.Init("", proto.ServiceType_unset, itopo.Callbacks{})
	topo, err := topology.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	_, _, err = itopo.SetStatic(topo, true)
	xtest.FailOnErr(t, err)
}

func createTestSigner(t *testing.T, key common.RawBytes) infra.Signer {
	signer, err := trust.NewBasicSigner(key, infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			IA:       xtest.MustParseIA("1-ff00:0:84"),
			ChainVer: 42,
			TRCVer:   21,
		},
		Algo: scrypto.Ed25519,
	})
	xtest.FailOnErr(t, err)
	return signer
}

var _ ctrl.Verifier = testVerifier{}

type testVerifier common.RawBytes

func (t testVerifier) VerifyPld(_ context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	src, err := ctrl.NewSignSrcDefFromRaw(spld.Sign.Src)
	SoMsg("Src err", err, ShouldBeNil)
	SoMsg("Src.IA", src.IA, ShouldResemble, xtest.MustParseIA("1-ff00:0:84"))
	SoMsg("Src.ChainVer", src.ChainVer, ShouldEqual, 42)
	SoMsg("Src.TrcVer", src.TRCVer, ShouldEqual, 21)
	pld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, common.NewBasicError("Cannot parse payload", err)
	}
	return pld, scrypto.Verify(spld.Sign.SigInput(spld.Blob, false), spld.Sign.Signature,
		common.RawBytes(t), scrypto.Ed25519)
}
