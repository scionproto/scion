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

package ifstate

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	timeout     = time.Second
	overlapTime = path_mgmt.MinRevTTL / 2
	expireTime  = time.Second + DefaultKeepaliveTimeout
	ia          = xtest.MustParseIA("1-ff00:0:111")
)

type brMsg struct {
	msg *path_mgmt.IFStateInfos
	a   net.Addr
}

func TestMain(m *testing.M) {
	itopo.Init("", proto.ServiceType_unset, itopo.Callbacks{})
	os.Exit(m.Run())
}

// TestNoRevocationIssued tests that if all interfaces receive if keepalives the revoker should do
// nothing.
func TestNoRevocationIssued(t *testing.T) {
	setupItopo(t)
	_, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := createTestSigner(t, priv)
	Convey("TestNoRevocationIssued", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msger := mock_infra.NewMockMessenger(mctrl)
		intfs := NewInterfaces(itopo.Get().IFInfoMap, Config{})
		activateAll(intfs)
		revoker := testRevoker(intfs, msger, signer)
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		Convey("Check interface state didn't change", func() {
			for ifid, intf := range intfs.All() {
				SoMsg(fmt.Sprintf("Intf %d should be active", ifid),
					intf.State(), ShouldEqual, Active)
			}
		})
	})
}

// TestRevokeInterface tests that if a keepalive didn't arrive for an interface it should be
// revoked.
func TestRevokeInterface(t *testing.T) {
	setupItopo(t)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := createTestSigner(t, priv)
	verifier := revVerifier(pub)
	Convey("TestRevokeInterface", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msger := mock_infra.NewMockMessenger(mctrl)
		intfs := NewInterfaces(itopo.Get().IFInfoMap, Config{})
		activateAll(intfs)
		intfs.Get(101).lastActivate = time.Now().Add(-expireTime)
		checkSentMessages := expectMessengerCalls(msger, 101)
		revoker := testRevoker(intfs, msger, signer)
		revoker.Run(ctx)
		Convey("Check interface state", func() {
			for ifid, intf := range intfs.All() {
				if ifid == 101 {
					SoMsg(fmt.Sprintf("Intf %d should be revoked", ifid),
						intf.State(), ShouldEqual, Revoked)
				} else {
					SoMsg(fmt.Sprintf("Intf %d should be active", ifid),
						intf.State(), ShouldEqual, Active)
				}
			}
		})
		checkSentMessages(t, verifier)
	})
}

// TestRevokedInterfaceNotRevokedImmediately tests that if an interface was revoked recently it
// shouldn't be revoked again.
func TestRevokedInterfaceNotRevokedImmediately(t *testing.T) {
	setupItopo(t)
	_, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := createTestSigner(t, priv)
	Convey("TestRevokedInterfaceNotRevokedImmediately", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msger := mock_infra.NewMockMessenger(mctrl)
		intfs := NewInterfaces(itopo.Get().IFInfoMap, Config{})
		activateAll(intfs)
		intfs.Get(101).state = Expired
		intfs.Get(101).Revoke(toSigned(t, &path_mgmt.RevInfo{
			IfID:         101,
			RawIsdas:     ia.IAInt(),
			LinkType:     proto.LinkType_peer,
			RawTimestamp: util.TimeToSecs(time.Now().Add(-500 * time.Millisecond)),
			RawTTL:       10,
		}))
		revoker := testRevoker(intfs, msger, signer)
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		Convey("Check interface state didn't change", func() {
			for ifid, intf := range intfs.All() {
				if ifid == 101 {
					SoMsg(fmt.Sprintf("Intf %d should be revoked", ifid),
						intf.State(), ShouldEqual, Revoked)
				} else {
					SoMsg(fmt.Sprintf("Intf %d should be active", ifid),
						intf.State(), ShouldEqual, Active)
				}
			}
		})
	})
}

// TestRevokedInterfaceRevokedAgain test that if an interface was revoked and the overlap period
// started it should be revoked again.
func TestRevokedInterfaceRevokedAgain(t *testing.T) {
	setupItopo(t)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := createTestSigner(t, priv)
	verifier := revVerifier(pub)
	Convey("TestRevokedInterfaceRevokedAgain", t, func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msger := mock_infra.NewMockMessenger(mctrl)
		intfs := NewInterfaces(itopo.Get().IFInfoMap, Config{})
		activateAll(intfs)
		intfs.Get(101).state = Expired
		intfs.Get(101).Revoke(toSigned(t, &path_mgmt.RevInfo{
			IfID:         101,
			RawIsdas:     ia.IAInt(),
			LinkType:     proto.LinkType_peer,
			RawTimestamp: util.TimeToSecs(time.Now().Add(-6 * time.Second)),
			RawTTL:       10,
		}))
		checkSentMessages := expectMessengerCalls(msger, 101)
		revoker := testRevoker(intfs, msger, signer)
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		Convey("Check interface state didn't change", func() {
			for ifid, intf := range intfs.All() {
				if ifid == 101 {
					SoMsg(fmt.Sprintf("Intf %d should be revoked", ifid),
						intf.State(), ShouldEqual, Revoked)
				} else {
					SoMsg(fmt.Sprintf("Intf %d should be active", ifid),
						intf.State(), ShouldEqual, Active)
				}
			}
		})
		checkSentMessages(t, verifier)
	})
}

// TODO(lukedirtwalker): test revoking multiple interfaces at once.

func expectMessengerCalls(msger *mock_infra.MockMessenger,
	revokedIfId common.IFIDType) func(*testing.T, revVerifier) {

	var brMsgs []brMsg
	var brMsgsMtx sync.Mutex
	msger.EXPECT().SendIfStateInfos(gomock.Any(),
		gomock.Any(), gomock.Any(), gomock.Any()).Times(brCount()).DoAndReturn(
		func(_ context.Context, msg *path_mgmt.IFStateInfos, a net.Addr, _ uint64) error {
			brMsgsMtx.Lock()
			defer brMsgsMtx.Unlock()
			brMsgs = append(brMsgs, brMsg{msg: msg, a: a})
			return nil
		})
	var psAddr net.Addr
	var psMsg *path_mgmt.SignedRevInfo
	msger.EXPECT().SendRev(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).DoAndReturn(
		func(_ context.Context, msg *path_mgmt.SignedRevInfo, a net.Addr, _ uint64) error {
			psAddr = a
			psMsg = msg
			return nil
		})
	return func(t *testing.T, verifier revVerifier) {
		Convey("Check sent BR messages", func() {
			SoMsg("Should send correct amount of messages", len(brMsgs), ShouldEqual, brCount())
			sentBRs := expectedBRs()
			for _, brMsg := range brMsgs {
				brName := brId(t, brMsg.a.(*snet.Addr))
				delete(sentBRs, brName)
				checkBRMessage(t, brName, brMsg.msg, revokedIfId, verifier)
			}
			SoMsg("Should have sent to all brs", sentBRs, ShouldBeEmpty)
		})
		Convey("Check sent PS message", func() {
			saddr := psAddr.(*snet.Addr)
			SoMsg("Should send to local IA", saddr.IA, ShouldResemble, ia)
			topo := itopo.Get()
			isPsAddr := false
			for _, tAddr := range topo.PS {
				if tAddr.PublicAddr(topo.Overlay).Equal(saddr.Host) {
					isPsAddr = true
					break
				}
			}
			SoMsg("Should send to PS", isPsAddr, ShouldBeTrue)
			checkRevocation(t, psMsg, revokedIfId, verifier)
		})
	}
}

func checkBRMessage(t *testing.T, brId string, infos *path_mgmt.IFStateInfos,
	revokedIfId common.IFIDType, verifier revVerifier) {

	Convey(fmt.Sprintf("Check ifstateinfo for %s", brId), func() {
		SoMsg("Should contain correct amount of infos", len(infos.Infos), ShouldEqual, 1)
		SoMsg("Correct ifid", infos.Infos[0].IfID, ShouldEqual, revokedIfId)
		SoMsg("Not active", infos.Infos[0].Active, ShouldBeFalse)
		checkRevocation(t, infos.Infos[0].SRevInfo, revokedIfId, verifier)
	})
}

func checkRevocation(t *testing.T, srev *path_mgmt.SignedRevInfo,
	revokedIfId common.IFIDType, verifier revVerifier) {

	Convey("Check revocation", func() {
		verifier.Verify(t, srev)
		revInfo, err := srev.RevInfo()
		xtest.FailOnErr(t, err)
		SoMsg("correct ifId", revInfo.IfID, ShouldEqual, revokedIfId)
		SoMsg("correct IA", revInfo.RawIsdas, ShouldEqual, ia.IAInt())
		SoMsg("correct linkType", revInfo.LinkType,
			ShouldEqual, itopo.Get().IFInfoMap[revokedIfId].LinkType)
		rawNow := util.TimeToSecs(time.Now())
		SoMsg("recent revocation", revInfo.RawTimestamp, ShouldBeBetween, rawNow-1, rawNow+1)
		SoMsg("minTTL", revInfo.RawTTL, ShouldEqual, uint32(path_mgmt.MinRevTTL.Seconds()))
	})
}

func brId(t *testing.T, saddr *snet.Addr) string {
	topo := itopo.Get()
	for brId, brInfo := range topo.BR {
		if brInfo.CtrlAddrs.PublicAddr(topo.Overlay).Equal(saddr.Host) {
			return brId
		}
	}
	t.Fatalf("Didn't find br ID for %s", saddr.Host)
	return "" // meh, makes the compiler happy.
}

// expectedBRs return a set of BR ids for which we expect a if state update push.
func expectedBRs() map[string]struct{} {
	brIds := make(map[string]struct{})
	for brId := range itopo.Get().BR {
		brIds[brId] = struct{}{}
	}
	return brIds
}

func toSigned(t *testing.T, r *path_mgmt.RevInfo) *path_mgmt.SignedRevInfo {
	t.Helper()
	sr, err := path_mgmt.NewSignedRevInfo(r, nil)
	xtest.FailOnErr(t, err)
	return sr
}

func brCount() int {
	return len(itopo.Get().BR)
}

func activateAll(intfs *Interfaces) {
	for _, intf := range intfs.All() {
		intf.Activate(42)
	}
}

func testRevoker(intfs *Interfaces, msger infra.Messenger, signer infra.Signer) *Revoker {
	return NewRevoker(intfs, msger, signer, RevConfig{RevOverlap: overlapTime})
}

func setupItopo(t *testing.T) {
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

type revVerifier common.RawBytes

func (v revVerifier) Verify(t *testing.T, srev *path_mgmt.SignedRevInfo) {
	sign := srev.Sign
	err := scrypto.Verify(sign.SigInput(srev.Blob, false), sign.Signature,
		common.RawBytes(v), scrypto.Ed25519)
	xtest.FailOnErr(t, err)
}
