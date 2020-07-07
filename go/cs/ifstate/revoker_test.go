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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/ifstate/mock_ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

var (
	timeout     = time.Second
	ttl         = path_mgmt.MinRevTTL
	overlapTime = ttl / 2
	expireTime  = time.Second + DefaultKeepaliveTimeout
	ia          = xtest.MustParseIA("1-ff00:0:111")
)

type brMsg struct {
	msg *path_mgmt.IFStateInfos
	a   net.Addr
}

func TestMain(m *testing.M) {
	metrics.InitBSMetrics()
	log.Discard()
	os.Exit(m.Run())
}

// TestNoRevocationIssued tests that if all interfaces receive if keepalives the revoker should do
// nothing.
func TestNoRevocationIssued(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := createTestSigner(t, priv)
	Convey("TestNoRevocationIssued", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msgr := mock_infra.NewMockMessenger(mctrl)
		revInserter := mock_ifstate.NewMockRevInserter(mctrl)
		intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
		activateAll(intfs)
		cfg := RevokerConf{
			Intfs:        intfs,
			Msgr:         msgr,
			Signer:       signer,
			RevConfig:    RevConfig{RevOverlap: overlapTime},
			TopoProvider: topoProvider,
			RevInserter:  revInserter,
		}
		revoker := cfg.New()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		checkInterfaces(intfs, map[common.IFIDType]State{})
	})
}

// TestRevokeInterface tests that if a keepalive didn't arrive for an interface it should be
// revoked.
func TestRevokeInterface(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
	signer := createTestSigner(t, priv)
	Convey("TestRevokeInterface", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msgr := mock_infra.NewMockMessenger(mctrl)
		revInserter := mock_ifstate.NewMockRevInserter(mctrl)
		intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
		activateAll(intfs)
		intfs.Get(101).lastActivate = time.Now().Add(-expireTime)
		revInserter.EXPECT().InsertRevocations(gomock.Any(), &matchers.SignedRevs{
			Verifier: revVerifier{pubKey: pub},
			MatchRevs: []path_mgmt.RevInfo{{
				RawIsdas: ia.IAInt(), IfID: 101, LinkType: proto.LinkType_peer},
			},
		})
		checkSentMessages := expectMessengerCalls(msgr, 101, topoProvider)
		cfg := RevokerConf{
			Intfs:        intfs,
			Msgr:         msgr,
			Signer:       signer,
			TopoProvider: topoProvider,
			RevInserter:  revInserter,
			RevConfig: RevConfig{
				RevTTL:     ttl,
				RevOverlap: overlapTime,
			},
		}
		revoker := cfg.New()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		revoker.Run(ctx)
		checkInterfaces(intfs, map[common.IFIDType]State{101: Revoked})
		checkSentMessages(t, revVerifier{pubKey: pub})
	})
}

// TestRevokedInterfaceNotRevokedImmediately tests that if an interface was revoked recently it
// shouldn't be revoked again.
func TestRevokedInterfaceNotRevokedImmediately(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := createTestSigner(t, priv)
	Convey("TestRevokedInterfaceNotRevokedImmediately", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msgr := mock_infra.NewMockMessenger(mctrl)
		revInserter := mock_ifstate.NewMockRevInserter(mctrl)
		intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
		activateAll(intfs)
		intfs.Get(101).state = Revoked
		srev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         101,
			RawIsdas:     ia.IAInt(),
			LinkType:     proto.LinkType_peer,
			RawTimestamp: util.TimeToSecs(time.Now().Add(-500 * time.Millisecond)),
			RawTTL:       uint32(ttl.Seconds()),
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		intfs.Get(101).SetRevocation(srev)
		cfg := RevokerConf{
			Intfs:        intfs,
			Msgr:         msgr,
			Signer:       signer,
			TopoProvider: topoProvider,
			RevInserter:  revInserter,
			RevConfig: RevConfig{
				RevTTL:     ttl,
				RevOverlap: overlapTime,
			},
		}
		revoker := cfg.New()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		SoMsg("Revocation should be same", intfs.Get(101).Revocation(), ShouldEqual, srev)
		checkInterfaces(intfs, map[common.IFIDType]State{101: Revoked})
	})
}

// TestRevokedInterfaceRevokedAgain test that if an interface was revoked and the overlap period
// started it should be revoked again.
func TestRevokedInterfaceRevokedAgain(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology.json")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
	signer := createTestSigner(t, priv)
	Convey("TestRevokedInterfaceRevokedAgain", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		msgr := mock_infra.NewMockMessenger(mctrl)
		revInserter := mock_ifstate.NewMockRevInserter(mctrl)
		intfs := NewInterfaces(topoProvider.Get().IFInfoMap(), Config{})
		activateAll(intfs)
		intfs.Get(101).state = Revoked
		srev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         101,
			RawIsdas:     ia.IAInt(),
			LinkType:     proto.LinkType_peer,
			RawTimestamp: util.TimeToSecs(time.Now().Add(-(overlapTime + 1) * time.Second)),
			RawTTL:       uint32(ttl.Seconds()),
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		intfs.Get(101).SetRevocation(srev)
		revInserter.EXPECT().InsertRevocations(gomock.Any(), &matchers.SignedRevs{
			Verifier: revVerifier{pubKey: pub},
			MatchRevs: []path_mgmt.RevInfo{{
				RawIsdas: ia.IAInt(), IfID: 101, LinkType: proto.LinkType_peer},
			},
		})
		checkSentMessages := expectMessengerCalls(msgr, 101, topoProvider)
		cfg := RevokerConf{
			Intfs:        intfs,
			Msgr:         msgr,
			Signer:       signer,
			TopoProvider: topoProvider,
			RevInserter:  revInserter,
			RevConfig: RevConfig{
				RevTTL:     ttl,
				RevOverlap: overlapTime,
			},
		}
		revoker := cfg.New()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		revoker.Run(ctx)
		// gomock tests that no calls to the messenger are made.
		checkInterfaces(intfs, map[common.IFIDType]State{101: Revoked})
		SoMsg("Revocation should be different", intfs.Get(101).Revocation(), ShouldNotEqual, srev)
		checkSentMessages(t, revVerifier{pubKey: pub})
	})
}

// TODO(lukedirtwalker): test revoking multiple interfaces at once.

func expectMessengerCalls(msger *mock_infra.MockMessenger,
	revokedIfId common.IFIDType, topoProvider topology.Provider) func(*testing.T, revVerifier) {

	var brMsgs []brMsg
	var brMsgsMtx sync.Mutex
	msger.EXPECT().SendIfStateInfos(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(len(topoProvider.Get().BRNames())).DoAndReturn(
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
			SoMsg("Should send correct amount of messages", len(brMsgs),
				ShouldEqual, len(topoProvider.Get().BRNames()))
			sentBRs := expectedBRs(topoProvider)
			for _, brMsg := range brMsgs {
				brName := brId(t, topoProvider, brMsg.a.(*snet.UDPAddr))
				delete(sentBRs, brName)
				checkBRMessage(t, brName, brMsg.msg, revokedIfId, verifier, topoProvider)
			}
			SoMsg("Should have sent to all brs", sentBRs, ShouldBeEmpty)
		})
		Convey("Check sent PS message", func() {
			saddr := psAddr.(*snet.SVCAddr)
			SoMsg("Should send to local IA", saddr.IA, ShouldResemble, ia)
			SoMsg("Should send to PS", saddr.SVC, ShouldResemble, addr.SvcPS)
			checkRevocation(t, psMsg, revokedIfId, verifier, topoProvider)
		})
	}
}

func checkBRMessage(t *testing.T, brId string, infos *path_mgmt.IFStateInfos,
	revokedIfId common.IFIDType, verifier revVerifier, topoProvider topology.Provider) {

	Convey(fmt.Sprintf("Check ifstateinfo for %s", brId), func() {
		SoMsg("Should contain correct amount of infos", len(infos.Infos), ShouldEqual, 1)
		SoMsg("Correct ifid", infos.Infos[0].IfID, ShouldEqual, revokedIfId)
		SoMsg("Not active", infos.Infos[0].Active, ShouldBeFalse)
		checkRevocation(t, infos.Infos[0].SRevInfo, revokedIfId, verifier, topoProvider)
	})
}

func checkRevocation(t *testing.T, srev *path_mgmt.SignedRevInfo,
	revokedIfId common.IFIDType, verifier revVerifier, topoProvider topology.Provider) {

	Convey("Check revocation", func() {
		revInfo, err := srev.RevInfo()
		SoMsg("No err expected", err, ShouldBeNil)
		SoMsg("correct ifId", revInfo.IfID, ShouldEqual, revokedIfId)
		SoMsg("correct IA", revInfo.RawIsdas, ShouldEqual, ia.IAInt())
		SoMsg("correct linkType", revInfo.LinkType,
			ShouldEqual, topoProvider.Get().IFInfoMap()[revokedIfId].LinkType)
		rawNow := util.TimeToSecs(time.Now())
		SoMsg("recent revocation", revInfo.RawTimestamp,
			ShouldBeBetweenOrEqual, rawNow-1, rawNow)
		SoMsg("minTTL", revInfo.RawTTL, ShouldEqual, uint32(ttl.Seconds()))
	})
}

func checkInterfaces(intfs *Interfaces, nonActive map[common.IFIDType]State) {
	Convey("Check interface state", func() {
		for ifid, intf := range intfs.All() {
			expectedState := Active
			if st, ok := nonActive[ifid]; ok {
				expectedState = st
			}
			SoMsg(fmt.Sprintf("Intf %d state", ifid), intf.State(), ShouldEqual, expectedState)
		}
	})
}

func brId(t *testing.T, topoProvider topology.Provider, saddr *snet.UDPAddr) string {
	topo := topoProvider.Get()
	for _, brID := range topo.BRNames() {
		a := topo.SBRAddress(brID)
		if a.Host.IP.Equal(saddr.Host.IP) && a.IA == saddr.IA {
			return brID
		}
	}

	t.Fatalf("Didn't find br ID for %s", saddr.Host)
	return "" // meh, makes the compiler happy.
}

// expectedBRs return a set of BR ids for which we expect a if state update push.
func expectedBRs(topoProvider topology.Provider) map[string]struct{} {
	brIds := make(map[string]struct{})
	for _, brId := range topoProvider.Get().BRNames() {
		brIds[brId] = struct{}{}
	}
	return brIds
}

func activateAll(intfs *Interfaces) {
	for _, intf := range intfs.All() {
		intf.Activate(42)
	}
}

func createTestSigner(t *testing.T, key crypto.Signer) ctrl.Signer {
	return trust.Signer{
		PrivateKey: key,
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

type revVerifier struct {
	pubKey crypto.PublicKey
}

func (v revVerifier) Verify(_ context.Context, msg []byte, sign *proto.SignS) error {
	return verifyecdsa(sign.SigInput(msg, false), sign.Signature, v.pubKey)
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
