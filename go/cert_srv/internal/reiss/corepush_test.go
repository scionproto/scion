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

package reiss

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/mock_trustdb"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
)

var (
	localIA  = xtest.MustParseIA("1-ff00:0:311")
	localISD = localIA.I

	core1_110 = xtest.MustParseIA("1-ff00:0:110")
	core1_130 = xtest.MustParseIA("1-ff00:0:130")
	core1_120 = xtest.MustParseIA("1-ff00:0:120")

	trcISD1 = &trc.TRC{
		CoreASes: trc.CoreASMap{
			core1_110: nil,
			core1_120: nil,
			core1_130: nil,
		},
	}

	chain    *cert.Chain
	rawChain common.RawBytes
	chainMsg *cert_mgmt.Chain

	emptyChainMsg = &cert_mgmt.Chain{RawChain: nil}
)

func setup(t *testing.T) (*gomock.Controller, *mock_infra.MockMessenger, periodic.Task) {
	ctrl := gomock.NewController(t)
	trustDB := mock_trustdb.NewMockTrustDB(ctrl)
	msger := mock_infra.NewMockMessenger(ctrl)
	pusher := &CorePusher{
		LocalIA: localIA,
		TrustDB: trustDB,
		Msger:   msger,
	}
	var err error
	chain, err = cert.ChainFromFile("testdata/ISD1-ASff00_0_311-V1.crt", false)
	xtest.FailOnErr(t, err)
	rawChain, err = chain.Compress()
	xtest.FailOnErr(t, err)
	chainMsg = &cert_mgmt.Chain{RawChain: rawChain}
	SleepAfterFailure = 0

	trustDB.EXPECT().GetTRCMaxVersion(gomock.Any(), gomock.Eq(localISD)).Return(trcISD1, nil)
	trustDB.EXPECT().GetChainMaxVersion(gomock.Any(), gomock.Eq(localIA)).Return(chain, nil)

	return ctrl, msger, pusher
}

func TestNonExistingChainsArePushed(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	ctrl, msger, pusher := setup(t)
	defer ctrl.Finish()

	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_110), gomock.Any()).Return(
		emptyChainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_120), gomock.Any()).Return(
		emptyChainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_130), gomock.Any()).Return(
		emptyChainMsg, nil,
	)
	msger.EXPECT().SendCertChain(
		gomock.Any(), matchesChain(rawChain), matchers.IsSnetAddrWithIA(core1_110), gomock.Any())
	msger.EXPECT().SendCertChain(
		gomock.Any(), matchesChain(rawChain), matchers.IsSnetAddrWithIA(core1_120), gomock.Any())
	msger.EXPECT().SendCertChain(
		gomock.Any(), matchesChain(rawChain), matchers.IsSnetAddrWithIA(core1_130), gomock.Any())
	pusher.Run(ctx)
}

func TestExistingChainsAreNotPushed(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	ctrl, msger, pusher := setup(t)
	defer ctrl.Finish()

	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_110), gomock.Any()).Return(
		chainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_120), gomock.Any()).Return(
		chainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_130), gomock.Any()).Return(
		emptyChainMsg, nil,
	)
	msger.EXPECT().SendCertChain(
		gomock.Any(), matchesChain(rawChain), matchers.IsSnetAddrWithIA(core1_130), gomock.Any())
	pusher.Run(ctx)
}

func TestErrDuringSendIsRetried(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	ctrl, msger, pusher := setup(t)
	defer ctrl.Finish()

	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_110), gomock.Any()).Return(
		chainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_120), gomock.Any()).Return(
		chainMsg, nil,
	)
	msger.EXPECT().GetCertChain(
		gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_130), gomock.Any()).Return(
		emptyChainMsg, nil,
	)
	gomock.InOrder(
		msger.EXPECT().SendCertChain(
			gomock.Any(), matchesChain(rawChain), matchers.IsSnetAddrWithIA(core1_130),
			gomock.Any()).Return(common.NewBasicError("test error", nil)),
		msger.EXPECT().GetCertChain(
			gomock.Any(), gomock.Any(), matchers.IsSnetAddrWithIA(core1_130), gomock.Any()).Return(
			emptyChainMsg, nil,
		),
		msger.EXPECT().SendCertChain(
			gomock.Any(), matchesChain(rawChain),
			matchers.IsSnetAddrWithIA(core1_130), gomock.Any()),
	)
	pusher.Run(ctx)
}

var _ gomock.Matcher = (*chainMsgMatcher)(nil)

type chainMsgMatcher struct {
	rawChain common.RawBytes
}

func matchesChain(rawChain common.RawBytes) *chainMsgMatcher {
	return &chainMsgMatcher{
		rawChain: rawChain,
	}
}

func (m *chainMsgMatcher) Matches(x interface{}) bool {
	msg, ok := x.(*cert_mgmt.Chain)
	if !ok {
		return false
	}
	return bytes.Equal(m.rawChain, msg.RawChain)
}

func (m *chainMsgMatcher) String() string {
	return fmt.Sprintf("Chain msg with raw: %s", m.rawChain)
}
