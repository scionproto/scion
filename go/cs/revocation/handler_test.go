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

package revocation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/revocation/mock_revocation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia = xtest.MustParseIA("1-ff00:0:111")
)

func TestMain(m *testing.M) {
	metrics.InitBSMetrics()
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func TestHandler(t *testing.T) {

	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	signer := createTestSigner(t, priv)

	rev := &path_mgmt.RevInfo{
		RawIsdas:     ia.IAInt(),
		IfID:         101,
		LinkType:     proto.LinkType_peer,
		RawTimestamp: util.TimeToSecs(time.Now()),
		RawTTL:       uint32(path_mgmt.MinRevTTL.Seconds()),
	}
	sRev, err := path_mgmt.NewSignedRevInfo(rev, signer)
	xtest.FailOnErr(t, err)

	sRevInvalid, err := path_mgmt.NewSignedRevInfo(rev, signer)
	xtest.FailOnErr(t, err)
	// flip a bit
	sRevInvalid.Blob[0] ^= 0xFF

	tests := []struct {
		Name   string
		Rev    *path_mgmt.SignedRevInfo
		Ack    *ack.Ack
		Result *infra.HandlerResult
	}{
		{
			Name: "Unverifiable revocation is rejected",
			Rev:  sRevInvalid,
			Ack: &ack.Ack{
				Err:     proto.Ack_ErrCode_reject,
				ErrDesc: messenger.AckRejectFailedToVerify,
			},
			Result: infra.MetricsErrInvalid,
		},
		{
			Name: "Verifiable rev is stored and acked",
			Rev:  sRev,
			Ack: &ack.Ack{
				Err:     proto.Ack_ErrCode_ok,
				ErrDesc: "",
			},
			Result: infra.MetricsResultOk,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			verifier := mock_infra.NewMockVerifier(mctrl)
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, msg common.RawBytes, sign *proto.SignS) error {
					return scrypto.Verify(sign.SigInput(msg, false), sign.Signature,
						pub, scrypto.Ed25519)
				},
			)

			rw := mock_infra.NewMockResponseWriter(mctrl)
			if test.Ack != nil {
				rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: *test.Ack})
			}

			revStore := mock_revocation.NewMockStore(mctrl)
			if test.Result == infra.MetricsResultOk {
				rev, err := test.Rev.RevInfo()
				xtest.FailOnErr(t, err)
				revStore.EXPECT().InsertRevocations(gomock.Any(), &matchers.SignedRevs{
					Verifier:  revVerifier(pub),
					MatchRevs: []path_mgmt.RevInfo{*rev},
				})
			}

			serveCtx := infra.NewContextWithResponseWriter(context.Background(), rw)
			req := infra.NewRequest(serveCtx, test.Rev, nil, nil, 0)
			h := NewHandler(revStore, verifier, time.Second)
			res := h.Handle(req)
			if res != test.Result {
				t.Fatalf("Expected %v but was: %v", test.Result, res)
			}
		})
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

type revVerifier []byte

func (v revVerifier) Verify(_ context.Context, msg []byte, sign *proto.SignS) error {
	return scrypto.Verify(sign.SigInput(msg, false), sign.Signature, []byte(v), scrypto.Ed25519)
}
