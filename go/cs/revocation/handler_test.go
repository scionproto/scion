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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/revocation/mock_revocation"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/matchers"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia = xtest.MustParseIA("1-ff00:0:111")
)

func TestMain(m *testing.M) {
	metrics.InitBSMetrics()
	log.Discard()
	os.Exit(m.Run())
}

func TestHandler(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()
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

	tests := []struct {
		Name   string
		Rev    *path_mgmt.SignedRevInfo
		Ack    *ack.Ack
		Result *infra.HandlerResult
	}{
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

			rw := mock_infra.NewMockResponseWriter(mctrl)
			if test.Ack != nil {
				rw.EXPECT().SendAckReply(gomock.Any(), &matchers.AckMsg{Ack: *test.Ack})
			}

			revStore := mock_revocation.NewMockStore(mctrl)
			if test.Result == infra.MetricsResultOk {
				rev, err := test.Rev.RevInfo()
				xtest.FailOnErr(t, err)
				revStore.EXPECT().InsertRevocations(gomock.Any(), &matchers.SignedRevs{
					Verifier:  revVerifier{pubKey: pub},
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
