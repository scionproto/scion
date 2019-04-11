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

package seg

import (
	"bytes"
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	as110 = xtest.MustParseIA("1-ff00:0:110")
	as111 = xtest.MustParseIA("1-ff00:0:111")
	as112 = xtest.MustParseIA("1-ff00:0:112")
)

func TestPathSegmentAddASEntry(t *testing.T) {
	Convey("Adding AS entries results in a verifiable path segment", t, func() {
		asEntries := []*ASEntry{
			{
				RawIA:    as110.IAInt(),
				TrcVer:   1,
				CertVer:  3,
				MTU:      1500,
				IfIDSize: 12,
				HopEntries: []*HopEntry{
					{
						RemoteOutIF: 23,
						RawOutIA:    as111.IAInt(),
						RawHopField: make(common.RawBytes, spath.HopFieldLength),
					},
				},
			},
			{
				RawIA:    as110.IAInt(),
				TrcVer:   3,
				CertVer:  7,
				MTU:      1500,
				IfIDSize: 12,
				HopEntries: []*HopEntry{
					{
						RemoteInIF:  18,
						RawInIA:     as110.IAInt(),
						RemoteOutIF: 24,
						RawOutIA:    as112.IAInt(),
						RawHopField: make(common.RawBytes, spath.HopFieldLength),
					},
				},
			},
			{
				RawIA:    as110.IAInt(),
				TrcVer:   4,
				CertVer:  2,
				MTU:      1500,
				IfIDSize: 12,
				HopEntries: []*HopEntry{
					{
						RemoteInIF:  19,
						RawInIA:     as111.IAInt(),
						RawHopField: make(common.RawBytes, spath.HopFieldLength),
					},
				},
			},
		}
		var cryptographers []*cryptographer
		for range asEntries {
			cryptographers = append(cryptographers, newCryptographer(t))
		}
		pseg, err := NewSeg(&spath.InfoField{ISD: 1, TsInt: 13})
		xtest.FailOnErr(t, err)
		for i, entry := range asEntries {
			pseg.AddASEntry(entry, cryptographers[i])
		}
		for i, cryptographer := range cryptographers {
			err := pseg.VerifyASEntry(context.Background(), cryptographer, i)
			SoMsg("Err "+asEntries[i].IA().String(), err, ShouldBeNil)
		}

	})

}

type cryptographer struct {
	pubKey  common.RawBytes
	privKey common.RawBytes
}

func newCryptographer(t *testing.T) *cryptographer {
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	return &cryptographer{
		pubKey:  pub,
		privKey: priv,
	}
}

func (t *cryptographer) Sign(packedSegment common.RawBytes) (*proto.SignS, error) {
	sign := &proto.SignS{
		Src: common.RawBytes{1, 4, 4, 2},
	}
	signature, err := scrypto.Sign(packedSegment, t.privKey, scrypto.Ed25519)
	sign.Signature = signature
	return sign, err
}

func (t *cryptographer) Verify(_ context.Context, msg common.RawBytes,
	sign *proto.SignS) error {

	if !bytes.Equal(sign.Src, common.RawBytes{1, 4, 4, 2}) {
		return common.NewBasicError("Invalid sign", nil,
			"expected", common.RawBytes{1, 4, 4, 2}, "actual", sign.Src)
	}
	return scrypto.Verify(msg, sign.Signature, t.pubKey, scrypto.Ed25519)
}
