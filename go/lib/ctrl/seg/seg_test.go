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
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
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
					HopField: HopField{
						MAC: make([]byte, 3),
					},
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
					HopField: HopField{
						MAC: make([]byte, 3),
					},
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
					HopField: HopField{
						MAC: make([]byte, 3),
					},
				},
			},
		},
	}
	var keyPairs []*keyPair
	for range asEntries {
		keyPairs = append(keyPairs, newKeyPair(t))
	}
	Convey("When constructing a path segment by adding multiple AS entries", t, func() {
		rawInfo := make([]byte, spath.InfoFieldLength)
		(&spath.InfoField{ISD: 1, TsInt: 13}).Write(rawInfo)
		pseg, err := NewSeg(&PathSegmentSignedData{
			RawInfo:      make([]byte, spath.InfoFieldLength),
			RawTimestamp: 13,
			SegID:        1337,
		})
		xtest.FailOnErr(t, err)
		id, fullId := getIds(t, pseg)
		for i, entry := range asEntries {
			pseg.AddASEntry(context.Background(), entry, keyPairs[i])

			// Check that adding an AS entry modifies the segment id.
			newId, newFullId := getIds(t, pseg)
			SoMsg(fmt.Sprintf("ID differs %d", i), newId, ShouldNotEqual, id)
			SoMsg(fmt.Sprintf("FullID differs %d", i), newFullId, ShouldNotEqual, fullId)
			id, fullId = newId, newFullId
		}
		Convey("The segment should be verifiable", func() {
			for i, keyPair := range keyPairs {
				err := pseg.VerifyASEntry(context.Background(), keyPair, i)
				SoMsg("Err "+asEntries[i].IA().String(), err, ShouldBeNil)
			}
		})
		Convey("Modifying the first signature should render the segment unverifiable", func() {
			pseg.RawASEntries[0].Sign.Signature[3] ^= 0xFF
			for i, keyPair := range keyPairs {
				err := pseg.VerifyASEntry(context.Background(), keyPair, i)
				SoMsg("Err "+asEntries[i].IA().String(), err, ShouldNotBeNil)
			}
		})
		Convey("Modifying the first AS entry should render the segment unverifiable", func() {
			pseg.RawASEntries[0].Blob[3] ^= 0xFF
			for i, keyPair := range keyPairs {
				err := pseg.VerifyASEntry(context.Background(), keyPair, i)
				SoMsg("Err "+asEntries[i].IA().String(), err, ShouldNotBeNil)
			}
		})
	})
	Convey("When adding an AS entry fails, the segment is not affected", t, func() {
		rawInfo := make([]byte, spath.InfoFieldLength)
		(&spath.InfoField{ISD: 1, TsInt: 13}).Write(rawInfo)
		pseg, err := NewSeg(&PathSegmentSignedData{
			RawInfo:      make([]byte, spath.InfoFieldLength),
			RawTimestamp: 0,
			SegID:        1337,
		})
		xtest.FailOnErr(t, err)
		err = pseg.AddASEntry(context.Background(), asEntries[0], keyPairs[0])
		SoMsg("AddASEntry err", err, ShouldBeNil)
		raw, err := pseg.Pack()
		SoMsg("Pack seg err", err, ShouldBeNil)
		copySeg, err := NewBeaconFromRaw(raw)
		SoMsg("Parse seg err", err, ShouldBeNil)
		Convey("Invalid ASEntry causes an error", func() {
			err := pseg.AddASEntry(context.Background(), nil, keyPairs[1])
			SoMsg("err", err, ShouldNotBeNil)
			id, fullId := getIds(t, pseg)
			copyId, copyFullId := getIds(t, copySeg)
			SoMsg("ID equal", id, ShouldResemble, copyId)
			SoMsg("FullID equal", fullId, ShouldResemble, copyFullId)
			SoMsg("eq", pseg, ShouldResemble, copySeg)
		})
		Convey("Signing errors do not change the segment", func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			signer := mock_seg.NewMockSigner(ctrl)
			signer.EXPECT().Sign(gomock.Any(), gomock.Any()).Times(1).
				Return(nil, errors.New("fail"))
			err := pseg.AddASEntry(context.Background(), asEntries[1], signer)
			SoMsg("err", err, ShouldNotBeNil)
			id, fullId := getIds(t, pseg)
			copyId, copyFullId := getIds(t, copySeg)
			SoMsg("ID equal", id, ShouldResemble, copyId)
			SoMsg("FullID equal", fullId, ShouldResemble, copyFullId)
			SoMsg("eq", pseg, ShouldResemble, copySeg)
		})
	})
}

func getIds(t *testing.T, seg *PathSegment) (common.RawBytes, common.RawBytes) {
	t.Helper()
	return seg.ID(), seg.FullID()
}

type keyPair struct {
	pubKey  []byte
	privKey []byte
}

func newKeyPair(t *testing.T) *keyPair {
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)
	return &keyPair{
		pubKey:  pub,
		privKey: priv,
	}
}

func (t *keyPair) Sign(_ context.Context, packedSegment []byte) (*proto.SignS, error) {
	sign := &proto.SignS{
		Src: []byte{1, 4, 4, 2},
	}
	signature, err := scrypto.Sign(packedSegment, t.privKey, scrypto.Ed25519)
	sign.Signature = signature
	return sign, err
}

func (t *keyPair) Verify(_ context.Context, msg []byte,
	sign *proto.SignS) error {

	if !bytes.Equal(sign.Src, []byte{1, 4, 4, 2}) {
		return common.NewBasicError("Invalid sign", nil,
			"expected", []byte{1, 4, 4, 2}, "actual", sign.Src)
	}
	return scrypto.Verify(msg, sign.Signature, t.pubKey, scrypto.Ed25519)
}
