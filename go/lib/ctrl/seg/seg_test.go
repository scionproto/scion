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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

var (
	as110 = xtest.MustParseIA("1-ff00:0:110")
	as111 = xtest.MustParseIA("1-ff00:0:111")
	as112 = xtest.MustParseIA("1-ff00:0:112")
	as113 = xtest.MustParseIA("1-ff00:0:113")
)

func TestPathSegmentAddASEntry(t *testing.T) {
	asEntries := []ASEntry{
		{
			Local: as110,
			Next:  as111,
			MTU:   1500,
			HopEntry: HopEntry{
				HopField: HopField{
					ConsIngress: 0,
					ConsEgress:  1,
					ExpTime:     uint8(spath.DefaultHopFExpiry),
					MAC:         bytes.Repeat([]byte{0x11}, 6),
				},
				IngressMTU: 0,
			},
		},
		{
			Local: as111,
			Next:  as112,
			MTU:   1500,
			HopEntry: HopEntry{
				HopField: HopField{
					ConsIngress: 10,
					ConsEgress:  11,
					ExpTime:     uint8(spath.DefaultHopFExpiry),
					MAC:         bytes.Repeat([]byte{0x22}, 6),
				},
				IngressMTU: 1337,
			},
		},
		{
			Local: as112,
			Next:  as113,
			MTU:   1500,
			HopEntry: HopEntry{
				HopField: HopField{
					ConsIngress: 20,
					ConsEgress:  21,
					ExpTime:     uint8(spath.DefaultHopFExpiry),
					MAC:         bytes.Repeat([]byte{0x33}, 6),
				},
				IngressMTU: 1442,
			},
		},
	}
	var keyPairs []keyPair
	for range asEntries {
		keyPairs = append(keyPairs, newKeyPair(t))
	}

	ps, err := CreateSegment(time.Now(), 1337)
	require.NoError(t, err)

	for i, entry := range asEntries {
		id, fullID := ps.ID(), ps.FullID()
		err := ps.AddASEntry(context.Background(), entry, keyPairs[i])
		require.NoErrorf(t, err, "index: %d", i)

		// Check that adding an AS entry modifies the segment id.
		newID, newFullID := ps.ID(), ps.FullID()
		assert.NotEqual(t, id, newID)
		assert.NotEqual(t, fullID, newFullID)
	}

	for i, kp := range keyPairs {
		err := ps.VerifyASEntry(context.Background(), kp, i)
		require.NoErrorf(t, err, "index: %d", i)
	}

	c, err := BeaconFromPB(PathSegmentToPB(ps))
	require.NoError(t, err)
	for i, kp := range keyPairs {
		err := c.VerifyASEntry(context.Background(), kp, i)
		require.NoErrorf(t, err, "index: %d", i)
	}

	ps.ASEntries[0].Signed.Signature[3] ^= 0xFF
	for i, kp := range keyPairs {
		err := ps.VerifyASEntry(context.Background(), kp, i)
		assert.Errorf(t, err, "index: %d", i)
	}
}

type keyPair struct {
	pubKey  crypto.PublicKey
	privKey crypto.Signer
	keyID   []byte
}

func newKeyPair(t *testing.T) keyPair {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyID := make([]byte, 10)
	_, err = rand.Read(keyID)
	require.NoError(t, err)
	return keyPair{
		pubKey:  priv.Public(),
		privKey: priv,
		keyID:   keyID,
	}
}

func (p keyPair) Sign(_ context.Context, msg []byte,
	associatedData ...[]byte) (*cryptopb.SignedMessage, error) {

	var l int
	for _, d := range associatedData {
		l += len(d)
	}
	hdr := signed.Header{
		SignatureAlgorithm:   signed.ECDSAWithSHA256,
		Timestamp:            time.Now(),
		VerificationKeyID:    p.keyID,
		AssociatedDataLength: l,
	}
	return signed.Sign(hdr, msg, p.privKey, associatedData...)
}

func (p keyPair) Verify(_ context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	hdr, err := signed.ExtractUnverifiedHeader(signedMsg)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hdr.VerificationKeyID, p.keyID) {
		return nil, serrors.New("verification key ID does not match")
	}
	return signed.Verify(signedMsg, p.pubKey, associatedData...)

}
