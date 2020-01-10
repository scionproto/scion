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

package trc_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

type verifyTestCase struct {
	Modify         func(*testing.T, *[]trc.Signature)
	ExpectedErrMsg common.ErrMsg
}

var (
	verifySimpleTests = map[string]verifyTestCase{
		"Valid update": {
			Modify: func(_ *testing.T, _ *[]trc.Signature) {},
		},
		"Undecodable": {
			Modify: func(_ *testing.T, sigs *[]trc.Signature) {
				(*sigs)[0].EncodedProtected = "!"
			},
			ExpectedErrMsg: "illegal base64 data",
		},
	}

	verifyPOPTests = map[string]verifyTestCase{
		"Unexpected proof of possession signature": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				protected := trc.Protected{
					Algorithm:  scrypto.Ed25519,
					Type:       trc.POPSignature,
					KeyType:    trc.VotingOnlineKey,
					KeyVersion: 1,
					AS:         a190,
				}
				encProtected, err := trc.EncodeProtected(protected)
				require.NoError(t, err)
				*sigs = append(*sigs, trc.Signature{
					EncodedProtected: encProtected,
					Signature: xtest.MustParseHexString("e2a09de2a095e2a09e20e2a08" +
						"de2a08ae2a09de2a091"),
				})
			},
			ExpectedErrMsg: trc.ErrUnexpectedPOPSignature,
		},
		"Duplicate proof of possession": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				i := findSignature(t, *sigs, a110, trc.POPSignature)
				*sigs = append((*sigs), (*sigs)[i])
			},
			ExpectedErrMsg: trc.ErrDuplicatePOPSignature,
		},
		"Missing proof of possession": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				i := findSignature(t, *sigs, a110, trc.POPSignature)
				*sigs = append((*sigs)[:i], (*sigs)[i+1:]...)
			},
			ExpectedErrMsg: trc.ErrMissingPOPSignature,
		},
		"Proof of possession wrong Algorithm": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.POPSignature)]
				recodeProtected(t, sig, func(p *trc.Protected) {
					p.Algorithm = "invalid"
				})
			},
			ExpectedErrMsg: trc.ErrInvalidProtected,
		},
		// A wrong KeyType would be caught by a previous check.
		"Proof of possession wrong KeyVersion": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.POPSignature)]
				recodeProtected(t, sig, func(p *trc.Protected) {
					p.KeyVersion += 1
				})
			},
			ExpectedErrMsg: trc.ErrInvalidProtected,
		},
		"Mangled proof of possession signature": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.POPSignature)]
				sig.Signature[0] ^= 0xFF
			},
			ExpectedErrMsg: trc.ErrPOPVerification,
		},
	}

	verifyVoteTests = map[string]verifyTestCase{
		"Unexpected vote signature": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				protected := trc.Protected{
					Algorithm:  scrypto.Ed25519,
					Type:       trc.VoteSignature,
					KeyType:    trc.VotingOnlineKey,
					KeyVersion: 1,
					AS:         a190,
				}
				encProtected, err := trc.EncodeProtected(protected)
				require.NoError(t, err)
				*sigs = append(*sigs, trc.Signature{
					EncodedProtected: encProtected,
					Signature: xtest.MustParseHexString("e2a08be2a081e2a085e2a0912" +
						"0e2a08ee2a08ae2a09be2a09de2a081e2a09ee2a0a5e2a097e2a091"),
				})
			},
			ExpectedErrMsg: trc.ErrUnexpectedVoteSignature,
		},
		"Duplicate vote": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				i := findSignature(t, *sigs, a110, trc.VoteSignature)
				*sigs = append((*sigs), (*sigs)[i])
			},
			ExpectedErrMsg: trc.ErrDuplicateVoteSignature,
		},
		"Missing vote": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				i := findSignature(t, *sigs, a110, trc.VoteSignature)
				*sigs = append((*sigs)[:i], (*sigs)[i+1:]...)
			},
			ExpectedErrMsg: trc.ErrMissingVoteSignature,
		},
		"Vote wrong Algorithm": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.VoteSignature)]
				recodeProtected(t, sig, func(p *trc.Protected) {
					p.Algorithm = "invalid"
				})
			},
			ExpectedErrMsg: trc.ErrInvalidProtected,
		},
		"Vote wrong KeyType": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.VoteSignature)]
				recodeProtected(t, sig, func(p *trc.Protected) {
					p.KeyType = trc.VotingOnlineKey
				})
			},
			ExpectedErrMsg: trc.ErrInvalidProtected,
		},
		"Vote wrong KeyVersion": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.VoteSignature)]
				recodeProtected(t, sig, func(p *trc.Protected) {
					p.KeyVersion += 1
				})
			},
			ExpectedErrMsg: trc.ErrInvalidProtected,
		},
		"Mangled Vote signature": {
			Modify: func(t *testing.T, sigs *[]trc.Signature) {
				sig := &(*sigs)[findSignature(t, *sigs, a110, trc.VoteSignature)]
				sig.Signature[0] ^= 0xFF
			},
			ExpectedErrMsg: trc.ErrVoteVerification,
		},
	}
)

func TestUpdateVerifierVerify(t *testing.T) {
	tests := union(
		verifySimpleTests,
		verifyVoteTests,
		verifyPOPTests,
	)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			vt := newVerifyTestTRC(t, time.Now())
			prepareVerifyTest(t, &vt, test.Modify)
			v := trc.UpdateVerifier{
				Prev:        vt.Prev,
				Next:        vt.Next,
				NextEncoded: vt.Signed.EncodedTRC,
				Signatures:  vt.Signed.Signatures,
			}
			err := v.Verify()
			if test.ExpectedErrMsg == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestPOPVerifierVerify(t *testing.T) {
	tests := union(
		verifySimpleTests,
		verifyPOPTests,
	)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			vt := newVerifyTestTRC(t, time.Now())
			prepareVerifyTest(t, &vt, test.Modify)
			v := trc.POPVerifier{
				TRC:        vt.Next,
				Encoded:    vt.Signed.EncodedTRC,
				Signatures: vt.Signed.Signatures,
			}
			err := v.Verify()
			if test.ExpectedErrMsg == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func prepareVerifyTest(t *testing.T, vt *verifyTestTRC, modify func(*testing.T, *[]trc.Signature)) {
	modify(t, &(vt.Signed.Signatures))
	u := trc.UpdateValidator{
		Prev: vt.Prev,
		Next: vt.Next,
	}
	_, err := u.Validate()
	require.NoError(t, err)
}

type verifyTestTRC struct {
	Prev     *trc.TRC
	Next     *trc.TRC
	PrevKeys map[addr.AS]map[trc.KeyType][]byte
	NextKeys map[addr.AS]map[trc.KeyType][]byte
	Signed   trc.Signed
}

func newVerifyTestTRC(t *testing.T, now time.Time) verifyTestTRC {
	next, prev := newRegularUpdate(now)
	meta := next.PrimaryASes[a110].Keys[trc.VotingOnlineKey]
	meta.KeyVersion += 1
	next.PrimaryASes[a110].Keys[trc.VotingOnlineKey] = meta
	next.ProofOfPossession[a110] = append(next.ProofOfPossession[a110], trc.VotingOnlineKey)
	next.Votes[a110] = trc.VotingOfflineKey

	meta = next.PrimaryASes[a130].Keys[trc.IssuingGrantKey]
	meta.KeyVersion += 1
	next.PrimaryASes[a130].Keys[trc.IssuingGrantKey] = meta
	next.ProofOfPossession[a130] = append(next.ProofOfPossession[a130], trc.IssuingGrantKey)

	nextKeys, prevKeys := generateKeys(t, next, prev)
	signed := signTRC(t, next, prev, nextKeys, prevKeys)
	return verifyTestTRC{
		Prev:     prev,
		Next:     next,
		PrevKeys: prevKeys,
		NextKeys: nextKeys,
		Signed:   signed,
	}
}

func findSignature(t *testing.T, sigs []trc.Signature, as addr.AS, sigType trc.SignatureType) int {
	for i, sig := range sigs {
		p, err := sig.EncodedProtected.Decode()
		require.NoError(t, err)
		if p.AS == as && p.Type == sigType {
			return i
		}
	}
	return -1
}

func recodeProtected(t *testing.T, sig *trc.Signature, modify func(*trc.Protected)) {
	p, err := sig.EncodedProtected.Decode()
	require.NoError(t, err)
	modify(&p)
	sig.EncodedProtected, err = trc.EncodeProtected(p)
	require.NoError(t, err)
}

func generateKeys(t *testing.T, next, prev *trc.TRC) (map[addr.AS]map[trc.KeyType][]byte,
	map[addr.AS]map[trc.KeyType][]byte) {

	prevKeys := make(map[addr.AS]map[trc.KeyType][]byte)
	for as, primary := range prev.PrimaryASes {
		prevKeys[as] = make(map[trc.KeyType][]byte)
		for keyType, meta := range primary.Keys {
			pub, priv, err := scrypto.GenKeyPair(meta.Algorithm)
			require.NoError(t, err)
			prevKeys[as][keyType] = priv
			meta.Key = pub
			prev.PrimaryASes[as].Keys[keyType] = meta
		}
	}

	nextKeys := make(map[addr.AS]map[trc.KeyType][]byte)
	for as, primary := range next.PrimaryASes {
		nextKeys[as] = make(map[trc.KeyType][]byte)
		for keyType, meta := range primary.Keys {
			var pub, priv common.RawBytes
			if meta.KeyVersion == prev.PrimaryASes[as].Keys[keyType].KeyVersion {
				pub = prev.PrimaryASes[as].Keys[keyType].Key
				priv = prevKeys[as][keyType]
			} else {
				var err error
				pub, priv, err = scrypto.GenKeyPair(meta.Algorithm)
				require.NoError(t, err)
			}
			nextKeys[as][keyType] = priv
			meta.Key = pub
			next.PrimaryASes[as].Keys[keyType] = meta
		}
	}
	return nextKeys, prevKeys
}

func signTRC(t *testing.T, next, prev *trc.TRC, nextKeys,
	prevKeys map[addr.AS]map[trc.KeyType][]byte) trc.Signed {

	encoded, err := trc.Encode(next)
	require.NoError(t, err)

	signed := trc.Signed{
		EncodedTRC: encoded,
	}
	for as, keyType := range next.Votes {
		protected := trc.Protected{
			Algorithm:  scrypto.Ed25519,
			Type:       trc.VoteSignature,
			KeyType:    keyType,
			KeyVersion: prev.PrimaryASes[as].Keys[keyType].KeyVersion,
			AS:         as,
		}
		encProtected, err := trc.EncodeProtected(protected)
		require.NoError(t, err)

		sig, err := scrypto.Sign(trc.SigInput(encProtected, encoded), prevKeys[as][keyType],
			scrypto.Ed25519)
		require.NoError(t, err)

		signed.Signatures = append(signed.Signatures, trc.Signature{
			EncodedProtected: encProtected,
			Signature:        sig,
		})
	}
	for as, pops := range next.ProofOfPossession {
		for _, keyType := range pops {
			protected := trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.POPSignature,
				KeyType:    keyType,
				KeyVersion: next.PrimaryASes[as].Keys[keyType].KeyVersion,
				AS:         as,
			}
			encProtected, err := trc.EncodeProtected(protected)
			require.NoError(t, err)

			sig, err := scrypto.Sign(trc.SigInput(encProtected, encoded),
				nextKeys[as][protected.KeyType], scrypto.Ed25519)
			require.NoError(t, err)

			signed.Signatures = append(signed.Signatures, trc.Signature{
				EncodedProtected: encProtected,
				Signature:        sig,
			})
		}
	}
	return signed
}

func union(tests ...map[string]verifyTestCase) map[string]verifyTestCase {
	m := make(map[string]verifyTestCase)
	for _, test := range tests {
		for k, v := range test {
			m[k] = v
		}
	}
	return m
}
