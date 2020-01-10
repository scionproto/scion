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

package cert_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/util"
)

func TestASVerifierVerify(t *testing.T) {
	tests := map[string]struct {
		Modify         func(as *cert.AS, issuer *cert.Issuer, p *cert.ProtectedAS)
		ModifySigned   func(signed *cert.SignedAS)
		ExpectedErrMsg common.ErrMsg
	}{
		"valid": {
			Modify:       func(*cert.AS, *cert.Issuer, *cert.ProtectedAS) {},
			ModifySigned: func(*cert.SignedAS) {},
		},
		"unparsable protected": {
			Modify: func(*cert.AS, *cert.Issuer, *cert.ProtectedAS) {},
			ModifySigned: func(signed *cert.SignedAS) {
				signed.EncodedProtected = "!"
			},
			ExpectedErrMsg: "illegal base64 data at input byte 0",
		},
		"Issuer subject mismatch": {
			Modify: func(_ *cert.AS, issuer *cert.Issuer, _ *cert.ProtectedAS) {
				issuer.Subject.A++
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrUnexpectedIssuer,
		},
		"Issuer version mismatch": {
			Modify: func(_ *cert.AS, issuer *cert.Issuer, _ *cert.ProtectedAS) {
				issuer.Version++
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrUnexpectedCertificateVersion,
		},
		"Validity not covered": {
			Modify: func(cert *cert.AS, issuer *cert.Issuer, _ *cert.ProtectedAS) {
				issuer.Validity.NotBefore.Time = cert.Validity.NotBefore.Add(time.Second)
				issuer.Validity.NotAfter.Time = cert.Validity.NotAfter.Add(-time.Second)
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrASValidityNotCovered,
		},
		"Protected.IA mismatch": {
			Modify: func(_ *cert.AS, _ *cert.Issuer, p *cert.ProtectedAS) {
				p.IA.A++
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrInvalidProtected,
		},
		"Protected.Algorithm mismatch": {
			Modify: func(_ *cert.AS, _ *cert.Issuer, p *cert.ProtectedAS) {
				p.Algorithm = "other"
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrInvalidProtected,
		},
		"Protected.CertificateVersion mismatch": {
			Modify: func(_ *cert.AS, _ *cert.Issuer, p *cert.ProtectedAS) {
				p.CertificateVersion++
			},
			ModifySigned:   func(*cert.SignedAS) {},
			ExpectedErrMsg: cert.ErrInvalidProtected,
		},
		"Mangled signature": {
			Modify: func(*cert.AS, *cert.Issuer, *cert.ProtectedAS) {},
			ModifySigned: func(signed *cert.SignedAS) {
				signed.Signature[0] ^= 0xFF
			},
			ExpectedErrMsg: "Signature verification failed",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			as := newASCert(time.Now())
			issuer := newIssuerCert(time.Now())
			pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
			require.NoError(t, err)

			meta := issuer.Keys[cert.IssuingKey]
			meta.Key = pub
			issuer.Keys[cert.IssuingKey] = meta

			protected := cert.ProtectedAS{
				Algorithm:          meta.Algorithm,
				CertificateVersion: issuer.Version,
				IA:                 issuer.Subject,
			}
			test.Modify(&as, &issuer, &protected)
			packedAS, err := cert.EncodeAS(&as)
			require.NoError(t, err)
			packedProtected, err := cert.EncodeProtectedAS(protected)
			require.NoError(t, err)
			signed := cert.SignedAS{
				Encoded:          packedAS,
				EncodedProtected: packedProtected,
			}
			signed.Signature, err = scrypto.Sign(signed.SigInput(), priv, meta.Algorithm)
			require.NoError(t, err)
			test.ModifySigned(&signed)

			v := cert.ASVerifier{
				AS:       &as,
				Issuer:   &issuer,
				SignedAS: &signed,
			}
			err = v.Verify()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestIssuerVerifierVerify(t *testing.T) {
	tests := map[string]struct {
		Modify         func(issuer *cert.Issuer, trc *trc.TRC, p *cert.ProtectedIssuer)
		ModifySigned   func(signed *cert.SignedIssuer)
		ExpectedErrMsg string
	}{
		"valid": {
			Modify:       func(*cert.Issuer, *trc.TRC, *cert.ProtectedIssuer) {},
			ModifySigned: func(*cert.SignedIssuer) {},
		},
		"unparsable protected": {
			Modify: func(*cert.Issuer, *trc.TRC, *cert.ProtectedIssuer) {},
			ModifySigned: func(signed *cert.SignedIssuer) {
				signed.EncodedProtected = "!"
			},
			ExpectedErrMsg: "illegal base64 data at input byte 0",
		},
		"Non-primary": {
			Modify: func(issuer *cert.Issuer, trc *trc.TRC, _ *cert.ProtectedIssuer) {
				delete(trc.PrimaryASes, issuer.Subject.A)
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrNotIssuing.Error(),
		},

		"Non-issuing primary": {
			Modify: func(issuer *cert.Issuer, trcObj *trc.TRC, _ *cert.ProtectedIssuer) {
				meta := trcObj.PrimaryASes[issuer.Subject.A]
				meta.Attributes = trc.Attributes{trc.Core}
				trcObj.PrimaryASes[issuer.Subject.A] = meta
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrNotIssuing.Error(),
		},
		"TRC version mismatch": {
			Modify: func(_ *cert.Issuer, trc *trc.TRC, _ *cert.ProtectedIssuer) {
				trc.Version++
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrUnexpectedTRCVersion.Error(),
		},
		"Validity not covered": {
			Modify: func(issuer *cert.Issuer, trc *trc.TRC, _ *cert.ProtectedIssuer) {
				trc.Validity.NotBefore.Time = issuer.Validity.NotBefore.Time.Add(time.Second)
				trc.Validity.NotAfter.Time = issuer.Validity.NotAfter.Time.Add(-time.Second)
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrASValidityNotCovered.Error(),
		},
		"Protected.Algorithm mismatch": {
			Modify: func(_ *cert.Issuer, _ *trc.TRC, p *cert.ProtectedIssuer) {
				p.Algorithm = "other"
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrInvalidProtected.Error(),
		},
		"Protected.TRCVersion mismatch": {
			Modify: func(_ *cert.Issuer, _ *trc.TRC, p *cert.ProtectedIssuer) {
				p.TRCVersion++
			},
			ModifySigned:   func(*cert.SignedIssuer) {},
			ExpectedErrMsg: cert.ErrInvalidProtected.Error(),
		},
		"Mangled signature": {
			Modify: func(*cert.Issuer, *trc.TRC, *cert.ProtectedIssuer) {},
			ModifySigned: func(signed *cert.SignedIssuer) {
				signed.Signature[0] ^= 0xFF
			},
			ExpectedErrMsg: "Signature verification failed",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			issuer := newIssuerCert(time.Now())
			pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
			require.NoError(t, err)
			trc_ := trc.TRC{
				Version: issuer.Issuer.TRCVersion,
				PrimaryASes: trc.PrimaryASes{
					issuer.Subject.A: {
						Attributes: trc.Attributes{trc.Issuing},
						Keys: map[trc.KeyType]scrypto.KeyMeta{
							trc.IssuingGrantKey: {
								Algorithm:  scrypto.Ed25519,
								Key:        pub,
								KeyVersion: 1,
							},
						},
					},
				},
				Validity: &scrypto.Validity{
					NotBefore: util.UnixTime{Time: issuer.Validity.NotBefore.Add(-time.Second)},
					NotAfter:  util.UnixTime{Time: issuer.Validity.NotAfter.Add(time.Second)},
				},
			}

			protected := cert.ProtectedIssuer{
				Algorithm:  scrypto.Ed25519,
				TRCVersion: trc_.Version,
			}
			test.Modify(&issuer, &trc_, &protected)
			packedIssuer, err := cert.EncodeIssuer(&issuer)
			require.NoError(t, err)
			packedProtected, err := cert.EncodeProtectedIssuer(protected)
			require.NoError(t, err)
			signed := cert.SignedIssuer{
				Encoded:          packedIssuer,
				EncodedProtected: packedProtected,
			}
			signed.Signature, err = scrypto.Sign(signed.SigInput(), priv, scrypto.Ed25519)
			require.NoError(t, err)
			test.ModifySigned(&signed)

			v := cert.IssuerVerifier{
				Issuer:       &issuer,
				TRC:          &trc_,
				SignedIssuer: &signed,
			}
			err = v.Verify()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}
