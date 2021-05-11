// Copyright 2020 Anapaya Systems
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

package cppki_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	a110 = xtest.MustParseAS("ff00:0:110")
	a120 = xtest.MustParseAS("ff00:0:120")
)

func TestTRCValidateInvariant(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	testCases := map[string]struct {
		trc func() *cppki.TRC
		err error
	}{
		"valid": {
			trc: func() *cppki.TRC {
				return newBaseTRC(t)
			},
		},
		"invalid version": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Version = 2
				return trc
			},
			err: cppki.ErrInvalidTRCVersion,
		},
		"invalid ID": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.ID.ISD = 0
				return trc
			},
			err: cppki.ErrInvalidID,
		},
		"invalid validity period": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Validity.NotAfter = trc.Validity.NotBefore
				return trc
			},
			err: cppki.ErrInvalidValidityPeriod,
		},
		"non-zero grace on base": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.GracePeriod = 10 * time.Second
				return trc
			},
			err: cppki.ErrGracePeriodNonZero,
		},
		"votes on base": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Votes = []int{1}
				return trc
			},
			err: cppki.ErrVotesOnBaseTRC,
		},
		"quorum outside range": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Quorum = 4242
				return trc
			},
			err: cppki.ErrInvalidQuorumSize,
		},
		"invalid core ASes": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.CoreASes = nil
				return trc
			},
			err: cppki.ErrNoASes,
		},
		"invalid authoritative ASes": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.AuthoritativeASes = append(trc.AuthoritativeASes, 0)
				return trc
			},
			err: cppki.ErrWildcardAS,
		},
		"invalid cert type, unknown": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				cert := loadCert(t, "./testdata/sensitive-voting.crt")
				cert.UnknownExtKeyUsage = nil
				trc.Certificates = append(trc.Certificates, cert)
				return trc
			},
			err: cppki.ErrUnclassifiedCertificate,
		},
		"invalid cert type, as": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Certificates = append(trc.Certificates, loadCert(t, "./testdata/cp-as.crt"))
				return trc
			},
			err: cppki.ErrInvalidCertType,
		},
		"not enough regular": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Certificates = []*x509.Certificate{
					loadCert(t, "./testdata/sensitive-voting.crt")}
				return trc
			},
			err: cppki.ErrNotEnoughVoters,
		},
		"not enough sensitive": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Certificates = []*x509.Certificate{loadCert(t, "./testdata/regular-voting.crt")}
				return trc
			},
			err: cppki.ErrNotEnoughVoters,
		},
		"other ISD": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.ID.ISD = 42
				return trc
			},
			err: cppki.ErrCertForOtherISD,
		},
		"validity not covered": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Validity.NotBefore = time.Unix(0, 0)
				return trc
			},
			err: cppki.ErrTRCValidityNotCovered,
		},
		"duplicate issuer/serial": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				trc.Certificates = append(trc.Certificates, trc.Certificates...)
				return trc
			},
			err: cppki.ErrDuplicate,
		},
		"duplicate subject": {
			trc: func() *cppki.TRC {
				trc := newBaseTRC(t)
				reg := loadCert(t, "./testdata/regular-voting.crt")
				reg.Issuer.CommonName = "some other issuer"
				trc.Certificates = append(trc.Certificates, reg)
				return trc
			},
			err: cppki.ErrDuplicate,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.trc().Validate()
			xtest.AssertErrorsIs(t, err, tc.err)
		})
	}
}

// Position in TRC certificate list, dictated testcrypto.
const (
	Root110 = iota
	Regular110
	Sensitive110
	Root120
	Regular120
	Sensitive120
	Root130
	Regular130
	Sensitive130
)

func TestTRCValidateUpdate(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}
	testCases := map[string]struct {
		TRCs         func(t *testing.T) (pred, succ *cppki.TRC)
		Update       func(t *testing.T) cppki.Update
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid regular": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")

				return cppki.Update{
					Type: cppki.RegularUpdate,
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Regular110],
						pred.TRC.Certificates[Regular120],
						pred.TRC.Certificates[Regular130],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"valid regular, exact quorum": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = []int{Regular110, Regular120}
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				return cppki.Update{
					Type: cppki.RegularUpdate,
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Regular110],
						pred.TRC.Certificates[Regular120],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"valid regular, changed voter": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Regular110].Raw[0] ^= 0xFF
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Regular110].Raw[0] ^= 0xFF

				return cppki.Update{
					Type: cppki.RegularUpdate,
					NewVoters: []*x509.Certificate{
						succ.TRC.Certificates[Regular110],
					},
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Regular110],
						pred.TRC.Certificates[Regular120],
						pred.TRC.Certificates[Regular130],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"valid regular, changed root": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Root110].Raw[0] ^= 0xFF
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Root110].Raw[0] ^= 0xFF

				return cppki.Update{
					Type: cppki.RegularUpdate,
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Regular110],
						pred.TRC.Certificates[Regular120],
						pred.TRC.Certificates[Regular130],
					},
					RootAcknowledgments: []*x509.Certificate{
						pred.TRC.Certificates[Root110],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"valid sensitive": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = []int{Sensitive110, Sensitive120, Sensitive130}
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				return cppki.Update{
					Type: cppki.SensitiveUpdate,
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Sensitive110],
						pred.TRC.Certificates[Sensitive120],
						pred.TRC.Certificates[Sensitive130],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"valid sensitive, change all the things": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = []int{Sensitive120, Sensitive130}
				succ.TRC.Certificates[Sensitive110].Raw[0] ^= 0xFF
				succ.TRC.Certificates[Regular110].Raw[0] ^= 0xFF
				succ.TRC.Quorum = 3

				// Replace voter
				succ.TRC.Certificates[Sensitive120].Subject.CommonName += "fresh, ya"

				// Replace root
				succ.TRC.Certificates[Root110].Subject.CommonName += "fresh, ya"

				// Remove root
				succ.TRC.Certificates = succ.TRC.Certificates[:9]

				succ.TRC.CoreASes = append(succ.TRC.CoreASes, xtest.MustParseAS("ff00:0:119"))
				succ.TRC.AuthoritativeASes = succ.TRC.CoreASes

				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Sensitive110].Raw[0] ^= 0xFF
				succ.TRC.Certificates[Regular110].Raw[0] ^= 0xFF
				succ.TRC.Certificates[Sensitive120].Subject.CommonName += "fresh, ya"

				return cppki.Update{
					Type: cppki.SensitiveUpdate,
					NewVoters: []*x509.Certificate{
						succ.TRC.Certificates[Sensitive110],
						succ.TRC.Certificates[Sensitive120],
						succ.TRC.Certificates[Regular110],
					},
					Votes: []*x509.Certificate{
						pred.TRC.Certificates[Sensitive120],
						pred.TRC.Certificates[Sensitive130],
					},
				}
			},
			ErrAssertion: assert.NoError,
		},
		"nil predecessor": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				return nil, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"different ISD": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				pred.TRC.ID.ISD = 2
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"non-increment": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				pred.TRC.ID.Serial = 2
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"different base": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				pred.TRC.ID.Base = 2
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"trust reset changes": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				pred.TRC.NoTrustReset = !pred.TRC.NoTrustReset
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"quorum unmet": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = []int{1}
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, quorum changed": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Quorum++
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, core ASes rotated": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				l := len(succ.TRC.CoreASes)
				succ.TRC.CoreASes = append(succ.TRC.CoreASes[l-1:], succ.TRC.CoreASes[:l-1]...)
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, core ASes different": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.CoreASes = append(succ.TRC.CoreASes, xtest.MustParseAS("ff00:0:119"))
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, authoritative ASes rotated": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				l := len(succ.TRC.AuthoritativeASes)
				succ.TRC.AuthoritativeASes = append(succ.TRC.AuthoritativeASes[l-1:],
					succ.TRC.AuthoritativeASes[:l-1]...)
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, authoritative ASes different": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.AuthoritativeASes = append(succ.TRC.AuthoritativeASes,
					xtest.MustParseAS("ff00:0:119"))
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, sensitive modified": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Sensitive110].Raw[0] ^= 0xFF
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, sensitive replaced": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				c, err := x509.ParseCertificate(append([]byte{},
					succ.TRC.Certificates[Sensitive110].Raw...))
				require.NoError(t, err)
				c.Subject.CommonName += "fresh, ya"
				succ.TRC.Certificates[Sensitive110] = c
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, sensitive removed": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates = succ.TRC.Certificates[1:]
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, root replaced": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				c, err := x509.ParseCertificate(append([]byte{},
					succ.TRC.Certificates[Root110].Raw...))
				require.NoError(t, err)
				c.Subject.CommonName += "fresh, ya"
				succ.TRC.Certificates[Root110] = c
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, root removed": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates = append(succ.TRC.Certificates[:2],
					succ.TRC.Certificates[3:]...)
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, regular replaced": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				c, err := x509.ParseCertificate(append([]byte{},
					succ.TRC.Certificates[Regular110].Raw...))
				require.NoError(t, err)
				c.Subject.CommonName += "fresh, ya"
				succ.TRC.Certificates[Regular110] = c
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, regular removed": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates = append(succ.TRC.Certificates[:1],
					succ.TRC.Certificates[2:]...)
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, changed voter does not vote": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Certificates[Regular110].Raw[0] ^= 0xFF
				succ.TRC.Votes = []int{4, 7}
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"regular update, vote by sensitive": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = append(succ.TRC.Votes, 0)
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
		"sensitive update, vote by regular": {
			TRCs: func(t *testing.T) (*cppki.TRC, *cppki.TRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S1.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ.TRC.Votes = []int{0, 3, 6, 2}
				return &pred.TRC, &succ.TRC
			},
			Update: func(t *testing.T) cppki.Update {
				return cppki.Update{}
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pred, succ := tc.TRCs(t)
			update, err := succ.ValidateUpdate(pred)
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			expected := tc.Update(t)
			assert.Equal(t, expected.Type, update.Type)
			assert.ElementsMatch(t, expected.NewVoters, update.NewVoters)
			assert.ElementsMatch(t, expected.RootAcknowledgments, update.RootAcknowledgments)
			assert.ElementsMatch(t, expected.Votes, update.Votes)

		})
	}
}

func newBaseTRC(t *testing.T) *cppki.TRC {
	cert := loadCert(t, "./testdata/regular-voting.crt")
	trc := &cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    1,
			Base:   1,
			Serial: 1,
		},
		Validity: cppki.Validity{
			NotBefore: cert.NotBefore.Add(time.Hour),
			NotAfter:  cert.NotAfter.Add(-time.Hour),
		},
		GracePeriod:       0,
		NoTrustReset:      false,
		Votes:             nil,
		Quorum:            1,
		CoreASes:          []addr.AS{a110, a120},
		AuthoritativeASes: []addr.AS{a110},
		Description:       "This is a base TRC",
		Certificates: []*x509.Certificate{
			loadCert(t, "./testdata/sensitive-voting.crt"),
			loadCert(t, "./testdata/regular-voting.crt"),
			loadCert(t, "./testdata/cp-root.crt"),
		},
	}
	return trc
}
