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
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/scrypto/cms/oid"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestUpdateTRCs(t *testing.T) {
	if !*updateNonDeterministic {
		t.Skip("Specify -update-non-deterministic to update TRCs")
	}

	dir := t.TempDir()

	root, err := filepath.Abs("../../../../")
	require.NoError(t, err)

	cmd := exec.Command(filepath.Join(root, "bin/scion-pki"), "testcrypto",
		"--topo", "./testdata/update_trc.topo",
		"--out", dir,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	cmd = exec.Command(filepath.Join(root, "bin/scion-pki"), "testcrypto", "update",
		"--scenario", "re-sign",
		"--out", dir,
	)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	cmd = exec.Command(filepath.Join(root, "bin/scion-pki"), "testcrypto", "update",
		"--scenario", "extend",
		"--out", dir,
	)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	for _, file := range []string{"ISD1-B1-S1.trc", "ISD1-B1-S2.trc", "ISD1-B1-S3.trc"} {
		cmd := exec.Command("mv",
			filepath.Join(dir, "trcs", file),
			filepath.Join("./testdata", file),
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	t.Log("git add ./testdata/ISD1-B1-S*.tc")
}

func TestTRCVerifyUpdate(t *testing.T) {
	if *updateNonDeterministic {
		t.Skip("test crypto is being updated")
	}
	testCases := map[string]struct {
		TRCs         func(t *testing.T) (*cppki.TRC, cppki.SignedTRC)
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				return &pred.TRC, succ
			},
			ErrAssertion: assert.NoError,
		},
		"nil predecessor": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				return nil, succ
			},
			ErrAssertion: assert.Error,
		},
		"missing vote": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")

				succ.SignerInfos = dropInfos(succ.SignerInfos, pred.TRC.Certificates[Regular110])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"missing changed voter": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				succ.SignerInfos = dropInfos(succ.SignerInfos, succ.TRC.Certificates[Regular130])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"missing changed root": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				succ.SignerInfos = dropInfos(succ.SignerInfos, pred.TRC.Certificates[Root130])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"forged vote": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")

				succ.SignerInfos = forgeSig(succ.SignerInfos, pred.TRC.Certificates[Regular110])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"forged changed voter": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				succ.SignerInfos = forgeSig(succ.SignerInfos, succ.TRC.Certificates[Regular130])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"forged changed root": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")
				succ.SignerInfos = forgeSig(succ.SignerInfos, pred.TRC.Certificates[Root130])
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
		"modified contents": {
			TRCs: func(t *testing.T) (*cppki.TRC, cppki.SignedTRC) {
				pred := loadTRC(t, "./testdata/ISD1-B1-S2.trc")
				succ := loadTRC(t, "./testdata/ISD1-B1-S3.trc")

				succ.TRC.Validity.NotBefore = succ.TRC.Validity.NotBefore.Add(time.Second)
				raw, err := succ.TRC.Encode()
				require.NoError(t, err)
				succ.TRC.Raw = raw
				return &pred.TRC, succ
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pred, succ := tc.TRCs(t)
			err := succ.Verify(pred)
			tc.ErrAssertion(t, err)
		})
	}
}

func dropInfos(infos []protocol.SignerInfo, cert *x509.Certificate) []protocol.SignerInfo {
	var cut []protocol.SignerInfo
	for _, info := range infos {
		if _, err := info.FindCertificate([]*x509.Certificate{cert}); err == nil {
			continue
		}
		cut = append(cut, info)
	}
	return cut
}

func forgeSig(infos []protocol.SignerInfo, cert *x509.Certificate) []protocol.SignerInfo {
	var cut []protocol.SignerInfo
	for _, info := range infos {
		if _, err := info.FindCertificate([]*x509.Certificate{cert}); err == nil {
			info.Signature[len(info.Signature)-10] ^= 0xFF
		}
		cut = append(cut, info)
	}
	return cut
}

func TestTRCVerifyBase(t *testing.T) {
	if *updateNonDeterministic {
		t.Skip("test crypto is being updated")
	}
	testCases := map[string]struct {
		SignedTRC    func(t *testing.T) cppki.SignedTRC
		Predecessor  *cppki.TRC
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				return loadSignedTRC(t)
			},
			ErrAssertion: assert.NoError,
		},
		"superfluous signature": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				root := loadCert(t, "./testdata/cp-root.crt")
				sid, err := protocol.NewIssuerAndSerialNumber(root)
				require.NoError(t, err)

				signed.SignerInfos = append(signed.SignerInfos, protocol.SignerInfo{
					Version: 1,
					SID:     sid,
				})
				return signed
			},
			ErrAssertion: assert.NoError,
		},
		"invalid TRC payload": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.TRC.Version = 2
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"malformed signerInfo": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.SignerInfos = append(signed.SignerInfos, protocol.SignerInfo{
					Version: 1,
					SID:     asn1.RawValue{},
				})
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"digest mismatch": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.TRC.Raw[0] ^= 0xFF
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"wrong signature": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.SignerInfos[0].Signature[0] ^= 0xFF
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"invalid hash algorithm": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.SignerInfos[0].DigestAlgorithm.Algorithm = asn1.ObjectIdentifier{}
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"no digest in signed attributes": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				attrs := signed.SignerInfos[0].SignedAttrs
				for i, attr := range attrs {
					if attr.Type.Equal(oid.AttributeMessageDigest) {
						signed.SignerInfos[0].SignedAttrs = append(attrs[:i], attrs[i+1:]...)
						break
					}
				}
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"missing signature": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				signed := loadSignedTRC(t)
				signed.SignerInfos = signed.SignerInfos[:1]
				return signed
			},
			ErrAssertion: assert.Error,
		},
		"non-nil predecessor": {
			SignedTRC: func(t *testing.T) cppki.SignedTRC {
				return loadSignedTRC(t)
			},
			ErrAssertion: assert.Error,
			Predecessor:  &cppki.TRC{},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			signed := tc.SignedTRC(t)
			err := signed.Verify(tc.Predecessor)
			tc.ErrAssertion(t, err)
		})
	}
}

// TestTRCVerifyCompatibility checks the compatibility for TRC verification with
// TRCs that were generated with a go version prior to 1.15.
//
// As of go1.15 marshalling a SET in DER adheres to X690 Section 11.6 and
// produces an ordered set.
// (https://github.com/golang/go/commit/f0cea848679b8f8cdc5f76e1b1e36ebb924a68f8)
func TestTRCVerifyCompatibility(t *testing.T) {
	raw, err := os.ReadFile("./testdata/compatibility/ISD1-B1-S1-pre1.15.trc")
	require.NoError(t, err)
	signed, err := cppki.DecodeSignedTRC(raw)
	require.NoError(t, err)
	err = signed.Verify(nil)
	assert.NoError(t, err)

	raw, err = os.ReadFile("./testdata/compatibility/ISD1-B1-S2-pre1.15.trc")
	require.NoError(t, err)
	signed2, err := cppki.DecodeSignedTRC(raw)
	require.NoError(t, err)
	err = signed2.Verify(&signed.TRC)
	require.NoError(t, err)
}

func loadSignedTRC(t *testing.T) cppki.SignedTRC {
	t.Helper()
	raw, err := os.ReadFile("./testdata/ISD1-B1-S1.trc")
	require.NoError(t, err)
	signed, err := cppki.DecodeSignedTRC(raw)
	require.NoError(t, err)
	return signed
}
