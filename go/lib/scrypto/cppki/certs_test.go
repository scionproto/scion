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
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
)

var update = flag.Bool("update", false, "set to true to regenerate certificate files")

func updateCert(goldenCert string) ([]byte, error) {
	dir, cleanF := xtest.MustTempDir("", "safedir")
	defer cleanF()

	cmd := exec.Command("sh", "-c", "./testdata/update_certs.sh")
	cmd.Env = []string{
		"SAFEDIR=" + dir,
		"STARTDATE=20200624120000Z",
		"ENDDATE=20250624120000Z",
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, err
	}

	src, dst := filepath.Join(dir, goldenCert), filepath.Join("./testdata", goldenCert)
	command := fmt.Sprintf("mv %s %s", src, dst)
	return exec.Command("sh", "-c", command).CombinedOutput()
}

type testCase struct {
	modify    func(*x509.Certificate) *x509.Certificate
	assertErr assert.ErrorAssertionFunc
}

var generalCases = map[string]testCase{
	"nil content": {
		modify:    func(c *x509.Certificate) *x509.Certificate { return nil },
		assertErr: assert.Error,
	},
	"valid": {
		modify:    func(c *x509.Certificate) *x509.Certificate { return c },
		assertErr: assert.NoError,
	},
	"invalid version": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.Version = 2
			return c
		},
		assertErr: assert.Error,
	},
	"invalid no serial number": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.SerialNumber = nil
			return c
		},
		assertErr: assert.Error,
	},
	"invalid signature algo": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.SignatureAlgorithm = x509.DSAWithSHA1
			return c
		},
		assertErr: assert.Error,
	},
	"invalid no SubjectKeyId": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.SubjectKeyId = []byte{}
			return c
		},
		assertErr: assert.Error,
	},
	"invalid subjectKeyId is critical": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			m := []pkix.Extension{}
			for _, v := range c.Extensions {
				if v.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}) {
					v.Critical = true
				}
				m = append(m, v)
			}
			c.Extensions = m
			return c
		},
		assertErr: assert.Error,
	},
	"invalid if authorityKeyId exist and is critical": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			m := []pkix.Extension{}
			oid := asn1.ObjectIdentifier{2, 5, 29, 35}
			found := false
			for _, v := range c.Extensions {
				if v.Id.Equal(oid) {
					v.Critical = true
					found = true
				}
				m = append(m, v)
			}
			if !found {
				m = append(m, pkix.Extension{Id: oid, Critical: true})
			}
			c.Extensions = m
			return c
		},
		assertErr: assert.Error,
	},
}

var commonCACases = map[string]testCase{
	"invalid keyUsage no CertSign": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage &^ x509.KeyUsageCertSign
			c.KeyUsage = t
			return c
		},
		assertErr: assert.Error,
	},
	"valid keyUsage CRLSign": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage | x509.KeyUsageCRLSign
			c.KeyUsage = t
			return c
		},
		assertErr: assert.NoError,
	},
	"valid keyUsage no CRLSign": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage &^ x509.KeyUsageCRLSign
			c.KeyUsage = t
			return c
		},
		assertErr: assert.NoError,
	},
	"invalid digitalSignature is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage | x509.KeyUsageDigitalSignature
			c.KeyUsage = t
			return c
		},
		assertErr: assert.Error,
	},
	"invalid ExtKeyUsage id-kp-serverAuth is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			return c
		},
		assertErr: assert.Error,
	},
	"invalid ExtKeyUsage id-kp-clientAuth is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			return c
		},
		assertErr: assert.Error,
	},
	"invalid BasicConstraints no CA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.IsCA = false
			return c
		},
		assertErr: assert.Error,
	},
	"invalid BasicConstraints not critical": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			m := []pkix.Extension{}
			for _, v := range c.Extensions {
				// .19 is basicConstraints
				if v.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
					v.Critical = false
				}
				m = append(m, v)
			}
			c.Extensions = m
			return c
		},
		assertErr: assert.Error,
	},
	"invalid no valid issuer IA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			v := []pkix.AttributeTypeAndValue{
				{Type: cppki.OIDNameIA},
			}
			for _, name := range c.Issuer.Names {
				if name.Type.Equal(cppki.OIDNameIA) {
					continue
				}
				v = append(v, name)
			}
			c.Issuer.Names = v
			return c
		},
		assertErr: assert.Error,
	},
	"invalid missing issuer IA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			for i, name := range c.Issuer.Names {
				if name.Type.Equal(cppki.OIDNameIA) {
					c.Issuer.Names = append(c.Issuer.Names[:i], c.Issuer.Names[i+1:]...)
				}
			}
			return c
		},
		assertErr: assert.Error,
	},
	"invalid no valid subject IA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			v := []pkix.AttributeTypeAndValue{
				{Type: cppki.OIDNameIA},
			}
			for _, name := range c.Subject.Names {
				if name.Type.Equal(cppki.OIDNameIA) {
					continue
				}
				v = append(v, name)
			}
			c.Subject.Names = v
			return c
		},
		assertErr: assert.Error,
	},
	"invalid missing subject IA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			for i, name := range c.Subject.Names {
				if name.Type.Equal(cppki.OIDNameIA) {
					c.Subject.Names = append(c.Subject.Names[:i], c.Subject.Names[i+1:]...)
				}
			}
			return c
		},
		assertErr: assert.Error,
	},
	"invalid invalid subject IA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			for i, name := range c.Subject.Names {
				if name.Type.Equal(cppki.OIDNameIA) {
					name.Value = "invalid"
					c.Subject.Names[i] = name
				}
			}
			return c
		},
		assertErr: assert.Error,
	},
}

func TestValidateRoot(t *testing.T) {
	goldenCert := "cp-root.crt"
	testF := cppki.ValidateRoot

	if *update {
		out, err := updateCert(goldenCert)
		require.NoError(t, err, string(out))
		t.Logf("git add ./testdata/%s", goldenCert)
		return
	}
	testCases := map[string]testCase{
		"invalid should be self signed": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.AuthorityKeyId = []byte("other")
				return c
			},
			assertErr: assert.Error,
		},
		"invalid BasicConstraints MaxPathLen": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.MaxPathLen = 0
				return c
			},
			assertErr: assert.Error,
		},
		"invalid ExtKeyUsage id-kp-root is not set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				m := []asn1.ObjectIdentifier{}
				for _, v := range c.UnknownExtKeyUsage {
					if v.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 3, 3}) {
						continue
					}
					m = append(m, v)
				}
				c.UnknownExtKeyUsage = m
				return c
			},
			assertErr: assert.Error,
		},
	}

	for k, v := range generalCases {
		testCases[k] = v
	}

	for k, v := range commonCACases {
		testCases[k] = v
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", goldenCert))
			require.NoError(t, err)
			input := tc.modify(validCert[0])
			err = testF(input)
			tc.assertErr(t, err)
		})
	}

}

func TestValidateCA(t *testing.T) {
	testF := cppki.ValidateCA
	goldenCert := "cp-ca.crt"

	if *update {
		out, err := updateCert(goldenCert)
		require.NoError(t, err, string(out))
		t.Logf("git add ./testdata/%s", goldenCert)
		return
	}

	testCases := map[string]testCase{
		"invalid BasicConstraints MaxPathLen": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.MaxPathLen = 1
				return c
			},
			assertErr: assert.Error,
		},
		"invalid AuthorityKeyId is no present": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.AuthorityKeyId = []byte{}
				return c
			},
			assertErr: assert.Error,
		},
	}

	for k, v := range generalCases {
		testCases[k] = v
	}
	for k, v := range commonCACases {
		testCases[k] = v
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", goldenCert))
			require.NoError(t, err)
			input := tc.modify(validCert[0])
			err = testF(input)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateAS(t *testing.T) {
	testF := cppki.ValidateAS
	goldenCert := "cp-as.crt"

	if *update {
		out, err := updateCert(goldenCert)
		require.NoError(t, err, string(out))
		t.Logf("git add ./testdata/%s", goldenCert)
		return
	}

	testCases := map[string]testCase{
		"invalid keyUsage CertSign is set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				t := c.KeyUsage | x509.KeyUsageCertSign
				c.KeyUsage = t
				return c
			},
			assertErr: assert.Error,
		},
		"invalid keyUsage no digitalSignature": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				t := c.KeyUsage &^ x509.KeyUsageDigitalSignature
				c.KeyUsage = t
				return c
			},
			assertErr: assert.Error,
		},
		"invalid ExtKeyUsage id-kp-timeStamping is not set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				m := []x509.ExtKeyUsage{}
				for _, v := range c.ExtKeyUsage {
					if v == x509.ExtKeyUsageTimeStamping {
						continue
					}
					m = append(m, v)
				}
				c.ExtKeyUsage = m
				return c
			},
			assertErr: assert.Error,
		},
		"invalid BasicConstraints is present": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.BasicConstraintsValid = true
				c.IsCA = true
				add := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}}
				c.Extensions = append(c.Extensions, add)
				return c
			},
			assertErr: assert.Error,
		},
		"invalid no valid IA": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				v := []pkix.AttributeTypeAndValue{
					{Type: cppki.OIDNameIA},
				}
				for _, name := range c.Issuer.Names {
					if name.Type.Equal(cppki.OIDNameIA) {
						continue
					}
					v = append(v, name)
				}
				c.Issuer.Names = v
				return c
			},
			assertErr: assert.Error,
		},
		"invalid AuthorityKeyId is no present": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.AuthorityKeyId = []byte{}
				return c
			},
			assertErr: assert.Error,
		},
	}

	for k, v := range generalCases {
		testCases[k] = v
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", goldenCert))
			require.NoError(t, err)
			input := tc.modify(validCert[0])
			err = testF(input)
			tc.assertErr(t, err)
		})
	}
}

var commonVotingCases = map[string]testCase{
	"invalid should be self signed": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.AuthorityKeyId = []byte("other")
			return c
		},
		assertErr: assert.Error,
	},
	"invalid keyUsage CertSign is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage | x509.KeyUsageCertSign
			c.KeyUsage = t
			return c
		},
		assertErr: assert.Error,
	},
	"invalid keyUsage digitalSignature is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			t := c.KeyUsage | x509.KeyUsageDigitalSignature
			c.KeyUsage = t
			return c
		},
		assertErr: assert.Error,
	},
	"invalid ExtKeyUsage id-kp-timeStamping is not set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			m := []x509.ExtKeyUsage{}
			for _, v := range c.ExtKeyUsage {
				if v == x509.ExtKeyUsageTimeStamping {
					continue
				}
				m = append(m, v)
			}
			c.ExtKeyUsage = m
			return c
		},
		assertErr: assert.Error,
	},
	"invalid cert is a CA": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.BasicConstraintsValid = true
			c.IsCA = true
			return c
		},
		assertErr: assert.Error,
	},
	"invalid ExtKeyUsage id-kp-serverAuth is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			return c
		},
		assertErr: assert.Error,
	},
	"invalid ExtKeyUsage id-kp-clientAuth is set": {
		modify: func(c *x509.Certificate) *x509.Certificate {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			return c
		},
		assertErr: assert.Error,
	},
}

func TestValidateRegular(t *testing.T) {
	goldenCert := "regular-voting.crt"
	testF := cppki.ValidateRegular

	if *update {
		out, err := updateCert(goldenCert)
		require.NoError(t, err, out)
		t.Logf("git add ./testdata/%s", goldenCert)
		return
	}
	testCases := map[string]testCase{
		"invalid ExtKeyUsage id-kp-regular is not set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				m := []asn1.ObjectIdentifier{}
				for _, v := range c.UnknownExtKeyUsage {
					if v.Equal(cppki.OIDExtKeyUsageRegular) {
						continue
					}
					m = append(m, v)
				}
				c.UnknownExtKeyUsage = m
				return c
			},
			assertErr: assert.Error,
		},
		"multiple ExtKeyUsage set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, cppki.OIDExtKeyUsageSensitive)
				return c
			},
			assertErr: assert.Error,
		},
	}

	for k, v := range generalCases {
		testCases[k] = v
	}

	for k, v := range commonVotingCases {
		testCases[k] = v
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", goldenCert))
			require.NoError(t, err)
			input := tc.modify(validCert[0])
			err = testF(input)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateSensitive(t *testing.T) {
	goldenCert := "sensitive-voting.crt"
	testF := cppki.ValidateSensitive

	if *update {
		out, err := updateCert(goldenCert)
		require.NoError(t, err, out)
		t.Logf("git add ./testdata/%s", goldenCert)
		return
	}
	testCases := map[string]testCase{
		"invalid ExtKeyUsage id-kp-sensitive is not set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				m := []asn1.ObjectIdentifier{}
				for _, v := range c.UnknownExtKeyUsage {
					if v.Equal(cppki.OIDExtKeyUsageSensitive) {
						continue
					}
					m = append(m, v)
				}
				c.UnknownExtKeyUsage = m
				return c
			},
			assertErr: assert.Error,
		},
		"multiple ExtKeyUsage set": {
			modify: func(c *x509.Certificate) *x509.Certificate {
				c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, cppki.OIDExtKeyUsageRegular)
				return c
			},
			assertErr: assert.Error,
		},
	}

	for k, v := range generalCases {
		testCases[k] = v
	}

	for k, v := range commonVotingCases {
		testCases[k] = v
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", goldenCert))
			require.NoError(t, err)
			input := tc.modify(validCert[0])
			err = testF(input)
			tc.assertErr(t, err)
		})
	}
}

func TestValidateCert(t *testing.T) {
	testCases := map[string]struct {
		CertFile     string
		Modify       func(*x509.Certificate) *x509.Certificate
		ExpectedType cppki.CertType
		AssertErr    assert.ErrorAssertionFunc
	}{
		"as cert": {
			CertFile:     "cp-as.crt",
			ExpectedType: cppki.AS,
			AssertErr:    assert.NoError,
		},
		"ca cert": {
			CertFile:     "cp-ca.crt",
			ExpectedType: cppki.CA,
			AssertErr:    assert.NoError,
		},
		"root cert": {
			CertFile:     "cp-root.crt",
			ExpectedType: cppki.Root,
			AssertErr:    assert.NoError,
		},
		"regular voting cert": {
			CertFile:     "regular-voting.crt",
			ExpectedType: cppki.Regular,
			AssertErr:    assert.NoError,
		},
		"sensitive voting cert": {
			CertFile:     "sensitive-voting.crt",
			ExpectedType: cppki.Sensitive,
			AssertErr:    assert.NoError,
		},
		"nil cert": {
			CertFile:     "sensitive-voting.crt",
			Modify:       func(*x509.Certificate) *x509.Certificate { return nil },
			ExpectedType: cppki.Invalid,
			AssertErr:    assert.Error,
		},
		"invalid cert": {
			CertFile: "sensitive-voting.crt",
			Modify: func(c *x509.Certificate) *x509.Certificate {
				c.UnknownExtKeyUsage = nil
				return c
			},
			ExpectedType: cppki.Invalid,
			AssertErr:    assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validCert, err := cppki.ReadPEMCerts(filepath.Join("./testdata", tc.CertFile))
			require.NoError(t, err)
			input := validCert[0]
			if tc.Modify != nil {
				input = tc.Modify(input)
			}
			ct, err := cppki.ValidateCert(input)
			tc.AssertErr(t, err)
			assert.Equal(t, tc.ExpectedType, ct)
		})
	}
}

func TestValidateChain(t *testing.T) {
	validChainFile := "./testdata/verifychain/ISD1-ASff00_0_110.pem"
	testCases := map[string]struct {
		modify    func([]*x509.Certificate) []*x509.Certificate
		assertErr assert.ErrorAssertionFunc
	}{
		"invalid legth less than two": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				return c[:1]
			},
			assertErr: assert.Error,
		},
		"invalid legth more than two": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c = append(c, c[0])
				return c
			},
			assertErr: assert.Error,
		},
		"invalid first cert": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c[0].KeyUsage = 0
				return c
			},
			assertErr: assert.Error,
		},
		"invalid type of first": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c[0] = c[1]
				return c
			},
			assertErr: assert.Error,
		},
		"invalid second cert": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c[1].KeyUsage = 0
				return c
			},
			assertErr: assert.Error,
		},
		"invalid type of second": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c[1] = c[0]
				return c
			},
			assertErr: assert.Error,
		},
		"invalid period": {
			modify: func(c []*x509.Certificate) []*x509.Certificate {
				c[1].NotBefore = c[0].NotBefore.Add(time.Minute)
				return c
			},
			assertErr: assert.Error,
		},
		"valid": {
			modify:    func(c []*x509.Certificate) []*x509.Certificate { return c },
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			chain, err := cppki.ReadPEMCerts(validChainFile)
			require.NoError(t, err)
			input := tc.modify(chain)
			tc.assertErr(t, cppki.ValidateChain(input))
		})
	}
}

func TestVerifyChain(t *testing.T) {
	// testadata files generated with scion-pki:
	/*
		scion-pki testcrypto -t topology/default.topo -o gen
		cp gen/ISD1/ISD1-B1-S1.trc go/lib/scrypto/cppki/testdata/verifychain
		cp gen/ISD2/ISD2-B1-S1.trc go/lib/scrypto/cppki/testdata/verifychain
		cp gen/ISD1/ASff00_0_111/certs/ISD1-ASff00_0_111.pem \
			go/lib/scrypto/cppki/testdata/verifychain
		cp gen/ISD1/ASff00_0_110/certs/ISD1-ASff00_0_110.pem \
			go/lib/scrypto/cppki/testdata/verifychain
		cp gen/ISD2/ASff00_0_210/certs/ISD2-ASff00_0_210.pem \
			go/lib/scrypto/cppki/testdata/verifychain
	*/

	trc := loadTRC(t, "testdata/verifychain/ISD1-B1-S1.trc")
	trc2 := loadTRC(t, "testdata/verifychain/ISD2-B1-S1.trc")
	clientChain := xtest.LoadChain(t, "testdata/verifychain/ISD1-ASff00_0_111.pem")
	issuerChain := xtest.LoadChain(t, "testdata/verifychain/ISD1-ASff00_0_110.pem")
	isd2Chain := xtest.LoadChain(t, "testdata/verifychain/ISD2-ASff00_0_210.pem")
	invalidIntermediate := append([]*x509.Certificate{}, clientChain[0], isd2Chain[1])
	invalidTRC := trc
	invalidTRC.TRC.Certificates = append(trc.TRC.Certificates, &x509.Certificate{})

	testCases := map[string]struct {
		chain     []*x509.Certificate
		opts      cppki.VerifyOptions
		assertErr assert.ErrorAssertionFunc
	}{
		"valid client": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.NoError,
		},
		"valid issuer": {
			chain: issuerChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: issuerChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.NoError,
		},
		"missing TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"empty TRC slice": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"zero TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{{}},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"empty roots in TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{{Quorum: 2}},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"invalid chain": {
			chain: clientChain[:1],
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"invalid TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&invalidTRC.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"valid and valid TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC, &trc.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.NoError,
		},
		"valid and invalid TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC, &invalidTRC.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.NoError,
		},
		"invalid and valid TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&invalidTRC.TRC, &trc.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.NoError,
		},
		"invalid and invalid TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&invalidTRC.TRC, &invalidTRC.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"invalid time before": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(-time.Hour),
			},
			assertErr: assert.Error,
		},
		"invalid time after": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: clientChain[0].NotAfter.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"wrong TRC": {
			chain: clientChain,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc2.TRC},
				CurrentTime: clientChain[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
		"invalid intermediate": {
			chain: invalidIntermediate,
			opts: cppki.VerifyOptions{
				TRC:         []*cppki.TRC{&trc.TRC},
				CurrentTime: invalidIntermediate[0].NotBefore.Add(time.Hour),
			},
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := cppki.VerifyChain(tc.chain, tc.opts)
			tc.assertErr(t, err)
		})
	}
}

func loadTRC(t *testing.T, file string) cppki.SignedTRC {
	t.Helper()
	rawTRC, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	trc, err := cppki.DecodeSignedTRC(rawTRC)
	require.NoError(t, err)
	return trc
}
