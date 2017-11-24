// Copyright 2017 ETH Zurich
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

package cert

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/ed25519"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

// Interface assertions
var _ fmt.Stringer = (*Certificate)(nil)

var (
	fnLeaf         = "testdata/ISD1-AS10-V1.leaf"
	fnNoIndentLeaf = "testdata/noindent.leaf"

	rawSignature = common.RawBytes{0xdf, 0xa7, 0x61, 0xa1, 0xb5, 0x6c, 0x3c, 0x1b, 0x7a, 0x52,
		0x53, 0x02, 0x66, 0xd9, 0x98, 0x1e, 0x82, 0x89, 0x6e, 0xe4, 0xb7, 0x31, 0xb6, 0x4d,
		0xbe, 0xed, 0xb8, 0x9c, 0x0f, 0xa4, 0xb7, 0xbf, 0x34, 0x6d, 0xfe, 0x19, 0x7a, 0x72,
		0x2b, 0x7a, 0xeb, 0xe7, 0xc6, 0x98, 0x48, 0xc6, 0xe2, 0x37, 0xdb, 0xb7, 0x01, 0xa1,
		0xe0, 0xec, 0x07, 0xe4, 0xe0, 0xd4, 0x4b, 0xd2, 0x3e, 0x7c, 0x04, 0x06}

	rawEncKey = common.RawBytes{0x9c, 0xfd, 0x47, 0x91, 0x9c, 0x24, 0x5b, 0xcb, 0xa3, 0xa9,
		0xe1, 0x0e, 0xf3, 0x64, 0x5b, 0xf5, 0xc3, 0x7a, 0x01, 0x5a, 0x85, 0x3c, 0xed, 0x54,
		0x22, 0x2c, 0xa9, 0x75, 0x95, 0x3e, 0x74, 0x72}

	rawSigKey = common.RawBytes{0xe5, 0x86, 0x28, 0xfc, 0x38, 0xe8, 0xaf, 0xc2, 0xa8, 0x50,
		0xf6, 0xdc, 0x1b, 0xcf, 0x66, 0xd2, 0xc3, 0x97, 0x6e, 0x16, 0xb1, 0x53, 0xfc, 0x2c,
		0x7a, 0xb5, 0x5f, 0xed, 0x7e, 0x30, 0xd1, 0x6e}
)

func Test_CertificateFromRaw(t *testing.T) {
	Convey("CertificateFromRaw should parse bytes correctly", t, func() {
		cert, err := CertificateFromRaw(loadRaw(fnLeaf, t))
		SoMsg("err", err, ShouldEqual, nil)
		SoMsg("CanIssue", cert.CanIssue, ShouldEqual, false)
		SoMsg("Comment", cert.Comment, ShouldEqual, "AS Certificate☂☂☂☂")
		SoMsg("EncAlgo", cert.EncAlgorithm, ShouldEqual, crypto.Curve25519xSalsa20Poly1305)
		SoMsg("ExpTime", cert.ExpirationTime, ShouldEqual, 1539868933)
		SoMsg("IssueTime", cert.IssuingTime, ShouldEqual, 1508332933)
		SoMsg("SignAlgo", cert.SignAlgorithm, ShouldEqual, crypto.Ed25519)
		SoMsg("TRCVer", cert.TRCVersion, ShouldEqual, 2)
		SoMsg("Ver", cert.Version, ShouldEqual, 1)
		SoMsg("Issuer", cert.Issuer.String(), ShouldEqual, "1-13")
		SoMsg("Subject", cert.Subject.String(), ShouldEqual, "1-10")
		SoMsg("Signature", cert.Signature, ShouldResemble, rawSignature)
		SoMsg("EncKey", cert.SubjectEncKey, ShouldResemble, rawEncKey)
		SoMsg("SigKey", cert.SubjectSignKey, ShouldResemble, rawSigKey)
	})

	Convey("CertificateFromRaw should throw error for invalid bytes", t, func() {
		tmpCert := loadRaw(fnLeaf, t)
		tmpCert[0] ^= 0xFF
		_, err := CertificateFromRaw(tmpCert)
		SoMsg("err", err, ShouldNotBeNil)
	})
}

func Test_Certificate_Verify(t *testing.T) {
	Convey("Load Certificate from Raw and init values", t, func() {
		cert := loadCert(fnLeaf, t)
		pub, priv, _ := ed25519.GenerateKey(nil)
		subject := &addr.ISD_AS{I: 1, A: 10}
		pubRaw, privRaw := []byte(pub), []byte(priv)

		cert.IssuingTime = uint64(time.Now().Unix())
		cert.ExpirationTime = cert.IssuingTime + 1<<20
		cert.Sign(privRaw, crypto.Ed25519)

		Convey("Certificate is verifiable", func() {
			err := cert.Verify(subject, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldBeNil)
		})

		Convey("Wrong subject throws error", func() {
			err := cert.Verify(&addr.ISD_AS{I: 1, A: 14}, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong pub throws error", func() {
			pubRaw[0] ^= 0xFF
			err := cert.Verify(subject, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong signature Algo throws error", func() {
			err := cert.Verify(subject, pubRaw, "ECDSA-256")
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong signature throws error", func() {
			cert.Signature[0] ^= 0xFF
			err := cert.Verify(subject, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Early usage throws error", func() {
			cert.IssuingTime = uint64(time.Now().Unix()) + 1<<20
			cert.ExpirationTime = cert.IssuingTime + 1<<20
			cert.Sign(privRaw, crypto.Ed25519)
			err := cert.Verify(subject, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Late usage throws error", func() {
			cert.IssuingTime = uint64(time.Now().Unix()) - 1<<20
			cert.ExpirationTime = uint64(time.Now().Unix()) - 1
			cert.Sign(privRaw, crypto.Ed25519)
			err := cert.Verify(subject, pubRaw, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

func Test_Certificate_Sign(t *testing.T) {
	Convey("Certificate is signed correctly", t, func() {
		cert := loadCert(fnLeaf, t)
		cert.Signature = nil
		key := []byte{0x41, 0x4d, 0x5c, 0x19, 0x03, 0x93, 0x31, 0x19, 0xce, 0x90, 0xa8,
			0x20, 0x7b, 0xa6, 0x5d, 0x1f, 0xc2, 0x0d, 0xdc, 0xec, 0xc4, 0xd0, 0x10,
			0x17, 0x18, 0xf5, 0x71, 0xa8, 0x04, 0xfe, 0x2f, 0x39, 0x92, 0xa8, 0x7d,
			0x58, 0x97, 0xd5, 0x1f, 0x5d, 0x3f, 0x6a, 0x91, 0xf6, 0xef, 0xcb, 0xda,
			0xaf, 0x97, 0x9c, 0xdc, 0x06, 0x08, 0x53, 0x92, 0xe3, 0x75, 0x2d, 0x67,
			0xed, 0x23, 0xf9, 0xfa, 0x9f}
		err := cert.Sign(key, crypto.Ed25519)
		So(err, ShouldEqual, nil)
		So(cert.Signature, ShouldResemble, rawSignature)
	})
}

func Test_Certificate_String(t *testing.T) {
	Convey("Certificate is returned as String correctly", t, func() {
		cert := loadCert(fnLeaf, t)
		So(cert.String(), ShouldEqual, "Certificate 1-10v1")
	})
}

func Test_Certificate_JSON(t *testing.T) {
	Convey("Certificate is returned as Json correctly", t, func() {
		cert := loadCert(fnLeaf, t)
		s := loadRaw(fnNoIndentLeaf, t)
		j, err := cert.JSON(false)
		So(err, ShouldEqual, nil)
		So(string(j)+"\n", ShouldEqual, string(s))
	})
}

func Test_Certificate_Eq(t *testing.T) {
	Convey("Load Certificate from Raw", t, func() {
		c1 := loadCert(fnLeaf, t)
		c2 := loadCert(fnLeaf, t)

		Convey("Certificates are equal", func() {
			SoMsg("Eq", c1.Eq(c2), ShouldBeTrue)
		})
		Convey("Certificates are unequal (CanIssue)", func() {
			c1.CanIssue = true
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (Comment)", func() {
			c1.Comment = "Nope"
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (EncAlgorithm)", func() {
			c1.EncAlgorithm = "Ceasar Cipher"
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (ExpirationTime)", func() {
			c1.ExpirationTime = 0
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (Issuer)", func() {
			c1.Issuer = &addr.ISD_AS{I: 13, A: 37}
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (IssuingTime)", func() {
			c1.IssuingTime = 0
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (SignAlgorithm)", func() {
			c1.SignAlgorithm = "ByHand"
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (Signature)", func() {
			c1.Signature[0] ^= 0xFF
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (Subject)", func() {
			c1.Subject = &addr.ISD_AS{I: 13, A: 37}
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (SubjectEncKey)", func() {
			c1.SubjectEncKey[0] ^= 0xFF
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (SubjectSigKey)", func() {
			c1.SubjectSignKey[0] ^= 0xFF
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (TRCVersion)", func() {
			c1.TRCVersion = 10
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Certificates are unequal (Version)", func() {
			c1.Version = 10
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
	})
}

func loadCert(filename string, t *testing.T) *Certificate {
	trc, err := CertificateFromRaw(loadRaw(filename, t))
	if err != nil {
		t.Fatalf("Error loading Certificate from '%s': %v", filename, err)
	}
	return trc
}

func loadRaw(filename string, t *testing.T) []byte {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Unable to load raw from '%s': %v", filename, err)
	}
	return b
}
