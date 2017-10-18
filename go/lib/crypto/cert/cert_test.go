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
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/bouk/monkey"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

// Interface assertions
var _ fmt.Stringer = (*Certificate)(nil)

var (
	rawCert = []byte(`{
    "SignAlgorithm": "ed25519",
    "SubjectSigKey": "5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=",
    "Version": 1,
    "EncAlgorithm": "curve25519xsalsa20poly1305",
    "SubjectEncKey": "nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=",
    "TRCVersion": 2,
    "ExpirationTime": 1539868933,
    "Signature": "/hoJBGTQ0F2+4OqpfCTrPgZjAEX7/3XuqTLbPhmZpsVhX4E+gLHKVG0/+/ASyq6PZjF97WtzApPjVw5jOIEtAg==",
    "Issuer": "1-13",
    "CanIssue": false,
    "Subject": "1-10",
    "IssuingTime": 1508332933,
    "Comment": "AS Certificate\u2602\u2602\u2602\u2602"
}`)

	rawSignature = []byte{0xfe, 0x1a, 0x09, 0x04, 0x64, 0xd0, 0xd0, 0x5d, 0xbe, 0xe0, 0xea,
		0xa9, 0x7c, 0x24, 0xeb, 0x3e, 0x06, 0x63, 0x00, 0x45, 0xfb, 0xff, 0x75, 0xee, 0xa9,
		0x32, 0xdb, 0x3e, 0x19, 0x99, 0xa6, 0xc5, 0x61, 0x5f, 0x81, 0x3e, 0x80, 0xb1, 0xca,
		0x54, 0x6d, 0x3f, 0xfb, 0xf0, 0x12, 0xca, 0xae, 0x8f, 0x66, 0x31, 0x7d, 0xed, 0x6b,
		0x73, 0x02, 0x93, 0xe3, 0x57, 0x0e, 0x63, 0x38, 0x81, 0x2d, 0x02}

	rawEncKey = []byte{0x9c, 0xfd, 0x47, 0x91, 0x9c, 0x24, 0x5b, 0xcb, 0xa3, 0xa9, 0xe1, 0x0e,
		0xf3, 0x64, 0x5b, 0xf5, 0xc3, 0x7a, 0x01, 0x5a, 0x85, 0x3c, 0xed, 0x54, 0x22, 0x2c,
		0xa9, 0x75, 0x95, 0x3e, 0x74, 0x72}

	rawSigKey = []byte{0xe5, 0x86, 0x28, 0xfc, 0x38, 0xe8, 0xaf, 0xc2, 0xa8, 0x50, 0xf6, 0xdc,
		0x1b, 0xcf, 0x66, 0xd2, 0xc3, 0x97, 0x6e, 0x16, 0xb1, 0x53, 0xfc, 0x2c, 0x7a, 0xb5,
		0x5f, 0xed, 0x7e, 0x30, 0xd1, 0x6e}
)

func Test_CertificateFromRaw(t *testing.T) {
	Convey("CertificateFromRaw should parse bytes correctly", t, func() {
		cert, err := CertificateFromRaw(rawCert)
		SoMsg("err", err, ShouldEqual, nil)
		SoMsg("CanIssue", cert.CanIssue, ShouldEqual, false)
		SoMsg("Comment", cert.Comment, ShouldEqual, "AS Certificate☂☂☂☂")
		SoMsg("EncAlgo", cert.EncAlgorithm, ShouldEqual, "curve25519xsalsa20poly1305")
		SoMsg("ExpTime", cert.ExpirationTime, ShouldEqual, 1539868933)
		SoMsg("IssueTime", cert.IssuingTime, ShouldEqual, 1508332933)
		SoMsg("SignAlgo", cert.SignAlgorithm, ShouldEqual, "ed25519")
		SoMsg("TRCVer", cert.TRCVersion, ShouldEqual, 2)
		SoMsg("Ver", cert.Version, ShouldEqual, 1)
		SoMsg("Issuer", cert.Issuer.String(), ShouldEqual, "1-13")
		SoMsg("Subject", cert.Subject.String(), ShouldEqual, "1-10")
		SoMsg("Signature", bytes.Compare(cert.Signature, rawSignature), ShouldEqual, 0)
		SoMsg("EncKey", bytes.Compare(cert.SubjectEncKey, rawEncKey), ShouldEqual, 0)
		SoMsg("SigKey", bytes.Compare(cert.SubjectSigKey, rawSigKey), ShouldEqual, 0)
	})

	Convey("CertificateFromRaw should throw error for invalid bytes", t, func() {
		rawCert[0] ^= 0xFF
		_, err := CertificateFromRaw(rawCert)
		SoMsg("err", err, ShouldNotBeNil)
		rawCert[0] ^= 0xFF
	})
}

func Test_Certificate_Verify(t *testing.T) {
	Convey("Load Certificate from Raw and init values", t, func() {
		cert, _ := CertificateFromRaw(rawCert)
		key := []byte{0x92, 0xa8, 0x7d, 0x58, 0x97, 0xd5, 0x1f, 0x5d, 0x3f, 0x6a, 0x91,
			0xf6, 0xef, 0xcb, 0xda, 0xaf, 0x97, 0x9c, 0xdc, 0x06, 0x08, 0x53, 0x92,
			0xe3, 0x75, 0x2d, 0x67, 0xed, 0x23, 0xf9, 0xfa, 0x9f}
		subject := &addr.ISD_AS{I: 1, A: 10}

		valid := time.Date(2017, 10, 19, 0, 0, 0, 0, time.UTC)
		monkey.Patch(time.Now, func() time.Time { return valid })
		Convey("Certificate is verifyable", func() {
			err := cert.Verify(subject, key, crypto.Ed25519)
			SoMsg("err", err, ShouldBeNil)
		})

		Convey("Wrong subject throws error", func() {
			err := cert.Verify(&addr.ISD_AS{I: 1, A: 14}, key, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong key throws error", func() {
			key[0] ^= 0xFF
			err := cert.Verify(subject, key, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong signature Algo throws error", func() {
			err := cert.Verify(subject, key, "ECDSA-256")
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Wrong signature throws error", func() {
			cert.Signature[0] ^= 0xFF
			err := cert.Verify(subject, key, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Early usage throws error", func() {
			early := time.Date(2016, 10, 19, 0, 0, 0, 0, time.UTC)
			monkey.Patch(time.Now, func() time.Time { return early })
			err := cert.Verify(subject, key, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})

		Convey("Late usage throws error", func() {
			late := time.Date(2019, 10, 19, 0, 0, 0, 0, time.UTC)
			monkey.Patch(time.Now, func() time.Time { return late })
			err := cert.Verify(subject, key, crypto.Ed25519)
			SoMsg("err", err, ShouldNotBeNil)
		})
		monkey.UnpatchAll()
	})
}

func Test_Certificate_Sign(t *testing.T) {
	Convey("Certificate is signed correctly", t, func() {
		cert, err := CertificateFromRaw(rawCert)
		cert.Signature = nil
		key := []byte{0x41, 0x4d, 0x5c, 0x19, 0x03, 0x93, 0x31, 0x19, 0xce, 0x90, 0xa8,
			0x20, 0x7b, 0xa6, 0x5d, 0x1f, 0xc2, 0x0d, 0xdc, 0xec, 0xc4, 0xd0, 0x10,
			0x17, 0x18, 0xf5, 0x71, 0xa8, 0x04, 0xfe, 0x2f, 0x39, 0x92, 0xa8, 0x7d,
			0x58, 0x97, 0xd5, 0x1f, 0x5d, 0x3f, 0x6a, 0x91, 0xf6, 0xef, 0xcb, 0xda,
			0xaf, 0x97, 0x9c, 0xdc, 0x06, 0x08, 0x53, 0x92, 0xe3, 0x75, 0x2d, 0x67,
			0xed, 0x23, 0xf9, 0xfa, 0x9f}
		err = cert.Sign(key, crypto.Ed25519)
		So(err, ShouldEqual, nil)
		So(bytes.Compare(cert.Signature, rawSignature), ShouldEqual, 0)
	})
}

func Test_Certificate_String(t *testing.T) {
	Convey("Certificate is returned as String correctly", t, func() {
		cert, err := CertificateFromRaw(rawCert)
		s := `{"CanIssue":false,"Comment":"AS Certificate☂☂☂☂","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"/hoJBGTQ0F2+4OqpfCTrPgZjAEX7/3XuqTLbPhmZpsVhX4E+gLHKVG0/+/ASyq6PZjF97WtzApPjVw5jOIEtAg==","Subject":"1-10","SubjectEncKey":"nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=","SubjectSigKey":"5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=","TRCVersion":2,"Version":1}`
		So(err, ShouldEqual, nil)
		So(cert.String(), ShouldEqual, s)
	})
}
