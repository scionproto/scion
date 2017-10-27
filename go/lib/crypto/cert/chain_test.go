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
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"golang.org/x/crypto/ed25519"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto"
)

// Interface assertions
var _ fmt.Stringer = (*Certificate)(nil)

var (
	rawChain = []byte(`
	{
	    "0": {
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
	    },
	    "1": {
		"SignAlgorithm": "ed25519",
		"SubjectSigKey": "kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=",
		"Version": 1,
		"EncAlgorithm": "curve25519xsalsa20poly1305",
		"SubjectEncKey": "MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=",
		"TRCVersion": 2,
		"ExpirationTime": 1539868933,
		"Signature": "22iMWzSgocC1MRJ64ZRH2rL2sLxT9+sJWa4a2VbQ8R7MdXlOM/b7cjzSCLZqNXpVOXf8cQ1yGmhypFQTxUEJCA==",
		"Issuer": "1-13",
		"CanIssue": true,
		"Subject": "1-13",
		"IssuingTime": 1508332933,
		"Comment": "Core AS Certificate"
	    }
	}`)

	packChain, _ = hex.DecodeString("d4040000b27b0a202020202230223a200b00010f00f10243616e4973" +
		"737565223a2066616c73652c2600011b00f70949737375696e6754696d65223a2031353038333332" +
		"3933332300fe10436f6d6d656e74223a202241532043657274696669636174655c75323630320600" +
		"17223d00f9565369676e6174757265223a20222f686f4a424754513046322b344f71706643547250" +
		"675a6a414558372f33587571544c6250686d5a707356685834452b674c484b5647302f2b2f415379" +
		"7136505a6a46393757747a4170506a5677356a4f49457441673d3d71005175626a6563ae0049312d" +
		"31308c00021b00f9265369674b6579223a20223559596f2f446a6f72384b6f555062634738396d30" +
		"734f5862686178552f777365725666375834773057346400b856657273696f6e223a20317a00ff08" +
		"69676e416c676f726974686d223a20226564323535313983000033456e638300f91c6e5031486b5a" +
		"776b5738756a7165454f3832526239634e3641567146504f315549697970645a552b644849830039" +
		"456e636c005163757276656f00f8017873616c73613230706f6c79313330357f0001060213721c01" +
		"18331a00a545787069726174696f6e0b025a33393836380b0236545243fc0072320a202020207d02" +
		"012f22317302063f7472757202275a436f726520770208b700095f02f9493232694d577a53676f63" +
		"43314d524a36345a524832724c32734c7854392b734a57613461325662513852374d64586c4f4d2f" +
		"6237636a7a53434c5a714e5870564f58663863513179476d6879704651547855454a43413d3d7100" +
		"0244020f430101031b00065f02f91c6b716839574a66564831302f61704832373876617235656333" +
		"41594955354c6a6453316e375350352b7038dc010663010f5f022eff1b4d78784649502b4b6c6849" +
		"7971787376364230556d3732442b4e506f4c4b477542504e74386231342f525f02825020207d0a7d")

	rawLeaf = []byte(`
	{
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
	rawCore = []byte(`
	{
	    "SignAlgorithm": "ed25519",
	    "SubjectSigKey": "kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=",
	    "Version": 1,
	    "EncAlgorithm": "curve25519xsalsa20poly1305",
	    "SubjectEncKey": "MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=",
	    "TRCVersion": 2,
	    "ExpirationTime": 1539868933,
	    "Signature": "22iMWzSgocC1MRJ64ZRH2rL2sLxT9+sJWa4a2VbQ8R7MdXlOM/b7cjzSCLZqNXpVOXf8cQ1yGmhypFQTxUEJCA==",
	    "Issuer": "1-13",
	    "CanIssue": true,
	    "Subject": "1-13",
	    "IssuingTime": 1508332933,
	    "Comment": "Core AS Certificate"
	}`)
)

func Test_ChainFromRaw(t *testing.T) {
	Convey("ChainFromRaw should parse bytes correctly", t, func() {
		chain, err := ChainFromRaw(rawChain, false)
		SoMsg("err", err, ShouldBeNil)

		Convey("Leaf Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawLeaf)
			SoMsg("Leaf", chain.Leaf.String(), ShouldEqual, cert.String())
		})

		Convey("Core Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawCore)
			SoMsg("Core", chain.Core.String(), ShouldEqual, cert.String())
		})
	})

	Convey("ChainFromRaw should parse packed bytes correctly", t, func() {
		chain, err := ChainFromRaw(packChain, true)
		SoMsg("err", err, ShouldBeNil)

		Convey("Leaf Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawLeaf)
			SoMsg("Leaf", chain.Leaf.String(), ShouldEqual, cert.String())
		})

		Convey("Core Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawCore)
			SoMsg("Core", chain.Core.String(), ShouldEqual, cert.String())
		})
	})

	Convey("ChainFromRaw should avoid unpack bombs", t, func() {
		raw := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		_, err := ChainFromRaw(raw, true)
		SoMsg("err", err, ShouldNotBeNil)
	})
}

func Test_Chain_Verify(t *testing.T) {
	Convey("Chain is verifiable", t, func() {
		// FIXME(roosd): Update with TRC implementation
		chain, _ := ChainFromRaw(rawChain, false)
		pub, priv, _ := ed25519.GenerateKey(nil)
		pubRaw, privRaw := []byte(pub), []byte(priv)

		chain.Leaf.IssuingTime = time.Now().Unix()
		chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + 1<<20
		chain.Leaf.Sign(privRaw, crypto.Ed25519)
		chain.Core.SubjectSigKey = pubRaw
		err := chain.Verify(&addr.ISD_AS{I: 1, A: 10}, nil)
		SoMsg("err", err, ShouldBeNil)
	})
}

func Test_Chain_Compress(t *testing.T) {
	Convey("Chain is compressed correctly", t, func() {
		chain, _ := ChainFromRaw(rawChain, false)
		comp, err := chain.Compress()
		SoMsg("err", err, ShouldBeNil)
		pChain, _ := ChainFromRaw(comp, true)
		SoMsg("Compare", pChain.Eq(chain), ShouldBeTrue)
	})
}

func Test_Chain_String(t *testing.T) {
	Convey("Chain is returned as String correctly", t, func() {
		chain, err := ChainFromRaw(rawChain, false)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Compare", chain.String(), ShouldEqual, "CertificateChain 1-10v1")
	})
}

func Test_Chain_JSON(t *testing.T) {
	Convey("Chain is returned as Json correctly", t, func() {
		s := `{"0":{"CanIssue":false,"Comment":"AS Certificate☂☂☂☂","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"/hoJBGTQ0F2+4OqpfCTrPgZjAEX7/3XuqTLbPhmZpsVhX4E+gLHKVG0/+/ASyq6PZjF97WtzApPjVw5jOIEtAg==","Subject":"1-10","SubjectEncKey":"nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=","SubjectSigKey":"5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=","TRCVersion":2,"Version":1},"1":{"CanIssue":true,"Comment":"Core AS Certificate","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"22iMWzSgocC1MRJ64ZRH2rL2sLxT9+sJWa4a2VbQ8R7MdXlOM/b7cjzSCLZqNXpVOXf8cQ1yGmhypFQTxUEJCA==","Subject":"1-13","SubjectEncKey":"MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=","SubjectSigKey":"kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=","TRCVersion":2,"Version":1}}`
		cert, _ := ChainFromRaw(rawChain, false)
		j, err := cert.JSON(false)
		So(err, ShouldEqual, nil)
		So(string(j), ShouldEqual, s)
	})
}

func Test_Chain_IAVer(t *testing.T) {
	Convey("IA version tuple is returned correctly", t, func() {
		chain, err := ChainFromRaw(rawChain, false)
		SoMsg("err", err, ShouldBeNil)
		ia, ver := chain.IAVer()
		SoMsg("IA", ia.Eq(&addr.ISD_AS{I: 1, A: 10}), ShouldBeTrue)
		SoMsg("Ver", ver, ShouldEqual, 1)
	})
}

func Test_Chain_Eq(t *testing.T) {
	Convey("Load Certificate from Raw", t, func() {
		c1, _ := ChainFromRaw(rawChain, false)
		c2, _ := ChainFromRaw(rawChain, false)

		Convey("Chains are equal", func() {
			SoMsg("Eq", c1.Eq(c2), ShouldBeTrue)
		})
		Convey("Chains are unequal (Leaf)", func() {
			c1.Leaf.CanIssue = true
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Chains are unequal (Core)", func() {
			c1.Core.CanIssue = false
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
	})
}

func Test_Chain_Key(t *testing.T) {
	Convey("Key is returned correctly", t, func() {
		chain, err := ChainFromRaw(rawChain, false)
		SoMsg("err", err, ShouldBeNil)
		key := *chain.Key()
		SoMsg("Key", key, ShouldResemble, Key{IA: addr.ISD_AS{I: 1, A: 10}, Ver: 1})
	})
}

func Test_Key_String(t *testing.T) {
	Convey("Key represented as string correctly", t, func() {
		SoMsg("Key", (&Key{IA: addr.ISD_AS{I: 1, A: 10}, Ver: 1}).String(), ShouldEqual, "1-10.1")
	})
}
