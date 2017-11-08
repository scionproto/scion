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
		"SubjectSignKey": "5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=",
		"Version": 1,
		"EncAlgorithm": "curve25519xsalsa20poly1305",
		"SubjectEncKey": "nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=",
		"TRCVersion": 2,
		"ExpirationTime": 1539868933,
		"Signature": "36dhobVsPBt6UlMCZtmYHoKJbuS3MbZNvu24nA+kt780bf4ZenIreuvnxphIxuI327cBoeDsB+Tg1EvSPnwEBg==",
		"Issuer": "1-13",
		"CanIssue": false,
		"Subject": "1-10",
		"IssuingTime": 1508332933,
		"Comment": "AS Certificate\u2602\u2602\u2602\u2602"
	    },
	    "1": {
		"SignAlgorithm": "ed25519",
		"SubjectSignKey": "kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=",
		"Version": 1,
		"EncAlgorithm": "curve25519xsalsa20poly1305",
		"SubjectEncKey": "MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=",
		"TRCVersion": 2,
		"ExpirationTime": 1539868933,
		"Signature": "CbjEsqIe4LW7kjMsyMBim4RdRn0YwM4kCjED+1Lbja4o3lwQVHqxVzQ8Rx0CsmHdsm4mwPoNg++KKUlUxrRmCg==",
		"Issuer": "1-13",
		"CanIssue": true,
		"Subject": "1-13",
		"IssuingTime": 1508332933,
		"Comment": "Core AS Certificate"
	    }
	}`)

	packChain, _ = hex.DecodeString("bb030000fe277b2230223a7b2243616e4973737565223a66616c7365" +
		"2c22436f6d6d656e74223a2241532043657274696669636174655c75323630320600f24a222c2245" +
		"6e63416c676f726974686d223a22637572766532353531397873616c73613230706f6c7931333035" +
		"222c2245787069726174696f6e54696d65223a313533393836383933332c22497373756572223a22" +
		"312d313322100034696e6729005130383333322900485369676e72002165646f0012221a00f7a061" +
		"74757265223a22333664686f62567350427436556c4d435a746d59486f4b4a627553334d625a4e76" +
		"7532346e412b6b743738306266345a656e49726575766e7870684978754933323763426f65447342" +
		"2b546731457653506e774542673d3d222c225375626a656374223a22312d3130222c225375626a65" +
		"6374456e634b6579223a226e5031486b5a776b5738756a7165454f3832526239634e364156714650" +
		"4f315549697970645a552b6448495000425369676e4000f52f3559596f2f446a6f72384b6f555062" +
		"634738396d30734f5862686178552f777365725666375834773057343d222c225452435665727369" +
		"6f6e223a322c220c005a317d2c2231e70139747275e6015a436f726520eb010fd30187ff4643626a" +
		"4573714965344c57376b6a4d73794d42696d345264526e3059774d346b436a45442b314c626a6134" +
		"6f336c775156487178567a513852783043736d4864736d346d77506f4e672b2b4b4b556c55787252" +
		"6d43d301001633940105d301ff1b4d78784649502b4b6c68497971787376364230556d3732442b4e" +
		"506f4c4b477542504e74386231342f52d30103ff1c6b716839574a66564831302f61704832373876" +
		"61723565633341594955354c6a6453316e375350352b7038d3010750223a317d7d")

	rawLeaf = []byte(`
	{
	    "SignAlgorithm": "ed25519",
	    "SubjectSignKey": "5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=",
	    "Version": 1,
	    "EncAlgorithm": "curve25519xsalsa20poly1305",
	    "SubjectEncKey": "nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=",
	    "TRCVersion": 2,
	    "ExpirationTime": 1539868933,
	    "Signature": "36dhobVsPBt6UlMCZtmYHoKJbuS3MbZNvu24nA+kt780bf4ZenIreuvnxphIxuI327cBoeDsB+Tg1EvSPnwEBg==",
	    "Issuer": "1-13",
	    "CanIssue": false,
	    "Subject": "1-10",
	    "IssuingTime": 1508332933,
	    "Comment": "AS Certificate\u2602\u2602\u2602\u2602"
	}`)
	rawCore = []byte(`
	{
	    "SignAlgorithm": "ed25519",
	    "SubjectSignKey": "kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=",
	    "Version": 1,
	    "EncAlgorithm": "curve25519xsalsa20poly1305",
	    "SubjectEncKey": "MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=",
	    "TRCVersion": 2,
	    "ExpirationTime": 1539868933,
	    "Signature": "CbjEsqIe4LW7kjMsyMBim4RdRn0YwM4kCjED+1Lbja4o3lwQVHqxVzQ8Rx0CsmHdsm4mwPoNg++KKUlUxrRmCg==",
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
			SoMsg("Leaf", chain.Leaf.Eq(cert), ShouldBeTrue)
		})

		Convey("Core Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawCore)
			SoMsg("Core", chain.Core.Eq(cert), ShouldBeTrue)
		})
	})

	Convey("ChainFromRaw should parse packed bytes correctly", t, func() {
		chain, err := ChainFromRaw(packChain, true)
		SoMsg("err", err, ShouldBeNil)

		Convey("Leaf Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawLeaf)
			SoMsg("Leaf", chain.Leaf.Eq(cert), ShouldBeTrue)
		})

		Convey("Core Certifiacte is parsed correctly", func() {
			cert, _ := CertificateFromRaw(rawCore)
			SoMsg("Core", chain.Core.Eq(cert), ShouldBeTrue)
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
		chain.Core.SubjectSignKey = pubRaw
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
		s := `{"0":{"CanIssue":false,"Comment":"AS Certificate☂☂☂☂","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"36dhobVsPBt6UlMCZtmYHoKJbuS3MbZNvu24nA+kt780bf4ZenIreuvnxphIxuI327cBoeDsB+Tg1EvSPnwEBg==","Subject":"1-10","SubjectEncKey":"nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=","SubjectSignKey":"5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=","TRCVersion":2,"Version":1},"1":{"CanIssue":true,"Comment":"Core AS Certificate","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"CbjEsqIe4LW7kjMsyMBim4RdRn0YwM4kCjED+1Lbja4o3lwQVHqxVzQ8Rx0CsmHdsm4mwPoNg++KKUlUxrRmCg==","Subject":"1-13","SubjectEncKey":"MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=","SubjectSignKey":"kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=","TRCVersion":2,"Version":1}}`
		cert, _ := ChainFromRaw(rawChain, false)
		j, err := cert.JSON(false)
		So(err, ShouldEqual, nil)
		So(string(j), ShouldResemble, s)
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
