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
		"Signature": "MBNoxBcdebrYrZT2fduTICHSsKhiPe5L2ayURDlslP1igHoKWuhtdGs9OFnYohy8QoUo5wUm4S3nmK2HzLbKAA==",
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
		"Signature": "AnOc9G+5IvaCVeh7MFpuQLRAbKutb4OVHZay26XL+xIo2/N3QPtQS4GQNwkoxcPhoJQM+4EvVIQt5w+Nl0utBg==",
		"Issuer": "1-13",
		"CanIssue": true,
		"Subject": "1-13",
		"IssuingTime": 1508332933,
		"Comment": "Core AS Certificate"
	    }
	}`)

	packChain, _ = hex.DecodeString("d4040000b27b0a202020202230223a200b00010f00c156657273696f" +
		"6e223a20312c2100011600fe015375626a656374223a2022312d3130221b00f827456e634b657922" +
		"3a20226e5031486b5a776b5738756a7165454f3832526239634e3641567146504f31554969797064" +
		"5a552b6448493d4900365452437d0018326200f95469676e6174757265223a20224d424e6f784263" +
		"6465627259725a54326664755449434853734b68695065354c3261795552446c736c50316967486f" +
		"4b57756874644773394f466e596f687938516f556f3577556d3453336e6d4b32487a4c624b41413d" +
		"8a0003ee0033536967d300f91c3559596f2f446a6f72384b6f555062634738396d30734f58626861" +
		"78552f77736572566637583477305734d300fb0143616e4973737565223a2066616c7365d500f805" +
		"416c676f726974686d223a2022656432353531398800f70c45787069726174696f6e54696d65223a" +
		"20313533393836383933334a0039456e6349005163757276654c00f8017873616c73613230706f6c" +
		"79313330355c007549737375696e6759005a3038333332590001bb001372f40118333d0061436f6d" +
		"6d656e0f02fe0541532043657274696669636174655c7532363032060011224b02127db6002f2231" +
		"73021f097f0003a001067302ff1b4d78784649502b4b6c68497971787376364230556d3732442b4e" +
		"506f4c4b477542504e74386231342f52730221ff47416e4f6339472b3549766143566568374d4670" +
		"75514c5241624b757462344f56485a61793236584c2b78496f322f4e3351507451533447514e776b" +
		"6f786350686f4a514d2b3445765649517435772b4e6c307574426773020cff1c6b716839574a6656" +
		"4831302f6170483237387661723565633341594955354c6a6453316e375350352b70387302053f74" +
		"72757202c15a436f726520770290220a202020207d0a7d")

	rawLeaf = []byte(`
	{
	    "SignAlgorithm": "ed25519",
	    "SubjectSigKey": "5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=",
	    "Version": 1,
	    "EncAlgorithm": "curve25519xsalsa20poly1305",
	    "SubjectEncKey": "nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=",
	    "TRCVersion": 2,
	    "ExpirationTime": 1539868933,
	    "Signature": "MBNoxBcdebrYrZT2fduTICHSsKhiPe5L2ayURDlslP1igHoKWuhtdGs9OFnYohy8QoUo5wUm4S3nmK2HzLbKAA==",
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
	    "Signature": "AnOc9G+5IvaCVeh7MFpuQLRAbKutb4OVHZay26XL+xIo2/N3QPtQS4GQNwkoxcPhoJQM+4EvVIQt5w+Nl0utBg==",
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
		s := `{"0":{"CanIssue":false,"Comment":"AS Certificate☂☂☂☂","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"MBNoxBcdebrYrZT2fduTICHSsKhiPe5L2ayURDlslP1igHoKWuhtdGs9OFnYohy8QoUo5wUm4S3nmK2HzLbKAA==","Subject":"1-10","SubjectEncKey":"nP1HkZwkW8ujqeEO82Rb9cN6AVqFPO1UIiypdZU+dHI=","SubjectSigKey":"5YYo/Djor8KoUPbcG89m0sOXbhaxU/wserVf7X4w0W4=","TRCVersion":2,"Version":1},"1":{"CanIssue":true,"Comment":"Core AS Certificate","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1539868933,"Issuer":"1-13","IssuingTime":1508332933,"SignAlgorithm":"ed25519","Signature":"AnOc9G+5IvaCVeh7MFpuQLRAbKutb4OVHZay26XL+xIo2/N3QPtQS4GQNwkoxcPhoJQM+4EvVIQt5w+Nl0utBg==","Subject":"1-13","SubjectEncKey":"MxxFIP+KlhIyqxsv6B0Um72D+NPoLKGuBPNt8b14/RI=","SubjectSigKey":"kqh9WJfVH10/apH278var5ec3AYIU5LjdS1n7SP5+p8=","TRCVersion":2,"Version":1}}`
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
