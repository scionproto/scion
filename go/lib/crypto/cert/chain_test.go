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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/xtest"
)

// Interface assertions
var _ fmt.Stringer = (*Certificate)(nil)

var (
	fnChain       = "testdata/ISD1-ASff00_0_311-V1.crt"
	fnCore        = "testdata/ISD1-ASff00_0_311-V1.core"
	fnNoIndentCrt = "testdata/noindent.crt"
	fnTRC         = "testdata/ISD1-V2.trc"
)

func Test_ChainFromRaw(t *testing.T) {
	Convey("ChainFromRaw should parse bytes correctly", t, func() {
		chain, err := ChainFromRaw(loadRaw(fnChain, t), false)
		SoMsg("err", err, ShouldBeNil)
		Convey("Leaf Certificate is parsed correctly", func() {
			cert := loadCert(fnLeaf, t)
			SoMsg("Leaf", chain.Leaf.Eq(cert), ShouldBeTrue)
		})

		Convey("Issuer Certificate is parsed correctly", func() {
			cert := loadCert(fnCore, t)
			SoMsg("Issuer", chain.Issuer.Eq(cert), ShouldBeTrue)
		})
	})

	// TODO(kormat): Renable once we have scion-pki generating test data.
	//Convey("ChainFromRaw should parse packed bytes correctly", t, func() {
	//	chain, err := ChainFromRaw(packChain, true)
	//	SoMsg("err", err, ShouldBeNil)

	//	Convey("Leaf Certificate is parsed correctly", func() {
	//		cert := loadCert(fnLeaf, t)
	//		SoMsg("Leaf", chain.Leaf.Eq(cert), ShouldBeTrue)
	//	})

	//	Convey("Issuer Certificate is parsed correctly", func() {
	//		cert := loadCert(fnCore, t)
	//		SoMsg("Issuer", chain.Issuer.Eq(cert), ShouldBeTrue)
	//	})
	//})

	Convey("ChainFromRaw should fail for unknown fields", t, func() {
		var m map[string]interface{}
		xtest.FailOnErr(t, json.Unmarshal(loadRaw(fnTRC, t), &m))
		m["xeno"] = "UNKNOWN"
		b, err := json.Marshal(m)
		xtest.FailOnErr(t, err)
		_, err = ChainFromRaw(b, false)
		SoMsg("err", err, ShouldNotBeNil)

	})

	Convey("ChainFromRaw should fail for missing fields", t, func() {
		var m map[string]interface{}
		xtest.FailOnErr(t, json.Unmarshal(loadRaw(fnTRC, t), &m))
		delete(m, "0")
		b, err := json.Marshal(m)
		xtest.FailOnErr(t, err)
		_, err = ChainFromRaw(b, false)
		SoMsg("err", err, ShouldNotBeNil)
	})

	Convey("ChainFromRaw should avoid unpack bombs", t, func() {
		raw := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		_, err := ChainFromRaw(raw, true)
		SoMsg("err", err, ShouldNotBeNil)
	})
}

func Test_Chain_Verify(t *testing.T) {
	Convey("Chain is verifiable", t, func() {
		chain := loadChain(fnChain, t)
		pub, priv, _ := ed25519.GenerateKey(nil)
		pubCoreRaw, privCoreRaw := []byte(pub), []byte(priv)
		pub, priv, _ = ed25519.GenerateKey(nil)
		pubTRCRaw, privTRCRaw := []byte(pub), []byte(priv)
		trc_ := loadTRC(fnTRC, t)

		chain.Leaf.IssuingTime = uint32(time.Now().Unix())
		chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + 1<<20
		chain.Leaf.Sign(privCoreRaw, crypto.Ed25519)

		chain.Issuer.SubjectSignKey = pubCoreRaw
		chain.Issuer.IssuingTime = uint32(time.Now().Unix())
		chain.Issuer.ExpirationTime = chain.Leaf.IssuingTime + 1<<20
		chain.Issuer.Sign(privTRCRaw, crypto.Ed25519)

		trc_.CoreASes[chain.Issuer.Issuer].OnlineKey = pubTRCRaw
		trc_.ExpirationTime = chain.Issuer.ExpirationTime
		err := chain.Verify(addr.IA{I: 1, A: 0xff0000000311}, trc_)
		SoMsg("err", err, ShouldBeNil)
	})
}

func Test_Chain_Compress(t *testing.T) {
	Convey("Chain is compressed correctly", t, func() {
		chain := loadChain(fnChain, t)
		comp, err := chain.Compress()
		SoMsg("err", err, ShouldBeNil)
		pChain, _ := ChainFromRaw(comp, true)
		SoMsg("Compare", pChain.Eq(chain), ShouldBeTrue)
	})
}

func Test_Chain_String(t *testing.T) {
	Convey("Chain is returned as String correctly", t, func() {
		chain := loadChain(fnChain, t)
		SoMsg("Compare", chain.String(), ShouldEqual, "CertificateChain 1-ff00:0:311v1")
	})
}

func Test_Chain_JSON(t *testing.T) {
	Convey("Chain is returned as Json correctly", t, func() {
		s := loadRaw(fnNoIndentCrt, t)
		chain := loadChain(fnChain, t)
		j, err := chain.JSON(false)
		So(err, ShouldEqual, nil)
		So(string(j)+"\n", ShouldResemble, string(s))
	})
}

func Test_Chain_IAVer(t *testing.T) {
	Convey("IA version tuple is returned correctly", t, func() {
		chain := loadChain(fnChain, t)
		ia, ver := chain.IAVer()
		SoMsg("IA", ia.Eq(addr.IA{I: 1, A: 0xff0000000311}), ShouldBeTrue)
		SoMsg("Ver", ver, ShouldEqual, 1)
	})
}

func Test_Chain_Eq(t *testing.T) {
	Convey("Load Certificate from Raw", t, func() {
		c1 := loadChain(fnChain, t)
		c2 := loadChain(fnChain, t)

		Convey("Chains are equal", func() {
			SoMsg("Eq", c1.Eq(c2), ShouldBeTrue)
		})
		Convey("Chains are unequal (Leaf)", func() {
			c1.Leaf.CanIssue = true
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
		Convey("Chains are unequal (Issuer)", func() {
			c1.Issuer.CanIssue = false
			SoMsg("Eq", c1.Eq(c2), ShouldBeFalse)
		})
	})
}

func Test_Chain_Key(t *testing.T) {
	Convey("Key is returned correctly", t, func() {
		chain := loadChain(fnChain, t)
		key := *chain.Key()
		SoMsg("Key", key, ShouldResemble, Key{IA: addr.IA{I: 1, A: 0xff0000000311}, Ver: 1})
	})
}

func Test_Key_String(t *testing.T) {
	Convey("Key represented as string correctly", t, func() {
		SoMsg("Key", (&Key{IA: addr.IA{I: 1, A: 0xff0000000311}, Ver: 1}).String(), ShouldEqual,
			"1-ff00:0:311v1")
	})
}

func loadChain(filename string, t *testing.T) *Chain {
	chain, err := ChainFromRaw(loadRaw(filename, t), false)
	if err != nil {
		t.Fatalf("Error loading Certificate Chain from '%s': %v", filename, err)
	}
	return chain
}

func loadTRC(filename string, t *testing.T) *trc.TRC {
	trc_, err := trc.TRCFromRaw(loadRaw(filename, t), false)
	if err != nil {
		t.Fatalf("Error loading TRC from '%s': %v", filename, err)
	}
	return trc_
}
