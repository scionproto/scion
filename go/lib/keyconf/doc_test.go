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

package keyconf

import (
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func ExampleKey_encoding() {
	k := Key{
		ID: ID{
			Usage:   ASSigKeyFile,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
			Version: 2,
		},
		Type:      PublicKey,
		Algorithm: scrypto.Ed25519,
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: util.SecsToTime(1560000000)},
			NotAfter:  util.UnixTime{Time: util.SecsToTime(1600000000)},
		},
		Bytes: make([]byte, ed25519.PublicKeySize),
	}
	block := k.PEM()
	fmt.Println(string(pem.EncodeToMemory(&block)))
	// Output:
	// -----BEGIN PUBLIC KEY-----
	// algorithm: ed25519
	// ia: 1-ff00:0:110
	// not_after: 2020-09-13 12:26:40+0000
	// not_before: 2019-06-08 13:20:00+0000
	// usage: as-signing.key
	// version: 2
	//
	// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	// -----END PUBLIC KEY-----
}

func ExampleKey_filename() {
	publicKey := Key{
		ID: ID{
			Usage:   ASSigningKey,
			Version: 2,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
		},
		Type: PublicKey,
	}
	privateKey := Key{
		ID: ID{
			Usage:   ASRevocationKey,
			Version: 10,
			IA:      xtest.MustParseIA("1-ff00:0:110"),
		},
		Type: PrivateKey,
	}
	fmt.Println("Public key: ", publicKey.File())
	fmt.Println("Private key:", privateKey.File())
	// Output:
	// Public key:  ISD1-ASff00_0_110-as-signing-v2.pub
	// Private key: as-revocation-v10.key
}
