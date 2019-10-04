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

package testdata

import (
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

// GoldenKeys contains the decoded keys.toml file.
var GoldenKeys = Keys(42424242)

// Keys generates a key configuration for testing.
func Keys(notBefore uint32) conf.Keys {
	return conf.Keys{
		Primary: map[trc.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			trc.IssuingKey: {
				1: keyMeta(scrypto.Ed25519, notBefore, 365*24*time.Hour),
			},
			trc.OfflineKey: {
				1: keyMeta(scrypto.Ed25519, notBefore, 365*24*time.Hour),
			},
			trc.OnlineKey: {
				1: keyMeta(scrypto.Ed25519, notBefore, 365*24*time.Hour),
				2: keyMeta(scrypto.Ed25519, notBefore, 365*24*time.Hour),
			},
		},
		Issuer: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.IssuingKey: {
				1: keyMeta(scrypto.Ed25519, notBefore, 180*24*time.Hour),
			},
			cert.RevocationKey: {
				2: keyMeta(scrypto.Ed25519, notBefore, 180*24*time.Hour),
			},
		},
		AS: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.EncryptionKey: {
				1: keyMeta(scrypto.Curve25519xSalsa20Poly1305, notBefore, 90*24*time.Hour),
			},
			cert.RevocationKey: {
				2: keyMeta(scrypto.Ed25519, notBefore, 90*24*time.Hour),
			},
			cert.SigningKey: {
				3: keyMeta(scrypto.Ed25519, notBefore, 90*24*time.Hour),
			},
		},
	}
}

func keyMeta(algo string, notBefore uint32, validity time.Duration) conf.KeyMeta {
	return conf.KeyMeta{
		Algorithm: algo,
		Validity: conf.Validity{
			NotBefore: notBefore,
			Validity:  util.DurWrap{Duration: validity},
		},
	}
}
