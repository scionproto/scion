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

package tmpl

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func genKeysTmpl(ia addr.IA, val conf.Validity, isd *conf.ISDCfg) conf.Keys {
	keys := conf.Keys{
		Primary: make(map[trc.KeyType]map[scrypto.KeyVersion]conf.KeyMeta),
		Issuer:  make(map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta),
		AS: map[cert.KeyType]map[scrypto.KeyVersion]conf.KeyMeta{
			cert.SigningKey:    {1: {Algorithm: scrypto.Ed25519, Validity: val}},
			cert.RevocationKey: {1: {Algorithm: scrypto.Ed25519, Validity: val}},
			cert.EncryptionKey: {1: {Algorithm: scrypto.Curve25519xSalsa20Poly1305, Validity: val}},
		},
	}
	if pkicmn.ContainsAS(isd.TRC.VotingASes, ia.A) {
		keys.Primary[trc.OnlineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: val},
		}
		keys.Primary[trc.OfflineKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: val},
		}
	}
	if pkicmn.ContainsAS(isd.TRC.IssuingASes, ia.A) {
		keys.Primary[trc.IssuingKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: val},
		}
		keys.Issuer[cert.IssuingKey] = map[scrypto.KeyVersion]conf.KeyMeta{
			1: {Algorithm: scrypto.Ed25519, Validity: val},
		}
	}
	return keys
}
