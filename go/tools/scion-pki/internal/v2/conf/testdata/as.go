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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

// GoldenAS contains the decoded
var GoldenAS = AS(42424242)

// AS generates a AS certificate configuration for testing.
func AS(notBefore uint32) conf.AS {
	s, e, r := scrypto.KeyVersion(1), scrypto.KeyVersion(1), scrypto.KeyVersion(1)
	return conf.AS{
		Description:          "Testing AS",
		Version:              1,
		SigningKeyVersion:    &s,
		EncryptionKeyVersion: &e,
		RevocationKeyVersion: &r,
		IssuerIA:             xtest.MustParseIA("1-ff00:0:110"),
		IssuerCertVersion:    1,
		OptDistPoints:        []addr.IA{xtest.MustParseIA("2-ff00:0:210")},
		Validity: conf.Validity{
			NotBefore: notBefore,
			Validity:  util.DurWrap{Duration: 3 * 24 * time.Hour},
		},
	}
}
