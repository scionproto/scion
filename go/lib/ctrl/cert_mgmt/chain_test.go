// Copyright 2020 Anapaya Systems
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

package cert_mgmt_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPackUnpack(t *testing.T) {
	chain0 := xtest.LoadChain(t, "testdata/chain0.pem")
	chain1 := xtest.LoadChain(t, "testdata/chain1.pem")
	chains := [][]*x509.Certificate{chain0, chain1}

	chainMsg := cert_mgmt.NewChain(chains)
	parsedChains, err := chainMsg.Chains()
	assert.NoError(t, err)
	assert.Equal(t, chains, parsedChains)
}

func TestChainString(t *testing.T) {
	chain0 := xtest.LoadChain(t, "testdata/chain0.pem")
	chain1 := xtest.LoadChain(t, "testdata/chain1.pem")
	chains := [][]*x509.Certificate{chain0, chain1}

	chainMsg := cert_mgmt.NewChain(chains)
	str := chainMsg.String()
	chain0Str := "IA: 1-ff00:0:110, SubjectKeyID: 2508d0fc26dd2fac4ac2dc0076423166b56ccc99," +
		" Validity: [2020-06-24 12:00:00 +0000 UTC, 2020-06-27 12:00:00 +0000 UTC]"
	chain1Str := "IA: 1-ff00:0:110, SubjectKeyID: 2b4364537fadc842b94596d1fcf9e7e5c475ecca," +
		" Validity: [2020-06-26 12:00:00 +0000 UTC, 2020-06-29 12:00:00 +0000 UTC]"
	expected := strings.Join([]string{"chains:", chain0Str, chain1Str}, "\n")
	assert.Equal(t, expected, str)
}
