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

package trust_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/cs/trust"
)

func TestLoadingRing(t *testing.T) {
	ring := trust.LoadingRing{Dir: "testdata/common/ISD1/ASff00_0_111/crypto/as/"}

	privKeys, err := ring.PrivateKeys(context.Background())
	require.NoError(t, err)
	assert.Len(t, privKeys, 1)

	raw, err := ioutil.ReadFile("testdata/common/ISD1/ASff00_0_111/crypto/as/cp-as.key")
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	expexted, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, expexted.(crypto.Signer), privKeys[0])
}
