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

package trcs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDecode(t *testing.T) {
	signed, err := DecodeFromFile("./testdata/admin/ISD-B1-S1.trc")
	require.NoError(t, err)

	assert.Equal(t, addr.ISD(1), signed.TRC.ID.ISD)
	assert.Equal(t, scrypto.Version(1), signed.TRC.ID.Serial)
	assert.Equal(t, scrypto.Version(1), signed.TRC.ID.Base)
	assert.Zero(t, signed.TRC.GracePeriod)
	assert.False(t, signed.TRC.NoTrustReset)
	assert.Empty(t, signed.TRC.Votes)
	assert.Equal(t, 2, signed.TRC.Quorum)
	assert.ElementsMatch(t, xtest.MustParseASes("ff00:0:110,ff00:0:111"),
		signed.TRC.CoreASes)
	assert.ElementsMatch(t, xtest.MustParseASes("ff00:0:110,ff00:0:111"),
		signed.TRC.AuthoritativeASes)
	assert.Equal(t, "Test ISD", signed.TRC.Description)
	assert.Len(t, signed.TRC.Certificates, 9)

	assert.Len(t, signed.SignerInfos, 6)
}
