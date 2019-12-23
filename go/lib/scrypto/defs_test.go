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

package scrypto_test

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
)

func TestJWSignatureMarshalUnmarshal(t *testing.T) {
	type container struct {
		Signature scrypto.JWSignature
	}

	orig := container{Signature: make(scrypto.JWSignature, 32)}
	_, err := rand.Read(orig.Signature)
	require.NoError(t, err)
	enc, err := json.Marshal(orig)
	require.NoError(t, err)
	var dec container
	err = json.Unmarshal(enc, &dec)
	require.NoError(t, err)
	assert.Equal(t, orig, dec)
}
