// Copyright 2022 ETH Zurich
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

package drkey_test

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
)

var (
	update = xtest.UpdateGoldenFiles()
)

func TestDeriveSV(t *testing.T) {

	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}

	got, err := drkey.DeriveSV(0, drkey.NewEpoch(0, 1), asSecret)
	require.NoError(t, err)

	goldenFile := "testdata/" + xtest.SanitizedName(t)
	if *update {
		keyStr := hex.EncodeToString(got.Key[:])
		require.NoError(t, os.WriteFile(goldenFile, []byte(keyStr), 0666))
	}
	goldenRaw, err := os.ReadFile(goldenFile)
	require.NoError(t, err)

	var expectedKey drkey.Key
	goldenKey, err := hex.DecodeString(string(goldenRaw))
	require.NoError(t, err)
	copy(expectedKey[:], goldenKey)
	require.Equal(t, expectedKey, got.Key)
}
