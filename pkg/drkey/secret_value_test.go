// Copyright 2020 ETH Zurich
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
)

func TestDeriveSV(t *testing.T) {

	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	targetKey := drkey.Key{0xc3, 0xb4, 0x84, 0x3c, 0x99, 0x3,
		0x14, 0xf9, 0xac, 0x55, 0x4f, 0x9b, 0x78, 0x1c, 0xde, 0xb7}

	got, err := drkey.DeriveSV(0, drkey.NewEpoch(0, 1), asSecret)
	require.NoError(t, err)
	require.EqualValues(t, targetKey, got.Key)
}
