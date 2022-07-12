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

package generic_test

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/drkey/drkeytest"
)

var (
	update  = xtest.UpdateGoldenFiles()
	protoId = drkey.Generic
	epoch   = drkey.NewEpoch(0, 1)
	srcIA   = xtest.MustParseIA("1-ff00:0:111")
	dstIA   = xtest.MustParseIA("1-ff00:0:112")
	srcHost = "127.0.0.2"
	dstHost = "127.0.0.1"
)

func TestDeriveASHostGeneric(t *testing.T) {
	level1Key := drkeytest.GetLevel1(t, protoId, epoch, srcIA, dstIA)

	testCases := map[string]struct {
		meta            drkey.ASHostMeta
		assertFormatErr assert.ErrorAssertionFunc
	}{
		"wrong no-host": {
			meta: drkey.ASHostMeta{
				ProtoId: drkey.Protocol(10000),
			},
			assertFormatErr: assert.Error,
		},
		"invalid as-host": {
			meta: drkey.ASHostMeta{
				ProtoId: drkey.Protocol(10000),
				DstHost: "<malformed address>",
			},
			assertFormatErr: assert.Error,
		},
		"valid as-host": {
			meta: drkey.ASHostMeta{
				ProtoId: drkey.Protocol(10000),
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			key, err := drkeytest.DeriveASHostGeneric(tc.meta, level1Key)
			tc.assertFormatErr(t, err)
			if err != nil {
				return
			}
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				keyStr := hex.EncodeToString(key.Key[:])
				require.NoError(t, os.WriteFile(goldenFile, []byte(keyStr), 0666))
			}
			goldenRaw, err := os.ReadFile(goldenFile)
			require.NoError(t, err)

			var expectedKey drkey.Key
			goldenKey, err := hex.DecodeString(string(goldenRaw))
			require.NoError(t, err)
			copy(expectedKey[:], goldenKey)
			require.Equal(t, expectedKey, key.Key)
		})
	}
}

func TestDeriveGenericHostAS(t *testing.T) {
	level1Key := drkeytest.GetLevel1(t, protoId, epoch, srcIA, dstIA)
	testCases := map[string]struct {
		meta            drkey.HostASMeta
		assertFormatErr assert.ErrorAssertionFunc
	}{
		"valid host-as": {
			meta: drkey.HostASMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
			},
			assertFormatErr: assert.NoError,
		},
		"invalid host-as": {
			meta: drkey.HostASMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: "<malformed address>",
			},
			assertFormatErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			key, err := drkeytest.DeriveHostASGeneric(tc.meta, level1Key)
			tc.assertFormatErr(t, err)
			if err != nil {
				return
			}
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				keyStr := hex.EncodeToString(key.Key[:])
				require.NoError(t, os.WriteFile(goldenFile, []byte(keyStr), 0666))
			}
			goldenRaw, err := os.ReadFile(goldenFile)
			require.NoError(t, err)

			var expectedKey drkey.Key
			goldenKey, err := hex.DecodeString(string(goldenRaw))
			require.NoError(t, err)
			copy(expectedKey[:], goldenKey)
			require.Equal(t, expectedKey, key.Key)
		})
	}
}

func TestDeriveGenericHostHost(t *testing.T) {
	level1Key := drkeytest.GetLevel1(t, protoId, epoch, srcIA, dstIA)

	testCases := map[string]struct {
		meta            drkey.HostHostMeta
		assertFormatErr assert.ErrorAssertionFunc
	}{
		"valid host-host": {
			meta: drkey.HostHostMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
		},
		"invalid host-host src": {
			meta: drkey.HostHostMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: "<malformed address>",
				DstHost: dstHost,
			},
			assertFormatErr: assert.Error,
		},
		"invalid host-host dst": {
			meta: drkey.HostHostMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
				DstHost: "<malformed address>",
			},
			assertFormatErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			key, err := drkeytest.DeriveHostHostGeneric(tc.meta, level1Key)
			tc.assertFormatErr(t, err)
			if err != nil {
				return
			}
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				keyStr := hex.EncodeToString(key.Key[:])
				require.NoError(t, os.WriteFile(goldenFile, []byte(keyStr), 0666))
			}
			goldenRaw, err := os.ReadFile(goldenFile)
			require.NoError(t, err)

			var expectedKey drkey.Key
			goldenKey, err := hex.DecodeString(string(goldenRaw))
			require.NoError(t, err)
			copy(expectedKey[:], goldenKey)
			require.Equal(t, expectedKey, key.Key)
		})
	}
}
