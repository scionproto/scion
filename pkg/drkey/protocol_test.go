// Copyright 2019 ETH Zurich
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/drkey/protocoltest"
)

func TestDeriveASHostGeneric(t *testing.T) {
	protoId := drkey.Generic
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	dstHost := "127.0.0.1"

	testCases := map[string]struct {
		meta            drkey.ASHostMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
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
			expectedKey: drkey.Key{0x2b, 0xc8, 0xfb, 0xb9, 0x45, 0x55,
				0x31, 0xa8, 0x4, 0xcf, 0x7f, 0xd5, 0xe5, 0xe5, 0x12, 0xa4},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			key, err := protocoltest.DeriveASHostGeneric(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveGenericHostAS(t *testing.T) {
	protoId := drkey.Generic
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	srcHost := "127.0.0.2"
	testCases := map[string]struct {
		meta            drkey.HostASMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
	}{
		"valid host-as": {
			meta: drkey.HostASMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x33, 0x41, 0xfe, 0x33, 0x9e, 0xc9,
				0x49, 0x2d, 0xd1, 0x55, 0x9, 0xce, 0x3a, 0x8, 0xb9, 0x60},
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

			key, err := protocoltest.DeriveHostASGeneric(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveGenericHostHost(t *testing.T) {
	protoId := drkey.Generic
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	srcHost := "127.0.0.2"
	dstHost := "127.0.0.1"

	testCases := map[string]struct {
		meta            drkey.HostHostMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
	}{
		"valid host-host": {
			meta: drkey.HostHostMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0xf7, 0xf4, 0xd4, 0x2c, 0xed, 0x8b, 0x7d,
				0x4, 0xb, 0xe5, 0x1b, 0x2f, 0x68, 0x37, 0xf8, 0x86},
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

			key, err := protocoltest.DeriveHostHostGeneric(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveASHostSpecific(t *testing.T) {
	protoId := drkey.SCMP
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	dstHost := ("127.0.0.1")

	testCases := map[string]struct {
		meta            drkey.ASHostMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
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
			expectedKey: drkey.Key{0xb5, 0xa7, 0x56, 0xca, 0xa2, 0xe0,
				0x30, 0xf3, 0xa2, 0xb6, 0xdb, 0xfb, 0x3, 0xe0, 0x3e, 0xb0},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			key, err := protocoltest.DeriveASHostSpecific(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveSpecificHostAS(t *testing.T) {
	protoId := drkey.SCMP
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	srcHost := "127.0.0.2"
	testCases := map[string]struct {
		meta            drkey.HostASMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
	}{
		"valid host-as": {
			meta: drkey.HostASMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x4c, 0xca, 0x42, 0xcd, 0x61, 0xec,
				0x9f, 0x84, 0x80, 0x2b, 0x65, 0xf7, 0x77, 0x4e, 0x98, 0x54},
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

			key, err := protocoltest.DeriveHostASSpecific(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveSpecificHostHost(t *testing.T) {
	protoId := drkey.SCMP
	epoch := drkey.NewEpoch(0, 1)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	lvl1Key := protocoltest.GetLvl1(t, protoId, epoch, srcIA, dstIA)
	srcHost := "127.0.0.2"
	dstHost := "127.0.0.1"

	testCases := map[string]struct {
		meta            drkey.HostHostMeta
		assertFormatErr assert.ErrorAssertionFunc
		expectedKey     drkey.Key
	}{
		"valid host-host": {
			meta: drkey.HostHostMeta{
				ProtoId: drkey.Protocol(10000),
				SrcHost: srcHost,
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x16, 0x4f, 0xc8, 0x46, 0x8, 0x25,
				0xbc, 0x1a, 0xbf, 0x88, 0xb4, 0x68, 0x9c, 0x70, 0xf5, 0x59},
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

			key, err := protocoltest.DeriveHostHostSpecific(tc.meta, lvl1Key)
			tc.assertFormatErr(t, err)
			if err == nil {
				assert.EqualValues(t, tc.expectedKey, key.Key)
			}
		})
	}
}

func TestDeriveLvl1(t *testing.T) {
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	sv, err := drkey.DeriveSV(drkey.SCMP, drkey.NewEpoch(0, 1), asSecret)
	require.NoError(t, err)

	deriver := &drkey.SpecificDeriver{}

	dstIA := xtest.MustParseIA("1-ff00:0:112")

	lvl1Target := drkey.Key{0xa8, 0x23, 0xf5, 0xb9, 0x56, 0xde,
		0x7c, 0xc, 0xbc, 0x5a, 0x69, 0x42, 0xf5, 0xb6, 0xfc, 0x10}

	key, err := deriver.DeriveLvl1(dstIA, sv.Key)
	require.NoError(t, err)
	assert.Equal(t, lvl1Target, key)

	// Calling a second time with the same deriver should yield the
	// same key
	key, err = deriver.DeriveLvl1(dstIA, sv.Key)
	require.NoError(t, err)

	assert.Equal(t, lvl1Target, key)

}
