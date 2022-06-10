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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
			},
			assertFormatErr: assert.Error,
		},
		"invalid as-host": {
			meta: drkey.ASHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				DstHost: "<malformed address>",
			},
			assertFormatErr: assert.Error,
		},
		"valid as-host": {
			meta: drkey.ASHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x5d, 0xe0, 0xd2, 0x4d, 0x7f, 0xd0,
				0xab, 0x2e, 0xeb, 0x9d, 0x40, 0xb6, 0x23, 0x10, 0xbd, 0xd1},
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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: srcHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0xe4, 0x2e, 0xfc, 0x50, 0x1a, 0x21,
				0xdb, 0x6e, 0x14, 0x83, 0x88, 0x81, 0x9b, 0xb9, 0xd0, 0x18},
		},
		"invalid host-as": {
			meta: drkey.HostASMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: srcHost,
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x56, 0xd0, 0x9, 0x4d, 0xe3, 0x3,
				0xf7, 0x3f, 0xf9, 0x25, 0x1a, 0x8b, 0x65, 0x23, 0x2f, 0x4},
		},
		"invalid host-host src": {
			meta: drkey.HostHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: "<malformed address>",
				DstHost: dstHost,
			},
			assertFormatErr: assert.Error,
		},
		"invalid host-host dst": {
			meta: drkey.HostHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
			},
			assertFormatErr: assert.Error,
		},
		"invalid as-host": {
			meta: drkey.ASHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				DstHost: "<malformed address>",
			},
			assertFormatErr: assert.Error,
		},
		"valid as-host": {
			meta: drkey.ASHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0xab, 0x5e, 0x5e, 0x58, 0xb7, 0x7e, 0xdc,
				0xb1, 0x88, 0xc1, 0x36, 0xb9, 0x7d, 0x61, 0xcb, 0xdd},
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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: srcHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x36, 0x4e, 0xd4, 0x79, 0x2d, 0x6b, 0x7f,
				0x2d, 0xa2, 0xa9, 0xcb, 0xab, 0x8c, 0xa6, 0xcd, 0xcf},
		},
		"invalid host-as": {
			meta: drkey.HostASMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
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
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: srcHost,
				DstHost: dstHost,
			},
			assertFormatErr: assert.NoError,
			expectedKey: drkey.Key{0x7f, 0x40, 0xc5, 0xe9, 0xdf, 0x22, 0x5a,
				0xe9, 0x93, 0x97, 0x91, 0xcc, 0x2a, 0x8f, 0xbc, 0xf7},
		},
		"invalid host-host src": {
			meta: drkey.HostHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
				SrcHost: "<malformed address>",
				DstHost: dstHost,
			},
			assertFormatErr: assert.Error,
		},
		"invalid host-host dst": {
			meta: drkey.HostHostMeta{
				Lvl2Meta: drkey.Lvl2Meta{
					ProtoId: drkey.Protocol(10000),
				},
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

	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")

	lvl1Meta := drkey.Lvl1Meta{
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: drkey.SCMP,
	}
	lvl1Target := drkey.Key{0xa8, 0x23, 0xf5, 0xb9, 0x56, 0xde,
		0x7c, 0xc, 0xbc, 0x5a, 0x69, 0x42, 0xf5, 0xb6, 0xfc, 0x10}

	key, err := deriver.DeriveLvl1(lvl1Meta, sv.Key)
	require.NoError(t, err)
	assert.Equal(t, lvl1Target, key)

	// Calling a second time with the same deriver should yield the
	// same key
	key, err = deriver.DeriveLvl1(lvl1Meta, sv.Key)
	require.NoError(t, err)

	assert.Equal(t, lvl1Target, key)

}
